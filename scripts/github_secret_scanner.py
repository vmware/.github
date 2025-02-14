import argparse
import requests
import logging
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import sys
import time
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


class Logger:
    _instance = None

    def __new__(cls, log_level='INFO'):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            numeric_level = getattr(logging, log_level.upper(), None)
            if not isinstance(numeric_level, int):
                raise ValueError(f'Invalid log level: {log_level}')
            logging.basicConfig(level=numeric_level, format='%(asctime)s - %(levelname)s - %(message)s')
        return cls._instance


class GitHubClient:
    def __init__(self, token, max_retries=3):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {"Authorization": f"token {self.token}", "Accept": "application/vnd.github.v3+json"}
        self.max_retries = max_retries
        self.session = self._create_session()
        self.logger = Logger()
        self.rate_limit_remaining = None
        self.rate_limit_reset = None

    def _create_session(self):
        session = requests.Session()
        session.headers.update(self.headers)
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _handle_rate_limit(self):
        if self.rate_limit_remaining is None:
            self.validate_token()

        if self.rate_limit_remaining < 10:
            wait_time = (self.rate_limit_reset - datetime.now()).total_seconds() + 5
            if wait_time > 0:
                logging.info(f"Rate limit approaching. Waiting for {wait_time:.0f} seconds.")
                time.sleep(wait_time)
            self.validate_token()

    def _request(self, method, url, **kwargs):
        self._handle_rate_limit()
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            if 'X-RateLimit-Remaining' in response.headers:
                self.rate_limit_remaining = int(response.headers['X-RateLimit-Remaining'])
                self.rate_limit_reset = datetime.fromtimestamp(int(response.headers['X-RateLimit-Reset']))

            return response
        except requests.exceptions.RequestException as e:
            logging.exception(f"Request failed: {e}")
            raise

    def validate_token(self):
        url = f"{self.base_url}/rate_limit"
        try:
            response = self.session.get(url)
            response.raise_for_status()
            rate_limit = response.json()['resources']['core']
            self.rate_limit_remaining = rate_limit['remaining']
            self.rate_limit_reset = datetime.fromtimestamp(rate_limit['reset'])

            logging.info(f"Rate Limit: {self.rate_limit_remaining} remaining. Reset at {self.rate_limit_reset}")
        except requests.exceptions.RequestException as e:
            logging.exception(f"Token validation failed: {e}")
            raise

    def fetch_repositories(self, org):
        repos = []
        url = f"{self.base_url}/orgs/{org}/repos?per_page=100"
        try:
            while url:
                response = self._request("GET", url)
                repos.extend(response.json())
                url = response.links.get('next', {}).get('url')
        except requests.exceptions.RequestException as e:
            logging.exception(f"Failed to fetch repositories for {org}: {e}")
            raise
        return repos

    def fetch_secret_alerts(self, org, repo, state="open"):
        alerts = []
        url = f"{self.base_url}/repos/{org}/{repo}/secret-scanning/alerts?per_page=100&state={state}"
        try:
            while url:
                response = self._request("GET", url)
                alerts.extend(response.json())
                url = response.links.get('next', {}).get('url')
        except requests.exceptions.RequestException as e:
            logging.exception(f"Failed to fetch {state} alerts for {repo}: {e}")
            raise
        return alerts


class SecretScanner:
    def __init__(self, org, token, output_file, include_inactive=False, log_level='INFO', max_workers=10, max_retries=3):
        self.org = org
        self.token = token
        self.output_file = output_file
        self.include_inactive = include_inactive
        self.max_workers = max_workers
        self.client = GitHubClient(self.token, max_retries)
        self.logger = Logger(log_level)
        self.total_alerts = 0
        self.inactive_alerts = 0
        self.active_alerts = 0


    def generate_report(self):
        try:
            self.client.validate_token()
            repos = self.client.fetch_repositories(self.org)

            if not repos:
                logging.warning("No repositories found in the organization.")
                print("__NO_REPOS__")
                return

            with open(self.output_file, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(["Repository", "Alert ID", "Secret Type", "State", "Alert URL", "Created At", "Updated At", "Resolved Reason"])


                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_repo = {}
                    # Fetch open alerts
                    for repo in repos:
                        future_to_repo[executor.submit(self.client.fetch_secret_alerts, self.org, repo['name'], "open")] = (repo, "open")

                    # Fetch fixed and resolved alerts if include_inactive is True
                    if self.include_inactive:
                        for repo in repos:
                            future_to_repo[executor.submit(self.client.fetch_secret_alerts, self.org, repo['name'], "fixed")] = (repo, "fixed")
                        for repo in repos:
                            future_to_repo[executor.submit(self.client.fetch_secret_alerts, self.org, repo['name'], "resolved")] = (repo, "resolved")


                    for future in as_completed(future_to_repo):
                        (repo, state) = future_to_repo[future]
                        try:
                            alerts = future.result()
                            logging.info(f"Processing {repo['name']} ({state} alerts): Found {len(alerts)} alerts.")
                            for alert in alerts:
                                self.total_alerts += 1
                                if state == "open":
                                  self.active_alerts += 1
                                else:
                                    self.inactive_alerts +=1

                                resolved_reason = alert.get('resolution_comment') if state == 'resolved' else ''

                                writer.writerow([
                                    repo['name'],
                                    alert['number'],
                                     alert.get('secret_type_display_name', alert.get('secret_type', 'Unknown')),
                                    alert['state'],
                                    alert['html_url'],
                                    alert['created_at'],
                                    alert['updated_at'],
                                    resolved_reason
                                ])
                        except Exception as e:
                            logging.exception(f"Error processing alerts for {repo['name']}: {e}")

            logging.info(f"Report generated: {self.output_file}")
            logging.info(f"Total alerts found: {self.total_alerts}")
            logging.info(f"Active alerts: {self.active_alerts}")
            logging.info(f"Inactive alerts: {self.inactive_alerts}")


        except Exception as e:
            logging.exception(f"Failed to generate report: {e}")
            sys.exit(1)

    def get_stats(self):
        return {"total": self.total_alerts, "active": self.active_alerts, "inactive": self.inactive_alerts}




def main():
    parser = argparse.ArgumentParser(description="GitHub Secret Scanner")
    parser.add_argument("--org", required=True, help="GitHub organization name")
    parser.add_argument("--token", required=True, help="GitHub token")
    parser.add_argument("--output", required=True, help="Output CSV file path")
    parser.add_argument("--include-inactive", action='store_true', help="Include inactive alerts in the report")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    parser.add_argument("--max-workers", type=int, default=10, help="Maximum concurrent workers")
    parser.add_argument("--max-retries", type=int, default=3, help="Maximum retries for API requests")

    args = parser.parse_args()

    try:
        scanner = SecretScanner(args.org, args.token, args.output, args.include_inactive, args.log_level, args.max_workers, args.max_retries)
        scanner.generate_report()
        stats = scanner.get_stats()
        print(f"__STATS_START__total={stats['total']},active={stats['active']},inactive={stats['inactive']}__STATS_END__")

    except Exception as e:
        logging.exception(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    
