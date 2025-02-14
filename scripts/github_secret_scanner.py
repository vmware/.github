import argparse
import requests
import logging
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from datetime import datetime, timedelta
from contextlib import contextmanager
import sys
import time
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


# Logger class to manage logging levels and messages
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


# GitHubClient class to handle GitHub API interactions (repos, secret scanning)
class GitHubClient:
    def __init__(self, token, max_retries=3):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {"Authorization": f"token {self.token}", "Accept": "application/vnd.github.v3+json"}
        self.max_retries = max_retries
        self.session = self._create_session()  # Create session once
        self.logger = Logger()  # Use the Logger instance
        self.rate_limit_remaining = None
        self.rate_limit_reset = None

    def _create_session(self):
        """Create a requests session with retry logic."""
        session = requests.Session()
        session.headers.update(self.headers)
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=2,  # Exponential backoff
            status_forcelist=[429, 500, 502, 503, 504],  # Retry on these status codes
            allowed_methods=["GET"]  # Only retry GET requests
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)  # Usually not needed for GitHub API
        return session

    def _handle_rate_limit(self):
        """Checks remaining rate limit and waits if necessary."""
        if self.rate_limit_remaining is None or self.rate_limit_remaining < 50: # Threshold.
            self.validate_token() # Updates the rate limits

        if self.rate_limit_remaining < 10:
            wait_time = (self.rate_limit_reset - datetime.now()).total_seconds() + 5 # Add a buffer
            if wait_time > 0:
                self.logger.info(f"Rate limit approaching. Waiting for {wait_time:.0f} seconds.")
                time.sleep(wait_time)
            self.validate_token() # Refresh after waiting.

    def _request(self, method, url, **kwargs):
        """Centralized request handling with rate limit checks and error handling."""
        self._handle_rate_limit()
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            if 'X-RateLimit-Remaining' in response.headers:
                self.rate_limit_remaining = int(response.headers['X-RateLimit-Remaining'])
                self.rate_limit_reset = datetime.fromtimestamp(int(response.headers['X-RateLimit-Reset']))

            return response
        except requests.exceptions.RequestException as e:
            self.logger.exception(f"Request failed: {e}")  # Use exception for full traceback
            raise

    def validate_token(self):
        url = f"{self.base_url}/rate_limit"
        try:
            response = self._request("GET", url)
            rate_limit = response.json()['resources']['core']
            self.rate_limit_remaining = rate_limit['remaining']
            self.rate_limit_reset = datetime.fromtimestamp(rate_limit['reset'])

            if self.rate_limit_remaining > 0:
                self.logger.info(f"Rate Limit: {self.rate_limit_remaining} remaining. Reset at {self.rate_limit_reset}")
            else:
                self.logger.error(f"Rate limit exceeded. Reset at {self.rate_limit_reset}")
                raise Exception("Rate limit exceeded.")
        except requests.exceptions.RequestException as e:
            self.logger.exception(f"Token validation failed: {e}")
            raise

    @lru_cache(maxsize=100)
    def fetch_default_branch(self, org, repo):
        """Fetch default branch of a repo (cached)."""
        url = f"{self.base_url}/repos/{org}/{repo}"
        try:
            response = self._request("GET", url)
            return response.json()['default_branch']
        except requests.exceptions.RequestException as e:
            self.logger.exception(f"Failed to fetch default branch for {repo}: {e}")
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
            self.logger.exception(f"Failed to fetch repositories for {org}: {e}")
            raise
        return repos

    def fetch_secret_alerts(self, org, repo):
        alerts = []
        url = f"{self.base_url}/repos/{org}/{repo}/secret-scanning/alerts?per_page=100&state=open"
        try:
            while url:
                response = self._request("GET", url)
                alerts.extend(response.json())
                url = response.links.get('next', {}).get('url')
        except requests.exceptions.RequestException as e:
            self.logger.exception(f"Failed to fetch alerts for {repo}: {e}")
            raise
        return alerts


# SecretScanner class to handle the logic related to scanning and reporting
class SecretScanner:
    def __init__(self, org, token, output_file, include_inactive=False, log_level='INFO', max_workers=10, max_retries=3):
        self.org = org
        self.token = token
        self.output_file = output_file
        self.include_inactive = include_inactive
        self.max_workers = max_workers
        self.client = GitHubClient(self.token, max_retries) #Pass max_retries
        self.logger = Logger(log_level)  # Initialize and use the Logger

    def is_alert_active(self, org, repo, alert):
        """Checks if an alert is active (at HEAD of default branch)."""
        try:
            default_branch = self.client.fetch_default_branch(org, repo)
            if 'locations' in alert and alert['locations']:
                for location in alert['locations']:
                    if location.get('type') == 'commit':
                        details_url = location.get('details_url')
                        if details_url:  # Check if details_url exists
                            location_details = self.client._request("GET", details_url).json()
                            path = location_details.get('path')
                            commit_sha = location_details.get('commit_sha')
                            if path and commit_sha:
                                commits_url = f"{self.client.base_url}/repos/{org}/{repo}/commits?path={path}&sha={default_branch}"
                                commits = self.client._request("GET", commits_url).json()

                                if commits and commits[0]['sha'] == commit_sha:
                                    return True
            return False
        except requests.exceptions.RequestException as e:
            self.logger.exception(f"Error checking if alert is active for {repo}: {e}")
            return False

    def generate_report(self):
        try:
            # Validate token
            self.client.validate_token()

            # Fetch repositories
            repos = self.client.fetch_repositories(self.org)

            with open(self.output_file, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(["Repository", "Alert ID", "Secret Type", "Status", "Alert URL", "Last Updated"])

                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_repo = {
                        executor.submit(self.client.fetch_secret_alerts, self.org, repo['name']): repo
                        for repo in repos
                    }

                    for future in as_completed(future_to_repo):
                        repo = future_to_repo[future]
                        try:
                            alerts = future.result()
                            for alert in alerts:
                                is_active = self.is_alert_active(self.org, repo['name'], alert)
                                if self.include_inactive or is_active:
                                    status = "Active" if is_active else "Inactive"
                                    writer.writerow([
                                        repo['name'],
                                        alert['number'],
                                        alert.get('secret_type_display_name', alert.get('secret_type', 'Unknown')),
                                        status,
                                        alert['html_url'],
                                        alert['updated_at']
                                    ])
                        except Exception as e:
                            self.logger.exception(f"Error processing alerts for {repo['name']}: {e}")

            self.logger.info(f"Report generated: {self.output_file}")

        except Exception as e:
            self.logger.exception(f"Failed to generate report: {e}")
            sys.exit(1)


# ReportGenerator class to process the report (kept as-is, since no issues found)
class ReportGenerator:
    @staticmethod
    def count_alerts(input_file):
        total = 0
        with open(input_file, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header
            for _ in reader:
                total += 1
        return total

    @staticmethod
    def count_active_alerts(input_file):
        active = 0
        with open(input_file, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header
            for row in reader:
                if row[3] == "Active":
                    active += 1
        return active


# Main function to handle arguments and initiate the scanning process
def main():
    parser = argparse.ArgumentParser(description="GitHub Secret Scanner")
    parser.add_argument("--org", required=True, help="GitHub organization name")
    parser.add_argument("--token", required=True, help="GitHub token")
    parser.add_argument("--output", required=True, help="Output CSV file path")
    parser.add_argument("--include-inactive", action='store_true', help="Include inactive alerts in the report")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    parser.add_argument("--max-workers", type=int, default=10, help="Maximum concurrent workers")
    parser.add_argument("--max-retries", type=int, default=3, help="Maximum retries for API requests") # Added argument

    args = parser.parse_args()

    try:
        scanner = SecretScanner(args.org, args.token, args.output, args.include_inactive, args.log_level, args.max_workers, args.max_retries) # Pass max_retries
        scanner.generate_report()

        total_alerts = ReportGenerator.count_alerts(args.output)
        active_alerts = ReportGenerator.count_active_alerts(args.output)

        logging.info(f"Total alerts found: {total_alerts}")  # Use logging.info
        logging.info(f"Active alerts: {active_alerts}")

    except Exception as e:
        logging.exception(f"An error occurred: {e}") # Use logging.exception.
        sys.exit(1)


if __name__ == "__main__":
    main()
