import argparse
import requests
import logging
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from datetime import datetime
from contextlib import contextmanager


# Logger class to manage logging levels and messages
class Logger:
    @staticmethod
    def setup(log_level='INFO'):
        logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')


# GitHubClient class to handle GitHub API interactions (repos, secret scanning)
class GitHubClient:
    def __init__(self, token):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {"Authorization": f"token {self.token}"}

    @contextmanager
    def github_session(self):
        """Context manager to handle GitHub API session."""
        session = requests.Session()
        session.headers.update(self.headers)
        try:
            yield session
        finally:
            session.close()

    def validate_token(self):
        url = f"{self.base_url}/rate_limit"
        with self.github_session() as session:
            response = session.get(url)
            if response.status_code == 200:
                rate_limit = response.json()['resources']['core']
                if rate_limit['remaining'] > 0:
                    logging.info(f"Rate Limit: {rate_limit['remaining']} remaining.")
                else:
                    logging.error(f"Rate limit exceeded. Reset at {datetime.utcfromtimestamp(rate_limit['reset'])}")
                    raise Exception("Rate limit exceeded.")
            else:
                logging.error("Token validation failed.")
                raise Exception("Invalid GitHub token.")

    @lru_cache(maxsize=100)
    def fetch_default_branch(self, org, repo):
        """Fetch default branch of a repo (cached to avoid redundant calls)."""
        url = f"{self.base_url}/repos/{org}/{repo}"
        with self.github_session() as session:
            response = session.get(url)
            if response.status_code == 200:
                repo_data = response.json()
                return repo_data['default_branch']
            else:
                logging.error(f"Failed to fetch default branch for {repo}: {response.status_code}")
                raise Exception(f"Error fetching default branch for {repo}")

    def fetch_repositories(self, org):
        repos = []
        url = f"{self.base_url}/orgs/{org}/repos?per_page=100"
        with self.github_session() as session:
            while url:
                response = session.get(url)
                if response.status_code == 200:
                    repos.extend(response.json())
                    url = response.links.get('next', {}).get('url')
                else:
                    logging.error(f"Failed to fetch repositories: {response.status_code}")
                    raise Exception("Error fetching repositories")
        return repos

    def fetch_secret_alerts(self, org, repo):
        url = f"{self.base_url}/repos/{org}/{repo}/secret-scanning/alerts?per_page=100"
        alerts = []
        with self.github_session() as session:
            while url:
                response = session.get(url)
                if response.status_code == 200:
                    alerts.extend(response.json())
                    url = response.links.get('next', {}).get('url')
                else:
                    logging.error(f"Failed to fetch alerts for {repo}: {response.status_code}")
                    raise Exception("Error fetching secret alerts")
        return alerts


# SecretScanner class to handle the logic related to scanning and reporting
class SecretScanner:
    def __init__(self, org, token, output_file, include_inactive=False, log_level='INFO', max_workers=10):
        self.org = org
        self.token = token
        self.output_file = output_file
        self.include_inactive = include_inactive
        self.max_workers = max_workers
        self.client = GitHubClient(self.token)
        Logger.setup(log_level)

    def generate_report(self):
        # Validate token
        self.client.validate_token()

        # Fetch repositories and secret alerts concurrently
        repos = self.client.fetch_repositories(self.org)
        with open(self.output_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Repository", "Alert ID", "Secret Type", "Status", "Alert URL", "Last Updated"])

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Fetch repository details and secret alerts concurrently
                futures = {
                    executor.submit(self.client.fetch_secret_alerts, self.org, repo['name']): repo for repo in repos
                }

                # Fetch and process data concurrently
                for future in as_completed(futures):
                    repo = futures[future]
                    try:
                        alerts = future.result()
                        for alert in alerts:
                            status = "Resolved" if alert['state'] == "resolved" else "Active"
                            if not self.include_inactive and status == "Resolved":
                                continue  # Skip inactive alerts
                            writer.writerow([repo['name'], alert['id'], alert['secret_type'], status,
                                             f"https://github.com/{self.org}/{repo['name']}/security/secret-scanning/alerts/{alert['id']}",
                                             alert['created_at']])

        logging.info(f"Report generated: {self.output_file}")


# ReportGenerator class to process the report
class ReportGenerator:
    @staticmethod
    def count_alerts(input_file):
        total = 0
        with open(input_file, mode='r') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header
            for row in reader:
                total += 1
        return total

    @staticmethod
    def count_active_alerts(input_file):
        active = 0
        with open(input_file, mode='r') as file:
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

    args = parser.parse_args()

    # Instantiate SecretScanner and generate the report
    scanner = SecretScanner(args.org, args.token, args.output, args.include_inactive, args.log_level, args.max_workers)
    scanner.generate_report()

    # Process report statistics
    total_alerts = ReportGenerator.count_alerts(args.output)
    active_alerts = ReportGenerator.count_active_alerts(args.output)

    logging.info(f"Total alerts found: {total_alerts}")
    logging.info(f"Active alerts: {active_alerts}")


if __name__ == "__main__":
    main()
