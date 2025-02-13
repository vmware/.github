import argparse
import requests
import logging
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from datetime import datetime
from contextlib import contextmanager
import sys

# Logger class to manage logging levels and messages
class Logger:
    @staticmethod
    def setup(log_level='INFO'):
        numeric_level = getattr(logging, log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f'Invalid log level: {log_level}')
        logging.basicConfig(level=numeric_level, format='%(asctime)s - %(levelname)s - %(message)s')


# GitHubClient class to handle GitHub API interactions (repos, secret scanning)
class GitHubClient:
    def __init__(self, token):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {"Authorization": f"token {self.token}", "Accept": "application/vnd.github.v3+json"}

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
        try:
            with self.github_session() as session:
                response = session.get(url)
                response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
                rate_limit = response.json()['resources']['core']
                if rate_limit['remaining'] > 0:
                    logging.info(f"Rate Limit: {rate_limit['remaining']} remaining.")
                else:
                    logging.error(f"Rate limit exceeded. Reset at {datetime.utcfromtimestamp(rate_limit['reset'])}")
                    raise Exception("Rate limit exceeded.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Token validation failed: {e}")
            raise  # Re-raise the exception to be caught by the main function

    @lru_cache(maxsize=100)
    def fetch_default_branch(self, org, repo):
        """Fetch default branch of a repo (cached to avoid redundant calls)."""
        url = f"{self.base_url}/repos/{org}/{repo}"
        try:
            with self.github_session() as session:
                response = session.get(url)
                response.raise_for_status()
                repo_data = response.json()
                return repo_data['default_branch']
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to fetch default branch for {repo}: {e}")
            raise

    def fetch_repositories(self, org):
        repos = []
        url = f"{self.base_url}/orgs/{org}/repos?per_page=100"
        try:
            with self.github_session() as session:
                while url:
                    response = session.get(url)
                    response.raise_for_status()
                    repos.extend(response.json())
                    url = response.links.get('next', {}).get('url')
        except requests.exceptions.RequestException as e:
             logging.error(f"Failed to fetch repositories for {org}: {e}")
             raise
        return repos

    def fetch_secret_alerts(self, org, repo):
        alerts = []
        url = f"{self.base_url}/repos/{org}/{repo}/secret-scanning/alerts?per_page=100&state=open" # Consider only Open Alerts.
        try:
            with self.github_session() as session:
                while url:
                    response = session.get(url)
                    response.raise_for_status()
                    alerts.extend(response.json())
                    url = response.links.get('next', {}).get('url')
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to fetch alerts for {repo}: {e}")
            raise
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

    def is_alert_active(self, org, repo, alert):
        """Checks if an alert is active (at HEAD of default branch)."""
        try:
            default_branch = self.client.fetch_default_branch(org, repo)
            if 'locations' in alert:
                for location in alert['locations']:
                    if location['type'] == 'commit':
                        with self.client.github_session() as session:
                            location_response = session.get(location['details_url'])
                            location_response.raise_for_status()
                            location_details = location_response.json()

                            if 'path' in location_details: # sometimes, details do not have the path element.
                                commits_url = f"{self.client.base_url}/repos/{org}/{repo}/commits?path={location_details['path']}&sha={default_branch}"
                                commits_response = session.get(commits_url)
                                commits_response.raise_for_status()
                                commits = commits_response.json()

                                if commits and commits[0]['sha'] == location_details['commit_sha']:
                                    return True # Found the commit at head
            return False # Not found, or no locations.
        except requests.exceptions.RequestException as e:
            logging.error(f"Error checking if alert is active for {repo}: {e}")
            return False # Consider not active if errors occur

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
                    # Submit all fetch_secret_alerts tasks
                    future_to_repo = {
                        executor.submit(self.client.fetch_secret_alerts, self.org, repo['name']): repo
                        for repo in repos
                    }

                    # Process results as they become available
                    for future in as_completed(future_to_repo):
                        repo = future_to_repo[future]
                        try:
                            alerts = future.result()  # Get the result (list of alerts)
                            for alert in alerts:
                                is_active = self.is_alert_active(self.org, repo['name'], alert)
                                if self.include_inactive or is_active:
                                    status = "Active" if is_active else "Inactive" #Explicit state.
                                    writer.writerow([
                                        repo['name'],
                                        alert['number'],
                                        alert.get('secret_type_display_name', alert.get('secret_type', 'Unknown')),
                                        status,
                                        alert['html_url'],
                                        alert['updated_at']
                                    ])
                        except Exception as e:
                            logging.error(f"Error processing alerts for {repo['name']}: {e}") # Log individual repo errors.

            logging.info(f"Report generated: {self.output_file}")

        except Exception as e:
            logging.error(f"Failed to generate report: {e}")
            sys.exit(1)  # Exit with an error code to signal failure to the workflow


# ReportGenerator class to process the report (kept as-is, since no issues found)
class ReportGenerator:
    @staticmethod
    def count_alerts(input_file):
        total = 0
        with open(input_file, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header
            for _ in reader:  # Use _ for unused loop variable
                total += 1
        return total

    @staticmethod
    def count_active_alerts(input_file):
        active = 0
        with open(input_file, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header
            for row in reader:
                if row[3] == "Active":  # Index 3 now corresponds to "Status"
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

    try:
        # Instantiate SecretScanner and generate the report
        scanner = SecretScanner(args.org, args.token, args.output, args.include_inactive, args.log_level, args.max_workers)
        scanner.generate_report()

        # Process report statistics
        total_alerts = ReportGenerator.count_alerts(args.output)
        active_alerts = ReportGenerator.count_active_alerts(args.output)

        logging.info(f"Total alerts found: {total_alerts}")
        logging.info(f"Active alerts: {active_alerts}")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1) # Exit with error code to be captured on GH Actions.


if __name__ == "__main__":
    main()
