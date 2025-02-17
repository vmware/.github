import os
import csv
import requests
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import sys
import time
import json


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
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "dependency-alerts-report-script"
        }
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
            allowed_methods=["GET"]  # Only retry GET requests
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _handle_rate_limit(self):
        if self.rate_limit_remaining is None:
            self.validate_token()

        if self.rate_limit_remaining < 50:  # More conservative threshold
            wait_time = (self.rate_limit_reset - datetime.now()).total_seconds() + 5
            if wait_time > 0:
                logging.info(f"Rate limit approaching. Waiting for {wait_time:.0f} seconds.")
                time.sleep(wait_time)
            self.validate_token()  # Re-validate after waiting

    def _request(self, method, url, **kwargs):
        self._handle_rate_limit()
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            if 'X-RateLimit-Remaining' in response.headers:
                self.rate_limit_remaining = int(response.headers['X-RateLimit-Remaining'])
                self.rate_limit_reset = datetime.fromtimestamp(int(response.headers['X-RateLimit-Reset']))
            return response

        except requests.exceptions.RequestException as e:
            logging.exception(f"Request failed: {e}")
            raise

    def validate_token(self):
        """Validates the GitHub token and retrieves initial rate limit information."""
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


    def get_repositories(self, org_name, repo_list=None):
        """Retrieves a list of repositories to scan.  Prioritizes org, then list."""
        repositories = []
        if org_name:
            # Fetch all repos in the organization (with pagination)
            url = f"{self.base_url}/orgs/{org_name}/repos?per_page=100"
            while url:
                response = self._request("GET", url)
                for repo in response.json():
                    repositories.append({"name": repo["name"], "owner": repo["owner"]["login"]})
                url = response.links.get("next", {}).get("url")

        elif repo_list:
            # Use the provided comma-separated list
            for repo_name in repo_list.split(","):
                parts = repo_name.strip().split("/")
                if len(parts) == 2:
                    owner, repo = parts
                else:
                    owner = os.environ.get("GITHUB_REPOSITORY", "/").split("/")[0]
                    repo = parts[0]
                repositories.append({"name": repo, "owner": owner})
        else:
            # Default to the current repository
            full_repo = os.environ.get("GITHUB_REPOSITORY")
            if not full_repo:
                raise ValueError("GITHUB_REPOSITORY environment variable is not set.")
            owner, repo = full_repo.split("/")
            repositories.append({"name": repo, "owner": owner})

        return repositories


    def get_dependabot_alerts(self, owner, repo_name):
        """Retrieves Dependabot alerts for a single repository (with pagination)."""
        alerts = []
        url = f"{self.base_url}/repos/{owner}/{repo_name}/dependabot/alerts?per_page=100&state=open"
        while url:
            response = self._request("GET", url)
            if response.status_code == 404:
                logging.info(f"Dependabot alerts not available or repo not found for {owner}/{repo_name}.")
                return []  # Return empty list, not None
            response.raise_for_status()  # Handle other errors
            alerts.extend(response.json())
            url = response.links.get("next", {}).get("url")
        return alerts

    def get_dependency_version(self, owner, repo_name, dependency_name):
        """Retrieves the current version of a dependency using the Dependency Graph API."""
        # Use the compare API to get the diff between the base and HEAD, including dependency changes
        url = f"{self.base_url}/repos/{owner}/{repo_name}/dependency-graph/compare/HEAD...main" # Assuming 'main' as default branch, change it to your branch.
        try:
            response = self._request("GET", url)
            response.raise_for_status()
            data = response.json()

            # Find the dependency in the 'dependencies' list
            for dep in data.get('dependencies', []):
                if dep.get('package_url') and dependency_name in dep.get('package_url'):
                    # Extract version information. It can be a dictionary or a string.
                    if isinstance(dep.get('version'), dict):
                         return dep['version'].get('version', 'N/A') #Handle nested dictionaries.
                    else:
                        return dep.get('version', 'N/A') #Handle simple strings

            return "N/A" # Dependency not found

        except requests.exceptions.RequestException as e:
            logging.exception(f"Failed to get dependency version for {dependency_name} in {owner}/{repo_name}: {e}")
            return "N/A"


class DependencyScanner:
    """
    Scans GitHub repositories for vulnerable dependencies using the Dependabot alerts API.
    """

    def __init__(self, github_token, org_name=None, repo_list=None, log_level='INFO', max_workers=10, max_retries=3):
        """
        Initializes the DependencyScanner.
        """
        self.github_token = github_token
        self.org_name = org_name
        self.repo_list = repo_list
        self.max_workers = max_workers
        self.client = GitHubClient(github_token, max_retries)
        self.logger = Logger(log_level)  # Use the custom Logger class
        self.total_vulnerabilities = 0
        self.processed_repos = 0

    def generate_csv_report(self, filename=None):
        """Generates a CSV report of vulnerable dependencies."""

        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnerability_report_{timestamp}.csv"

        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)
        filepath = os.path.join(reports_dir, filename)

        all_vulnerabilities = []
        repositories = self.client.get_repositories(self.org_name, self.repo_list)
        if not repositories:
            logging.warning("No repositories found to scan.")
            print("__NO_REPOS__") #For github actions
            return


        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_repo = {
                executor.submit(self.client.get_dependabot_alerts, repo["owner"], repo["name"]): repo
                for repo in repositories
            }

            for future in as_completed(future_to_repo):
                repo = future_to_repo[future]
                try:
                    alerts = future.result()
                    self.processed_repos += 1
                    logging.info(f"Processed {repo['owner']}/{repo['name']}: Found {len(alerts)} alerts.")

                    for alert in alerts:
                        try:  # Robust error handling
                            dependency = alert.get("dependency", {})
                            pkg = dependency.get("package", {})
                            package_name = pkg.get("name", "N/A")

                            # --- CORRECTED VERSION RETRIEVAL ---
                            current_version = self.client.get_dependency_version(repo['owner'], repo['name'], package_name)
                            # --- END CORRECTED VERSION RETRIEVAL ---

                            security_advisory = alert.get("security_advisory", {})
                            vulnerable_range = security_advisory.get("vulnerable_version_range", "N/A")
                            severity = security_advisory.get("severity", "N/A")

                            security_vulnerability = alert.get("security_vulnerability", {})
                            first_patched = security_vulnerability.get("first_patched_version", {})
                            update_available = first_patched.get("identifier", "N/A") if first_patched else "N/A"

                            all_vulnerabilities.append({
                                "Repository Name": f"{repo['owner']}/{repo['name']}",
                                "Package Name": package_name,
                                "Current Version": current_version,
                                "Vulnerable Versions": vulnerable_range,
                                "Severity": severity,
                                "Update Available": update_available
                            })
                            self.total_vulnerabilities += 1
                        except KeyError as e:
                            logging.warning(f"Missing key in alert data for repo {repo['owner']}/{repo['name']}: {e}. Skipping.")
                            continue
                        except Exception as e:
                            logging.exception(f"Error processing alert data for repo {repo['owner']}/{repo['name']}: {e}. Skipping.")
                            continue
                except Exception as e:
                    logging.exception(f"Error processing repo {repo['owner']}/{repo['name']}: {e}")
                    # Don't raise here; continue with the next repository

        if not all_vulnerabilities:
            logging.info("No vulnerabilities found.")
            return


        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "Repository Name",
                "Package Name",
                "Current Version",
                "Vulnerable Versions",
                "Severity",
                "Update Available",
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_vulnerabilities)
        logging.info(f"CSV report generated: {filepath}")

    def run_scan(self, filename=None):
        """Runs the complete scan and report generation."""
        self.generate_csv_report(filename)

    def get_stats(self):
        return {"total": self.total_vulnerabilities, "processed_repos": self.processed_repos}


def main():
    parser = argparse.ArgumentParser(description="GitHub Dependency Scanner")
    parser.add_argument("--token", required=True, help="GitHub token")
    parser.add_argument("--output", required=True, help="Output CSV file path")
    parser.add_argument("--org", help="GitHub organization name (optional)")
    parser.add_argument("--repo-list", help="Comma-separated list of repositories (optional)")
    parser.add_argument("--log-level", default="INFO", help="Logging level (default: INFO)")
    parser.add_argument("--max-workers", type=int, default=10, help="Maximum concurrent workers (default: 10)")
    parser.add_argument("--max-retries", type=int, default=3, help="Maximum retries for API requests (default: 3)")

    args = parser.parse_args()

    if not args.org and not args.repo_list and not os.environ.get("GITHUB_REPOSITORY"):
        print("Error: Must specify either --org, --repo-list, or run within a GitHub Actions context.", file=sys.stderr)
        sys.exit(1)

    scanner = DependencyScanner(
        github_token=args.token,
        org_name=args.org,
        repo_list=args.repo_list,
        log_level=args.log_level,
        max_workers=args.max_workers,
        max_retries=args.max_retries
    )
    scanner.run_scan(args.output)
    stats = scanner.get_stats()
    print(f"__STATS_START__total={stats['total']},processed_repos={stats['processed_repos']}__STATS_END__")


if __name__ == "__main__":
    main()
    
