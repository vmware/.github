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
import re
import base64


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
                return []
            response.raise_for_status()
            alerts.extend(response.json())
            url = response.links.get("next", {}).get("url")
        return alerts

    def get_file_content(self, owner, repo_name, path):
        """Retrieves the content of a file from a GitHub repository."""
        url = f"{self.base_url}/repos/{owner}/{repo_name}/contents/{path}"
        try:
            response = self._request("GET", url)
            response.raise_for_status()
            content = response.json()['content']
            return base64.b64decode(content).decode('utf-8')
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to get file content for {path} in {owner}/{repo_name}: {e}")
            return None

    def get_dependency_version_from_manifest(self, owner, repo_name, manifest_path, package_name, ecosystem):
        """
        Gets the dependency version from the manifest file specified in the alert.
        This method handles different manifest file types and extracts the version.
        """
        if manifest_path == "N/A":
            return "N/A"

        content = self.get_file_content(owner, repo_name, manifest_path)
        if not content:
            return "N/A"

        try:
            if ecosystem.lower() == "npm":
                return self._parse_npm_manifest(content, package_name)
            elif ecosystem.lower() == "maven":
                return self._parse_pom_xml(content, package_name)
            elif ecosystem.lower() == "pip":
                return self._parse_requirements_txt(content, package_name)
            elif ecosystem.lower() == "go":  # Corrected ecosystem name
                return self._parse_go_mod(content, package_name)  # Call the go.mod parser
            # Add more elif blocks for other manifest types (Gemfile.lock, go.mod, etc.)
            else:
                logging.info(f"Unsupported ecosystem (manifest parsing not implemented): {ecosystem}")
                return "N/A"
        except Exception as e:
            logging.exception(f"Error in get_dependency_version_from_manifest: {e}")
            return "N/A"  # Don't crash the entire process.


    def _parse_npm_manifest(self, content, package_name):
        """Parses package-lock.json and yarn.lock files."""
        try:
            # Try parsing as JSON (package-lock.json)
            data = json.loads(content)
            if 'packages' in data:
                for path, package_data in data['packages'].items():
                     if path != "" and "node_modules/" + package_name == path:
                        return package_data.get('version', 'N/A')
            #If not found, check top level.
            if 'dependencies' in data:
                for dep_name, dep_data in data['dependencies'].items():
                    if dep_name == package_name:
                        return dep_data.get('version', 'N/A')
        except json.JSONDecodeError:
            # If JSON parsing fails, try parsing as yarn.lock
             for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):  # Skip empty lines and comments
                  continue
                # Check if ANY of the keys on this line contain the package name.
                for key in line.split(","):  # Split into individual keys
                    key = key.strip().split(":")[0] # Get rid of ""
                    if key.startswith(package_name + "@") or key == package_name: #check if starts with or equal
                        next_line = content.splitlines()[content.splitlines().index(line) + 1].strip() # Check the NEXT line for "version"
                        if next_line.startswith("version"):
                            match = re.search(r'version[:=]\s*"?([^\s",]+)"?', next_line) #check in the next line
                            if match:
                                return match.group(1)  # Group 1 contains the version
        return "N/A" # Package not found

    def _parse_requirements_txt(self, content, package_name):
        """Parses a requirements.txt file."""
        for line in content.splitlines():
            line = line.strip()
            if line.startswith(package_name + "=="):
                return line.split("==")[1]  # Extract version
            # Handle case where there's no '=='
            elif line.startswith(package_name):
               parts = line.split()
               if len(parts) > 1:
                   return parts[1]
        return "N/A"
    
    def _parse_go_mod(self, content, package_name):
      """
      Parses a go.mod file to find the version of a specific package.
      Handles direct and indirect dependencies, and quoted module paths.
      """
      in_require_block = False
      for line in content.splitlines():
          line = line.strip()
          if line.startswith("require ("):
              in_require_block = True
              continue
          elif line.startswith(")"):
              in_require_block = False
              continue
          if in_require_block:
              # Handles quoted and unquoted module paths
              parts = line.split()
              if len(parts) >= 2:
                  module_path = parts[0].strip('"')  # Remove quotes if present
                  if module_path == package_name:
                      version = parts[1]
                      # Handle indirect dependencies, marked with "// indirect"
                      if len(parts) > 2 and parts[2] == "//":
                          if "indirect" in parts[2:]:
                            version = f"{version} (indirect)" # Mark as indirect
                      return version
          #Handle requires outside the require block.
          elif line.startswith("require " + package_name):
              parts = line.split()
              if len(parts) >= 3: # require + package + version
                  return parts[2]
      return "N/A"  # Not found

    def _parse_pom_xml(self, content, package_name):
      try:
          # Use regex to find the dependency within the <dependencies> section
          match = re.search(rf'<artifactId>{package_name}</artifactId>.*?<version>(.*?)</version>', content, re.DOTALL)
          if match:
              version_str = match.group(1).strip()
              # Check if it's a property reference
              if version_str.startswith("${") and version_str.endswith("}"):
                  property_name = version_str[2:-1]
                  # Extract properties from the POM
                  properties = {}
                  properties_match = re.search(r'<properties>(.*?)</properties>', content, re.DOTALL)
                  if properties_match:
                      for prop_match in re.findall(r'<([^>]+)>(.*?)</\1>', properties_match.group(1)):
                          prop_name, prop_value = prop_match
                          properties[prop_name.strip()] = prop_value.strip()
                  return properties.get(property_name, "N/A") # Get value from properties
              else:
                 return version_str
          return "N/A" # Version not found
      except Exception as e:
          logging.exception(f"Error parsing pom.xml: {e}")
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
            print("__NO_REPOS__")
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
                        # print(json.dumps(alert, indent=2))  # Uncomment for debugging.
                        try:
                            dependency = alert.get("dependency", {})
                            pkg = dependency.get("package", {})
                            package_name = pkg.get("name", "N/A")
                            manifest_path = dependency.get("manifest_path", "N/A")
                            ecosystem = pkg.get("ecosystem", "N/A")

                             # --- Use dependency.version if available, otherwise fallback ---
                            current_version = dependency.get("version")
                            if current_version is None:  # If version is NOT in the alert
                                current_version = self.client.get_dependency_version_from_manifest(
                                    repo['owner'], repo['name'], manifest_path, package_name, ecosystem
                                )
                            # --- End Use Alert Data ---

                            security_advisory = alert.get("security_advisory", {})
                            # --- Use security_vulnerability, not vulnerabilities array ---
                            security_vulnerability = alert.get("security_vulnerability", {})
                            vulnerable_range = security_vulnerability.get("vulnerable_version_range", "N/A")
                            # --- End Use security_vulnerability ---

                            severity = security_advisory.get("severity", "N/A")
                            alert_url = alert.get("html_url", "N/A")  # Get alert URL
                            # Create Excel hyperlink formula
                            severity_link = f'=HYPERLINK("{alert_url}", "{severity}")'

                            first_patched = security_vulnerability.get("first_patched_version", {})
                            update_available = first_patched.get("identifier", "N/A") if first_patched else "N/A"

                            #print(f"DEBUG: Data before append: {repo['owner']}/{repo['name']}, {package_name}, {current_version}, {vulnerable_range}, {severity}, {update_available}")

                            all_vulnerabilities.append({
                                "Repository Name": f"{repo['owner']}/{repo['name']}",
                                "Package Name": package_name,
                                "Current Version": current_version,
                                "Vulnerable Versions": vulnerable_range,
                                "Severity": severity_link,  # Use the hyperlink formula
                                "Update Available": update_available
                            })
                            self.total_vulnerabilities += 1
                        except KeyError as e:
                            logging.warning(f"Missing key in alert data for repo {repo['owner']}/{repo['name']}: {e}. Skipping.")
                            print(f"KeyError: {e}") #KEEP
                            continue
                        except Exception as e:
                            logging.exception(f"Error processing alert data for repo {repo['owner']}/{repo['name']}: {e}. Skipping.")
                            print(f"Other Exception: {e}") #KEEP
                            continue
                except Exception as e:
                    logging.exception(f"Error processing repo {repo['owner']}/{repo['name']}: {e}")

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
    
