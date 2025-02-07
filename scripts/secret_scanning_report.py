import requests
import csv
import argparse
import time
from urllib.parse import urlparse

# Cache for default branches to minimize API calls
default_branches_cache = {}

def parse_link_header(link_header):
    """Parse GitHub's Link header for pagination"""
    links = {}
    if not link_header:
        return links
    for link in link_header.split(', '):
        parts = link.split('; ')
        if len(parts) < 2:
            continue
        url = parts[0].strip('<>')
        rel = parts[1].split('=')[1].strip('"')
        links[rel] = url
    return links

def get_alerts_with_retry(url, headers, retries=3):
    """Handle rate limits and transient errors"""
    for _ in range(retries):
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response
        elif response.status_code == 403 and 'rate limit' in response.text:
            reset_time = int(response.headers.get('X-RateLimit-Reset', time.time() + 300))
            sleep_time = max(reset_time - time.time(), 300)
            print(f"Rate limited. Sleeping for {sleep_time} seconds")
            time.sleep(sleep_time)
        else:
            time.sleep(2)
    response.raise_for_status()
    return response

def get_default_branch(repo, headers):
    """Get and cache the default branch for a repository"""
    if repo in default_branches_cache:
        return default_branches_cache[repo]
    
    repo_url = f"https://api.github.com/repos/{repo}"
    response = get_alerts_with_retry(repo_url, headers)
    default_branch = response.json()['default_branch']
    default_branches_cache[repo] = default_branch
    return default_branch

def is_at_head(repo, headers, file_path, commit_sha):
    """Check if a commit is at the HEAD of the default branch"""
    default_branch = get_default_branch(repo, headers)
    url = f"https://api.github.com/repos/{repo}/commits?path={file_path}&sha={default_branch}"
    response = get_alerts_with_retry(url, headers)
    commits = response.json()
    return commits and commits[0]['sha'] == commit_sha

def main():
    parser = argparse.ArgumentParser(description='Generate GHAS secret scanning report.')
    parser.add_argument('--org', required=True, help='GitHub organization')
    parser.add_argument('--token', required=True, help='GitHub access token')
    parser.add_argument('--output', default='secrets_report.csv', help='Output CSV file')
    parser.add_argument('--include-inactive', action='store_true', help='Include inactive alerts')
    args = parser.parse_args()

    headers = {
        'Authorization': f'token {args.token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    api_url = f'https://api.github.com/orgs/{args.org}/secret-scanning/alerts?per_page=100&state=open'

    with open(args.output, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['Repository', 'Alert ID', 'Secret Type', 'Is Active', 'Last Updated']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        next_url = api_url
        processed_count = 0
        
        while next_url:
            response = get_alerts_with_retry(next_url, headers)
            
            if response.status_code != 200:
                raise Exception(f'API request failed: {response.status_code} - {response.text}')
            
            alerts = response.json()
            for alert in alerts:
                repo_name = alert['repository']['full_name']
                alert_id = alert['number']
                secret_type = alert['secret_type_display_name']
                updated_at = alert['updated_at']
                
                is_active = False
                if 'locations' in alert:
                    for location in alert['locations']:
                        if location['type'] == 'commit':
                            location_details_url = location['details_url']
                            location_response = get_alerts_with_retry(location_details_url, headers)
                            location_details = location_response.json()

                            if 'path' in location_details:
                                if is_at_head(repo_name, headers, location_details['path'], location_details['commit_sha']):
                                    is_active = True
                                    break

                if is_active or args.include_inactive:
                    alert_url = f'https://github.com/{repo_name}/security/secret-scanning/{alert_id}'
                    alert_hyperlink = f'=HYPERLINK("{alert_url}", "{alert_id}")'

                    writer.writerow({
                        'Repository': repo_name,
                        'Alert ID': alert_hyperlink,
                        'Secret Type': secret_type,
                        'Is Active': 'Yes' if is_active else 'No',
                        'Last Updated': updated_at
                    })
                    processed_count += 1

            print(f"Processed {processed_count} alerts so far...")
            
            # Handle pagination
            link_header = response.headers.get('Link', '')
            links = parse_link_header(link_header)
            next_url = links.get('next')

if __name__ == '__main__':
    main()
