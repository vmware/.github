import os
import json
import urllib.request
import policy_selector 

def debug_log(message):
    print(f"::warning::{message}")

def github_api(url, token):
    headers = {
        "Authorization": f"Bearer {token}", 
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        debug_log(f"API Error: {e}")
        return {}

def main():
    debug_log("--- STARTING CENTRALIZED ORGANIZATION SWEEPER ---")
    
    gh_token = os.environ.get("GITHUB_TOKEN")
    org_name = os.environ.get("CENTRAL_ORG") # Need this to scan the Org
    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    if not org_name:
        debug_log("❌ Error: CENTRAL_ORG environment variable is missing.")
        return

    # 1. SEARCH for Open PRs across the ENTIRE Organization
    # Query: is:pr is:open org:YourOrg archived:false
    query = f"is:pr is:open org:{org_name} archived:false"
    encoded_query = urllib.parse.quote(query)
    url = f"{api_root}/search/issues?q={encoded_query}&per_page=100"
    
    debug_log(f"🔎 Scanning Organization '{org_name}' for open PRs...")
    result = github_api(url, gh_token)
    items = result.get("items", [])
    
    if not items:
        debug_log("No open PRs found in the Organization.")
        return

    debug_log(f"Found {len(items)} open PRs across the Org. Processing...")

    # 2. Loop through found PRs
    for item in items:
        try:
            # Extract Repo details from the 'repository_url' field
            # Format: https://api.github.com/repos/ORG/REPO
            repo_url = item.get("repository_url", "")
            repo_full_name = repo_url.replace(f"{api_root}/repos/", "")
            
            pr_number = item.get("number")
            pr_user = item.get("user", {}).get("login")
            
            # Note: Search API results don't include the SHA. We need to fetch the PR details.
            # Optimization: We could skip this fetch if we passed SHA logic differently, 
            # but to reuse policy_selector safely, let's just fetch the PR.
            pr_details = github_api(item.get("url"), gh_token)
            pr_head_sha = pr_details.get("head", {}).get("sha")

            if not pr_head_sha:
                continue

            # Call the shared logic
            debug_log(f"👉 Checking {repo_full_name}#{pr_number} (@{pr_user})")
            policy_selector.process_single_pr(
                pr_number, pr_head_sha, pr_user, 
                repo_full_name, gh_token, base_path, api_root
            )
        except Exception as e:
            debug_log(f"Failed to process PR {item.get('number')}: {e}")

if __name__ == "__main__":
    import urllib.parse
    main()
    
