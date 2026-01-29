import os
import json
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
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
    debug_log("--- STARTING PRODUCTION SWEEPER (OPTIMIZED) ---")
    
    gh_token = os.environ.get("GITHUB_TOKEN")
    org_name = os.environ.get("CENTRAL_ORG") 
    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    if not org_name:
        debug_log("❌ Error: CENTRAL_ORG environment variable is missing.")
        return

    # --- FILTER STRATEGY ---
    # 1. Recency: Only check PRs updated in the last 24 hours.
    #    This catches any new "I sign" comments without scanning stale PRs.
    since_time = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S')
    
    # 2. Construction:
    #    is:pr              -> Must be a Pull Request
    #    is:open            -> Must be Open
    #    is:public          -> Only Public Repos (Ignores internal private work)
    #    archived:false     -> No archived repos
    #    org:{org}          -> Your Organization
    #    updated:>{time}    -> Only active PRs
    query = f"is:pr is:open is:public archived:false org:{org_name} updated:>{since_time}"
    
    encoded_query = urllib.parse.quote(query)
    url = f"{api_root}/search/issues?q={encoded_query}&per_page=100"
    
    debug_log(f"🔎 Scanning active Public PRs in '{org_name}' (updated since {since_time})...")
    result = github_api(url, gh_token)
    items = result.get("items", [])
    
    if not items:
        debug_log("No active public PRs found (in the last 24h).")
        return

    debug_log(f"Found {len(items)} active PRs. Processing...")

    for item in items:
        try:
            repo_url = item.get("repository_url", "")
            repo_full_name = repo_url.replace(f"{api_root}/repos/", "")
            pr_number = item.get("number")
            pr_user = item.get("user", {}).get("login")
            
            # Fetch details to get Head SHA
            pr_details = github_api(item.get("url"), gh_token)
            pr_head_sha = pr_details.get("head", {}).get("sha")

            if not pr_head_sha: continue

            # Run Logic
            policy_selector.process_single_pr(
                pr_number, pr_head_sha, pr_user, 
                repo_full_name, gh_token, base_path, api_root
            )
        except Exception as e:
            debug_log(f"Failed to process PR {item.get('number')}: {e}")

if __name__ == "__main__":
    main()
    
