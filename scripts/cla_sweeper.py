import os
import json
import urllib.request
import policy_selector
from datetime import datetime, timedelta

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
        debug_log(f"API Error for {url}: {e}")
        return {}

def main():
    debug_log("--- STARTING DIRECT INSTALLATION SWEEPER (WITH DATE FILTER) ---")
    
    gh_token = os.environ.get("GITHUB_TOKEN")
    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    # --- CONFIGURATION: DATE FILTER ---
    # We only care about PRs updated in the last 24 hours.
    # If a user comments "I sign", the PR 'updated_at' timestamp updates instantly.
    HOURS_BACK = 24
    cutoff_time = datetime.utcnow() - timedelta(hours=HOURS_BACK)
    debug_log(f"🕒 Filtering: Ignoring PRs not updated since {cutoff_time.isoformat()}")

    # 1. Get All Repositories this App is Installed On
    install_url = f"{api_root}/installation/repositories?per_page=100"
    repo_data = github_api(install_url, gh_token)
    repos = repo_data.get("repositories", []) if isinstance(repo_data, dict) else []

    if not repos:
        debug_log("❌ No repositories found. Verify the GitHub App is installed.")
        return

    debug_log(f"✅ App is installed on {len(repos)} repositories.")

    total_prs_checked = 0
    total_prs_skipped = 0

    # 2. Iterate through each Repository
    for repo in repos:
        full_name = repo.get("full_name")
        
        # Sort by 'updated' desc so we see active ones first
        pr_url = f"{api_root}/repos/{full_name}/pulls?state=open&sort=updated&direction=desc&per_page=100"
        open_prs = github_api(pr_url, gh_token)
        
        if not open_prs or isinstance(open_prs, dict): 
            continue

        # 3. Process the PRs
        for pr in open_prs:
            try:
                pr_number = pr.get("number")
                pr_updated_str = pr.get("updated_at") # Format: 2023-10-27T10:00:00Z
                
                # DATE CHECK
                if pr_updated_str:
                    # Robust parsing for ISO format (replacing Z with +00:00 for python < 3.11 safety, though we use 3.11)
                    pr_date = datetime.fromisoformat(pr_updated_str.replace('Z', '+00:00'))
                    # Remove timezone info for comparison if cutoff is naive, or ensure both aware.
                    # Simplest approach: compare timestamps directly if possible or strip tz
                    pr_date_naive = pr_date.replace(tzinfo=None)
                    
                    if pr_date_naive < cutoff_time:
                        # Optimization: Since we sorted by updated desc, once we hit an old PR,
                        # all subsequent PRs in this list are also old. We can break the loop early!
                        total_prs_skipped += (len(open_prs) - open_prs.index(pr))
                        break 
                
                # If we are here, the PR is active. Process it.
                pr_head_sha = pr.get("head", {}).get("sha")
                pr_user = pr.get("user", {}).get("login")
                
                if pr.get("draft") is True: continue

                debug_log(f"👉 Checking active PR {full_name}#{pr_number} (@{pr_user})")
                
                policy_selector.process_single_pr(
                    pr_number, pr_head_sha, pr_user, 
                    full_name, gh_token, base_path, api_root
                )
                total_prs_checked += 1
                
            except Exception as e:
                debug_log(f"Failed to process PR {pr.get('number')}: {e}")

    debug_log(f"--- SWEEP COMPLETE. Checked {total_prs_checked} active PRs. Skipped {total_prs_skipped} stale PRs. ---")

if __name__ == "__main__":
    main()
    
