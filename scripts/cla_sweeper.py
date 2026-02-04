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
    
    # 1. AUTHENTICATION HANDOFF
    # Ensure the token logic in policy_selector has run.
    # We grab GH_TOKEN first because cla_auth sets that one explicitly.
    if hasattr(policy_selector, "ensure_valid_token"):
        policy_selector.ensure_valid_token()
        
    gh_token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    
    if gh_token:
        debug_log(f"[SWEEPER AUTH] Using Token with prefix: {gh_token[:4]}...")
    else:
        debug_log("❌ [SWEEPER AUTH] No Token found! Logic will likely fail.")

    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    # --- CONFIGURATION: DATE FILTER ---
    # Retrieve from environment (workflow input) or default to 24
    hours_back_str = os.environ.get("HOURS_BACK", "24")
    try:
        hours_back = int(hours_back_str)
    except ValueError:
        debug_log(f"⚠️ Invalid HOURS_BACK value '{hours_back_str}', defaulting to 24.")
        hours_back = 24

    cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
    debug_log(f"🕒 Filtering: Ignoring PRs not updated in the last {hours_back} hours (since {cutoff_time.isoformat()})")

    # 2. Get All Repositories this App is Installed On
    # This call REQUIRES the App Token (ghs_). A standard GITHUB_TOKEN will fail here.
    install_url = f"{api_root}/installation/repositories?per_page=100"
    repo_data = github_api(install_url, gh_token)
    repos = repo_data.get("repositories", []) if isinstance(repo_data, dict) else []

    if not repos:
        debug_log("❌ No repositories found. Verify the GitHub App is installed and the Token is valid.")
        return

    debug_log(f"✅ App is installed on {len(repos)} repositories.")

    total_prs_checked = 0
    total_prs_skipped = 0

    # 3. Iterate through each Repository
    for repo in repos:
        full_name = repo.get("full_name")
        
        # Sort by 'updated' desc so we see active ones first
        pr_url = f"{api_root}/repos/{full_name}/pulls?state=open&sort=updated&direction=desc&per_page=100"
        open_prs = github_api(pr_url, gh_token)
        
        if not open_prs or isinstance(open_prs, dict): 
            continue

        # 4. Process the PRs
        for pr in open_prs:
            try:
                pr_number = pr.get("number")
                pr_updated_str = pr.get("updated_at") 
                
                # DATE CHECK
                if pr_updated_str:
                    # Robust parsing for ISO format
                    pr_date = datetime.fromisoformat(pr_updated_str.replace('Z', '+00:00'))
                    pr_date_naive = pr_date.replace(tzinfo=None)
                    
                    if pr_date_naive < cutoff_time:
                        # Optimization: Break early if we hit old PRs
                        total_prs_skipped += (len(open_prs) - open_prs.index(pr))
                        break 
                
                # If we are here, the PR is active. Process it.
                pr_head_sha = pr.get("head", {}).get("sha")
                pr_user = pr.get("user", {}).get("login")
                
                if pr.get("draft") is True: continue

                debug_log(f"👉 Checking active PR {full_name}#{pr_number} (@{pr_user})")
                
                # Delegate to the shared logic
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
    
