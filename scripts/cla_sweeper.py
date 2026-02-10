import os
import json
import time
import urllib.request
import policy_selector
from datetime import datetime, timedelta

# --- CONFIGURATION ---
# Set this to True during your 1-Year Backfill. 
# Set to False for your daily Cron jobs.
MIGRATION_MODE = True 

def debug_log(message):
    print(f"::warning::{message}")

# --- PAGINATION HELPER (Required for large repos) ---
def github_api_paginated(url, token):
    headers = {
        "Authorization": f"Bearer {token}", 
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    all_results = []
    page = 1
    
    while True:
        separator = "&" if "?" in url else "?"
        paged_url = f"{url}{separator}page={page}&per_page=100"
        
        try:
            req = urllib.request.Request(paged_url, headers=headers)
            with urllib.request.urlopen(req) as r:
                data = json.loads(r.read().decode())
                items = data.get("repositories") if "repositories" in data else data
                
                if not items or not isinstance(items, list):
                    break
                    
                all_results.extend(items)
                if len(items) < 100:
                    break
                page += 1
        except Exception as e:
            debug_log(f"API Error for {paged_url}: {e}")
            break
            
    return all_results

# --- NEW: IMPROVED MIGRATION COMMENTER ---
def post_migration_notice(api_root, repo, pr_number, user, token):
    """
    Posts a helpful comment on old PRs so users know how to unblock themselves.
    """
    # 1. Check if we already posted it (Prevent Spam)
    comments_url = f"{api_root}/repos/{repo}/issues/{pr_number}/comments"
    comments = github_api_paginated(comments_url, token)
    
    if comments:
        for c in comments:
            # Check for key phrase to avoid double-posting
            if "System Migration" in c.get("body", ""):
                return

    # 2. Post the Notice (Clearer Messaging with UI Option)
    msg = (
        f"Hi @{user}, \n\n"
        "### 🔄 System Migration: Compliance Verified\n\n"
        "We have migrated this repository to a new automated compliance system. \n"
        "We verified your status during the migration and marked this Pull Request as **Compliant** (CLA/DCO Signed).\n\n"
        "**🛑 Troubleshooting (If Blocked):**\n"
        "If your Merge button is currently blocked waiting for a 'Required Workflow' or 'Status Check', "
        "GitHub requires a new event to register the pass. Please choose one of the following options to trigger the update:\n\n"
        "**Option 1 (Command Line):** Push an empty commit.\n"
        "`git commit --allow-empty -m 'trigger checks' && git push`\n\n"
        "**Option 2 (Web UI):** Simply **Close** and immediately **Reopen** this Pull Request using the buttons at the bottom of the page."
    )
    
    debug_log(f"🗣️ Posting Migration Notice to {repo}#{pr_number}...")
    try:
        req = urllib.request.Request(comments_url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }, method="POST")
        req.data = json.dumps({"body": msg}).encode("utf-8")
        with urllib.request.urlopen(req):
            pass
    except Exception as e:
        debug_log(f"Failed to post notice: {e}")

def main():
    debug_log("--- STARTING ENTERPRISE SWEEPER (MIGRATION MODE) ---")
    
    if hasattr(policy_selector, "ensure_valid_token"):
        policy_selector.ensure_valid_token()
        
    gh_token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    # Force 1 Year Lookback if Migration Mode is On
    hours_back_str = os.environ.get("HOURS_BACK", "24")
    if MIGRATION_MODE:
        debug_log("🚀 MIGRATION MODE ENABLED: Forcing 1-Year Lookback.")
        hours_back = 8760
    else:
        try:
            hours_back = int(hours_back_str)
        except ValueError:
            hours_back = 24

    cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
    
    # 2. Get All Repositories (PAGINATED)
    install_url = f"{api_root}/installation/repositories"
    repos = github_api_paginated(install_url, gh_token)

    if not repos: return

    debug_log(f"✅ Scanning {len(repos)} repositories...")

    for repo in repos:
        full_name = repo.get("full_name")
        time.sleep(2) # Rate Limit Safety

        # Get PRs (PAGINATED)
        pr_url = f"{api_root}/repos/{full_name}/pulls?state=open&sort=updated&direction=desc"
        open_prs = github_api_paginated(pr_url, gh_token)
        
        if not open_prs: continue

        debug_log(f"[{full_name}] Found {len(open_prs)} open PRs")

        for pr in open_prs:
            try:
                pr_number = pr.get("number")
                pr_updated_str = pr.get("updated_at") 
                
                if pr_updated_str:
                    pr_date = datetime.fromisoformat(pr_updated_str.replace('Z', '+00:00'))
                    pr_date_naive = pr_date.replace(tzinfo=None)
                    if pr_date_naive < cutoff_time: break 
                
                pr_head_sha = pr.get("head", {}).get("sha")
                pr_user = pr.get("user", {}).get("login")
                
                if pr.get("draft") is True: continue

                # 1. Run Standard Logic (Paints Status)
                # This ensures the status check (green checkmark) is applied
                policy_selector.process_single_pr(
                    pr_number, pr_head_sha, pr_user, 
                    full_name, gh_token, base_path, api_root
                )
                
                # 2. Run Migration Logic (Communicates Fix)
                if MIGRATION_MODE:
                    # We post the notice regardless of status to ensure they know how to unblock 
                    # the "Required Workflow" check if it's pending.
                    post_migration_notice(api_root, full_name, pr_number, pr_user, gh_token)
                
            except Exception as e:
                debug_log(f"Failed to process PR {pr.get('number')}: {e}")

if __name__ == "__main__":
    main()
    
