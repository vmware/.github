import os
import json
import time
import urllib.request
import policy_selector
from datetime import datetime, timedelta

def debug_log(message):
    print(f"::warning::{message}")

# --- NEW: PAGINATION HELPER IMPORT/COPY ---
# We use the same paginated helper to solve the 100 Repository / 100 PR Limit
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
                
                # Check for special 'repositories' wrapper key (used in installation API)
                items = data.get("repositories") if "repositories" in data else data
                
                if not items or not isinstance(items, list):
                    break
                    
                all_results.extend(items)
                
                # If we got fewer than 100 items, this is the last page
                if len(items) < 100:
                    break
                
                page += 1
        except Exception as e:
            debug_log(f"API Error for {paged_url}: {e}")
            break
            
    return all_results

def main():
    debug_log("--- STARTING ENTERPRISE SWEEPER (PAGINATED & SCALABLE) ---")
    
    # 1. AUTHENTICATION HANDOFF
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
    hours_back_str = os.environ.get("HOURS_BACK", "24")
    try:
        hours_back = int(hours_back_str)
    except ValueError:
        debug_log(f"⚠️ Invalid HOURS_BACK value '{hours_back_str}', defaulting to 24.")
        hours_back = 24

    cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
    debug_log(f"🕒 Filtering: Ignoring PRs not updated in the last {hours_back} hours (since {cutoff_time.isoformat()})")

    # 2. Get All Repositories (PAGINATED)
    # Solves Critical Gap: Will now fetch all 118 repos instead of stopping at 100
    install_url = f"{api_root}/installation/repositories"
    repos = github_api_paginated(install_url, gh_token)

    if not repos:
        debug_log("❌ No repositories found. Verify the GitHub App is installed and the Token is valid.")
        return

    debug_log(f"✅ App is installed on {len(repos)} repositories.")

    total_prs_checked = 0
    total_prs_skipped = 0

    # 3. Iterate through each Repository
    for repo in repos:
        full_name = repo.get("full_name")
        
        # RATE LIMIT PROTECTION:
        # Sleep 2 seconds between repos to prevent hitting 5000 requests/hr limit
        # and to prevent overwhelming the runner queue.
        time.sleep(2)

        # Get PRs (PAGINATED)
        # Solves PR Gap: Will now fetch all open PRs even if >100 per repo
        pr_url = f"{api_root}/repos/{full_name}/pulls?state=open&sort=updated&direction=desc"
        open_prs = github_api_paginated(pr_url, gh_token)
        
        if not open_prs: 
            continue

        debug_log(f"[{full_name}] Found {len(open_prs)} open PRs")

        # 4. Process the PRs
        for pr in open_prs:
            try:
                pr_number = pr.get("number")
                pr_updated_str = pr.get("updated_at") 
                
                # DATE CHECK
                if pr_updated_str:
                    pr_date = datetime.fromisoformat(pr_updated_str.replace('Z', '+00:00'))
                    pr_date_naive = pr_date.replace(tzinfo=None)
                    
                    if pr_date_naive < cutoff_time:
                        # Optimization: Break early if we hit old PRs
                        total_prs_skipped += (len(open_prs) - open_prs.index(pr))
                        # Note: We rely on API sorting by 'updated' desc. 
                        # If paginated, the loop might continue, but break optimizes this block.
                        break 
                
                pr_head_sha = pr.get("head", {}).get("sha")
                pr_user = pr.get("user", {}).get("login")
                
                if pr.get("draft") is True: continue

                debug_log(f"👉 Checking active PR {full_name}#{pr_number} (@{pr_user})")
                
                # Delegate to shared logic (which now includes retries & pagination)
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
    
