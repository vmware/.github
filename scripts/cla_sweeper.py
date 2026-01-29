import os
import json
import urllib.request
import policy_selector  # Imports the shared logic

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
        return []

def main():
    debug_log("--- STARTING COMPLIANCE SWEEPER (BATCH MODE) ---")
    
    repo_full_name = os.environ.get("GITHUB_REPOSITORY")
    gh_token = os.environ.get("GITHUB_TOKEN")
    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    # 1. Fetch Open PRs
    url = f"{api_root}/repos/{repo_full_name}/pulls?state=open&per_page=100"
    open_prs = github_api(url, gh_token)
    
    if not open_prs:
        debug_log("No open PRs found.")
        return

    debug_log(f"Found {len(open_prs)} open PRs. Processing...")

    # 2. Loop and Call Shared Logic
    for pr in open_prs:
        try:
            pr_number = pr.get("number")
            pr_head_sha = pr.get("head", {}).get("sha")
            pr_user = pr.get("user", {}).get("login")
            
            # Pass data to policy_selector's reusable function
            policy_selector.process_single_pr(
                pr_number, pr_head_sha, pr_user, 
                repo_full_name, gh_token, base_path, api_root
            )
        except Exception as e:
            debug_log(f"Failed to process PR {pr_number}: {e}")

if __name__ == "__main__":
    main()
    
