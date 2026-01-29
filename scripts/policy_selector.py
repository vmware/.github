import os
import sys
import json
import urllib.request
import time
import requires_cla 

# --- CONFIGURATION ---
STATUS_CONTEXT = "Check CLA/DCO" 
BOT_ALLOWLIST = ["dependabot[bot]", "github-actions[bot]", "renovate[bot]"]

def debug_log(message):
    print(f"::warning::{message}")

def github_api(url, token, method="GET", data=None):
    headers = {
        "Authorization": f"Bearer {token}", 
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    try:
        req = urllib.request.Request(url, headers=headers, method=method)
        if data: req.data = json.dumps(data).encode("utf-8")
        with urllib.request.urlopen(req) as r:
            if method == "DELETE": return {}
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        debug_log(f"API Error {e.code} for {url}: {e.read().decode()}")
        return None
    except Exception as e:
        debug_log(f"Network Error: {e}")
        return None

def force_merge_check_refresh(api_root, repo, pr_number, token):
    """
    HACK: Querying the PR details forces GitHub to recalculate 'mergeable' status.
    This often kills the 'infinite spinner'.
    """
    url = f"{api_root}/repos/{repo}/pulls/{pr_number}"
    debug_log(f"🔄 Probing PR #{pr_number} to force mergeability refresh...")
    github_api(url, token)

def set_commit_status(api_root, repo, sha, state, description, target_url, token):
    url = f"{api_root}/repos/{repo}/statuses/{sha}"
    payload = {
        "state": state,
        "context": STATUS_CONTEXT,
        "description": description,
        "target_url": target_url
    }
    debug_log(f"⚡ Painting Commit {sha[:7]} as '{state}'...")
    github_api(url, token, "POST", payload)

def main():
    debug_log("--- STARTING DEEP DIAGNOSTICS ---")
    
    # 1. Load Event Data
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    pr_head_sha = ""
    pr_number = ""
    repo_full_name = os.environ.get("GITHUB_REPOSITORY")
    
    if event_path and os.path.exists(event_path):
        with open(event_path, 'r') as f:
            event = json.load(f)
            pr_data = event.get("pull_request", {})
            pr_head_sha = pr_data.get("head", {}).get("sha", "")
            pr_number = pr_data.get("number")
            
            debug_log(f"📌 PR HEAD SHA: {pr_head_sha}")
            debug_log(f"📌 PR NUMBER:   {pr_number}")
    
    current_sha = os.environ.get("GITHUB_SHA", "")
    debug_log(f"🏃 RUNNING SHA:  {current_sha}")

    # 2. Setup Inputs
    pr_user = os.environ.get("PR_AUTHOR")
    gh_token = os.environ.get("GITHUB_TOKEN")
    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    # 3. Bot Check
    if pr_user in BOT_ALLOWLIST or pr_user.endswith("[bot]"):
        debug_log(f"🤖 Bot {pr_user} detected. Bypassing.")
        if pr_head_sha: 
            set_commit_status(api_root, repo_full_name, pr_head_sha, "success", "Bot Bypass", "", gh_token)
        sys.exit(0)

    # 4. Check Policy
    is_strict = requires_cla.requires_CLA(repo_full_name, token=gh_token)
    mode = "CLA" if is_strict else "DCO"

    # 5. Check Signature
    sig_file_path = f"{base_path}/signatures/{mode.lower()}.json"
    has_signed = False
    try:
        with open(sig_file_path, 'r') as f:
            data = json.load(f)
            contributors = data.get("signedContributors", []) if isinstance(data, dict) else data
            for c in contributors:
                if c.get("name", "").lower() == pr_user.lower():
                    has_signed = True
                    break
    except Exception as e:
        debug_log(f"⚠️ Error reading signature file: {e}")

    # 6. REPORT RESULTS & FIX SPIN
    doc_url = os.environ.get("CLA_DOC_URL") if mode == "CLA" else os.environ.get("DCO_DOC_URL")
    
    if has_signed:
        debug_log(f"✅ User {pr_user} has signed.")
        
        # A. Paint PR Head (User Commit)
        if pr_head_sha:
            set_commit_status(api_root, repo_full_name, pr_head_sha, "success", f"{mode} Signed", "", gh_token)
            
        # B. Paint Merge Commit (Engine Commit)
        if current_sha and current_sha != pr_head_sha:
            set_commit_status(api_root, repo_full_name, current_sha, "success", f"{mode} Signed", "", gh_token)

        # C. FORCE REFRESH (The Anti-Spin Logic)
        if pr_number:
            # We wait 1 second to ensure the status write propagates
            time.sleep(1)
            force_merge_check_refresh(api_root, repo_full_name, pr_number, gh_token)
            
        sys.exit(0)
    else:
        debug_log(f"❌ User {pr_user} has NOT signed.")
        if pr_head_sha:
            set_commit_status(api_root, repo_full_name, pr_head_sha, "failure", f"{mode} Missing", doc_url or "", gh_token)
        sys.exit(1)

if __name__ == "__main__":
    main()
    
