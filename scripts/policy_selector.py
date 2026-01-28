import os
import sys
import json
import urllib.request
import requires_cla 

# --- CONFIGURATION ---
# This Context Name must match your Branch Rule EXACTLY
STATUS_CONTEXT = "Check CLA/DCO" 
BOT_ALLOWLIST = ["dependabot[bot]", "github-actions[bot]", "renovate[bot]"]

def debug_log(message):
    """Prints a warning message so it stands out in GitHub Actions logs."""
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
            return json.loads(r.read().decode()) if method != "PUT" else {}
    except urllib.error.HTTPError as e:
        debug_log(f"API Error {e.code} for {url}: {e.read().decode()}")
        return None
    except Exception as e:
        debug_log(f"Network Error: {e}")
        return None

def set_commit_status(api_root, repo, sha, state, description, target_url, token):
    """
    Manually updates the status of a specific commit.
    This bypasses the default behavior and ensures the PR UI gets the signal.
    """
    url = f"{api_root}/repos/{repo}/statuses/{sha}"
    payload = {
        "state": state,
        "context": STATUS_CONTEXT,
        "description": description,
        "target_url": target_url
    }
    debug_log(f"⚡ FORCE UPDATE: Painting Commit {sha[:7]} as '{state}'...")
    response = github_api(url, token, "POST", payload)
    if response:
        debug_log(f"✅ Status updated successfully for {sha[:7]}")
    else:
        debug_log(f"❌ Failed to update status for {sha[:7]}")

def main():
    debug_log("--- STARTING DEBUG DIAGNOSTICS ---")
    
    # 1. IDENTIFY THE COMMITS
    # We need to find the REAL commit the user pushed (PR Head),
    # distinct from the 'safe' commit this workflow is running on.
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    pr_head_sha = ""
    repo_full_name = os.environ.get("GITHUB_REPOSITORY")
    
    if event_path and os.path.exists(event_path):
        with open(event_path, 'r') as f:
            event = json.load(f)
            # This is the SHA the GitHub UI is waiting for:
            pr_head_sha = event.get("pull_request", {}).get("head", {}).get("sha", "")
            debug_log(f"📌 TARGET SHA (PR Head): {pr_head_sha}")
    
    # This is the SHA the runner is currently on:
    current_sha = os.environ.get("GITHUB_SHA", "")
    debug_log(f"🏃 RUNNING SHA (Context): {current_sha}")
    
    if pr_head_sha and current_sha != pr_head_sha:
        debug_log("⚠️ SHA MISMATCH DETECTED: This is normal for pull_request_target.")
        debug_log("   -> We will manually target the PR Head SHA to fix the 'Gray Button'.")

    # 2. SETUP INPUTS
    pr_user = os.environ.get("PR_AUTHOR")
    gh_token = os.environ.get("GITHUB_TOKEN")
    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    comments_url = os.environ.get("PR_COMMENTS_URL")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    # 3. BOT BYPASS
    if pr_user in BOT_ALLOWLIST or pr_user.endswith("[bot]"):
        debug_log(f"🤖 User {pr_user} is a bot. Bypassing.")
        if pr_head_sha:
            set_commit_status(api_root, repo_full_name, pr_head_sha, "success", "Bot Detected - Bypass", "", gh_token)
        sys.exit(0)

    # 4. POLICY CHECK
    # We use the token to check repo contents if needed by requires_cla
    is_strict = requires_cla.requires_CLA(repo_full_name, token=gh_token)
    mode = "CLA" if is_strict else "DCO"
    debug_log(f"ℹ️  Policy Determined: {mode}")

    # 5. SIGNATURE CHECK
    sig_file_path = f"{base_path}/signatures/{mode.lower()}.json"
    has_signed = False
    try:
        with open(sig_file_path, 'r') as f:
            data = json.load(f)
            contributors = data.get("signedContributors", []) if isinstance(data, dict) else data
            # Case-insensitive comparison
            for c in contributors:
                if c.get("name", "").lower() == pr_user.lower():
                    has_signed = True
                    break
    except Exception as e:
        debug_log(f"⚠️ Error reading signature file: {e}")

    # 6. REPORT RESULTS & FORCE STATUS
    doc_url = os.environ.get("CLA_DOC_URL") if mode == "CLA" else os.environ.get("DCO_DOC_URL")
    
    if has_signed:
        debug_log(f"✅ User {pr_user} has signed.")
        # FORCE GREEN on the PR HEAD
        if pr_head_sha:
            set_commit_status(api_root, repo_full_name, pr_head_sha, "success", f"{mode} Signed", "", gh_token)
        sys.exit(0)
    else:
        debug_log(f"❌ User {pr_user} has NOT signed.")
        # FORCE RED on the PR HEAD
        if pr_head_sha:
            set_commit_status(api_root, repo_full_name, pr_head_sha, "failure", f"{mode} Missing", doc_url or "", gh_token)
        
        # (Optional) Post failure comment logic here if needed...
        sys.exit(1)

if __name__ == "__main__":
    main()
    
