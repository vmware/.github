import os
import sys
import json
import urllib.request
import time
import requires_cla

# --- CONFIGURATION ---
STATUS_CONTEXT = "Check CLA/DCO" # This MUST match your Ruleset string exactly
BOT_ALLOWLIST = ["dependabot[bot]", "github-actions[bot]", "renovate[bot]"]

def debug_log(message):
    print(f"::warning::{message}") # Prints in yellow in GitHub Logs

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
    url = f"{api_root}/repos/{repo}/statuses/{sha}"
    payload = {
        "state": state,
        "context": STATUS_CONTEXT,
        "description": description,
        "target_url": target_url
    }
    debug_log(f"⚡ Painting Commit {sha[:7]} as '{state}' context='{STATUS_CONTEXT}'...")
    response = github_api(url, token, "POST", payload)
    if response:
        debug_log(f"✅ Successfully updated status for {sha[:7]}")
    else:
        debug_log(f"❌ Failed to update status for {sha[:7]}")

def main():
    debug_log("--- STARTING DEBUG DIAGNOSTICS ---")
    
    # 1. Load Event Data to find the REAL Commit SHA
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    pr_head_sha = ""
    repo_full_name = os.environ.get("GITHUB_REPOSITORY")
    
    if event_path and os.path.exists(event_path):
        with open(event_path, 'r') as f:
            event = json.load(f)
            # For pull_request_target, we MUST get the head sha from the event
            pr_head_sha = event.get("pull_request", {}).get("head", {}).get("sha", "")
            debug_log(f"📌 PR Head SHA (Target): {pr_head_sha}")
    
    current_sha = os.environ.get("GITHUB_SHA", "")
    debug_log(f"🏃 Running Context SHA: {current_sha}")
    
    if pr_head_sha and current_sha != pr_head_sha:
        debug_log("⚠️ MISMATCH DETECTED: Script is running on a different commit than the PR Head.")
        debug_log("   -> This explains why the native check is green but the PR is gray.")
        debug_log("   -> Attempting to manually fix status...")

    # 2. Setup Inputs
    pr_user = os.environ.get("PR_AUTHOR")
    gh_token = os.environ.get("GITHUB_TOKEN")
    current_org = os.environ.get("CENTRAL_ORG")
    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    comments_url = os.environ.get("PR_COMMENTS_URL")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    
    # 3. Bot Check
    if pr_user in BOT_ALLOWLIST or pr_user.endswith("[bot]"):
        debug_log(f"🤖 User {pr_user} is a bot. Bypassing.")
        if pr_head_sha:
            set_commit_status(api_root, repo_full_name, pr_head_sha, "success", "Bot Detected - Bypass", "", gh_token)
        sys.exit(0)

    # 4. Policy Check
    is_strict = requires_cla.requires_CLA(repo_full_name, token=gh_token)
    mode = "CLA" if is_strict else "DCO"
    debug_log(f"ℹ️  Policy Determined: {mode}")

    # 5. Signature Check
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
    except: 
        debug_log(f"⚠️ Could not read signature file: {sig_file_path}")

    # 6. REPORT RESULTS
    doc_url = os.environ.get("CLA_DOC_URL") if mode == "CLA" else os.environ.get("DCO_DOC_URL")
    
    if has_signed:
        debug_log(f"✅ User {pr_user} has signed.")
        # FORCE STATUS UPDATE ON THE CORRECT SHA
        if pr_head_sha:
            set_commit_status(api_root, repo_full_name, pr_head_sha, "success", f"{mode} Signed", "", gh_token)
        sys.exit(0)
    else:
        debug_log(f"❌ User {pr_user} has NOT signed.")
        # Fail the status explicitly
        if pr_head_sha:
            set_commit_status(api_root, repo_full_name, pr_head_sha, "failure", f"{mode} Missing", doc_url, gh_token)
        
        # (Comment posting logic remains the same...)
        sys.exit(1)

if __name__ == "__main__":
    main()
    
