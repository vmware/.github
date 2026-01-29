import os
import sys
import json
import urllib.request
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
    debug_log(f"⚡ Painting Commit {sha[:7]} as '{state}'...")
    github_api(url, token, "POST", payload)

def main():
    debug_log("--- STARTING COMPLIANCE CHECK ---")
    
    # 1. Identify BOTH Commits (The "Bridge")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    pr_head_sha = ""
    repo_full_name = os.environ.get("GITHUB_REPOSITORY")
    
    if event_path and os.path.exists(event_path):
        with open(event_path, 'r') as f:
            event = json.load(f)
            pr_head_sha = event.get("pull_request", {}).get("head", {}).get("sha", "")
    
    current_sha = os.environ.get("GITHUB_SHA", "")
    
    # 2. Setup Inputs
    pr_user = os.environ.get("PR_AUTHOR")
    gh_token = os.environ.get("GITHUB_TOKEN")
    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    # 3. Bot Check
    if pr_user in BOT_ALLOWLIST or pr_user.endswith("[bot]"):
        debug_log(f"🤖 Bot {pr_user} detected. Bypassing.")
        if pr_head_sha: set_commit_status(api_root, repo_full_name, pr_head_sha, "success", "Bot Bypass", "", gh_token)
        sys.exit(0)

    # 4. Policy Check
    is_strict = requires_cla.requires_CLA(repo_full_name, token=gh_token)
    mode = "CLA" if is_strict else "DCO"

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
    except Exception as e:
        debug_log(f"⚠️ Error reading signature file: {e}")

    # 6. REPORT RESULTS (The Double-Paint Fix)
    doc_url = os.environ.get("CLA_DOC_URL") if mode == "CLA" else os.environ.get("DCO_DOC_URL")
    
    if has_signed:
        debug_log(f"✅ User {pr_user} has signed.")
        
        # 1. Paint the PR Head (Unblocks the 'Gate' Ruleset)
        if pr_head_sha:
            set_commit_status(api_root, repo_full_name, pr_head_sha, "success", f"{mode} Signed", "", gh_token)
            
        # 2. Paint the Merge Commit (Satisfies the 'Engine' Ruleset)
        if current_sha and current_sha != pr_head_sha:
            set_commit_status(api_root, repo_full_name, current_sha, "success", f"{mode} Signed", "", gh_token)
            
        sys.exit(0)
    else:
        debug_log(f"❌ User {pr_user} has NOT signed.")
        if pr_head_sha:
            set_commit_status(api_root, repo_full_name, pr_head_sha, "failure", f"{mode} Missing", doc_url or "", gh_token)
        sys.exit(1)

if __name__ == "__main__":
    main()
    
