import os
import sys
import json
import urllib.request
import urllib.error
import time

# --- [INTEGRATION START] IMPORT CLA AUTHENTICATION MODULE ---
# This module is responsible for auto-installing dependencies (PyJWT, Cryptography)
# and generating a "Super Token" to bypass stale YAML configurations.
try:
    import cla_auth
except ImportError:
    # This acts as a fallback or warning if the file is missing in local testing
    print("::warning::[SETUP] 'cla_auth.py' module not found. Token upgrade checks may fail.")

try:
    import requires_cla
except ImportError:
    # Fallback for local testing if requires_cla is missing
    print("::warning::[SETUP] 'requires_cla' module not found. Assuming strict CLA policy.")
    class requires_cla_stub:
        @staticmethod
        def requires_CLA(repo, token=None): return True
    requires_cla = requires_cla_stub
# --- [INTEGRATION END] -------------------------------------

# --- CONFIGURATION ---
STATUS_CONTEXT = "Check CLA/DCO" 
BOT_ALLOWLIST = ["dependabot[bot]", "github-actions[bot]", "renovate[bot]"]
SIGNATURE_PHRASE = "I have read the {doc_type} Document and I hereby sign the {doc_type}"

# --- USER FACING MESSAGE ---
INSTRUCTION_MESSAGE_LINES = [
    "### 🛑 Legal Compliance Check Failed",
    "Hi @{user}, thank you for your contribution!",
    "",
    "To merge this Pull Request, you must sign our **{doc_type}**.",
    "",
    "**Note:** Even if you signed off your commits locally (using `git commit -s`), you must post the comment below to register your signature with our automated system.",
    "**Note:** This is a one-time process. Once signed, future pull requests will be verified automatically.",
    "",
    "**1. Read the Document:** [Click here to read the {doc_type}]({url})",
    "**2. Sign via Comment:** Copy and paste the exact line below into a new comment on this Pull Request:",
    "",
    "```text",
    "I have read the {doc_type} Document and I hereby sign the {doc_type}",
    "```",
    "",
    "---",
    "**⏳ Processing Schedule:**",
    "Our 'Compliance Sweeper' runs automatically **approximately every 15-20 minutes**.",
    "After you post the comment, your status will update automatically during the next scheduled run.",
    "You do not need to take any further action."
]
INSTRUCTION_MESSAGE = "\n".join(INSTRUCTION_MESSAGE_LINES)

# --- [INTEGRATION START] TOKEN UPGRADE LOGIC ---
def ensure_valid_token():
    """
    Checks if the current environment has valid credentials.
    If 'CLA_APP_ID' and 'CLA_APP_PRIVATE_KEY' are present, it uses cla_auth
    to generate a fresh token with 'members:read' and 'statuses:write' permissions.
    This fixes the '404 Not Found' errors caused by stale YAML in child repos.
    """
    # Check if we've already done this to avoid spamming logs
    if os.environ.get("CLA_TOKEN_UPGRADED") == "true":
        return

    print("::warning::[AUTH] Checking for available credentials to upgrade token...")
    
    app_id = os.environ.get("CLA_APP_ID")
    private_key = os.environ.get("CLA_APP_PRIVATE_KEY")
    org_name = os.environ.get("CENTRAL_ORG") or "vmware"

    # If we don't have the App secrets, we can't upgrade.
    if not app_id or not private_key:
        print("::warning::[AUTH] CLA_APP_ID or CLA_APP_PRIVATE_KEY missing. Cannot perform token upgrade.")
        return

    try:
        # Generate the Super Token using the new cla_auth module
        # print(f"::warning::[AUTH] Attempting to generate FRESH token for org: {org_name}...")
        fresh_token = cla_auth.get_installation_access_token(app_id, private_key, org_name)
        
        if fresh_token:
            # OVERWRITE the environment variables so all subsequent functions use the new token
            os.environ["GH_TOKEN"] = fresh_token
            os.environ["GITHUB_TOKEN"] = fresh_token
            os.environ["CLA_TOKEN_UPGRADED"] = "true" # Mark as done
            print("::warning::[AUTH] ✅ Token Upgrade Successful! (Permissions: members:read, statuses:write enforced)")
        else:
            print("::error::[AUTH] Token Upgrade Failed. The script will proceed with the default token (which may fail).")
            
    except Exception as e:
        print(f"::error::[AUTH CRASH] Unexpected error during token upgrade: {e}")

# --- EXECUTE TOKEN UPGRADE IMMEDIATELY ON IMPORT ---
# This ensures that both 'policy_selector.py' (Event) AND 'cla_sweeper.py' (Schedule)
# benefit from the fix without changing any other files.
ensure_valid_token()
# ---------------------------------------------------

# --- TOKEN DEBUG BLOCK ---
def debug_token_availability():
    print("::warning::[PYTHON DEBUG] Inspecting Environment Variables inside Python...")
    
    # Check GH_TOKEN
    gh_token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if gh_token:
        # Print first 4 chars to verify it's the App Token (usually starts with 'ghs_' or 'ghu_')
        print(f"::warning::[PYTHON DEBUG] ✅ GH_TOKEN found! Prefix: {gh_token[:4]}...")
    else:
        print("::error::[PYTHON DEBUG] ❌ GH_TOKEN is MISSING or None.")

    # Check GITHUB_TOKEN
    github_token = os.environ.get("GITHUB_TOKEN")
    if github_token:
        print(f"::warning::[PYTHON DEBUG] ✅ GITHUB_TOKEN found! Prefix: {github_token[:4]}...")
    else:
        print("::warning::[PYTHON DEBUG] ⚠️ GITHUB_TOKEN is MISSING or None.")

# Run the debug check immediately (restored to global scope)
debug_token_availability()
# -------------------------

def debug_log(message):
    print(f"::warning::{message}")

def is_org_member(api_root, org_name, user, token):
    url = f"{api_root}/orgs/{org_name}/members/{user}"
    
    debug_log(f"🕵️ Checking membership for @{user} in {org_name}...")

    try:
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CLA-Sweeper"
        })
        # If this succeeds (204), we print scopes and return True
        with urllib.request.urlopen(req) as response:
            debug_log(f"::warning::[DEBUG SCOPE] Token has: {response.headers.get('X-OAuth-Scopes', 'none')}")
            if response.getcode() == 204:
                return True

    except urllib.error.HTTPError as e:
        # The headers are hidden inside 'e.headers' when it fails
        actual_scopes = e.headers.get('X-OAuth-Scopes', 'none')
        debug_log(f"::warning::[DEBUG SCOPE] Token actually has: {actual_scopes}")
        debug_log(f"❌ GitHub API error: {e.code} - {e.reason}")
        
        if e.code == 404:
             debug_log("-> NOTE: 404 means 'Not Found'. If you ARE a member, check the scopes above!")
        return False
        
    except Exception as e:
        debug_log(f"⚠️ Unexpected error: {e}")
        return False
    
    return False
        
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
            if r.status == 204: return {} 
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        debug_log(f"API Error {e.code} for {url}: {e.read().decode()}")
        return None
    except Exception as e:
        debug_log(f"Network Error: {e}")
        return None

def add_reaction_to_comment(api_root, repo, comment_id, token):
    if not comment_id: return
    reaction_url = f"{api_root}/repos/{repo}/issues/comments/{comment_id}/reactions"
    try:
        github_api(reaction_url, token, "POST", {"content": "rocket"})
    except:
        pass

def check_comments_for_signature(api_root, repo, pr_number, user, doc_type, token):
    """
    Scans comments for a matching signature.
    Includes 'Universal Acceptor' logic: matches EITHER CLA or DCO signatures
    to prevent policy mismatches.
    """
    if not pr_number: return False
    
    # Pagination: Ensure we see all comments
    url = f"{api_root}/repos/{repo}/issues/{pr_number}/comments?per_page=100"
    comments = github_api(url, token)
    if not comments: return False

    # FIX: Check for BOTH types of signatures.
    possible_types = ["CLA", "DCO"]
    
    for c in comments:
        body = c.get("body", "")
        comment_user = c.get("user", {}).get("login")
        
        # Verify Author
        if comment_user and user and comment_user.lower() == user.lower():
            # Sanitize invisible characters (NBSP fix)
            normalized_body = body.replace("\xa0", " ").strip()
            
            # Check against BOTH CLA and DCO phrases
            for current_type in possible_types:
                target_phrase = SIGNATURE_PHRASE.format(doc_type=current_type)
                
                if target_phrase in normalized_body:
                    debug_log(f"✅ Found matching {current_type} signature from {user}!")
                    add_reaction_to_comment(api_root, repo, c.get("id"), token)
                    return True
            
            # Debugging Help for Close Matches
            if "I hereby sign" in normalized_body:
                debug_log(f"⚠️ Close match found but failed exact check: '{normalized_body}'")

    debug_log(f"❌ No matching CLA or DCO signature found in {len(comments)} comments.")
    return False

def post_pr_comment(api_root, repo, pr_number, message, token):
    if not pr_number: return
    comments_url = f"{api_root}/repos/{repo}/issues/{pr_number}/comments"
    existing_comments = github_api(comments_url, token)
    if existing_comments:
        for c in existing_comments:
            if "I have read the" in c.get("body", "") and "Sign via Comment" in c.get("body", ""):
                return # Skip duplicate instructions
    payload = {"body": message}
    github_api(comments_url, token, "POST", payload)

def force_merge_check_refresh(api_root, repo, pr_number, token):
    url = f"{api_root}/repos/{repo}/pulls/{pr_number}"
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

import base64
from datetime import datetime

def record_signature(api_root, org_name, doc_type, user, repo_name, token):
    """
    Fetches the signature JSON, adds the user (with ID and real Repo), and commits it.
    """
    target_repo = f"{org_name}/.github"
    file_path = f"signatures/{doc_type.lower()}.json" # Enforce lowercase filename
    url = f"{api_root}/repos/{target_repo}/contents/{file_path}"
    
    debug_log(f"💾 Attempting to record signature for @{user} in {target_repo}/{file_path}...")

    # 1. Fetch User ID (Required for CLA Assistant Lite compatibility)
    user_details = github_api(f"{api_root}/users/{user}", token)
    user_id = user_details.get("id") if user_details else None

    # 2. Get current file content
    data = github_api(url, token)
    if not data or "content" not in data:
        debug_log(f"❌ Failed to fetch signature file. Check permissions for {target_repo}.")
        return False

    try:
        file_content = base64.b64decode(data["content"]).decode("utf-8")
        json_data = json.loads(file_content)
        
        if "signedContributors" not in json_data:
            json_data["signedContributors"] = []
        
        contributors = json_data["signedContributors"]

        # 3. Check for duplicates
        for c in contributors:
            # Check by Name OR ID
            if isinstance(c, dict):
                if c.get("name", "").lower() == user.lower(): return True
                if user_id and c.get("id") == user_id: return True
            elif isinstance(c, str) and c.lower() == user.lower():
                 return True

        # 4. Add User (Standard Format)
        new_entry = {
            "name": user,
            "id": user_id,  # Added ID for compatibility
            "signedAt": datetime.utcnow().isoformat() + "Z",
            "org": org_name,
            "repo": repo_name # Use the REAL repo name
        }
        contributors.append(new_entry)
        
        # 5. Commit
        updated_content = json.dumps(json_data, indent=2)
        commit_message = f"Sign {doc_type} for @{user}"
        
        put_payload = {
            "message": commit_message,
            "content": base64.b64encode(updated_content.encode("utf-8")).decode("utf-8"),
            "sha": data["sha"]
        }
        
        response = github_api(url, token, "PUT", put_payload)
        return True if response else False

    except Exception as e:
        debug_log(f"❌ Error updating signature file: {e}")
        return False
        
def process_single_pr(pr_number, pr_head_sha, pr_user, repo_full_name, gh_token, base_path, api_root):
    """
    Reusable Logic for checking a single PR. 
    Called by main() (Event) OR by cla_sweeper.py (Schedule).
    """
    
    # [INTEGRATION] Ensure we grab the upgraded token if it exists
    # This protects us if the caller (cla_sweeper.py) passed a stale token.
    gh_token = os.environ.get("GH_TOKEN") or gh_token

    debug_log(f"🔍 Checking PR #{pr_number} by @{pr_user}...")

    # 1. Bot Check
    if pr_user in BOT_ALLOWLIST or pr_user.endswith("[bot]"):
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", "Bot Bypass", "", gh_token)
        return

    # 2. Org Member/Owner Check (THE FIX)
    org_name = repo_full_name.split("/")[0]
    if is_org_member(api_root, org_name, pr_user, gh_token):
        debug_log(f"🛡️ User @{pr_user} is an Organization Member. Skipping check.")
        # We paint a generic 'Member Bypass' status so the PR goes Green
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", "Member Bypass", "", gh_token)
        return
        
    # 3. Policy & Doc Type
    is_strict = requires_cla.requires_CLA(repo_full_name, token=gh_token)
    
    debug_log(f"🧐 POLICY DECISION for {repo_full_name}:")
    debug_log(f"   requires_CLA() returned: {is_strict}")
    debug_log(f"   Resulting doc_type: {'CLA' if is_strict else 'DCO'}")

    doc_type = "CLA" if is_strict else "DCO"
    
    # 1. Check JSON File (Legacy/Manual)
    sig_file_path = f"{base_path}/signatures/{doc_type.lower()}.json"
    has_signed_json = False
    try:
        with open(sig_file_path, 'r') as f:
            data = json.load(f)
            contributors = data.get("signedContributors", []) if isinstance(data, dict) else data
            for c in contributors:
                if c.get("name", "").lower() == pr_user.lower():
                    has_signed_json = True
                    break
    except Exception:
        pass 

    # 2. Check Comments (Universal Acceptor)
    has_signed_comment = False
    if not has_signed_json:
        has_signed_comment = check_comments_for_signature(api_root, repo_full_name, pr_number, pr_user, doc_type, gh_token)

    doc_url = os.environ.get("CLA_DOC_URL") if doc_type == "CLA" else os.environ.get("DCO_DOC_URL")

    # Result
    if has_signed_json:
        # Case A: User is ALREADY in the JSON file. No write needed.
        debug_log(f"✅ User {pr_user} is COMPLIANT (Found in JSON).")
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", f"{doc_type} Signed", "", gh_token)
        
    elif has_signed_comment:
        # Case B: User just signed via comment. We MUST write to disk.
        debug_log(f"✅ User {pr_user} is COMPLIANT (Signature comment found).")
        
        # --- WRITE LOGIC START ---
        # Derive org name from "org/repo" string
        org_name = repo_full_name.split("/")[0]
        record_signature(api_root, org_name, doc_type, pr_user, repo_full_name, gh_token)
        # --- WRITE LOGIC END ---
        
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", f"{doc_type} Signed", "", gh_token)
        
        # UI Refresh
        time.sleep(1)
        force_merge_check_refresh(api_root, repo_full_name, pr_number, gh_token)
        
    else:
        # Case C: Not compliant
        debug_log(f"❌ User {pr_user} is NOT compliant.")
        set_commit_status(api_root, repo_full_name, pr_head_sha, "failure", f"{doc_type} Missing", doc_url or "", gh_token)
        formatted_message = INSTRUCTION_MESSAGE.format(user=pr_user, doc_type=doc_type, url=doc_url or "#")
        post_pr_comment(api_root, repo_full_name, pr_number, formatted_message, gh_token)

def main():
    # Only runs when triggered by an Event (pull_request_target)
    debug_log("--- STARTING COMPLIANCE ENGINE (EVENT MODE) ---")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    repo_full_name = os.environ.get("GITHUB_REPOSITORY")
    gh_token = os.environ.get("GITHUB_TOKEN")
    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    if event_path and os.path.exists(event_path):
        with open(event_path, 'r') as f:
            event = json.load(f)
            pr_data = event.get("pull_request", {})
            pr_number = pr_data.get("number")
            pr_head_sha = pr_data.get("head", {}).get("sha", "")
            pr_user = pr_data.get("user", {}).get("login")
            
            if pr_number:
                process_single_pr(pr_number, pr_head_sha, pr_user, repo_full_name, gh_token, base_path, api_root)

if __name__ == "__main__":
    main()
    
