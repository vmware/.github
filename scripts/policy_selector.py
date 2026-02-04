import os
import sys
import json
import urllib.request
import urllib.error
import time
import yaml
import base64
import tempfile 

# --- [INTEGRATION START] IMPORT CLA AUTHENTICATION MODULE ---
try:
    import cla_auth
except ImportError:
    print("::warning::[SETUP] 'cla_auth.py' module not found. Token upgrade checks may fail.")

try:
    import requires_cla
except ImportError:
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

# --- TOKEN UPGRADE LOGIC ---
def ensure_valid_token():
    if os.environ.get("CLA_TOKEN_UPGRADED") == "true": return
    print("::warning::[AUTH] Checking for available credentials to upgrade token...")
    app_id = os.environ.get("CLA_APP_ID")
    private_key = os.environ.get("CLA_APP_PRIVATE_KEY")
    org_name = os.environ.get("CENTRAL_ORG") or "vmware"

    if not app_id or not private_key:
        print("::warning::[AUTH] CLA_APP_ID or CLA_APP_PRIVATE_KEY missing. Cannot perform token upgrade.")
        return

    try:
        fresh_token = cla_auth.get_installation_access_token(app_id, private_key, org_name)
        if fresh_token:
            os.environ["GH_TOKEN"] = fresh_token
            os.environ["GITHUB_TOKEN"] = fresh_token
            os.environ["CLA_TOKEN_UPGRADED"] = "true"
            print("::warning::[AUTH] ✅ Token Upgrade Successful!")
        else:
            print("::error::[AUTH] Token Upgrade Failed.")
    except Exception as e:
        print(f"::error::[AUTH CRASH] Unexpected error during token upgrade: {e}")

# Run upgrade immediately
ensure_valid_token()

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
        with urllib.request.urlopen(req) as response:
            if response.getcode() == 204: return True
    except urllib.error.HTTPError as e:
        debug_log(f"❌ GitHub API error: {e.code} - {e.reason}")
        if e.code == 404: debug_log("-> NOTE: 404 means 'Not Found'.")
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

# --- UNIFIED RESOURCE LOADER (WITH FALLBACKS) ---
def fetch_mothership_file(api_root, file_path, token):
    """
    Fetches a file from the central repo via API.
    """
    central_org = os.environ.get("CENTRAL_ORG") or "vmware"
    mothership_repo = f"{central_org}/.github"
    url = f"{api_root}/repos/{mothership_repo}/contents/{file_path}"
    
    debug_log(f"📥 API Fetch: {mothership_repo}/{file_path}")
    
    data = github_api(url, token)
    if data and "content" in data:
        try:
            return base64.b64decode(data["content"]).decode("utf-8")
        except Exception as e:
            debug_log(f"❌ Failed to decode file {file_path}: {e}")
            return None
    return None

def fetch_file_with_fallback(api_root, primary_path, secondary_path, token):
    """
    Tries to fetch the file from the primary path.
    If that fails, tries the secondary path.
    """
    content = fetch_mothership_file(api_root, primary_path, token)
    if content:
        return content
    
    debug_log(f"⚠️ Primary path {primary_path} failed. Trying fallback: {secondary_path}")
    return fetch_mothership_file(api_root, secondary_path, token)

def add_reaction_to_comment(api_root, repo, comment_id, token):
    if not comment_id: return
    reaction_url = f"{api_root}/repos/{repo}/issues/comments/{comment_id}/reactions"
    try:
        github_api(reaction_url, token, "POST", {"content": "rocket"})
    except:
        pass

def check_comments_for_signature(api_root, repo, pr_number, user, doc_type, token):
    if not pr_number: return False
    url = f"{api_root}/repos/{repo}/issues/{pr_number}/comments?per_page=100"
    comments = github_api(url, token)
    if not comments: return False

    possible_types = ["CLA", "DCO"]
    for c in comments:
        body = c.get("body", "")
        comment_user = c.get("user", {}).get("login")
        if comment_user and user and comment_user.lower() == user.lower():
            normalized_body = body.replace("\xa0", " ").strip()
            for current_type in possible_types:
                target_phrase = SIGNATURE_PHRASE.format(doc_type=current_type)
                if target_phrase in normalized_body:
                    debug_log(f"✅ Found matching {current_type} signature from {user}!")
                    add_reaction_to_comment(api_root, repo, c.get("id"), token)
                    return True
    debug_log(f"❌ No matching CLA or DCO signature found in {len(comments)} comments.")
    return False

def post_pr_comment(api_root, repo, pr_number, message, token):
    if not pr_number: return
    comments_url = f"{api_root}/repos/{repo}/issues/{pr_number}/comments"
    existing_comments = github_api(comments_url, token)
    if existing_comments:
        for c in existing_comments:
            if "I have read the" in c.get("body", "") and "Sign via Comment" in c.get("body", ""):
                return 
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

from datetime import datetime

def record_signature(api_root, org_name, doc_type, user, repo_name, token):
    target_repo = f"{org_name}/.github"
    file_path = f"signatures/{doc_type.lower()}.json"
    url = f"{api_root}/repos/{target_repo}/contents/{file_path}"
    
    debug_log(f"💾 Attempting to record signature via API...")

    user_details = github_api(f"{api_root}/users/{user}", token)
    user_id = user_details.get("id") if user_details else None

    data = github_api(url, token)
    if not data or "content" not in data:
        debug_log(f"❌ Failed to fetch signature file. Check permissions for {target_repo}.")
        return False

    try:
        file_content = base64.b64decode(data["content"]).decode("utf-8")
        json_data = json.loads(file_content)
        if "signedContributors" not in json_data: json_data["signedContributors"] = []
        contributors = json_data["signedContributors"]

        for c in contributors:
            if isinstance(c, dict):
                if c.get("name", "").lower() == user.lower(): return True
                if user_id and c.get("id") == user_id: return True
            elif isinstance(c, str) and c.lower() == user.lower(): return True

        new_entry = {
            "name": user,
            "id": user_id,
            "signedAt": datetime.utcnow().isoformat() + "Z",
            "org": org_name,
            "repo": repo_name
        }
        contributors.append(new_entry)
        
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
    gh_token = os.environ.get("GH_TOKEN") or gh_token
    debug_log(f"🔍 Checking PR #{pr_number} by @{pr_user}...")

    # 1. Bot Check
    if pr_user in BOT_ALLOWLIST or pr_user.endswith("[bot]"):
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", "Bot Bypass", "", gh_token)
        return

    # 2. Org Member/Owner Check
    org_name = repo_full_name.split("/")[0]
    if is_org_member(api_root, org_name, pr_user, gh_token):
        debug_log(f"🛡️ User @{pr_user} is an Organization Member. Skipping check.")
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", "Member Bypass", "", gh_token)
        return
        
    # --- [SECURE] LOAD ALLOWLIST (API) ---
    # UPDATED: Try 'cla/' first as requested, then 'data/'
    raw_allowlist = fetch_file_with_fallback(api_root, "cla/allowlist.yml", "data/allowlist.yml", gh_token)
    allowlist_repos = []
    
    if raw_allowlist:
        try:
            allowlist_data = yaml.safe_load(raw_allowlist)
            allowlist_repos = allowlist_data.get("repositories", [])
            debug_log(f"✅ Allowlist loaded via API. Found {len(allowlist_repos)} repos.")
        except Exception as e:
            debug_log(f"⚠️ Failed to parse allowlist YAML: {e}")
    else:
        debug_log("⚠️ Allowlist not found in 'cla/' or 'data/'. Proceeding with empty list.")

    # --- [SECURE] LOAD LICENSES (API + TEMP FILE) ---
    # UPDATED: Try 'cla/' first as requested, then 'data/'
    raw_licenses = fetch_file_with_fallback(api_root, "cla/licenses_all.json", "data/licenses_all.json", gh_token)
    
    # SAFETY: If API fails completely, use an empty JSON array to prevent FileNotFound crash
    if not raw_licenses:
        debug_log("❌ CRITICAL: Could not load licenses from API. Using empty fallback.")
        raw_licenses = "[]"
    
    # Context manager ensures file is DELETED after use
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=True) as temp_license_file:
        temp_license_file.write(raw_licenses)
        temp_license_file.flush()
        
        # Point env var to the temp file so requires_cla finds it
        os.environ["LICENSES_JSON"] = temp_license_file.name
        debug_log(f"✅ Licenses loaded into temp file: {temp_license_file.name}")

        # 3. Policy & Doc Type
        is_strict = requires_cla.requires_CLA(repo_full_name, token=gh_token)
        
    # NOTE: temp_license_file is auto-deleted here.
    
    if repo_full_name in allowlist_repos:
        debug_log(f"ℹ️ Repo {repo_full_name} is in Allowlist. Enforcing DCO only.")
        is_strict = False

    debug_log(f"🧐 POLICY DECISION for {repo_full_name}: {'CLA' if is_strict else 'DCO'}")
    doc_type = "CLA" if is_strict else "DCO"
    
    # --- [SECURE] LOAD SIGNATURES (API) ---
    has_signed_json = False
    sig_file_path = f"signatures/{doc_type.lower()}.json"
    raw_signatures = fetch_mothership_file(api_root, sig_file_path, gh_token)
    
    if raw_signatures:
        try:
            data = json.loads(raw_signatures)
            contributors = data.get("signedContributors", []) if isinstance(data, dict) else data
            for c in contributors:
                if isinstance(c, dict):
                    if c.get("name", "").lower() == pr_user.lower(): has_signed_json = True; break
                elif isinstance(c, str):
                    if c.lower() == pr_user.lower(): has_signed_json = True; break
        except Exception as e:
            debug_log(f"⚠️ Failed to parse Signatures JSON: {e}")
            
    # 2. Check Comments (Universal Acceptor)
    has_signed_comment = False
    if not has_signed_json:
        has_signed_comment = check_comments_for_signature(api_root, repo_full_name, pr_number, pr_user, doc_type, gh_token)

    doc_url = os.environ.get("CLA_DOC_URL") if doc_type == "CLA" else os.environ.get("DCO_DOC_URL")

    if has_signed_json:
        debug_log(f"✅ User {pr_user} is COMPLIANT (Found in JSON).")
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", f"{doc_type} Signed", "", gh_token)
        
    elif has_signed_comment:
        debug_log(f"✅ User {pr_user} is COMPLIANT (Signature comment found).")
        record_signature(api_root, org_name, doc_type, pr_user, repo_full_name, gh_token)
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", f"{doc_type} Signed", "", gh_token)
        time.sleep(1)
        force_merge_check_refresh(api_root, repo_full_name, pr_number, gh_token)
        
    else:
        debug_log(f"❌ User {pr_user} is NOT compliant.")
        set_commit_status(api_root, repo_full_name, pr_head_sha, "failure", f"{doc_type} Missing", doc_url or "", gh_token)
        formatted_message = INSTRUCTION_MESSAGE.format(user=pr_user, doc_type=doc_type, url=doc_url or "#")
        post_pr_comment(api_root, repo_full_name, pr_number, formatted_message, gh_token)

def main():
    debug_log("--- STARTING COMPLIANCE ENGINE (EVENT MODE) ---")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_path = os.path.dirname(script_dir)
    
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    repo_full_name = os.environ.get("GITHUB_REPOSITORY")
    gh_token = os.environ.get("GITHUB_TOKEN")
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
    ensure_valid_token()
    main()
    
