import os
import sys
import json
import urllib.request
import urllib.error
import time
import yaml
import base64
import gzip
import io

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
        def requires_CLA(repo, token=None, licenses_data=None, permissive_data=None, allowlist_data=None): return True
    requires_cla = requires_cla_stub
# --- [INTEGRATION END] -------------------------------------

# --- CONFIGURATION ---
STATUS_CONTEXT = "Check CLA/DCO" 
BOT_ALLOWLIST = ["dependabot[bot]", "github-actions[bot]", "renovate[bot]"]
SIGNATURE_PHRASE = "I have read the {doc_type} Document and I hereby sign the {doc_type}"

# --- UPDATED TEXT: STANDING WARRANTY ---
INSTRUCTION_MESSAGE_LINES = [
    "### 🛑 Legal Compliance Check Failed",
    "Hi @{user}, thank you for your contribution!",
    "",
    "To merge this Pull Request, you must sign our **{doc_type}**.",
    "",
    "**Note:** Even if you signed off your commits locally (using `git commit -s`), you must post the comment below to register your signature with our automated system.",
    "**Note:** This is a one-time process. Once signed, future contributions to this repository will be verified automatically.",
    "",
    "**1. Read the Document:** [Click here to read the {doc_type}]({url})",
    "**2. Sign via Comment:** Copy and paste the exact line below into a new comment on this Pull Request:",
    "",
    "```text",
    "I have read the {doc_type} Document and I hereby sign the {doc_type} for this and all future contributions.",
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
        if e.code != 404:
            debug_log(f"API Error {e.code} for {url}: {e.read().decode()}")
        return None
    except Exception as e:
        debug_log(f"Network Error: {e}")
        return None

# --- UNIFIED RESOURCE LOADER ---
def fetch_mothership_file(api_root, file_path, token):
    central_org = os.environ.get("CENTRAL_ORG") or "vmware"
    mothership_repo = f"{central_org}/.github"
    url = f"{api_root}/repos/{mothership_repo}/contents/{file_path}"
    debug_log(f"📥 API Fetch: {mothership_repo}/{file_path}")
    
    data = github_api(url, token)
    content_b64 = None
    
    if data:
        if "content" in data and data["content"]:
            content_b64 = data["content"]
        elif "sha" in data:
            debug_log(f"📦 Large file detected ({data.get('size')} bytes). Fetching blob {data['sha']}...")
            blob_url = f"{api_root}/repos/{mothership_repo}/git/blobs/{data['sha']}"
            blob_data = github_api(blob_url, token)
            if blob_data and "content" in blob_data:
                content_b64 = blob_data["content"]
    
    if content_b64:
        try:
            decoded_bytes = base64.b64decode(content_b64)
            if file_path.endswith(".gz"):
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(decoded_bytes)) as gz:
                        return gz.read().decode("utf-8")
                except Exception as gz_e:
                    debug_log(f"❌ Gzip Decompression Failed: {gz_e}")
                    return None
            return decoded_bytes.decode("utf-8")
        except Exception as e:
            debug_log(f"❌ Failed to decode/read file {file_path}: {e}")
            return None
    return None

def fetch_json_with_fallback(api_root, primary_path, secondary_path, token):
    candidates = [primary_path, f"{primary_path}.gz", secondary_path, f"{secondary_path}.gz"]
    for path in candidates:
        raw = fetch_mothership_file(api_root, path, token)
        if raw:
            try:
                return json.loads(raw)
            except json.JSONDecodeError as e:
                debug_log(f"❌ JSON Parse Error for {path}: {e}")
                continue
    return None

def add_reaction_to_comment(api_root, repo, comment_id, token):
    if not comment_id: return
    reaction_url = f"{api_root}/repos/{repo}/issues/comments/{comment_id}/reactions"
    try:
        github_api(reaction_url, token, "POST", {"content": "rocket"})
    except:
        pass

# --- CHANGED: Returns ID (int) instead of Bool for audit trail ---
def check_comments_for_signature(api_root, repo, pr_number, user, doc_type, token):
    if not pr_number: return None
    url = f"{api_root}/repos/{repo}/issues/{pr_number}/comments?per_page=100"
    comments = github_api(url, token)
    if not comments: return None

    possible_types = ["CLA", "DCO"]
    base_phrase = "I have read the {doc_type} Document and I hereby sign the {doc_type}"
    # The suffix we expect (without "to this repository")
    suffix_check = "for this and all future contributions"

    for c in comments:
        body = c.get("body", "")
        comment_user = c.get("user", {}).get("login")
        if comment_user and user and comment_user.lower() == user.lower():
            normalized_body = body.replace("\xa0", " ").strip()
            for current_type in possible_types:
                # We check the core phrase. If user includes "and future contributions", it still matches.
                target_phrase = base_phrase.format(doc_type=current_type)

                if target_phrase in normalized_body:
                    # OPTIONAL: We can enforce the suffix if strictness is required.
                    # Given the legal strategy, it's good to ensure they didn't just type half of it.
                    if suffix_check in normalized_body:
                        debug_log(f"✅ Found matching {current_type} signature from {user}!")
                        add_reaction_to_comment(api_root, repo, c.get("id"), token)
                        return c.get("id")
                                            
    debug_log(f"❌ No matching CLA or DCO signature found in {len(comments)} comments.")
    return None

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

# --- CHANGED: Accepts & Stores Context Metadata ---
def record_signature(api_root, org_name, doc_type, user, repo_name, token, pr_number, head_sha, comment_id):
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

        # 1. Check if already signed (The Registry Check)
        for c in contributors:
            if isinstance(c, dict):
                if c.get("name", "").lower() == user.lower(): return True
                if user_id and c.get("id") == user_id: return True
            elif isinstance(c, str) and c.lower() == user.lower(): return True

        # 2. If new, Capture Hybrid Context (The Enrollment)
        new_entry = {
            "name": user,
            "id": user_id,
            "signedAt": datetime.utcnow().isoformat() + "Z",
            "org": org_name,
            "repo": repo_name,
            "pr_number": pr_number,      # Context
            "head_sha": head_sha,        # Forensic Link
            "comment_id": comment_id,    # Audit Trail
            "agreement_version": "1.0"   # Future Proofing
        }
        contributors.append(new_entry)
        
        updated_content = json.dumps(json_data, indent=2)
        commit_message = f"Sign {doc_type} for @{user} (PR #{pr_number})"
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
        
    # --- 1. FETCH CONFIGURATION ---
    
    # A. Allowlist (Try cla/ -> data/)
    raw_allowlist = fetch_mothership_file(api_root, "cla/allowlist.yml", gh_token)
    if not raw_allowlist:
        raw_allowlist = fetch_mothership_file(api_root, "data/allowlist.yml", gh_token)
        
    allowlist_repos = []
    allowlist_data = {} 
    
    if raw_allowlist:
        try:
            allowlist_data = yaml.safe_load(raw_allowlist)
            # Handle nesting under 'license_overrides' -> 'repos'
            repos_config = allowlist_data.get("license_overrides", {}).get("repos", {})
            if not repos_config:
                 repos_config = allowlist_data.get("repos", {})
            
            if isinstance(repos_config, dict):
                for r_name, r_config in repos_config.items():
                    if r_config.get("require_cla") is False:
                        allowlist_repos.append(r_name)
            
            allowlist_repos.extend(allowlist_data.get("repositories", []))
            debug_log(f"✅ Allowlist loaded via API. Found {len(allowlist_repos)} DCO-only repos.")
        except Exception as e:
            debug_log(f"⚠️ Failed to parse allowlist YAML: {e}")

    # B. Licenses
    licenses_data = fetch_json_with_fallback(api_root, "data/licenses_all.json", "cla/licenses_all.json", gh_token) or []
    
    # C. Permissive Names
    permissive_data = fetch_json_with_fallback(api_root, "data/permissive_names.json", "cla/permissive_names.json", gh_token) or []

    # --- 2. DETERMINE POLICY ---
    is_strict = True
    try:
        is_strict = requires_cla.requires_CLA(
            repo_full_name, 
            token=gh_token, 
            licenses_data=licenses_data,
            permissive_data=permissive_data,
            allowlist_data=allowlist_data
        )
    except Exception as e:
        debug_log(f"⚠️ Logic Module Error: {e}. Defaulting to STRICT mode.")
        is_strict = True
        
    # Allowlist Override
    if repo_full_name in allowlist_repos:
        debug_log(f"ℹ️ Repo {repo_full_name} is in Allowlist. Enforcing DCO only.")
        is_strict = False

    debug_log(f"🧐 POLICY DECISION for {repo_full_name}: {'CLA' if is_strict else 'DCO'}")
    doc_type = "CLA" if is_strict else "DCO"
    
    # --- 3. CHECK SIGNATURES (Registry Check) ---
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
            
    # 4. Check Comments (Forensics Collection)
    comment_id = None
    if not has_signed_json:
        # Returns ID (int) if found, None if not
        comment_id = check_comments_for_signature(api_root, repo_full_name, pr_number, pr_user, doc_type, gh_token)

    doc_url = os.environ.get("CLA_DOC_URL") if doc_type == "CLA" else os.environ.get("DCO_DOC_URL")

    if has_signed_json:
        debug_log(f"✅ User {pr_user} is COMPLIANT (Found in JSON).")
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", f"{doc_type} Signed", "", gh_token)
        
    elif comment_id:
        debug_log(f"✅ User {pr_user} is COMPLIANT (Signature comment found).")
        # RECORD HYBRID METADATA
        record_signature(api_root, org_name, doc_type, pr_user, repo_full_name, gh_token, pr_number, pr_head_sha, comment_id)
        
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
    
