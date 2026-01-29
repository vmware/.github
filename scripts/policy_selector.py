import os
import sys
import json
import urllib.request
import time
import requires_cla 

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
            if r.status == 204: return {} 
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        debug_log(f"API Error {e.code} for {url}: {e.read().decode()}")
        return None
    except Exception as e:
        debug_log(f"Network Error: {e}")
        return None

def get_open_prs(api_root, repo, token):
    """Fetch all open PRs for the Sweeper Loop."""
    url = f"{api_root}/repos/{repo}/pulls?state=open&per_page=100"
    return github_api(url, token) or []

def add_reaction_to_comment(api_root, repo, comment_id, token):
    """Adds a Rocket emoji to the signature comment."""
    if not comment_id: return
    reaction_url = f"{api_root}/repos/{repo}/issues/comments/{comment_id}/reactions"
    github_api(reaction_url, token, "POST", {"content": "rocket"})

def check_comments_for_signature(api_root, repo, pr_number, user, doc_type, token):
    """Scans PR comments for the magic signature phrase."""
    if not pr_number: return False
    
    url = f"{api_root}/repos/{repo}/issues/{pr_number}/comments"
    comments = github_api(url, token)
    if not comments: return False

    target_phrase = SIGNATURE_PHRASE.format(doc_type=doc_type)
    
    for c in comments:
        body = c.get("body", "").strip()
        comment_user = c.get("user", {}).get("login")
        
        # FIX: Case-insensitive comparison for robustness
        if comment_user and user and comment_user.lower() == user.lower():
            if target_phrase in body:
                comment_id = c.get("id")
                add_reaction_to_comment(api_root, repo, comment_id, token)
                return True
            
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
    """Fixes the UI Infinite Spinner."""
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

def process_single_pr(pr_data, repo_full_name, gh_token, base_path, api_root):
    """Core Logic: Processes a single PR (used by both Main and Sweeper)."""
    
    pr_number = pr_data.get("number")
    pr_head_sha = pr_data.get("head", {}).get("sha")
    # Robust user extraction
    pr_user = pr_data.get("user", {}).get("login") 
    if not pr_user: 
        pr_user = pr_data.get("head", {}).get("user", {}).get("login")

    debug_log(f"🔍 Checking PR #{pr_number} by @{pr_user}...")

    # Bot Check
    if pr_user in BOT_ALLOWLIST or pr_user.endswith("[bot]"):
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", "Bot Bypass", "", gh_token)
        return

    # Policy & Doc Type
    is_strict = requires_cla.requires_CLA(repo_full_name, token=gh_token)
    doc_type = "CLA" if is_strict else "DCO"
    
    # 1. Check JSON File (Official List)
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

    # 2. Check Comments (The "Sweeper" Check)
    has_signed_comment = False
    if not has_signed_json:
        has_signed_comment = check_comments_for_signature(api_root, repo_full_name, pr_number, pr_user, doc_type, gh_token)

    doc_url = os.environ.get("CLA_DOC_URL") if doc_type == "CLA" else os.environ.get("DCO_DOC_URL")

    # DECISION TIME
    if has_signed_json or has_signed_comment:
        debug_log(f"✅ User {pr_user} is COMPLIANT.")
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", f"{doc_type} Signed", "", gh_token)
        
        # Apply UI Fixes
        time.sleep(1)
        force_merge_check_refresh(api_root, repo_full_name, pr_number, gh_token)
    else:
        debug_log(f"❌ User {pr_user} is NOT compliant.")
        set_commit_status(api_root, repo_full_name, pr_head_sha, "failure", f"{doc_type} Missing", doc_url or "", gh_token)
        
        formatted_message = INSTRUCTION_MESSAGE.format(user=pr_user, doc_type=doc_type, url=doc_url or "#")
        post_pr_comment(api_root, repo_full_name, pr_number, formatted_message, gh_token)

def main():
    debug_log("--- STARTING COMPLIANCE ENGINE ---")
    
    repo_full_name = os.environ.get("GITHUB_REPOSITORY")
    gh_token = os.environ.get("GITHUB_TOKEN")
    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    event_path = os.environ.get("GITHUB_EVENT_PATH")

    # MODE 1: Scheduled Sweeper (Batch Mode)
    if event_name == "schedule":
        debug_log("⏰ Running in SWEEPER MODE (Schedule)...")
        open_prs = get_open_prs(api_root, repo_full_name, gh_token)
        debug_log(f"found {len(open_prs)} open PRs.")
        for pr in open_prs:
            try:
                process_single_pr(pr, repo_full_name, gh_token, base_path, api_root)
            except Exception as e:
                debug_log(f"Failed to process PR {pr.get('number')}: {e}")

    # MODE 2: Event Trigger (Single PR Mode)
    elif event_path and os.path.exists(event_path):
        debug_log("⚡ Running in TRIGGER MODE (Event)...")
        with open(event_path, 'r') as f:
            event = json.load(f)
            pr_data = event.get("pull_request")
            if pr_data:
                process_single_pr(pr_data, repo_full_name, gh_token, base_path, api_root)

if __name__ == "__main__":
    main()
    
