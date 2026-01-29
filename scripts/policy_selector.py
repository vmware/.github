import os
import sys
import json
import urllib.request
import time
import requires_cla 

# --- CONFIGURATION ---
STATUS_CONTEXT = "Check CLA/DCO" 
BOT_ALLOWLIST = ["dependabot[bot]", "github-actions[bot]", "renovate[bot]"]

# --- USER FACING MESSAGES ---

# Message 1: The Instruction (Posted when they fail)
INSTRUCTION_MESSAGE_LINES = [
    "### 🛑 Legal Compliance Check Failed",
    "Hi @{user}, thank you for your contribution!",
    "",
    "To merge this Pull Request, you must sign our **{doc_type}**.",
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

# Message 2: The Receipt (Posted/Reacted when they pass via Sweeper)
# Note: This runs silently in the background, but good to have the logic ready.

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
            # Handle 204 No Content (often returned by Reactions API)
            if r.status == 204: return {} 
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        debug_log(f"API Error {e.code} for {url}: {e.read().decode()}")
        return None
    except Exception as e:
        debug_log(f"Network Error: {e}")
        return None

def post_pr_comment(api_root, repo, pr_number, message, token):
    if not pr_number: return
    comments_url = f"{api_root}/repos/{repo}/issues/{pr_number}/comments"
    existing_comments = github_api(comments_url, token)
    
    # Avoid spam
    if existing_comments:
        for c in existing_comments:
            if "I have read the" in c.get("body", "") and "Sign via Comment" in c.get("body", ""):
                debug_log("⚠️ Instruction comment already exists. Skipping.")
                return

    payload = {"body": message}
    debug_log(f"💬 Posting instruction comment to PR #{pr_number}...")
    github_api(comments_url, token, "POST", payload)

def add_reaction_to_comment(api_root, repo, pr_number, user, token):
    """
    Finds the user's signing comment and adds a Rocket emoji to confirm receipt.
    """
    if not pr_number: return
    comments_url = f"{api_root}/repos/{repo}/issues/{pr_number}/comments"
    comments = github_api(comments_url, token)
    
    if not comments: return

    for c in comments:
        # Look for the user's signature comment
        if c.get("user", {}).get("login") == user and "I hereby sign" in c.get("body", ""):
            comment_id = c.get("id")
            reaction_url = f"{api_root}/repos/{repo}/issues/comments/{comment_id}/reactions"
            # Add Rocket 🚀
            debug_log(f"🚀 Adding reaction to comment {comment_id}...")
            github_api(reaction_url, token, "POST", {"content": "rocket"})
            return

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

def main():
    debug_log("--- STARTING COMPLIANCE CHECK ---")
    
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
    
    current_sha = os.environ.get("GITHUB_SHA", "")
    pr_user = os.environ.get("PR_AUTHOR")
    gh_token = os.environ.get("GITHUB_TOKEN")
    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    # Bot Check
    if pr_user in BOT_ALLOWLIST or pr_user.endswith("[bot]"):
        if pr_head_sha: 
            set_commit_status(api_root, repo_full_name, pr_head_sha, "success", "Bot Bypass", "", gh_token)
        sys.exit(0)

    # Policy Check
    is_strict = requires_cla.requires_CLA(repo_full_name, token=gh_token)
    doc_type = "CLA" if is_strict else "DCO"
    
    # Signature Check
    sig_file_path = f"{base_path}/signatures/{doc_type.lower()}.json"
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

    # Results
    doc_url = os.environ.get("CLA_DOC_URL") if doc_type == "CLA" else os.environ.get("DCO_DOC_URL")
    
    if has_signed:
        debug_log(f"✅ User {pr_user} has signed.")
        if pr_head_sha:
            set_commit_status(api_root, repo_full_name, pr_head_sha, "success", f"{doc_type} Signed", "", gh_token)
        if current_sha and current_sha != pr_head_sha:
            set_commit_status(api_root, repo_full_name, current_sha, "success", f"{doc_type} Signed", "", gh_token)
        
        # UX Polish: Refresh Spinner AND React to Comment
        if pr_number:
            time.sleep(1)
            force_merge_check_refresh(api_root, repo_full_name, pr_number, gh_token)
            # Try to react to their comment (if it exists) to close the loop
            try:
                add_reaction_to_comment(api_root, repo_full_name, pr_number, pr_user, gh_token)
            except Exception:
                pass # Non-critical failure

        sys.exit(0)
    else:
        debug_log(f"❌ User {pr_user} has NOT signed.")
        if pr_head_sha:
            set_commit_status(api_root, repo_full_name, pr_head_sha, "failure", f"{doc_type} Missing", doc_url or "", gh_token)
        
        if pr_number:
            formatted_message = INSTRUCTION_MESSAGE.format(
                user=pr_user, 
                doc_type=doc_type, 
                url=doc_url or "#"
            )
            post_pr_comment(api_root, repo_full_name, pr_number, formatted_message, gh_token)
            
        sys.exit(1)

if __name__ == "__main__":
    main()
    
