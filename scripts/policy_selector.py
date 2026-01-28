import os
import sys
import json
import urllib.request
import re
import requires_cla # Your helper script

# --- CONFIGURATION ---
BOT_ALLOWLIST = ["dependabot[bot]", "github-actions[bot]", "renovate[bot]"]
# The specific text we look for to know if we already posted instructions
INSTRUCTION_MARKER = "Compliance Check Failed" 

def github_api(url, token, method="GET", data=None):
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    try:
        req = urllib.request.Request(url, headers=headers, method=method)
        if data: req.data = json.dumps(data).encode("utf-8")
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read().decode()) if method != "PUT" else {}
    except urllib.error.HTTPError as e:
        print(f"⚠️ API Error {e.code} for {url}")
        return None
    except Exception as e:
        print(f"⚠️ Network Error: {e}")
        return None

def post_failure_comment(comments_url, token, user, mode, doc_url):
    """
    Posts the 'Please Sign' instructions ONLY if they aren't already there.
    """
    # 1. Check existing comments to avoid spam
    comments = github_api(comments_url, token) or []
    for c in comments:
        # If we (the bot) already posted the instructions, don't do it again
        if INSTRUCTION_MARKER in c.get("body", "") and c.get("user", {}).get("type") == "Bot":
            print("ℹ️  Instruction comment already exists. Skipping.")
            return

    # 2. Construct the comment
    body = (
        f"🔴 **{INSTRUCTION_MARKER}**\n\n"
        f"@{user}, this repository requires you to sign a **{mode}**.\n\n"
        f"📄 **[Read the {mode} Document Here]({doc_url})**\n\n"
        f"To sign, please copy and paste the following comment exactly:\n"
        f"```text\nI have read the {mode} Document and I hereby sign the {mode}\n```"
    )

    # 3. Post it
    print("📢 Posting instruction comment to PR...")
    github_api(comments_url, token, "POST", {"body": body})

def main():
    # 1. Capture Inputs
    pr_user = os.environ.get("PR_AUTHOR")
    gh_token = os.environ.get("GITHUB_TOKEN")
    current_org = os.environ.get("CENTRAL_ORG")
    base_path = os.environ.get("TOOLS_PATH", ".github-tools")
    comments_url = os.environ.get("PR_COMMENTS_URL")
    
    # --- FEATURE 1: BOT ALLOWLIST ---
    if pr_user in BOT_ALLOWLIST or pr_user.endswith("[bot]"):
        print(f"🤖 User @{pr_user} is a bot. Bypassing check.")
        with open(os.environ['GITHUB_OUTPUT'], 'a') as fh: fh.write("bypass=true\n")
        sys.exit(0)

    # --- EXISTING: MEMBER CHECK ---
    is_member = False
    url = f"https://api.github.com/orgs/{current_org}/members/{pr_user}"
    try:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {gh_token}"})
        with urllib.request.urlopen(req) as r:
            if r.getcode() == 204: is_member = True
    except: pass

    if is_member:
        print(f"✅ User @{pr_user} is an Org Member. Bypassing.")
        with open(os.environ['GITHUB_OUTPUT'], 'a') as fh: fh.write("bypass=true\n")
        sys.exit(0)

    # --- EXISTING: DETECT POLICY ---
    repo_full = os.environ.get("GITHUB_REPOSITORY", "")
    is_strict = requires_cla.requires_CLA(repo_full, token=gh_token)
    mode = "CLA" if is_strict else "DCO"
    print(f"ℹ️  Policy Determined: {mode}")

    # Select the correct document URL based on mode
    # You can customize these ENV vars in the YAML if needed
    doc_url = os.environ.get("CLA_DOC_URL") if mode == "CLA" else os.environ.get("DCO_DOC_URL")
    if not doc_url: doc_url = "#" # Fallback

    # --- EXISTING: VERIFY SIGNATURE ---
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
    except: pass

    # --- RESULT HANDLER ---
    if has_signed:
        print(f"✅ Success: User @{pr_user} has signed the {mode}.")
        sys.exit(0)
    else:
        print(f"❌ Failure: User @{pr_user} has NOT signed the {mode}.")
        
        # --- FEATURE 2: POST COMMENT ---
        # We only post if we have the URL and Token
        if comments_url and gh_token:
            post_failure_comment(comments_url, gh_token, pr_user, mode, doc_url)
        
        # Job Summary (Backup visual)
        if "GITHUB_STEP_SUMMARY" in os.environ:
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
                f.write(f"### 🔴 Compliance Check Failed\n")
                f.write(f"User @{pr_user} must sign the **[{mode}]({doc_url})**.\n")

        sys.exit(1) # Fail the build

if __name__ == "__main__":
    main()
    
    
