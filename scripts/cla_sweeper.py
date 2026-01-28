#!/usr/bin/env python3
import os
import json
import re
import base64
import time
import urllib.request
import urllib.parse
from datetime import datetime, timedelta

import jwt 

REQUIRED_CONTEXT = "Check CLA/DCO" 
SIGN_REGEX = r"I have read the (CLA|DCO) Document and I hereby sign the (CLA|DCO)"

def get_app_token(org_name, app_id, private_key):
    if not app_id or not private_key: return None
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + (9 * 60), "iss": app_id}
    encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")
    url = f"https://api.github.com/orgs/{org_name}/installation"
    headers = {"Authorization": f"Bearer {encoded_jwt}", "Accept": "application/vnd.github+json"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as r:
            installation_id = json.loads(r.read().decode())["id"]
        token_url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        req = urllib.request.Request(token_url, headers=headers, method="POST")
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read().decode())["token"]
    except Exception as e:
        print(f"Auth Error for {org_name}: {e}")
        return None

def github_api(url, token, method="GET", data=None):
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    try:
        req = urllib.request.Request(url, headers=headers, method=method)
        if data: req.data = json.dumps(data).encode("utf-8")
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read().decode()) if method != "PUT" else {}
    except Exception as e:
        print(f"API Error {url}: {e}")
        return None

def post_success_comment(comments_url, user, mode, token):
    body = (
        f"@{user} **Verification Successful!**\n\n"
        f"I have recorded your {mode} signature.\n"
        f"✅ *Status check has been forced to GREEN. You may merge now.*"
    )
    comments = github_api(comments_url, token) or []
    for c in comments:
        if "Verification Successful!" in c.get("body", "") and c.get("user", {}).get("type") == "Bot":
            return
    github_api(comments_url, token, "POST", {"body": body})

def force_green_status(repo_url, head_sha, token, target_url=""):
    print(f"Forcing status '{REQUIRED_CONTEXT}' to success for {head_sha}...")
    status_url = f"{repo_url}/statuses/{head_sha}"
    payload = {
        "state": "success",
        "context": REQUIRED_CONTEXT,
        "description": "Signature verified by Legal Compliance Bot",
        "target_url": target_url
    }
    github_api(status_url, token, "POST", payload)

def get_signature_list(central_org, central_repo, mode, token):
    path = f"signatures/{mode.lower()}.json"
    url = f"https://api.github.com/repos/{central_org}/{central_repo}/contents/{path}"
    data = github_api(url, token)
    if not data: return [], None, None
    
    content = {"signedContributors": []}
    try:
        decoded = json.loads(base64.b64decode(data["content"]).decode())
        if "signedContributors" in decoded:
            content = decoded
        elif "signed" in decoded:
            content["signedContributors"] = decoded["signed"]
    except: pass
    
    return content["signedContributors"], data["sha"], url

def update_central_signature(url, sha, current_list, user_data, mode, token):
    if any(u.get("name", "").lower() == user_data["login"].lower() for u in current_list):
        return True

    new_entry = {
        "name": user_data["login"],
        "id": user_data["id"],
        "comment_id": user_data.get("comment_id", 0),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "repoId": user_data.get("repo_id", 0),
        "pullRequestNo": user_data.get("pr_number", 0)
    }
    
    current_list.append(new_entry)
    file_content = {"signedContributors": current_list}
    
    payload = {
        "message": f"Sweeper App Sign {mode} for @{user_data['login']}",
        "content": base64.b64encode(json.dumps(file_content, indent=2).encode()).decode(),
        "sha": sha
    }
    return github_api(url, token, method="PUT", data=payload) is not None

def main():
    app_id = os.environ.get("CLA_APP_ID")
    private_key = os.environ.get("CLA_APP_PRIVATE_KEY")
    current_org = os.environ.get("ORG_NAME")
    central_org = os.environ.get("CENTRAL_ORG")
    central_repo = os.environ.get("CONFIG_REPO", ".github")

    local_token = get_app_token(current_org, app_id, private_key)
    mothership_token = get_app_token(central_org, app_id, private_key)
    
    if not local_token or not mothership_token: return

    # 1. Fetch Lists
    cla_list, cla_sha, cla_url = get_signature_list(central_org, central_repo, "CLA", mothership_token)
    dco_list, dco_sha, dco_url = get_signature_list(central_org, central_repo, "DCO", mothership_token)
    
    # 2. Search Recent PRs
    since = (datetime.utcnow() - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%S")
    query = f'org:{current_org} is:pr is:open updated:>{since}'
    results = github_api(f"https://api.github.com/search/issues?q={urllib.parse.quote(query)}", local_token)
    
    if not results: return

    for item in results.get("items", []):
        pr_user = item["user"]["login"]
        
        # --- OPTIMIZATION START ---
        # Skip Members/Owners immediately (Free check, no API call)
        # They are already bypassed by the main workflow.
        assoc = item.get("author_association", "NONE")
        if assoc in ["MEMBER", "OWNER"]:
            continue 
        # --- OPTIMIZATION END ---

        repo_url = item["repository_url"]
        pr_number = item["number"]

        is_cla_signed = any(u.get("name", "").lower() == pr_user.lower() for u in cla_list)
        is_dco_signed = any(u.get("name", "").lower() == pr_user.lower() for u in dco_list)
        
        # SCENARIO A: Already Signed (Force Green)
        if is_cla_signed or is_dco_signed:
            print(f"User @{pr_user} is already signed (Assoc: {assoc}). Forcing Green.")
            pr_details = github_api(item["pull_request"]["url"], local_token)
            head_sha = pr_details["head"]["sha"]
            force_green_status(repo_url, head_sha, local_token, target_url=item["html_url"])
            continue

        # SCENARIO B: Not Signed (Check for Comment)
        comments_url = item["comments_url"]
        comments = github_api(comments_url, local_token) or []
        mode_signed = None
        found_comment_id = 0

        for c in comments:
            if c["user"]["login"] == pr_user:
                m = re.search(SIGN_REGEX, c["body"], re.IGNORECASE)
                if m:
                    mode_signed = m.group(2).upper()
                    found_comment_id = c["id"]
                    break
        
        if mode_signed:
            print(f"New signature found: {mode_signed} for {pr_user}")
            
            user_data = {
                "login": pr_user,
                "id": item["user"]["id"],
                "comment_id": found_comment_id,
                "repo_id": 0,
                "pr_number": pr_number
            }
            
            target_list = cla_list if mode_signed == "CLA" else dco_list
            target_sha = cla_sha if mode_signed == "CLA" else dco_sha
            target_url = cla_url if mode_signed == "CLA" else dco_url

            if update_central_signature(target_url, target_sha, target_list, user_data, mode_signed, mothership_token):
                post_success_comment(comments_url, pr_user, mode_signed, local_token)
                
                pr_details = github_api(item["pull_request"]["url"], local_token)
                head_sha = pr_details["head"]["sha"]
                force_green_status(repo_url, head_sha, local_token, target_url=item["html_url"])

if __name__ == "__main__":
    main()
    
