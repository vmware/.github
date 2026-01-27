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

WORKFLOW_NAME = "Legal Compliance Gate"
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
    """Posts a comment to the PR confirming success."""
    body = (
        f"@{user} **Verification Successful!**\n\n"
        f"I have recorded your {mode} signature and re-triggered the checks.\n"
        f"🔄 *The status should update momentarily. If the Merge button remains disabled, please refresh this page.*"
    )
    # Check if we already posted (to avoid spamming if script runs twice)
    comments = github_api(comments_url, token) or []
    for c in comments:
        if "Verification Successful!" in c.get("body", "") and c.get("user", {}).get("type") == "Bot":
            return # Already commented
            
    github_api(comments_url, token, "POST", {"body": body})

def update_central_signature(central_org, central_repo, user_data, mode, token):
    path = f"signatures/{mode.lower()}.json"
    url = f"https://api.github.com/repos/{central_org}/{central_repo}/contents/{path}"
    data = github_api(url, token)
    
    if not data: return False
    
    content = {"signedContributors": []}
    try:
        decoded = json.loads(base64.b64decode(data["content"]).decode())
        if "signedContributors" in decoded:
            content = decoded
        elif "signed" in decoded:
            content["signedContributors"] = decoded["signed"]
    except: pass

    if any(u.get("name", "").lower() == user_data["login"].lower() for u in content["signedContributors"]):
        return True

    new_entry = {
        "name": user_data["login"],
        "id": user_data["id"],
        "comment_id": user_data.get("comment_id", 0),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "repoId": user_data.get("repo_id", 0),
        "pullRequestNo": user_data.get("pr_number", 0)
    }

    content["signedContributors"].append(new_entry)
    
    payload = {
        "message": f"Sweeper App Sign {mode} for @{user_data['login']}",
        "content": base64.b64encode(json.dumps(content, indent=2).encode()).decode(),
        "sha": data["sha"]
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

    # Scan last 15 mins
    since = (datetime.utcnow() - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%S")
    query = f'org:{current_org} is:pr is:open updated:>{since} "I have read the"'
    results = github_api(f"https://api.github.com/search/issues?q={urllib.parse.quote(query)}", local_token)
    
    if not results: return

    for item in results.get("items", []):
        pr_user = item["user"]["login"]
        pr_user_id = item["user"]["id"]
        repo_url = item["repository_url"]
        pr_number = item["number"]
        comments_url = item["comments_url"]

        repo_data = github_api(repo_url, local_token)
        repo_id = repo_data["id"] if repo_data else 0
        repo_full_name = repo_data["full_name"] if repo_data else "unknown/repo"
        
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
            print(f"Signing {mode_signed} for {pr_user} in {repo_full_name}")
            
            user_data = {
                "login": pr_user,
                "id": pr_user_id,
                "comment_id": found_comment_id,
                "repo_id": repo_id,
                "pr_number": pr_number
            }

            if update_central_signature(central_org, central_repo, user_data, mode_signed, mothership_token):
                # 1. Post Comment (Forces UI update + Informs user)
                post_success_comment(comments_url, pr_user, mode_signed, local_token)
                
                # 2. Trigger Re-run
                pr_head_sha = github_api(item["pull_request"]["url"], local_token)["head"]["sha"]
                runs_url = f"{repo_url}/actions/runs?head_sha={pr_head_sha}"
                runs = github_api(runs_url, local_token)
                if runs:
                    for run in runs.get("workflow_runs", []):
                        if run["name"] == WORKFLOW_NAME and run["conclusion"] == "failure":
                            print(f"Triggering re-run for {run['id']}...")
                            github_api(f"{repo_url}/actions/runs/{run['id']}/rerun", local_token, "POST", {})

if __name__ == "__main__":
    main()
    
