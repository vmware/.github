#!/usr/bin/env python3
import os
import json
import re
import base64
import time
import urllib.request
import urllib.parse
from datetime import datetime, timedelta

# Import JWT dependencies (assumes pip install ran)
import jwt 

WORKFLOW_NAME = "Legal Compliance Gate"
SIGN_REGEX = r"I have read the (CLA|DCO) Document and I hereby sign the (CLA|DCO)"

def get_app_token(org_name, app_id, private_key):
    # Same helper function as above
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

def update_central_signature(central_org, central_repo, user, mode, token):
    path = f"signatures/{mode.lower()}.json"
    url = f"https://api.github.com/repos/{central_org}/{central_repo}/contents/{path}"
    data = github_api(url, token)
    if not data: return False
    try:
        content = json.loads(base64.b64decode(data["content"]).decode())
    except: return False
    
    if any(u["github"].lower() == user.lower() for u in content.get("signed", [])):
        return True

    content["signed"].append({
        "name": user, "github": user, "date": datetime.utcnow().isoformat() + "Z", 
        "link": "https://github.com", "mode": mode, "org_origin": os.environ.get("ORG_NAME")
    })
    payload = {
        "message": f"Sweeper App Sign {mode} for @{user}",
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

    # 1. Generate Tokens
    local_token = get_app_token(current_org, app_id, private_key)
    mothership_token = get_app_token(central_org, app_id, private_key)
    
    if not local_token or not mothership_token: return

    # 2. Scan Local Org
    since = (datetime.utcnow() - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%S")
    query = f'org:{current_org} is:pr is:open updated:>{since} "I have read the"'
    results = github_api(f"https://api.github.com/search/issues?q={urllib.parse.quote(query)}", local_token)
    
    if not results: return

    for item in results.get("items", []):
        pr_user = item["user"]["login"]
        repo_full = item["repository_url"].replace("https://api.github.com/repos/", "")
        
        comments = github_api(item["comments_url"], local_token) or []
        mode_signed = None
        for c in comments:
            if c["user"]["login"] == pr_user:
                m = re.search(SIGN_REGEX, c["body"], re.IGNORECASE)
                if m:
                    mode_signed = m.group(2).upper()
                    break
        
        if mode_signed:
            print(f"Signing {mode_signed} for {pr_user} in {repo_full}")
            if update_central_signature(central_org, central_repo, pr_user, mode_signed, mothership_token):
                # Re-run
                pr_data = github_api(item["pull_request"]["url"], local_token)
                if pr_data:
                    runs_url = f"{item['repository_url']}/actions/runs?head_sha={pr_data['head']['sha']}"
                    runs = github_api(runs_url, local_token)
                    for run in runs.get("workflow_runs", []):
                        if run["name"] == WORKFLOW_NAME and run["conclusion"] == "failure":
                            github_api(f"{item['repository_url']}/actions/runs/{run['id']}/rerun", local_token, "POST", {})

if __name__ == "__main__":
    main()
  
