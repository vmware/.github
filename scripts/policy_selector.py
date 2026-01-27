#!/usr/bin/env python3
import os
import sys
import json
import re
import base64
import time
import urllib.request
import urllib.error
from datetime import datetime

# Dependency Check
try:
    import jwt  # pip install PyJWT cryptography
    import requires_cla
except ImportError:
    print("::error::Missing dependencies. Ensure PyJWT, cryptography, and requires_cla.py are present.")
    sys.exit(1)

SIGN_REGEX = r"I have read the (CLA|DCO) Document and I hereby sign the (CLA|DCO)"

def get_app_token(org_name, app_id, private_key):
    """Generates an Installation Access Token for a specific Org."""
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + (9 * 60), "iss": app_id}
    encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")

    # Get Installation ID
    url = f"https://api.github.com/orgs/{org_name}/installation"
    headers = {"Authorization": f"Bearer {encoded_jwt}", "Accept": "application/vnd.github+json"}
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as r:
            installation_id = json.loads(r.read().decode())["id"]
    except Exception as e:
        print(f"::error::App not installed in {org_name}. Cannot generate token.")
        return None

    # Get Access Token
    token_url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    try:
        req = urllib.request.Request(token_url, headers=headers, method="POST")
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read().decode())["token"]
    except Exception as e:
        print(f"::error::Token generation failed for {org_name}: {e}")
        return None

def github_request(url, token, method="GET", data=None):
    if not token: return None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    try:
        req = urllib.request.Request(url, headers=headers, method=method)
        if data: req.data = json.dumps(data).encode("utf-8")
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read().decode()) if method != "PUT" else {}
    except urllib.error.HTTPError as e:
        if e.code == 404: return None
        print(f"::warning::API Error {e.code} ({url})")
        return None
    except Exception as e:
        print(f"::error::API Exception: {e}")
        return None

def update_signature_file(central_org, central_repo, file_path, user, pr_url, mode, token):
    contents_url = f"https://api.github.com/repos/{central_org}/{central_repo}/contents/{file_path}"
    file_data = github_request(contents_url, token)
    
    signatures = {"signed": []}
    sha = None
    
    if file_data and "content" in file_data:
        sha = file_data["sha"]
        try:
            signatures = json.loads(base64.b64decode(file_data["content"]).decode())
        except: pass

    if any(u.get("github", "").lower() == user.lower() for u in signatures.get("signed", [])):
        print(f"DEBUG: User {user} found in Central {mode} database.")
        return True

    signatures["signed"].append({
        "name": user, "github": user, "date": datetime.utcnow().isoformat() + "Z",
        "link": pr_url, "mode": mode, "org_origin": os.environ.get("GITHUB_REPOSITORY_OWNER")
    })
    
    put_data = {
        "message": f"Sign {mode} for @{user}",
        "content": base64.b64encode(json.dumps(signatures, indent=2).encode()).decode(),
        "sha": sha
    }
    return github_request(contents_url, token, method="PUT", data=put_data) is not None

def main():
    app_id = os.environ.get("CLA_APP_ID")
    private_key = os.environ.get("CLA_APP_PRIVATE_KEY")
    gh_token = os.environ.get("GITHUB_TOKEN") # Local read-only context
    repo_full = os.environ.get("GITHUB_REPOSITORY")
    pr_user = os.environ.get("PR_AUTHOR")
    pr_comments_url = os.environ.get("PR_COMMENTS_URL")
    central_org = os.environ.get("CENTRAL_ORG")
    config_repo = os.environ.get("CONFIG_REPO", ".github")

    if not all([app_id, private_key, central_org]):
        print("::error::Missing App Configuration.")
        sys.exit(1)

    # 1. Auth Strategy
    current_org = repo_full.split("/")[0]
    
    # Token A: Local Org (For Membership Check)
    local_token = get_app_token(current_org, app_id, private_key)
    
    # Token B: Mothership (For Writing) - Reuse if same org
    mothership_token = local_token if current_org == central_org else get_app_token(central_org, app_id, private_key)

    # Fork Detection: If we can't get a local token (no secrets), we are in a fork.
    # Actually, for an App, 'local_token' generation relies on secrets. 
    # If this runs in a fork, 'CLA_APP_ID' is missing, so app_id is None -> exit.
    is_fork_pr = (local_token is None)

    print(f"::group::App-Based Policy Check for {repo_full} (@{pr_user})")

    # 2. Membership Check
    is_member = False
    if not is_fork_pr:
        # Check membership using App Token
        url = f"https://api.github.com/orgs/{current_org}/members/{pr_user}"
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {local_token}"})
            with urllib.request.urlopen(req) as r:
                if r.getcode() == 204: is_member = True
        except: pass

    if is_member:
        print(f"✅ User @{pr_user} is Member. Bypassing.")
        with open(os.environ['GITHUB_OUTPUT'], 'a') as fh: fh.write("bypass=true\n")
        sys.exit(0)
    
    with open(os.environ['GITHUB_OUTPUT'], 'a') as fh: fh.write("bypass=false\n")

    # 3. License Logic
    try:
        is_strict = requires_cla.requires_CLA(repo_full, token=gh_token)
        mode = "CLA" if is_strict else "DCO"
        sig_file = f"signatures/{mode.lower()}.json"
        doc_url = f"https://github.com/{central_org}/{config_repo}/blob/main/{mode}.md"
    except Exception as e:
        print(f"::error::License check failed: {e}")
        sys.exit(1)

    # 4. Self-Healing (Write to Mothership)
    if not is_fork_pr and pr_comments_url:
        comments = github_request(pr_comments_url, gh_token) or []
        for c in comments:
            if c.get("user", {}).get("login") == pr_user:
                if re.search(SIGN_REGEX, c.get("body", ""), re.IGNORECASE):
                    if mode in c.get("body", ""):
                        print(f"Found {mode} signature. Syncing to Mothership...")
                        update_signature_file(central_org, config_repo, sig_file, pr_user, "", mode, mothership_token)
                        break

    with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
        fh.write(f"mode={mode}\n")
        fh.write(f"signature_path={sig_file}\n")
        fh.write(f"document_url={doc_url}\n")
    
    print("::endgroup::")

if __name__ == "__main__":
    main()
    
