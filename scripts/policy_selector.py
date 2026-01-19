import os
import sys
import json
import urllib.request
import urllib.error

# Add the directory containing your uploaded scripts to sys.path
# Assumes structure: .github/scripts/requires_cla.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import requires_cla  # Your uploaded library

def check_org_membership(org, user, token):
    """
    Returns True if user is a member of the org.
    API: GET /orgs/{org}/members/{username} -> 204 (Yes) or 404 (No)
    """
    if not token:
        print("::warning::No GITHUB_TOKEN. Cannot check org membership. Assuming external.")
        return False
        
    url = f"https://api.github.com/orgs/{org}/members/{user}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "CLA-Policy-Check"
    })
    
    try:
        with urllib.request.urlopen(req) as response:
            return response.getcode() == 204
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        print(f"::warning::Membership check API error: {e}")
        return False

def main():
    token = os.environ.get("GITHUB_TOKEN")
    repo_full = os.environ.get("GITHUB_REPOSITORY") # "org/repo"
    pr_user = os.environ.get("PR_AUTHOR")
    
    if not repo_full or "/" not in repo_full:
        print("::error::Invalid GITHUB_REPOSITORY environment variable.")
        sys.exit(1)

    org_name = repo_full.split("/")[0]

    print(f"::group::Analyzing Policy for {repo_full} (User: {pr_user})")

    # 1. Check Org Membership (Bypass)
    if check_org_membership(org_name, pr_user, token):
        print(f"User @{pr_user} is a member of {org_name}. Bypassing check.")
        with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
            fh.write("bypass=true\n")
        sys.exit(0)
    else:
        print(f"User @{pr_user} is NOT a member of {org_name}. Enforcing policy.")
        with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
            fh.write("bypass=false\n")

    # 2. Determine License Policy (Your Custom Logic)
    try:
        # returns True (CLA) or False (DCO) based on requires_cla.py
        is_strict = requires_cla.requires_CLA(repo_full, token=token)
        
        if is_strict:
            print("Decision: Strict License detected -> CLA Required")
            mode = "CLA"
            sig_file = "signatures/cla.json"
            # Point to your actual CLA document
            doc_url = f"https://github.com/{org_name}/.github/blob/main/CLA.md" 
        else:
            print("Decision: Permissive License detected -> DCO Required")
            mode = "DCO"
            sig_file = "signatures/dco.json"
            # Point to your actual DCO document
            doc_url = f"https://github.com/{org_name}/.github/blob/main/DCO.md"

        # Output variables for the GitHub Action step
        with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
            fh.write(f"mode={mode}\n")
            fh.write(f"signature_path={sig_file}\n")
            fh.write(f"document_url={doc_url}\n")
            
    except Exception as e:
        print(f"::error::Policy detection failed: {str(e)}")
        sys.exit(1)
    print("::endgroup::")

if __name__ == "__main__":
    main()
