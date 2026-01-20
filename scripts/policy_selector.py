import os
import sys
import json
import urllib.request
import urllib.error

# Add the directory containing your uploaded scripts to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Try importing the library, handle failure gracefully for debugging
try:
    import requires_cla
except ImportError:
    print("::error::Could not import requires_cla.py. Check PYTHONPATH.")
    sys.exit(1)

def check_org_membership(org, user, token):
    """
    Returns True if user is a member of the org.
    """
    if not token:
        print(f"DEBUG: No token provided for membership check of {user}.")
        return False
        
    url = f"https://api.github.com/orgs/{org}/members/{user}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "CLA-Policy-Check"
    }
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as response:
            code = response.getcode()
            print(f"DEBUG: Membership API for {user} returned HTTP {code}")
            return code == 204
    except urllib.error.HTTPError as e:
        print(f"DEBUG: Membership API for {user} returned HTTP {e.code}")
        # 404 = Not a member (or private membership hidden from token)
        # 403 = Token permission issue
        return False
    except Exception as e:
        print(f"DEBUG: API Error: {e}")
        return False

def main():
    # INPUTS
    gh_token = os.environ.get("GITHUB_TOKEN")
    pat_token = os.environ.get("PAT_TOKEN") 
    repo_full = os.environ.get("GITHUB_REPOSITORY")
    pr_user = os.environ.get("PR_AUTHOR")
    
    if not repo_full or "/" not in repo_full:
        print("::error::Invalid GITHUB_REPOSITORY environment variable.")
        sys.exit(1)

    org_name = repo_full.split("/")[0]

    print(f"::group::Analyzing Policy for {repo_full} (User: {pr_user})")

    # 1. CHECK MEMBERSHIP
    # Critical: Use PAT if available because GITHUB_TOKEN cannot see private members
    token_to_use = pat_token if pat_token else gh_token
    token_type = "PAT" if pat_token else "GITHUB_TOKEN"
    print(f"DEBUG: Checking membership using {token_type}...")

    if check_org_membership(org_name, pr_user, token_to_use):
        print(f"✅ User @{pr_user} is a member of {org_name}. Bypassing check.")
        with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
            fh.write("bypass=true\n")
        sys.exit(0)
    else:
        print(f"User @{pr_user} is NOT a member (or token lacked permission). Enforcing policy.")
        with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
            fh.write("bypass=false\n")

    # 2. DETERMINE LICENSE POLICY
    try:
        print(f"DEBUG: Running requires_CLA for {repo_full}...")
        # requires_cla needs a token to read the repo license
        is_strict = requires_cla.requires_CLA(repo_full, token=gh_token)
        
        if is_strict:
            print("Decision: Strict License detected -> CLA Required")
            mode = "CLA"
            sig_file = "signatures/cla.json"
            doc_url = f"https://github.com/{org_name}/.github/blob/main/CLA.md" 
        else:
            print("Decision: Permissive License detected -> DCO Required")
            mode = "DCO"
            sig_file = "signatures/dco.json"
            doc_url = f"https://github.com/{org_name}/.github/blob/main/DCO.md"

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
    
