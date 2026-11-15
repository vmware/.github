"""
cla_auth.py
-----------
Self-contained authentication module for CLA Sweeper.
1. Auto-installs missing dependencies (PyJWT, cryptography) on the fly.
2. Generates a 'Super Token' with explicit permissions to bypass Stale YAML.
"""
import sys
import subprocess
import time
import os
import json

# --- 1. SELF-HEALING DEPENDENCY INSTALLER ---
# This ensures the script works even if the child repo's YAML is old/broken.
def install_dependencies():
    required = ['PyJWT', 'cryptography', 'requests']
    installed = []
    
    # Check what's missing
    try:
        import jwt
        installed.append("jwt")
    except ImportError:
        pass

    try:
        from cryptography.hazmat.primitives import serialization
        installed.append("cryptography")
    except ImportError:
        pass
        
    try:
        import requests
        installed.append("requests")
    except ImportError:
        pass

    # If anything is missing, install it
    if len(installed) < 3:
        print(f"::group::[AUTO-FIX] Installing Auth Dependencies ({', '.join(required)})...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + required, stdout=subprocess.DEVNULL)
            print("::debug::Dependencies installed successfully.")
        except Exception as e:
            print(f"::error::Failed to auto-install dependencies: {e}")
        print("::endgroup::")

# Run install check immediately upon import
install_dependencies()

# Now safe to import
import jwt
import requests

def get_integration_token(app_id, private_key_pem):
    """
    Signs a JWT (JSON Web Token) using the App's Private Key.
    """
    now = int(time.time())
    # Allow for the runner's clock being a little ahead of GitHub's. GitHub
    # rejects a JWT (HTTP 401) whose "iat" is in the future or whose "exp" is
    # more than 10 minutes ahead, so backdate "iat" by 60 seconds (GitHub's own
    # recommendation) and keep "exp" at 9 minutes. The JWT is used within
    # seconds, only to fetch an installation token.
    payload = {
        "iat": now - 60,
        "exp": now + (9 * 60),
        "iss": app_id
    }
    
    # Encode JWT using RS256
    encoded_jwt = jwt.encode(
        payload, 
        private_key_pem, 
        algorithm="RS256"
    )
    return encoded_jwt

def get_installation_access_token(app_id, private_key_pem, org_name):
    """
    Exchanges the JWT for a valid GHS Access Token with ALL required permissions.
    """
    # 1. Define the permissions the bot NEEDS to do its job.
    # We ask for these explicitly to override the "None" scope from Stale YAML.
    needed_permissions = {
        "members": "read",          # To fix the 404 error
        "contents": "write",        # To write the repo code
        "metadata": "read",         # Basic info
        "statuses": "write",        # To "Paint" commits (Green/Red)
        "checks": "write",          # To create check runs
        "pull_requests": "write"    # To post comments if needed
    }

    try:
        jwt_token = get_integration_token(app_id, private_key_pem)
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        # 2. Find the Installation ID for the specific Org
        install_url = f"https://api.github.com/orgs/{org_name}/installation"
        resp = requests.get(install_url, headers=headers)
        
        if resp.status_code != 200:
            try:
                reason = str(resp.json().get("message", ""))
            except Exception:  # body isn't a JSON object; the status alone will do
                reason = ""
            print(f"::warning::[AUTH] Could not find App Installation on org '{org_name}'. Status: {resp.status_code} {reason}".rstrip())
            return None
        
        installation_id = resp.json().get("id")
        
        # 3. Request the Token
        token_url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        payload = {"permissions": needed_permissions}
        
        token_resp = requests.post(token_url, headers=headers, json=payload)
        
        if token_resp.status_code == 201:
            token = token_resp.json().get("token")
            return token
        else:
            print(f"::error::[AUTH] Failed to generate token. Status: {token_resp.status_code}")
            return None
            
    except Exception as e:
        print(f"::error::[AUTH CRASH] {e}")
        return None
        
