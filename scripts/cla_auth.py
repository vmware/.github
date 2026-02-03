"""
cla_auth.py
-----------
Handles "Client-Side Authentication" for the CLA Sweeper.
This allows the Python script to generate its own high-privilege tokens,
bypassing stale YAML configurations in child repositories.
"""
import os
import sys
import time
import subprocess
import json
import logging

# --- 1. SELF-HEALING DEPENDENCY CHECK ---
# If the Child Repo's YAML is old, it might not have installed these libs.
# We install them dynamically at runtime to prevent crashes.
def install_dependencies():
    required = ['PyJWT', 'cryptography', 'requests']
    try:
        import jwt
        import requests
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        print("::group::[AUTO-FIX] Installing Missing Auth Dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + required)
        print("::endgroup::")

# Run check immediately
install_dependencies()

# Now safe to import
import jwt
import requests

def get_integration_token(app_id, private_key_pem):
    """
    Generates a JWT (JSON Web Token) to authenticate as the GitHub App.
    """
    now = int(time.time())
    payload = {
        "iat": now,
        "exp": now + (10 * 60),  # 10 minute expiration
        "iss": app_id
    }
    
    # Encode JWT using RS256
    encoded_jwt = jwt.encode(
        payload, 
        private_key_pem, 
        algorithm="RS256"
    )
    return encoded_jwt

def get_installation_access_token(app_id, private_key_pem, org_name, permissions=None):
    """
    Exchanges the JWT for a usable Installation Access Token (ghs_...)
    Explicitly requests 'members: read' to fix the 404 error.
    """
    if permissions is None:
        permissions = {
            "members": "read",
            "contents": "read",
            "metadata": "read"
        }

    jwt_token = get_integration_token(app_id, private_key_pem)
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # 1. Find the Installation ID for the specific Org
    # (The App might be installed on many orgs; we need the ID for THIS one)
    install_url = f"https://api.github.com/orgs/{org_name}/installation"
    resp = requests.get(install_url, headers=headers)
    
    if resp.status_code != 200:
        print(f"::error::[AUTH FAIL] Could not find App Installation on org '{org_name}'. Status: {resp.status_code}")
        print(f"::debug::Response: {resp.text}")
        return None
    
    installation_id = resp.json().get("id")
    
    # 2. Request the Token with Specific Permissions
    token_url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    payload = {"permissions": permissions}
    
    token_resp = requests.post(token_url, headers=headers, json=payload)
    
    if token_resp.status_code == 201:
        token = token_resp.json().get("token")
        # print("::warning::[AUTH SUCCESS] Generated FRESH token from Python logic.")
        return token
    else:
        print(f"::error::[AUTH FAIL] Failed to generate token. Status: {token_resp.status_code}")
        print(f"::error::Reason: {token_resp.text}")
        return None
      
