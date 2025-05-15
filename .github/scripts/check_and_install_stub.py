# File: .github/scripts/check_and_install_stub.py
# Purpose: This script is executed by the 'manage-cla-stubs.yml' workflow for each target repository.
# It determines the repository's license, classifies it as permissive or non-permissive,
# and then creates/updates/removes a CLA trigger workflow stub in the target repository accordingly.

import os
import json
import subprocess
import base64
import time
import logging
from github import Github, GithubException, UnknownObjectException

# --- Configuration ---
# GITHUB_REPOSITORY_OWNER is an environment variable automatically set by GitHub Actions,
# representing the owner of the repository where the workflow is running (i.e., your organization name).
ORG_NAME = os.environ.get("GITHUB_REPOSITORY_OWNER")
TARGET_STUB_VERSION = "1.0.2"  # Increment this version when the stub's content/logic changes.
STUB_WORKFLOW_PATH = ".github/workflows/cla-check-trigger.yml" # Path where the stub will be placed in target repos.

# Ensure ORG_NAME is available, as it's crucial for the 'uses' path in the stub.
if not ORG_NAME:
    logging.critical("CRITICAL: GITHUB_REPOSITORY_OWNER environment variable not set. Cannot proceed.")
    exit(1) # Critical failure

# Define the content of the stub workflow using an f-string.
# This content will be written to STUB_WORKFLOW_PATH in target repositories.
STUB_WORKFLOW_CONTENT_TEMPLATE = f"""\
# This file is auto-generated and managed by the organization's .github repository.
# Do not modify manually. Version: {TARGET_STUB_VERSION}
name: CLA Check Trigger

on:
  pull_request_target:
    types: [opened, synchronize, reopened]

jobs:
  call_cla_check:
    uses: {ORG_NAME}/.github/.github/workflows/reusable-cla-check.yml@main # Consider pinning to a SHA/tag like @v1.0.1
    secrets:
      GH_TOKEN_CLA_ASSISTANT: ${{{{ secrets.CLA_ASSISTANT_PAT }}}}
      GIST_URL_CLA: ${{{{ secrets.CLA_GIST_URL }}}}
"""

# Configure basic logging for the script.
# Outputs will be visible in the GitHub Actions workflow logs.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions ---

def get_license_info(repo_full_name, gh_token, temp_base_dir="temp_license_check"):
    """
    Fetches the license file from the specified repository, runs the 'licensee' tool
    via Docker to detect the license, and returns the SPDX ID and classification.
    
    Args:
        repo_full_name (str): The full name of the repository (e.g., "owner/repo").
        gh_token (str): GitHub PAT for API access.
        temp_base_dir (str): Base directory for temporary license files.

    Returns:
        tuple: (spdx_id_or_code, classification_string)
               e.g., ("MIT", "permissive") or ("NO_LICENSE_FILE", "non-permissive")
    """
    g = Github(gh_token) # Initialize PyGithub client
    try:
        repo = g.get_repo(repo_full_name)
    except UnknownObjectException:
        logging.warning(f"Repository {repo_full_name} not found or PAT lacks access.")
        return "REPO_NOT_FOUND", "non-permissive" # Assume non-permissive if repo is inaccessible
    except Exception as e:
        logging.error(f"Error accessing repository {repo_full_name} object: {e}")
        return "REPO_ACCESS_ERROR", "non-permissive"

    license_content = None
    license_filename = "LICENSE" # Default filename to save as locally

    # Common names for license files
    common_license_files = ["LICENSE", "LICENSE.MD", "LICENSE.TXT", "COPYING", "COPYING.MD", "UNLICENSE"]
    try:
        # Attempt to get contents of the root directory to find a license file.
        contents = repo.get_contents("")
        for content_file in contents:
            # Case-insensitive check against common license filenames.
            if content_file.name.upper() in common_license_files:
                license_filename = content_file.name # Store the actual filename
                # Fetch and decode the license file content.
                license_content_b64 = repo.get_contents(content_file.path).content
                license_content = base64.b64decode(license_content_b64).decode('utf-8', errors='replace')
                logging.info(f"Found license file '{content_file.path}' in {repo_full_name}.")
                break # Found a license file, no need to check further in root.
    except Exception as e:
        logging.warning(f"Could not list root contents or read license file from root for {repo_full_name}: {e}. Will try specific paths.")
        # If listing root failed (e.g., empty repo) or file not found, try common paths directly.
        for fname in common_license_files:
            try:
                license_content_b64 = repo.get_contents(fname).content
                license_content = base64.b64decode(license_content_b64).decode('utf-8', errors='replace')
                license_filename = fname
                logging.info(f"Found license file '{fname}' directly in {repo_full_name}.")
                break
            except UnknownObjectException:
                continue # File not found at this specific path
            except Exception as e_inner:
                logging.warning(f"Error fetching specific license file {fname} for {repo_full_name}: {e_inner}")
                continue # Error fetching this specific file
    
    if not license_content:
        logging.info(f"No common license file found for {repo_full_name} via API. Classifying as non-permissive.")
        return "NO_LICENSE_FILE", "non-permissive" # If no license file is found, treat as non-permissive.

    # Create a unique temporary directory for this repository's license file.
    # This is to ensure that parallel 'licensee' runs don't interfere with each other.
    repo_temp_dir = os.path.join(temp_base_dir, repo_full_name.replace("/", "_"))
    os.makedirs(repo_temp_dir, exist_ok=True)
    temp_license_filepath = os.path.join(repo_temp_dir, license_filename)

    try:
        # Write the fetched license content to the temporary file.
        with open(temp_license_filepath, "w", encoding="utf-8") as f:
            f.write(license_content)

        # Construct the Docker command to run 'licensee'.
        # Mounts the temporary directory (repo_temp_dir) into the Docker container at '/scan_dir'.
        # 'licensee' then detects licenses within '/scan_dir'.
        # Pinning rubyfmt/licensee to a specific version tag is recommended for production.
        cmd = [
            "docker", "run", "--rm", # Run and remove the container afterwards.
            "-v", f"{os.path.abspath(repo_temp_dir)}:/scan_dir", # Volume mount.
            "rubyfmt/licensee:latest", "detect", "/scan_dir", "--json" # Command to run in container.
        ]
        logging.info(f"Running licensee for {repo_full_name}: {' '.join(cmd)}")
        # Execute the command, capturing output and stderr, with a timeout.
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)

        if result.returncode != 0:
            logging.error(f"Licensee Docker command failed for {repo_full_name}. Exit code: {result.returncode}, Stderr: {result.stderr[:500]}")
            return "LICENSEE_ERROR", "non-permissive"

        license_data = json.loads(result.stdout) # Parse JSON output from licensee.
        
        spdx_id = "OTHER" # Default if no clear SPDX ID found.
        # Attempt to extract the SPDX ID from various possible structures in licensee's JSON output.
        if license_data.get("licenses") and isinstance(license_data["licenses"], list) and license_data["licenses"]:
            # Prefer license with highest confidence if available, otherwise take the first.
            best_license = max(license_data["licenses"], key=lambda lic: lic.get("confidence", 0), default=None)
            if best_license and best_license.get("spdx_id"):
                spdx_id = best_license["spdx_id"]
            elif license_data["licenses"][0].get("spdx_id"): # Fallback to first if no confidence score
                 spdx_id = license_data["licenses"][0].get("spdx_id", "OTHER")
        # Older licensee format or different structure check
        elif license_data.get("matched_files") and license_data["matched_files"][0].get("license") \
             and license_data["matched_files"][0]["license"].get("spdx_id"):
            spdx_id = license_data["matched_files"][0]["license"]["spdx_id"]
        
        logging.info(f"License for {repo_full_name} determined by licensee as: {spdx_id}")
        return spdx_id, classify_license(spdx_id) # Classify the identified SPDX ID.

    except subprocess.TimeoutExpired:
        logging.error(f"Licensee Docker command timed out for {repo_full_name}.")
        return "LICENSEE_TIMEOUT", "non-permissive"
    except subprocess.CalledProcessError as e: # Should be caught by check=False and result.returncode check
        logging.error(f"Licensee execution subprocess error for {repo_full_name}: {e.stderr[:500]}")
        return "LICENSEE_SUBPROCESS_ERROR", "non-permissive"
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse licensee JSON output for {repo_full_name}. Output: {result.stdout[:300]}. Error: {e}")
        return "LICENSEE_JSON_ERROR", "non-permissive"
    except Exception as e:
        logging.error(f"Unexpected error during licensee processing for {repo_full_name}: {e}")
        return "UNKNOWN_ERROR_LICENSEE_PROCESSING", "non-permissive"
    finally:
        # Cleanup: Remove the temporary license file and directory.
        if os.path.exists(temp_license_filepath):
            os.remove(temp_license_filepath)
        if os.path.exists(repo_temp_dir) and not os.listdir(repo_temp_dir): # Only remove if empty
            os.rmdir(repo_temp_dir)
        # Attempt to clean up the base temp directory if it's now empty (less critical).
        if os.path.exists(temp_base_dir) and not os.listdir(temp_base_dir):
            try:
                os.rmdir(temp_base_dir)
            except OSError: # Ignore if other parallel processes are still using subdirectories.
                pass


def classify_license(spdx_id):
    """
    Classifies a given SPDX ID as 'permissive' or 'non-permissive' based on a predefined list.
    
    Args:
        spdx_id (str): The SPDX identifier of the license.

    Returns:
        str: "permissive" or "non-permissive".
    """
    # Get the list of permissive SPDX IDs from environment variable, with a default list.
    # Normalize to uppercase for case-insensitive comparison.
    permissive_spdx_ids_str = os.environ.get("PERMISSIVE_SPDX_IDS", "MIT,Apache-2.0,BSD-3-Clause,ISC,BSD-2-Clause,CC0-1.0,Unlicense")
    permissive_ids = {pid.strip().upper() for pid in permissive_spdx_ids_str.split(',')}
    
    if spdx_id is None: # Should generally not happen if 'OTHER' is used as a default.
        logging.warning("classify_license received None SPDX ID, defaulting to non-permissive.")
        return "non-permissive"
        
    # For example, if licensee sometimes returns "Public Domain" instead of CC0-1.0 or Unlicense,
    # and you want to treat "PUBLIC DOMAIN" as permissive, add it to your PERMISSIVE_SPDX_IDS var.
    # if spdx_id.upper() == "PUBLIC DOMAIN" and "PUBLIC DOMAIN" in permissive_ids: return "permissive"

    if spdx_id.upper() in permissive_ids:
        return "permissive"
    return "non-permissive"


def manage_stub(repo_full_name, gh_token):
    """
    Manages the CLA trigger stub in the target repository based on its license type.
    Creates/updates stub for non-permissive, removes for permissive.
    
    Args:
        repo_full_name (str): The full name of the repository (e.g., "owner/repo").
        gh_token (str): GitHub PAT for API access.

    Returns:
        str: A status code indicating the action taken or error encountered.
    """
    g = Github(gh_token) # Initialize PyGithub client.
    try:
        repo = g.get_repo(repo_full_name)
        if repo.archived:
            logging.info(f"Skipping archived repository: {repo_full_name}")
            return "skipped_archived"
        # Optionally add checks for repository visibility (e.g., skip private repos).
        # if repo.private: logging.info(f"Skipping private repo: {repo_full_name}"); return "skipped_private"

    except UnknownObjectException:
        logging.warning(f"Repository {repo_full_name} not found or PAT lacks access during stub management phase.")
        return "error_repo_not_found_stub_mgmt"
    except Exception as e:
        logging.error(f"Error accessing repository {repo_full_name} object for stub management: {e}")
        return "error_repo_access_stub_mgmt"

    logging.info(f"Managing stub for repository: {repo_full_name}")
    spdx_id, license_type = get_license_info(repo_full_name, gh_token) # Determine license type.
    
    logging.info(f"  License classification for {repo_full_name}: {license_type} (SPDX/Code: {spdx_id or 'N/A'})")

    action_taken = "no_action_default" # Default status
    if license_type == "non-permissive":
        logging.info(f"  Non-permissive license. Ensuring CLA stub workflow exists for {repo_full_name}.")
        try:
            existing_stub_file = None
            existing_content = ""
            try:
                # Try to get the existing stub file from the default branch.
                existing_stub_file = repo.get_contents(STUB_WORKFLOW_PATH, ref=repo.default_branch)
                existing_content = base64.b64decode(existing_stub_file.content).decode('utf-8')
            except UnknownObjectException: # File does not exist
                logging.info(f"    No existing stub found at {STUB_WORKFLOW_PATH} in {repo_full_name}.")
                pass # existing_content remains "", existing_stub_file is None
            
            # Extract version from existing content, if any.
            current_version_str = "0.0.0" # Default if no version comment found.
            if existing_content:
                for line in existing_content.splitlines():
                    if "# Version:" in line:
                        current_version_str = line.split("# Version:")[1].strip()
                        break
            
            # Compare content for robustness, not just version string, to ensure actual content matches.
            # .strip() handles potential trailing newlines.
            if existing_stub_file and current_version_str == TARGET_STUB_VERSION and \
               existing_content.strip() == STUB_WORKFLOW_CONTENT_TEMPLATE.strip():
                logging.info(f"    CLA stub '{STUB_WORKFLOW_PATH}' is up-to-date (Version {TARGET_STUB_VERSION}) in {repo_full_name}.")
                action_taken = "skipped_stub_up_to_date"
            elif existing_stub_file: # File exists but needs update (version or content mismatch)
                sha = existing_stub_file.sha
                commit_message = f"ci: Update CLA trigger workflow to v{TARGET_STUB_VERSION}"
                logging.info(f"    Updating existing CLA stub '{STUB_WORKFLOW_PATH}' (Old: v{current_version_str}) in {repo_full_name}.")
                repo.update_file(STUB_WORKFLOW_PATH, commit_message, STUB_WORKFLOW_CONTENT_TEMPLATE, sha, branch=repo.default_branch)
                logging.info(f"    Successfully updated '{STUB_WORKFLOW_PATH}' in {repo_full_name}.")
                action_taken = "stub_updated"
            else: # File does not exist, create it.
                commit_message = f"ci: Add CLA trigger workflow v{TARGET_STUB_VERSION}"
                logging.info(f"    CLA stub '{STUB_WORKFLOW_PATH}' not found. Creating in {repo_full_name}.")
                repo.create_file(STUB_WORKFLOW_PATH, commit_message, STUB_WORKFLOW_CONTENT_TEMPLATE, branch=repo.default_branch)
                logging.info(f"    Successfully created '{STUB_WORKFLOW_PATH}' in {repo_full_name}.")
                action_taken = "stub_created"

        except GithubException as e:
            logging.error(f"    GitHub API error managing stub for non-permissive repo {repo_full_name}: Status {e.status}, Data {e.data}")
            action_taken = f"error_api_non_permissive_{e.status}"
        except Exception as e:
            logging.error(f"    Unexpected error managing stub for non-permissive repo {repo_full_name}: {e}")
            action_taken = "error_unknown_non_permissive"

    elif license_type == "permissive":
        logging.info(f"  Permissive license ({spdx_id}). Ensuring CLA stub does NOT exist for {repo_full_name}.")
        try:
            # Check if the stub file exists.
            existing_stub_file = repo.get_contents(STUB_WORKFLOW_PATH, ref=repo.default_branch)
            sha = existing_stub_file.sha
            commit_message = f"ci: Remove CLA trigger workflow (license: {spdx_id} is permissive)"
            logging.info(f"    Permissive license; removing existing CLA stub '{STUB_WORKFLOW_PATH}' from {repo_full_name}.")
            repo.delete_file(STUB_WORKFLOW_PATH, commit_message, sha, branch=repo.default_branch)
            logging.info(f"    Successfully removed '{STUB_WORKFLOW_PATH}' from {repo_full_name}.")
            action_taken = "stub_removed_permissive"
        except UnknownObjectException: # File does not exist, which is the desired state.
            logging.info(f"    Permissive license; CLA stub '{STUB_WORKFLOW_PATH}' does not exist in {repo_full_name}. No action needed.")
            action_taken = "skipped_permissive_no_stub"
        except GithubException as e:
            logging.error(f"    GitHub API error removing stub for permissive repo {repo_full_name}: Status {e.status}, Data {e.data}")
            action_taken = f"error_api_permissive_{e.status}"
        except Exception as e:
            logging.error(f"    Unexpected error removing stub for permissive repo {repo_full_name}: {e}")
            action_taken = "error_unknown_permissive"
    else: # Should not happen if license_type is always 'permissive' or 'non-permissive'.
        logging.warning(f"  Unknown license type '{license_type}' for {repo_full_name} (SPDX/Code: {spdx_id}). No action taken on stub.")
        action_taken = "skipped_unknown_license_type"
    return action_taken


# Main execution block when script is run directly.
if __name__ == "__main__":
    # Get required environment variables passed by the GitHub Actions workflow.
    repo_to_process = os.environ.get("TARGET_REPO_FULL_NAME")
    org_pat = os.environ.get("ORG_PAT")

    if not repo_to_process:
        logging.critical("CRITICAL: TARGET_REPO_FULL_NAME environment variable not set.")
        exit(1)
    if not org_pat:
        logging.critical("CRITICAL: ORG_PAT environment variable not set.")
        exit(1)

    # Basic retry mechanism for the entire 'manage_stub' operation for a single repository.
    # More granular retries (e.g., for specific API calls) could be added within functions.
    max_retries = 1 # Total 2 attempts (initial + 1 retry).
    final_status = "error_unknown_initial"
    for attempt in range(max_retries + 1):
        try:
            final_status = manage_stub(repo_to_process, org_pat)
            # If the status does not indicate an error, break the retry loop.
            if not final_status.startswith("error_"):
                break 
        except Exception as e: # Catch any unexpected exceptions from manage_stub itself.
            logging.error(f"Attempt {attempt+1} for {repo_to_process} failed with unhandled exception: {e}")
            final_status = f"error_unhandled_exception_attempt_{attempt+1}"
        
        # If not the last attempt and an error occurred, wait before retrying.
        if attempt < max_retries and final_status.startswith("error_"):
            sleep_duration = (attempt + 1) * 10 # Exponential backoff (10s, 20s...).
            logging.info(f"Retrying {repo_to_process} in {sleep_duration} seconds after status: {final_status}")
            time.sleep(sleep_duration)
        elif attempt == max_retries: # Log if all retries failed.
             logging.error(f"All {max_retries+1} attempts failed for {repo_to_process}. Final status: {final_status}")
    
    # Output status information. This can be captured by the calling GitHub Action
    # for creating job summaries or further processing.
    # These print statements are specifically for GHA to pick up as outputs if needed.
    print(f"REPO_PROCESSED_NAME={repo_to_process}")
    print(f"REPO_PROCESSED_STATUS={final_status}")

    # Exit with a non-zero code if the final status indicates an error,
    # causing the GitHub Actions step to fail.
    if final_status.startswith("error_"):
        exit(1)
