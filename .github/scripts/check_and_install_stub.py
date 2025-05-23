# File: .github/scripts/check_and_install_stub.py
# Purpose: Determines a repository's license, classifies it, and manages a CLA trigger workflow stub.
# The stub now triggers on both pull_request_target and issue_comment events.

import os
import json
import subprocess
import base64
import time
import logging
from github import Github, GithubException, UnknownObjectException

# --- Configuration ---
ORG_NAME = os.environ.get("GITHUB_REPOSITORY_OWNER")
# IMPORTANT: Increment this version due to changes in the stub template's trigger logic.
TARGET_STUB_VERSION = "1.1.0" # Example: Major.Minor.Patch -> new trigger is significant
STUB_WORKFLOW_PATH = ".github/workflows/cla-check-trigger.yml"

# Get the Licensee Docker image tag from an environment variable set by the workflow.
LICENSEE_DOCKER_IMAGE_TAG = os.environ.get("LICENSEE_DOCKER_IMAGE", "local-org-licensee:latest")

if not ORG_NAME:
    logging.critical("CRITICAL: GITHUB_REPOSITORY_OWNER environment variable not set. Cannot proceed.")
    exit(1)

# Default URL to your CLA document stored within the .github repository itself.
# This will be embedded in the stub workflow.
DEFAULT_CLA_DOCUMENT_URL_IN_STUB = f"https://github.com/{ORG_NAME}/.github/blob/main/.github/CONTRIBUTOR_LICENSE_AGREEMENT.md"
# If you prefer to configure this via an environment variable from manage-cla-stubs.yml:
# CLA_DOCUMENT_URL_FOR_STUB_FINAL = os.environ.get("CLA_DOCUMENT_URL_FOR_STUBS_ENV_VAR", DEFAULT_CLA_DOCUMENT_URL_IN_STUB)


# Define the content of the stub workflow file.
# This stub triggers the reusable workflow for both PR events and relevant PR comments.
STUB_WORKFLOW_CONTENT_TEMPLATE = f"""\
# This file is auto-generated and managed by the organization's .github repository.
# Do not modify manually. Version: {TARGET_STUB_VERSION}
name: CLA Check Trigger

on:
  # Trigger on pull request events (opened, new commits pushed, reopened)
  pull_request_target:
    types: [opened, synchronize, reopened]
  # Trigger on issue comments (pull requests are also 'issues' in GitHub's model)
  issue_comment:
    types: [created] # Only when a new comment is made

jobs:
  call_cla_check:
    # This job will run if:
    # 1. The event is 'pull_request_target'.
    # OR
    # 2. The event is 'issue_comment' AND the comment was made on a pull request.
    # The 'contributor-assistant/github-action' in the reusable workflow will then
    # determine if the comment body is relevant for CLA signing or rechecking.
    if: >
      github.event_name == 'pull_request_target' ||
      (github.event_name == 'issue_comment' && github.event.issue.pull_request)

    # Call the organization's centralized reusable CLA checking workflow.
    # Pinning to a specific versioned tag (e.g., @v1.0.0) or commit SHA of the reusable workflow is highly recommended for stability.
    uses: {ORG_NAME}/.github/.github/workflows/reusable-cla-check.yml@main
    secrets:
      # Pass the PAT required by contributor-assistant. This PAT needs permissions for:
      # - PR interactions (comments, labels, statuses) on THIS repository (where the stub runs).
      # - Contents Read & Write on the {ORG_NAME}/.github repository to manage the CLA.csv signature file.
      CONTRIBUTOR_ASSISTANT_PAT: ${{{{ secrets.CLA_ASSISTANT_PAT }}}} # Note: Secret name is still CLA_ASSISTANT_PAT as per previous setup
                                                                 # Can be renamed if desired, but ensure consistency.
    with:
      # Provide the URL to the CLA document.
      cla_document_url: {DEFAULT_CLA_DOCUMENT_URL_IN_STUB} # Using the default determined in Python script
      # Optional overrides for signature file path and branch if defaults in reusable workflow are not suitable:
      # signature_file_path: '.github/signatures/CLA.csv'
      # signature_branch: 'main'
"""

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- get_license_info function ---
# (This function remains unchanged from the previous correct version that builds licensee locally)
def get_license_info(repo_full_name, gh_token, temp_base_dir="temp_license_check"):
    g = Github(gh_token)
    try:
        repo = g.get_repo(repo_full_name)
    except UnknownObjectException:
        logging.warning(f"Repository {repo_full_name} not found or PAT lacks access.")
        return "REPO_NOT_FOUND", "non-permissive"
    except Exception as e:
        logging.error(f"Error accessing repository {repo_full_name} object: {e}")
        return "REPO_ACCESS_ERROR", "non-permissive"

    license_content = None; license_filename = "LICENSE"
    common_license_files = ["LICENSE", "LICENSE.MD", "LICENSE.TXT", "COPYING", "COPYING.MD", "UNLICENSE"]
    try:
        contents = repo.get_contents("")
        for content_file in contents:
            if content_file.name.upper() in common_license_files:
                license_filename = content_file.name
                license_content_b64 = repo.get_contents(content_file.path).content
                license_content = base64.b64decode(license_content_b64).decode('utf-8', errors='replace')
                logging.info(f"Found license file '{content_file.path}' in {repo_full_name}.")
                break
    except Exception as e:
        logging.warning(f"Could not list root contents or read license file from root for {repo_full_name}: {e}. Will try specific paths.")
        for fname in common_license_files:
            try:
                license_content_b64 = repo.get_contents(fname).content
                license_content = base64.b64decode(license_content_b64).decode('utf-8', errors='replace')
                license_filename = fname; logging.info(f"Found license file '{fname}' directly in {repo_full_name}."); break
            except UnknownObjectException: continue
            except Exception as e_inner: logging.warning(f"Error fetching specific license file {fname} for {repo_full_name}: {e_inner}"); continue
    if not license_content:
        logging.info(f"No common license file found for {repo_full_name} via API. Classifying as non-permissive.")
        return "NO_LICENSE_FILE", "non-permissive"

    repo_temp_dir = os.path.join(temp_base_dir, repo_full_name.replace("/", "_"))
    os.makedirs(repo_temp_dir, exist_ok=True)
    temp_license_filepath = os.path.join(repo_temp_dir, license_filename)
    try:
        with open(temp_license_filepath, "w", encoding="utf-8") as f: f.write(license_content)
        cmd = [ "docker", "run", "--rm", "-v", f"{os.path.abspath(repo_temp_dir)}:/scan_dir", LICENSEE_DOCKER_IMAGE_TAG, "detect", "/scan_dir", "--json" ]
        logging.info(f"Running licensee for {repo_full_name} using image {LICENSEE_DOCKER_IMAGE_TAG}: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=90)
        if result.returncode != 0:
            if "command not found" in result.stderr.lower() or "No such file or directory" in result.stderr.lower():
                 logging.error(f"Licensee Docker command failed for {repo_full_name}. Docker image '{LICENSEE_DOCKER_IMAGE_TAG}' might not be available or command inside is wrong. Stderr: {result.stderr[:500]}")
            else: logging.error(f"Licensee Docker command failed for {repo_full_name}. Exit: {result.returncode}, Stderr: {result.stderr[:500]}")
            return "LICENSEE_ERROR", "non-permissive"
        license_data = json.loads(result.stdout); spdx_id = "OTHER"
        if license_data.get("licenses") and isinstance(license_data["licenses"], list) and license_data["licenses"]:
            best_license = max(license_data["licenses"], key=lambda lic: lic.get("confidence", 0), default=None)
            if best_license and best_license.get("spdx_id"): spdx_id = best_license["spdx_id"]
            elif license_data["licenses"][0].get("spdx_id"): spdx_id = license_data["licenses"][0].get("spdx_id", "OTHER")
        elif license_data.get("matched_files") and license_data["matched_files"][0].get("license") and license_data["matched_files"][0]["license"].get("spdx_id"):
            spdx_id = license_data["matched_files"][0]["license"]["spdx_id"]
        logging.info(f"License for {repo_full_name} determined by licensee as: {spdx_id}")
        return spdx_id, classify_license(spdx_id)
    except subprocess.TimeoutExpired: logging.error(f"Licensee Docker command timed out for {repo_full_name}."); return "LICENSEE_TIMEOUT", "non-permissive"
    except json.JSONDecodeError as e: logging.error(f"Failed to parse licensee JSON for {repo_full_name}. Output: {result.stdout[:300]}. Error: {e}"); return "LICENSEE_JSON_ERROR", "non-permissive"
    except Exception as e: logging.error(f"Unexpected error during licensee processing for {repo_full_name}: {e}"); return "UNKNOWN_ERROR_LICENSEE_PROCESSING", "non-permissive"
    finally:
        if os.path.exists(temp_license_filepath): os.remove(temp_license_filepath)
        if os.path.exists(repo_temp_dir) and not os.listdir(repo_temp_dir): os.rmdir(repo_temp_dir)
        if os.path.exists(temp_base_dir) and not os.listdir(temp_base_dir):
            try: os.rmdir(temp_base_dir)
            except OSError: pass

# --- classify_license function ---
# (This function remains unchanged)
def classify_license(spdx_id):
    permissive_spdx_ids_str = os.environ.get("PERMISSIVE_SPDX_IDS", "MIT,Apache-2.0,BSD-3-Clause,ISC,BSD-2-Clause,CC0-1.0,Unlicense")
    permissive_ids = {pid.strip().upper() for pid in permissive_spdx_ids_str.split(',')}
    if spdx_id is None: logging.warning("classify_license received None SPDX ID, defaulting to non-permissive."); return "non-permissive"
    if spdx_id.upper() in permissive_ids: return "permissive"
    return "non-permissive"

# --- manage_stub function ---
# (This function's core logic for creating/updating/deleting files remains unchanged.
# It will use the updated STUB_WORKFLOW_CONTENT_TEMPLATE.)
def manage_stub(repo_full_name, gh_token):
    g = Github(gh_token)
    try:
        repo = g.get_repo(repo_full_name)
        if repo.archived: logging.info(f"Skipping archived repository: {repo_full_name}"); return "skipped_archived"
    except UnknownObjectException: logging.warning(f"Repository {repo_full_name} not found or PAT lacks access during stub management."); return "error_repo_not_found_stub_mgmt"
    except Exception as e: logging.error(f"Error accessing repository {repo_full_name} object for stub management: {e}"); return "error_repo_access_stub_mgmt"

    logging.info(f"Managing stub for repository: {repo_full_name}")
    spdx_id, license_type = get_license_info(repo_full_name, gh_token)
    logging.info(f"  License classification for {repo_full_name}: {license_type} (SPDX/Code: {spdx_id or 'N/A'})")

    action_taken = "no_action_default"
    if license_type == "non-permissive":
        logging.info(f"  Non-permissive license. Ensuring CLA stub workflow exists for {repo_full_name}.")
        try:
            existing_stub_file = None; existing_content = ""
            try:
                existing_stub_file = repo.get_contents(STUB_WORKFLOW_PATH, ref=repo.default_branch)
                existing_content = base64.b64decode(existing_stub_file.content).decode('utf-8')
            except UnknownObjectException: logging.info(f"    No existing stub found at {STUB_WORKFLOW_PATH} in {repo_full_name}.")
            current_version_str = "0.0.0"
            if existing_content:
                for line in existing_content.splitlines():
                    if "# Version:" in line: current_version_str = line.split("# Version:")[1].strip(); break
            if existing_stub_file and current_version_str == TARGET_STUB_VERSION and existing_content.strip() == STUB_WORKFLOW_CONTENT_TEMPLATE.strip():
                logging.info(f"    CLA stub '{STUB_WORKFLOW_PATH}' is up-to-date (v{TARGET_STUB_VERSION}) in {repo_full_name}.")
                action_taken = "skipped_stub_up_to_date"
            elif existing_stub_file:
                commit_message = f"ci: Update CLA trigger workflow to v{TARGET_STUB_VERSION}"
                logging.info(f"    Updating existing CLA stub '{STUB_WORKFLOW_PATH}' (Old: v{current_version_str}) in {repo_full_name}.")
                repo.update_file(STUB_WORKFLOW_PATH, commit_message, STUB_WORKFLOW_CONTENT_TEMPLATE, existing_stub_file.sha, branch=repo.default_branch)
                action_taken = "stub_updated"
            else:
                commit_message = f"ci: Add CLA trigger workflow v{TARGET_STUB_VERSION}"
                logging.info(f"    CLA stub '{STUB_WORKFLOW_PATH}' not found. Creating in {repo_full_name}.")
                repo.create_file(STUB_WORKFLOW_PATH, commit_message, STUB_WORKFLOW_CONTENT_TEMPLATE, branch=repo.default_branch)
                action_taken = "stub_created"
        except GithubException as e: logging.error(f"    GitHub API error (stub for non-permissive {repo_full_name}): Status {e.status}, Data {e.data}"); action_taken = f"error_api_non_permissive_{e.status}"
        except Exception as e: logging.error(f"    Unexpected error (stub for non-permissive {repo_full_name}): {e}"); action_taken = "error_unknown_non_permissive"
    elif license_type == "permissive":
        logging.info(f"  Permissive license ({spdx_id}). Ensuring CLA stub does NOT exist for {repo_full_name}.")
        try:
            existing_stub_file = repo.get_contents(STUB_WORKFLOW_PATH, ref=repo.default_branch)
            commit_message = f"ci: Remove CLA trigger workflow (license: {spdx_id} is permissive)"
            logging.info(f"    Permissive license; removing existing CLA stub '{STUB_WORKFLOW_PATH}' from {repo_full_name}.")
            repo.delete_file(STUB_WORKFLOW_PATH, commit_message, existing_stub_file.sha, branch=repo.default_branch)
            action_taken = "stub_removed_permissive"
        except UnknownObjectException: logging.info(f"    Permissive license; CLA stub '{STUB_WORKFLOW_PATH}' does not exist. No action needed."); action_taken = "skipped_permissive_no_stub"
        except GithubException as e: logging.error(f"    GitHub API error (removing stub for permissive {repo_full_name}): Status {e.status}, Data {e.data}"); action_taken = f"error_api_permissive_{e.status}"
        except Exception as e: logging.error(f"    Unexpected error (removing stub for permissive {repo_full_name}): {e}"); action_taken = "error_unknown_permissive"
    else: logging.warning(f"  Unknown license type '{license_type}' for {repo_full_name} (SPDX/Code: {spdx_id}). No action on stub."); action_taken = "skipped_unknown_license_type"
    return action_taken

# --- __main__ function ---
# (This function remains unchanged)
if __name__ == "__main__":
    repo_to_process = os.environ.get("TARGET_REPO_FULL_NAME")
    org_pat = os.environ.get("ORG_PAT")
    if not repo_to_process: logging.critical("CRITICAL: TARGET_REPO_FULL_NAME not set."); exit(1)
    if not org_pat: logging.critical("CRITICAL: ORG_PAT not set."); exit(1)
    max_retries = 1; final_status = "error_unknown_initial"
    for attempt in range(max_retries + 1):
        try:
            final_status = manage_stub(repo_to_process, org_pat)
            if not final_status.startswith("error_"): break 
        except Exception as e:
            logging.error(f"Attempt {attempt+1} for {repo_to_process} failed with unhandled exception: {e}")
            final_status = f"error_unhandled_exception_attempt_{attempt+1}"
        if attempt < max_retries and final_status.startswith("error_"):
            sleep_duration = (attempt + 1) * 10
            logging.info(f"Retrying {repo_to_process} in {sleep_duration}s after status: {final_status}"); time.sleep(sleep_duration)
        elif attempt == max_retries:
             logging.error(f"All {max_retries+1} attempts failed for {repo_to_process}. Final status: {final_status}")
    print(f"REPO_PROCESSED_NAME={repo_to_process}")
    print(f"REPO_PROCESSED_STATUS={final_status}")
    if final_status.startswith("error_"): exit(1)


