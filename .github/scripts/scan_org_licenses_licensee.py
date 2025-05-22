import os
import subprocess
import json
import tempfile
import shutil
import time
import sys
from github import Github, GithubException, RateLimitExceededException, UnknownObjectException

MAX_RETRIES_CLONE = 3
RETRY_DELAY_SECONDS = 10
LICENSEE_CONFIDENCE_THRESHOLD = "90" # Lowered confidence threshold

def run_command_robust(command_args, cwd=None, check_return_code=True, an_input=None):
    """
    Runs a shell command, captures its output, and handles errors robustly.
    Returns a tuple: (success, stdout, stderr)
    """
    try:
        process = subprocess.Popen(
            command_args,
            cwd=cwd,
            stdin=subprocess.PIPE if an_input else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ.copy()
        )
        stdout, stderr = process.communicate(input=an_input)
        
        if check_return_code and process.returncode != 0:
            print(f"Command failed with exit code {process.returncode}: {' '.join(command_args)}")
            print(f"Stderr: {stderr.strip()}")
            return False, stdout.strip(), stderr.strip()
        return True, stdout.strip(), stderr.strip()

    except FileNotFoundError:
        print(f"Error: Command not found - {command_args[0]}. Ensure it's installed and in PATH.")
        return False, "", f"Command not found: {command_args[0]}"
    except Exception as e:
        print(f"An unexpected error occurred while running command {' '.join(command_args)}: {e}")
        return False, "", str(e)

def extract_license_from_entry(license_entry_obj):
    """Helper to extract SPDX ID or name from a license object/dictionary."""
    if not isinstance(license_entry_obj, dict):
        return None
    
    spdx_id = license_entry_obj.get("spdx_id")
    if spdx_id and spdx_id != "NOASSERTION":
        return spdx_id
    
    name = license_entry_obj.get("name")
    if name:
        return name
    return None


def detect_license_with_licensee_cli(repo_dir_path):
    """Runs licensee detect in the given directory and parses the output."""
    command = ["licensee", "detect", "--json", ".", f"--confidence={LICENSEE_CONFIDENCE_THRESHOLD}"]
    # print(f"Detecting license in: {repo_dir_path} with command: {' '.join(command)}")
    success, stdout_raw, stderr_raw = run_command_robust(command, cwd=repo_dir_path, check_return_code=False)

    if not stdout_raw and not success:
         print(f"Licensee CLI failed to execute in {repo_dir_path}. Stderr: {stderr_raw}")
         return "LICENSEE_EXECUTION_ERROR"

    json_output_str = stdout_raw.strip()
    if not json_output_str or json_output_str == "null":
        if "No license found" in stderr_raw.lower():
             return "NONE_FOUND_BY_LICENSEE"
        print(f"Licensee produced empty or null JSON output for {repo_dir_path} with confidence {LICENSEE_CONFIDENCE_THRESHOLD}. Stderr: {stderr_raw}")
        return "LICENSEE_EMPTY_OUTPUT"

    try:
        license_data = json.loads(json_output_str)
        if not license_data: # Handles empty JSON object {}
            return "NONE_FOUND_BY_LICENSEE"

        # print(f"DEBUG: Full licensee JSON for {repo_dir_path} (Confidence: {LICENSEE_CONFIDENCE_THRESHOLD}): {json_output_str}")

        # Attempt 1: Top-level "license" key (if present and is an object/dict)
        # This would mirror the summary `License:` field in non-JSON output.
        top_level_license_obj = license_data.get("license") # Note: licensee might not have a single top-level "license" object.
                                                            # More commonly, it uses "matched_license" or the "licenses" array.
        if isinstance(top_level_license_obj, dict):
            license_id = extract_license_from_entry(top_level_license_obj)
            if license_id:
                # print(f"Found via top-level 'license' object: {license_id} for {repo_dir_path}")
                return license_id
        elif isinstance(top_level_license_obj, str): # Sometimes it might be just a string for the top-level license
            # print(f"Found via top-level 'license' string: {top_level_license_obj} for {repo_dir_path}")
            return top_level_license_obj


        # Attempt 2: "matched_license" (this is what licensee often uses for the primary match)
        matched_license_obj = license_data.get("matched_license")
        if isinstance(matched_license_obj, dict):
            license_id = extract_license_from_entry(matched_license_obj)
            if license_id:
                # print(f"Found via 'matched_license' object: {license_id} for {repo_dir_path}")
                return license_id
        
        # Attempt 3: Iterate through the "licenses" array (list of all potential licenses)
        licenses_array = license_data.get("licenses")
        if isinstance(licenses_array, list) and licenses_array:
            def get_confidence(lic_entry):
                conf = lic_entry.get("confidence")
                try: return float(conf) if conf is not None else 0.0
                except (ValueError, TypeError): return 0.0

            sorted_licenses = sorted(
                licenses_array,
                key=lambda lic: (isinstance(lic,dict) and lic.get("featured") is True, get_confidence(lic)),
                reverse=True
            )
            
            if sorted_licenses:
                best_license_entry = sorted_licenses[0]
                license_id = extract_license_from_entry(best_license_entry)
                if license_id:
                    # print(f"Found via 'licenses' array (best after sort): {license_id} for {repo_dir_path}")
                    return license_id
            
            # print(f"DEBUG: 'licenses' array was present for {repo_dir_path} but no usable ID found in chosen entry.")

        # Attempt 4: Iterate through "matched_files" array.
        # Each file can have its own license determination.
        matched_files_array = license_data.get("matched_files")
        if isinstance(matched_files_array, list) and matched_files_array:
            # Look for the license with the highest confidence among all matched files
            # Or, more simply, the first one that clearly states a license.
            # This can get complex if multiple files have different licenses.
            # For now, let's take the first one that has a determinable license.
            for file_match_entry in matched_files_array:
                if isinstance(file_match_entry, dict):
                    license_in_file_obj = file_match_entry.get("license")
                    license_id = extract_license_from_entry(license_in_file_obj)
                    if license_id:
                        # print(f"Found via 'matched_files[x].license': {license_id} from file {file_match_entry.get('filename')} for {repo_dir_path}")
                        return license_id # Return the first one found this way
            # print(f"DEBUG: 'matched_files' array was present for {repo_dir_path} but no usable ID found within its entries.")


        # If none of the above parsing strategies yielded a result
        print(f"DEBUG: No conclusive license found after all parsing strategies for {repo_dir_path} (Confidence: {LICENSEE_CONFIDENCE_THRESHOLD}).")
        print(f"DEBUG: Full licensee JSON for {repo_dir_path}: {json_output_str}")
        return "NONE_FOUND_BY_LICENSEE"

    except json.JSONDecodeError:
        print(f"Error decoding JSON from licensee output for {repo_dir_path}: {json_output_str}")
        return "LICENSEE_JSON_ERROR"
    except Exception as e:
        print(f"Unexpected error parsing licensee output for {repo_dir_path}: {e}. JSON was: {json_output_str}")
        return "LICENSEE_PARSE_ERROR"

# --- main() function remains IDENTICAL to the previous "complete script" version ---
# Make sure to copy the main() function from the previous "complete script"
# provided in the response before this one.
# For brevity, I am not repeating it here.

def main():
    organization_name = os.environ.get("ORGANIZATION_TO_SCAN")
    github_token = os.environ.get("GH_TOKEN_FOR_SCAN")
    output_filename = os.environ.get("OUTPUT_FILENAME_TO_USE", "organization_public_licenses_licensee.json")

    if not organization_name:
        print("Error: ORGANIZATION_TO_SCAN environment variable is not set.")
        sys.exit(1)
    if not github_token:
        print("Error: GH_TOKEN_FOR_SCAN environment variable is not set. Token is needed for API and git operations.")
        sys.exit(1)

    print(f"Python script starting scan for organization: {organization_name} using licensee CLI with confidence >= {LICENSEE_CONFIDENCE_THRESHOLD}%")
    print(f"Output file will be: {output_filename}")

    g = None 
    try:
        g = Github(github_token)
        try:
            user = g.get_user()
            print(f"Authenticated to GitHub API as: {user.login}")
            rate_limit_info = g.get_rate_limit().core
            reset_time_str = rate_limit_info.reset.strftime('%Y-%m-%d %H:%M:%S UTC') if rate_limit_info.reset else 'N/A'
            print(f"API Rate limit: {rate_limit_info.remaining}/{rate_limit_info.limit}, Resets at: {reset_time_str}")
        except GithubException as ge_user:
            is_integration_error = ge_user.status == 403 and "integration" in str(ge_user.data).lower()
            is_forbidden_generic = ge_user.status == 403
            
            if is_integration_error:
                print(f"Warning (non-critical): Could not get authenticated user info (g.get_user()): {ge_user.status} - {ge_user.data}. This can happen with GITHUB_TOKEN. Proceeding...")
            elif is_forbidden_generic:
                print(f"Warning (potentially critical): GET /user failed with 403 Forbidden: {ge_user.data}. The provided token may lack 'read:user' or similar scope if it's a PAT. Proceeding cautiously...")
            else:
                print(f"Error during g.get_user() call: {ge_user.status} - {ge_user.data}")
                if ge_user.status == 401:
                    print("This is a 401 Unauthorized error. The token is likely invalid or expired. Exiting.")
                    sys.exit(1)
                print("Proceeding, but initial user verification failed with an unexpected error.")
            
            if g: 
                try:
                    rate_limit_info = g.get_rate_limit().core
                    reset_time_str = rate_limit_info.reset.strftime('%Y-%m-%d %H:%M:%S UTC') if rate_limit_info.reset else 'N/A'
                    print(f"API Rate limit (fetched separately): {rate_limit_info.remaining}/{rate_limit_info.limit}, Resets at: {reset_time_str}")
                except Exception as e_rl:
                    print(f"Warning: Could not fetch rate limit information separately: {e_rl}")
        except Exception as e_user_other:
            print(f"Unexpected error during g.get_user() or initial rate limit check: {e_user_other}")
            print("Proceeding despite this initial error.")

    except Exception as e_init:
        print(f"CRITICAL Error initializing PyGithub object with token: {e_init}. This usually means the token is malformed or there's a fundamental issue with PyGithub or network.")
        sys.exit(1)
    
    if not g:
        print("CRITICAL: PyGithub object (g) could not be initialized. Exiting.")
        sys.exit(1)

    all_licenses_info = []
    repo_count = 0
    processed_repo_count = 0

    try:
        org = g.get_organization(organization_name)
        print(f"Successfully fetched organization object for: {org.login}")
        
        repos_paginator = org.get_repos(type="public")
        print("Starting to iterate through public repositories...")
        
        for repo in repos_paginator:
            repo_count += 1
            print("-----------------------------------------------------")
            print(f"Processing repository: {repo.full_name} (Discovered: {repo_count})")
            
            if repo.archived:
                print(f"Skipping archived repository: {repo.full_name}")
                all_licenses_info.append({"repository_name": repo.name, "license": "ARCHIVED_REPO_SKIPPED"})
                continue

            if repo.size == 0:
                 print(f"Skipping potentially empty repository (size 0 KB): {repo.full_name}")
                 all_licenses_info.append({"repository_name": repo.name, "license": "EMPTY_REPO_SKIPPED"})
                 continue

            current_license_info = {"repository_name": repo.name, "license": "ERROR_PROCESSING_REPO"}
            temp_clone_dir = tempfile.mkdtemp(prefix=f"repo_licensee_{repo.name.replace('/', '_')}_")
            
            cloned_successfully = False
            for attempt in range(1, MAX_RETRIES_CLONE + 1):
                clone_command = ["git", "clone", "--depth", "1", "--quiet", repo.clone_url, temp_clone_dir]
                
                if attempt > 1:
                    for item_name in os.listdir(temp_clone_dir):
                        item_path = os.path.join(temp_clone_dir, item_name)
                        try:
                            if os.path.isdir(item_path) and not os.path.islink(item_path):
                                shutil.rmtree(item_path)
                            else:
                                os.unlink(item_path)
                        except Exception as e_rm:
                            print(f"Warning: Failed to remove {item_path} for retry: {e_rm}")

                success, stdout_clone, stderr_clone = run_command_robust(clone_command, check_return_code=True)
                
                if success:
                    cloned_successfully = True
                    break
                else:
                    print(f"Clone failed for {repo.full_name} (attempt {attempt}). Stderr: {stderr_clone}")
                    if attempt < MAX_RETRIES_CLONE:
                        time.sleep(RETRY_DELAY_SECONDS)
                    else:
                        print(f"Max retries reached for cloning {repo.full_name}.")
                        current_license_info["license"] = "ERROR_CLONING"
            
            if cloned_successfully:
                license_id = detect_license_with_licensee_cli(temp_clone_dir)
                current_license_info["license"] = license_id
                print(f"License for {repo.name}: {license_id}")
            
            all_licenses_info.append(current_license_info)
            processed_repo_count +=1
            
            try:
                shutil.rmtree(temp_clone_dir)
            except Exception as e_clean:
                print(f"Error cleaning up temp directory {temp_clone_dir}: {e_clean}")

    except UnknownObjectException:
        print(f"Error: Organization '{organization_name}' not found or not accessible via API.")
    except RateLimitExceededException as rle:
        print(f"Error: GitHub API rate limit exceeded during repository processing. {rle.data}")
    except GithubException as ge:
        print(f"GitHub API error during repository processing: {ge.status} - {ge.data}")
    except Exception as e:
        print(f"An unexpected error occurred during main processing loop: {e}")
    finally:
        with open(output_filename, "w") as f_out:
            json.dump(all_licenses_info, f_out, indent=2)
        print(f"Output file '{output_filename}' written with {len(all_licenses_info)} entries (discovered {repo_count} repos, attempted to process {processed_repo_count}).")

    print("-----------------------------------------------------")
    print(f"Python + Licensee CLI: Public license scan finished. Report: {output_filename}")
    if repo_count == 0:
        print("No public repositories were discovered for this organization.")
    elif processed_repo_count == 0 and repo_count > 0:
        print(f"Discovered {repo_count} repositories, but none were processed (e.g., all archived/empty or errors before processing).")

if __name__ == "__main__":
    main()
    
