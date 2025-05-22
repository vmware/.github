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

def run_command_robust(command_args, cwd=None, check_return_code=True, an_input=None):
    """
    Runs a shell command, captures its output, and handles errors robustly.
    Returns a tuple: (success, stdout, stderr)
    """
    # print(f"DEBUG: Executing: {' '.join(command_args)} {'in ' + cwd if cwd else ''}") # Very verbose
    try:
        process = subprocess.Popen(
            command_args,
            cwd=cwd,
            stdin=subprocess.PIPE if an_input else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ.copy() # Pass current environment
        )
        stdout, stderr = process.communicate(input=an_input)
        
        if check_return_code and process.returncode != 0:
            print(f"Command failed with exit code {process.returncode}: {' '.join(command_args)}")
            print(f"Stderr: {stderr.strip()}")
            # print(f"Stdout: {stdout.strip()}") # Often not useful on error
            return False, stdout.strip(), stderr.strip()
        return True, stdout.strip(), stderr.strip()

    except FileNotFoundError:
        print(f"Error: Command not found - {command_args[0]}. Ensure it's installed and in PATH.")
        return False, "", f"Command not found: {command_args[0]}"
    except Exception as e:
        print(f"An unexpected error occurred while running command {' '.join(command_args)}: {e}")
        return False, "", str(e)

def detect_license_with_licensee_cli(repo_dir):
    """Runs licensee detect in the given directory and parses the output."""
    command = ["licensee", "detect", "--json", "."]
    # Don't check return code here, licensee can exit non-zero for "no license"
    success, stdout, stderr = run_command_robust(command, cwd=repo_dir, check_return_code=False)

    if not stdout and not success: # if licensee truly failed to run
         print(f"Licensee CLI failed to execute. Stderr: {stderr}")
         return "LICENSEE_EXECUTION_ERROR"

    if not stdout.strip() or stdout.strip() == "null":
        if "No license found" in stderr or "No license found" in stdout : # Check common messages
            # print(f"Licensee reported no license found for directory: {repo_dir}") # Can be verbose
            pass
        else:
            print(f"Licensee produced empty or null output for directory: {repo_dir}. Stderr: {stderr}")
        return "NONE_FOUND_BY_LICENSEE"

    try:
        license_data = json.loads(stdout)
        if not license_data:
            return "NONE_FOUND_BY_LICENSEE" # Empty JSON from licensee often means no license

        matched_license_obj = license_data.get("matched_license")
        
        if not matched_license_obj:
            # Check if it's because no license was found by licensee (e.g. licensee >= 9.15 "licenses": [])
            if "licenses" in license_data and isinstance(license_data["licenses"], list) and not license_data["licenses"]:
                return "NONE_FOUND_BY_LICENSEE"
            return "NO_MATCHED_LICENSE_KEY" # Key missing, licensee output format changed?
        
        spdx_id = matched_license_obj.get("spdx_id")
        name = matched_license_obj.get("name")
        
        return spdx_id or name or "UNKNOWN_LICENSEE_OUTPUT"
        
    except json.JSONDecodeError:
        print(f"Error decoding JSON from licensee output: {stdout}")
        return "LICENSEE_JSON_ERROR"
    except Exception as e:
        print(f"Unexpected error parsing licensee output: {e}")
        return "LICENSEE_PARSE_ERROR"

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

    print(f"Python script starting scan for organization: {organization_name} using licensee CLI")
    print(f"Output file will be: {output_filename}")

    g = None 
    try:
        g = Github(github_token)
        print("PyGithub object initialized.")
        
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
            repo_count += 1 # Total repos encountered from paginator
            print("-----------------------------------------------------")
            print(f"Processing repository: {repo.full_name} (Discovered: {repo_count})")
            
            # Skip archived repositories if desired (can save a lot of time/resources)
            if repo.archived:
                print(f"Skipping archived repository: {repo.full_name}")
                all_licenses_info.append({"repository_name": repo.name, "license": "ARCHIVED_REPO_SKIPPED"})
                continue

            # Skip empty repositories if desired
            if repo.size == 0: # Size in KB; 0 often means empty or nearly empty
                 print(f"Skipping potentially empty repository (size 0 KB): {repo.full_name}")
                 all_licenses_info.append({"repository_name": repo.name, "license": "EMPTY_REPO_SKIPPED"})
                 continue


            current_license_info = {"repository_name": repo.name, "license": "ERROR_PROCESSING_REPO"}
            temp_clone_dir = tempfile.mkdtemp(prefix=f"repo_licensee_{repo.name.replace('/', '_')}_")
            
            cloned_successfully = False
            for attempt in range(1, MAX_RETRIES_CLONE + 1):
                clone_command = ["git", "clone", "--depth", "1", "--quiet", repo.clone_url, temp_clone_dir]
                
                if attempt > 1: # Cleanup before retry
                    for item_name in os.listdir(temp_clone_dir):
                        item_path = os.path.join(temp_clone_dir, item_name)
                        try:
                            if os.path.isdir(item_path) and not os.path.islink(item_path):
                                shutil.rmtree(item_path)
                            else:
                                os.unlink(item_path)
                        except Exception as e_rm:
                            print(f"Warning: Failed to remove {item_path} for retry: {e_rm}")

                success, stdout, stderr = run_command_robust(clone_command, check_return_code=True)
                
                if success:
                    cloned_successfully = True
                    break
                else:
                    print(f"Clone failed for {repo.full_name} (attempt {attempt}). Stderr: {stderr}")
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
            processed_repo_count +=1 # Repos we actually attempted to process (not just discovered)
            
            try:
                shutil.rmtree(temp_clone_dir)
            except Exception as e_clean:
                print(f"Error cleaning up temp directory {temp_clone_dir}: {e_clean}")
            
            # Optional: brief pause to be nice to API during repo listing, though PyGithub handles pagination waits
            # if repo_count % 50 == 0: time.sleep(1)


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
