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
    print(f"Executing: {' '.join(command_args)} {'in ' + cwd if cwd else ''}")
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
            print(f"Stdout: {stdout.strip()}")
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
            print(f"Licensee reported no license found for directory: {repo_dir}")
        else:
            print(f"Licensee produced empty or null output for directory: {repo_dir}. Stderr: {stderr}")
        return "NONE_FOUND_BY_LICENSEE"

    try:
        license_data = json.loads(stdout)
        if not license_data or not license_data.get("matched_license"):
             # Check if it's because no license was found by licensee
            if license_data and "licenses" in license_data and not license_data["licenses"]:
                return "NONE_FOUND_BY_LICENSEE"
            return "NO_MATCHED_LICENSE_KEY"
        
        spdx_id = license_data["matched_license"].get("spdx_id")
        name = license_data["matched_license"].get("name")
        
        return spdx_id or name or "UNKNOWN_LICENSEE_OUTPUT"
        
    except json.JSONDecodeError:
        print(f"Error decoding JSON from licensee output: {stdout}")
        return "LICENSEE_JSON_ERROR"
    except Exception as e:
        print(f"Unexpected error parsing licensee output: {e}")
        return "LICENSEE_PARSE_ERROR"

def main():
    organization_name = os.environ.get("ORGANIZATION_TO_SCAN")
    github_token = os.environ.get("GH_TOKEN_FOR_SCAN") # Used by PyGithub and for git clone via gh auth setup-git
    output_filename = os.environ.get("OUTPUT_FILENAME_TO_USE", "organization_public_licenses_licensee.json")

    if not organization_name:
        print("Error: ORGANIZATION_TO_SCAN environment variable is not set.")
        sys.exit(1)
    if not github_token:
        # While public clones might not need it, PyGithub will, and consistent auth is good.
        print("Error: GH_TOKEN_FOR_SCAN environment variable is not set. Token is needed for API and potentially git operations.")
        sys.exit(1)

    print(f"Python script starting scan for organization: {organization_name} using licensee CLI")
    print(f"Output file will be: {output_filename}")

    try:
        g = Github(github_token)
        user = g.get_user() # Verify token and get rate limit info
        print(f"Authenticated to GitHub API as: {user.login}")
        print(f"API Rate limit: {g.get_rate_limit().core.remaining}/{g.get_rate_limit().core.limit}")
    except Exception as e:
        print(f"Error initializing GitHub API or authenticating: {e}")
        sys.exit(1)
    
    all_licenses_info = []
    repo_count = 0

    try:
        org = g.get_organization(organization_name)
        print(f"Fetching public repositories for organization: {org.login}")
        
        repos_paginator = org.get_repos(type="public")
        
        for repo in repos_paginator:
            repo_count += 1
            print("-----------------------------------------------------")
            print(f"Processing repository: {repo.full_name} ({repo_count})")
            
            current_license_info = {"repository_name": repo.name, "license": "ERROR_PROCESSING_REPO"}
            temp_clone_dir = tempfile.mkdtemp(prefix=f"repo_licensee_{repo.name.replace('/', '_')}_")
            print(f"Temporary clone directory: {temp_clone_dir}")

            cloned_successfully = False
            for attempt in range(1, MAX_RETRIES_CLONE + 1):
                print(f"Attempt {attempt}/{MAX_RETRIES_CLONE} to clone {repo.full_name}...")
                # git CLI will use token due to `gh auth setup-git` in workflow
                # Using repo.clone_url which is the HTTPS URL
                clone_command = ["git", "clone", "--depth", "1", "--quiet", repo.clone_url, temp_clone_dir]
                
                # Clean dir before retrying clone if it's not the first attempt
                if attempt > 1:
                    if os.path.exists(temp_clone_dir): # Dir was created by previous failed attempt
                        # shutil.rmtree(temp_clone_dir) # Remove old one
                        # temp_clone_dir = tempfile.mkdtemp(prefix=f"repo_licensee_{repo.name.replace('/', '_')}_") # Make new one
                        # Or better: clean inside the existing temp_clone_dir
                        for item_name in os.listdir(temp_clone_dir):
                            item_path = os.path.join(temp_clone_dir, item_name)
                            try:
                                if os.path.isdir(item_path) and not os.path.islink(item_path):
                                    shutil.rmtree(item_path)
                                else:
                                    os.unlink(item_path)
                            except Exception as e_rm:
                                print(f"Warning: Failed to remove {item_path} for retry: {e_rm}")
                    else: # Should not happen if tempfile.mkdtemp succeeded
                         temp_clone_dir = tempfile.mkdtemp(prefix=f"repo_licensee_{repo.name.replace('/', '_')}_")


                success, stdout, stderr = run_command_robust(clone_command)
                
                if success:
                    print("Clone successful.")
                    cloned_successfully = True
                    break
                else:
                    print(f"Clone failed for {repo.full_name} (attempt {attempt}). Stderr: {stderr}")
                    if attempt < MAX_RETRIES_CLONE:
                        print(f"Retrying in {RETRY_DELAY_SECONDS} seconds...")
                        time.sleep(RETRY_DELAY_SECONDS)
                    else:
                        print(f"Max retries reached for cloning {repo.full_name}.")
                        current_license_info["license"] = "ERROR_CLONING"
            
            if cloned_successfully:
                license_id = detect_license_with_licensee_cli(temp_clone_dir)
                current_license_info["license"] = license_id
            
            all_licenses_info.append(current_license_info)
            
            print(f"Cleaning up {temp_clone_dir}...")
            try:
                shutil.rmtree(temp_clone_dir)
                print(f"Cleaned up {temp_clone_dir}.")
            except Exception as e_clean:
                print(f"Error cleaning up temp directory {temp_clone_dir}: {e_clean}")
            
            # Optional: brief pause
            # time.sleep(0.1)

    except UnknownObjectException:
        print(f"Error: Organization '{organization_name}' not found or not accessible via API.")
        # Output what we have so far
    except RateLimitExceededException:
        print("Error: GitHub API rate limit exceeded while listing repositories. Try again later.")
        # Output what we have so far
    except GithubException as e:
        print(f"GitHub API error during repository processing: {e.status} {e.data}")
        # Output what we have so far
    except Exception as e:
        print(f"An unexpected error occurred during main processing: {e}")
        # Output what we have so far

    with open(output_filename, "w") as f_out:
        json.dump(all_licenses_info, f_out, indent=2)

    print("-----------------------------------------------------")
    print(f"Python + Licensee CLI: Public license report generated: {output_filename}")
    if not all_licenses_info and repo_count == 0:
        print("No public repositories found or processed.")

if __name__ == "__main__":
    main()
