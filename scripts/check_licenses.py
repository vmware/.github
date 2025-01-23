import os
import json
import re
from github import Github, GithubException

def check_license(repo):
    """Check if repository has a permissive license."""
    try:
        # Load permissive licenses from organization's .github repository
        org_github_repo = repo.organization.get_repo(".github")
        license_file = org_github_repo.get_contents(".github/permissive_licenses.json")
        permissive = json.loads(license_file.decoded_content.decode())['permissive']
        pattern = '|'.join(permissive)

        # Check for license file
        license_content = None
        try:
            contents = repo.get_contents("")
            for content in contents:
                if content.name.lower().startswith(('license', 'copying')):
                    license_content = content.decoded_content.decode()
                    break
        except GithubException as e:
            if e.status == 404:
                return False, "No license file found"
            raise

        if not license_content:
            return False, "No license file found"

        # Check first 20 lines for license match
        first_20_lines = '\n'.join(license_content.split('\n')[:20])
        if re.search(fr'\b({pattern})\b', first_20_lines, re.IGNORECASE):
            return True, "Permissive license found"
            
        return False, "Non-permissive license found"

    except Exception as e:
        return False, f"Error checking license: {str(e)}"

def install_trigger(repo):
    """Install CLA trigger workflow from template in organization's .github repo."""
    try:
        # Get template from organization's .github repository
        org_github_repo = repo.organization.get_repo(".github")
        template = org_github_repo.get_contents(".github/templates/cla-trigger-template.yml")
        workflow_content = template.decoded_content.decode()

        # Ensure workflows directory exists
        try:
            repo.get_contents('.github/workflows')
        except GithubException as e:
            if e.status == 404:
                repo.create_file(
                    '.github/workflows/.gitkeep',
                    'Create workflows directory',
                    ''
                )
            else:
                raise

        # Create/update workflow file
        workflow_path = '.github/workflows/cla-trigger.yml'
        try:
            existing_file = repo.get_contents(workflow_path)
            repo.update_file(
                workflow_path,
                'Update CLA trigger workflow',
                workflow_content,
                existing_file.sha
            )
        except GithubException as e:
            if e.status == 404:
                repo.create_file(
                    workflow_path,
                    'Add CLA trigger workflow',
                    workflow_content
                )
            else:
                raise

        return True
    except Exception as e:
        print(f"Error installing trigger in {repo.full_name}: {str(e)}")
        return False

def main():
    token = os.environ.get('ORG_TOKEN')
    if not token:
        print("Missing ORG_TOKEN environment variable")
        return 1

    g = Github(token)
    try:
        org_name = os.environ['GITHUB_REPOSITORY'].split('/')[0]
        org = g.get_organization(org_name)
        print(f"Scanning organization: {org.name}")
    except Exception as e:
        print(f"Error accessing organization: {str(e)}")
        return 1

    # Get repo filters
    excluded_repos = [r.strip() for r in os.environ.get('EXCLUDED_REPOS', '').split(',') if r.strip()]
    included_repos = [r.strip() for r in os.environ.get('INCLUDED_REPOS', '').split(',') if r.strip()]

    results = {
        'non_permissive': [],
        'trigger_installed': [],
        'excluded': excluded_repos,
        'errors': []
    }

    for repo in org.get_repos():
        repo_full_name = repo.full_name
        
        # Apply filters
        if repo_full_name in excluded_repos:
            continue
        if included_repos and repo_full_name not in included_repos:
            continue

        print(f"Processing repository: {repo_full_name}")
        
        try:
            # License check
            is_permissive, message = check_license(repo)
            if not is_permissive:
                results['non_permissive'].append({
                    'repo': repo_full_name,
                    'reason': message
                })
                
                # Install CLA trigger
                if install_trigger(repo):
                    results['trigger_installed'].append(repo_full_name)
                else:
                    results['errors'].append(f"Trigger installation failed for {repo_full_name}")
                    
        except Exception as e:
            results['errors'].append(f"{repo_full_name}: {str(e)}")
            continue

    # Save and output results
    with open('scan_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    if results['non_permissive'] or results['errors']:
        print("Scan completed with findings:")
        print(json.dumps(results, indent=2))
        return 1
        
    print("Scan completed successfully - no issues found")
    return 0

if __name__ == '__main__':
    exit(main())
