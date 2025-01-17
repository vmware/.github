import os
import json
from github import Github

def check_license(repo):
    """Check if repository has a permissive license"""
    try:
        with open('permissive_licenses.json') as f:
            permissive = json.load(f)['permissive']
        
        pattern = '|'.join(permissive)
        
        license_file = None
        contents = repo.get_contents("")
        for content in contents:
            if content.name.lower().startswith(('license', 'copying')):
                license_file = content
                break
        
        if not license_file:
            return False, "No license file found"
        
        license_content = license_file.decoded_content.decode()
        first_20_lines = '\n'.join(license_content.split('\n')[:20])
        
        import re
        if re.search(fr'\b({pattern})\b', first_20_lines, re.IGNORECASE):
            return True, "Permissive license found"
            
        return False, "Non-permissive license found"
        
    except Exception as e:
        return False, f"Error checking license: {str(e)}"

def install_trigger(repo):
    """Install the CLA trigger workflow"""
    try:
        workflow_content = '''name: "CLA Check Trigger"

on:
  pull_request_target:
    types: [opened, synchronize, closed]
  issue_comment:
    types: [created]

jobs:
  cla-check:
    uses: ${{ github.repository_owner }}/.github/.github/workflows/cla-workflow.yml@main
    secrets: inherit'''

        # Ensure .github/workflows directory exists
        try:
            repo.get_contents('.github/workflows')
        except:
            repo.create_file(
                '.github/workflows/.gitkeep',
                'Create workflows directory',
                ''
            )

        # Create or update trigger workflow
        workflow_path = '.github/workflows/cla-trigger.yml'
        try:
            existing_file = repo.get_contents(workflow_path)
            repo.update_file(
                workflow_path,
                'Update CLA trigger workflow',
                workflow_content,
                existing_file.sha
            )
        except:
            repo.create_file(
                workflow_path,
                'Add CLA trigger workflow',
                workflow_content
            )
        return True
    except Exception as e:
        print(f"Error installing trigger in {repo.full_name}: {str(e)}")
        return False

def main():
    token = os.environ['ORG_TOKEN']
    excluded_repos = os.environ.get('EXCLUDED_REPOS', '').split(',')
    excluded_repos = [repo.strip() for repo in excluded_repos if repo.strip()]

    g = Github(token)
    org = g.get_organization(os.environ['GITHUB_REPOSITORY'].split('/')[0])
    
    results = {
        'non_permissive': [],
        'trigger_installed': [],
        'excluded': excluded_repos,
        'errors': []
    }

    for repo in org.get_repos():
        if repo.full_name in excluded_repos:
            continue

        is_permissive, message = check_license(repo)
        if not is_permissive:
            results['non_permissive'].append({
                'repo': repo.full_name,
                'reason': message
            })
            if install_trigger(repo):
                results['trigger_installed'].append(repo.full_name)
            else:
                results['errors'].append(f"Failed to install trigger in {repo.full_name}")

    with open('scan_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    if results['non_permissive'] or results['errors']:
        print(json.dumps(results, indent=2))
        return 1
    return 0

if __name__ == '__main__':
    exit(main())
