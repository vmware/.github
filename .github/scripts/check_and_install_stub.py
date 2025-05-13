name: Manage CLA Stubs Org-Wide

on:
  schedule:
   # - cron: '0 3 * * *' # Daily at 3 AM UTC
  workflow_dispatch: # Allows manual triggering

permissions: {} # Top-level permissions. Will be defined per-job or rely on PAT.

env:
  # These should be set as Organization Variables or Secrets
  # Example: "repo1,repo2,.github" ('.github' repo itself should be excluded)
  EXCLUDE_REPOS_CSV: ${{ vars.EXCLUDE_REPOS || '.github' }}
  # Example: "important-project1,important-project2"
  # If empty, all non-excluded repos are considered.
  INCLUDE_REPOS_CSV: ${{ vars.INCLUDE_REPOS || '' }}
  # Example: "MIT,Apache-2.0,BSD-3-Clause,ISC"
  PERMISSIVE_SPDX_IDS_CSV: ${{ vars.PERMISSIVE_SPDX_IDS || 'MIT,Apache-2.0,BSD-3-Clause,ISC,BSD-2-Clause,CC0-1.0,Unlicense' }}

jobs:
  discover_repositories:
    runs-on: ubuntu-latest
    outputs:
      repositories: ${{ steps.get_repos.outputs.repo_list_json }}
    # This job needs permissions to list organization repositories if using GITHUB_TOKEN
    # However, we'll use ORG_PAT via github-script for broader compatibility/control
    # So, no specific 'permissions' block needed here for GITHUB_TOKEN if PAT is used.
    steps:
      - name: Get Organization Repositories
        id: get_repos
        uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.ORG_PAT }} # PAT with 'repo' scope (or 'admin:org' for org.listForAuthenticatedUser)
          script: |
            const includeReposList = (process.env.INCLUDE_REPOS_CSV || "").split(',').map(r => r.trim()).filter(r => r);
            const excludeReposList = (process.env.EXCLUDE_REPOS_CSV || "").split(',').map(r => r.trim()).filter(r => r);
            let reposToProcess = [];

            if (includeReposList.length > 0) {
              console.log("Processing only explicitly included repositories:", includeReposList);
              reposToProcess = includeReposList.map(repoName => `${context.repo.owner}/${repoName}`);
            } else {
              console.log("Fetching all repositories for organization:", context.repo.owner);
              const allRepos = [];
              for await (const response of github.paginate.iterator(github.rest.repos.listForOrg, {
                org: context.repo.owner,
                type: 'all', // public, private, internal etc.
                per_page: 100
              })) {
                for (const repo of response.data) {
                  if (!repo.archived) { // Optionally skip archived
                     allRepos.push(repo.full_name);
                  }
                }
              }
              console.log(`Found ${allRepos.length} repositories in the organization.`);
              reposToProcess = allRepos.filter(fullName => {
                const repoName = fullName.split('/')[1];
                return !excludeReposList.includes(repoName);
              });
            }
            
            // Further filter out explicitly excluded repos even if they were in the include list
            // (though logically, include would override exclude if a repo is in both)
            // For safety, let's ensure exclude always wins if something is in both.
            const finalRepos = reposToProcess.filter(fullName => {
                const repoName = fullName.split('/')[1];
                return !excludeReposList.includes(repoName);
            });

            console.log(`Final list of ${finalRepos.length} repositories to process:`, finalRepos);
            return JSON.stringify(finalRepos);
        env:
          INCLUDE_REPOS_CSV: ${{ env.INCLUDE_REPOS_CSV }}
          EXCLUDE_REPOS_CSV: ${{ env.EXCLUDE_REPOS_CSV }}

  process_repository:
    needs: discover_repositories
    if: needs.discover_repositories.outputs.repositories != '[]' # Only run if there are repos
    runs-on: ubuntu-latest
    # This job itself doesn't need write permissions via GITHUB_TOKEN,
    # as the Python script uses ORG_PAT for cross-repo writes.
    # However, for actions like checkout within this job, 'contents: read' is implicit.
    strategy:
      matrix:
        repository_full_name: ${{ fromJson(needs.discover_repositories.outputs.repositories) }}
      fail-fast: false # Allow other matrix jobs to continue if one fails
    
    steps:
      - name: Checkout .github repo (for scripts)
        uses: actions/checkout@v4 # Checks out the .github repo

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: pip install PyGithub==1.59.1 # Pin PyGithub version for stability

      - name: Check license and install/update CLA stub
        run: python .github/scripts/check_and_install_stub.py
        env:
          TARGET_REPO_FULL_NAME: ${{ matrix.repository_full_name }}
          ORG_PAT: ${{ secrets.ORG_PAT }}
          PERMISSIVE_SPDX_IDS: ${{ env.PERMISSIVE_SPDX_IDS_CSV }}
          GITHUB_REPOSITORY_OWNER: ${{ github.repository_owner }} # Pass org name to script
        # continue-on-error: true # Decide if one repo failure should fail the whole matrix entry
