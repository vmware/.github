#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import base64
import fnmatch
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

TARGET_STUB_VERSION = "7"
STUB_PATH = ".github/workflows/cla-check-trigger.yml"
WORK_BRANCH = "automation/cla-stub"
DEFAULT_EXCLUDES = [".github", ".github-*", "security", "security-*", "admin", "admin-*"]

# ---- requires_cla import ------------------------------------------------------
CANDIDATE_MODULE_DIRS = [
    os.path.join(os.getcwd(), ".github", "scripts"),
    os.getcwd(),
]
for p in CANDIDATE_MODULE_DIRS:
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

try:
    import requires_cla  # must expose requires_CLA("<org>/<repo>", token=...)
except Exception as e:
    print(f"ERROR: Could not import requires_cla.py: {e}", file=sys.stderr)
    sys.exit(2)

# ---- GitHub REST helpers ------------------------------------------------------
def _req(url: str, token: str, method: str = "GET",
         body: bytes | None = None,
         accept: str = "application/vnd.github+json") -> Dict:
    req = urllib.request.Request(url, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", accept)
    if body is not None:
        req.add_header("Content-Type", "application/json")
        req.data = body
    with urllib.request.urlopen(req) as r:
        raw = r.read()
        return json.loads(raw.decode()) if raw else {}

def gh_api(path: str, token: str, **kw) -> Dict:
    if path.startswith("http"):
        url = path
    else:
        url = "https://api.github.com" + path
    return _req(url, token, **kw)

def list_public_repos(org: str, token: str) -> List[Dict]:
    results, page = [], 1
    while True:
        data = gh_api(f"/orgs/{org}/repos?per_page=100&page={page}&type=public&sort=full_name&direction=asc", token)
        if not isinstance(data, list) or not data:
            break
        results.extend(data); page += 1
    return [r for r in results if not (r.get("archived") or r.get("disabled")) and r.get("private") is False]

def get_repo(owner: str, repo: str, token: str) -> Dict:
    return gh_api(f"/repos/{owner}/{repo}", token)

def get_default_branch(owner: str, repo: str, token: str) -> str:
    data = get_repo(owner, repo, token)
    return data.get("default_branch", "main")

def get_file(owner: str, repo: str, path: str, ref: str, token: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        data = gh_api(f"/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}?ref={urllib.parse.quote(ref)}", token)
        if isinstance(data, dict) and data.get("content"):
            content = base64.b64decode(data["content"]).decode()
            return content, data.get("sha")
    except Exception:
        pass
    return None, None

def put_file(owner: str, repo: str, path: str, ref: str, token: str,
             content: str, sha: str | None, message: str) -> Dict:
    body = {"message": message, "content": base64.b64encode(content.encode()).decode(), "branch": ref}
    if sha:
        body["sha"] = sha
    return gh_api(f"/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}", token,
                  method="PUT", body=json.dumps(body).encode())

def delete_file(owner: str, repo: str, path: str, ref: str, token: str,
                sha: str, message: str) -> Dict:
    body = {"message": message, "sha": sha, "branch": ref}
    return gh_api(f"/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}", token,
                  method="DELETE", body=json.dumps(body).encode())

def get_ref(owner: str, repo: str, ref: str, token: str) -> Optional[Dict]:
    try:
        return gh_api(f"/repos/{owner}/{repo}/git/ref/{urllib.parse.quote(ref, safe='')}", token)
    except Exception:
        return None

def create_ref(owner: str, repo: str, ref: str, sha: str, token: str) -> Dict:
    body = {"ref": f"refs/{ref}", "sha": sha}
    return gh_api(f"/repos/{owner}/{repo}/git/refs", token, method="POST", body=json.dumps(body).encode())

def update_ref(owner: str, repo: str, ref: str, sha: str, token: str, force: bool = True) -> Dict:
    body = {"sha": sha, "force": force}
    return gh_api(f"/repos/{owner}/{repo}/git/refs/{urllib.parse.quote(ref, safe='')}", token,
                  method="PATCH", body=json.dumps(body).encode())

def ensure_branch(owner: str, repo: str, base_branch: str, work_branch: str, token: str) -> str:
    # Get base branch SHA
    base = gh_api(f"/repos/{owner}/{repo}/git/ref/heads/{urllib.parse.quote(base_branch)}", token)
    base_sha = base["object"]["sha"]
    # Create or update work branch to base sha
    ref = f"heads/{work_branch}"
    existing = get_ref(owner, repo, ref, token)
    if existing and "object" in existing:
        update_ref(owner, repo, ref, base_sha, token, force=True)
    else:
        create_ref(owner, repo, ref, base_sha, token)
    return work_branch

def find_existing_pr(owner: str, repo: str, head_branch: str, base_branch: str, token: str) -> Optional[Dict]:
    head = f"{owner}:{head_branch}"
    q = f"/repos/{owner}/{repo}/pulls?state=open&head={urllib.parse.quote(head)}&base={urllib.parse.quote(base_branch)}&per_page=100"
    pulls = gh_api(q, token)
    if isinstance(pulls, list) and pulls:
        return pulls[0]
    return None

def comment_on_pr(owner: str, repo: str, pr_number: int, token: str, body: str) -> None:
    gh_api(f"/repos/{owner}/{repo}/issues/{pr_number}/comments", token,
           method="POST", body=json.dumps({"body": body}).encode())

def open_or_update_pr(owner: str, repo: str, head_branch: str, base_branch: str,
                      title: str, body: str, token: str) -> Dict:
    pr = find_existing_pr(owner, repo, head_branch, base_branch, token)
    if pr:
        number = pr["number"]
        # keep title/body current
        gh_api(f"/repos/{owner}/{repo}/pulls/{number}", token,
               method="PATCH", body=json.dumps({"title": title, "body": body}).encode())
        return pr
    payload = {"title": title, "head": head_branch, "base": base_branch, "body": body}
    pr = gh_api(f"/repos/{owner}/{repo}/pulls", token, method="POST", body=json.dumps(payload).encode())
    # one-time explanatory comment
    comment_on_pr(
        owner, repo, pr["number"], token,
        "🤖 **Org management automation:** This pull request was opened automatically to ensure "
        "that the required CLA trigger stub exists and is up to date. "
        "Merging this PR keeps the repository in compliance with the org-wide CLA policy."
    )
    return pr

# ---- Stub template ------------------------------------------------------------
def stub_template(reusable_ref, allowlist_branch, allowlist_path, sign_phrase, secret_name):
    return """# Auto-managed; DO NOT EDIT MANUALLY
# Stub Version: {version}
name: CLA — Trigger Stub

on:
  pull_request_target:
    types: [opened, synchronize, reopened]
  issue_comment:
    types: [created]

permissions:
  contents: read
  pull-requests: write
  issues: write
  statuses: write
  actions: read

concurrency:
  group: ${{{{ github.workflow }}}}-${{{{{ github.event.pull_request.number || github.run_id }}}}}
  cancel-in-progress: true

jobs:
  guard:
    name: Gate & Dispatch
    runs-on: ubuntu-latest
    if: >
      (github.event_name == 'pull_request_target') ||
      (github.event_name == 'issue_comment' && github.event.issue.pull_request)

    steps:
      - name: Short-circuit for org members (fast path)
        id: member
        uses: actions/github-script@v7
        with:
          script: |
            let isMember = false;
            try {{
              await github.rest.orgs.checkMembershipForUser(
                {{ org: context.repo.owner, username: context.payload.sender.login }}
              );
              isMember = true;
            }} catch {{}}
            core.setOutput('is_member', isMember ? 'true' : 'false');

      - name: Skip if org member
        if: ${{{{ steps.member.outputs.is_member == 'true' }}}}
        run: echo "Org member — skipping CLA."

      - name: Call reusable CLA checker
        if: ${{{{ steps.member.outputs.is_member != 'true' }}}}
        uses: ${{{{ github.repository_owner }}}}/.github/.github/workflows/reusable-cla-check.yml@{reusable_ref}
        with:
          allowlist_branch: "{allowlist_branch}"
          allowlist_path: "{allowlist_path}"
          sign_comment_exact: "{sign_phrase}"
        secrets:
          CONTRIBUTOR_ASSISTANT_PAT: ${{{{ secrets.{secret_name} }}}}
""".format(
        version=TARGET_STUB_VERSION,
        reusable_ref=reusable_ref,
        allowlist_branch=allowlist_branch,
        allowlist_path=allowlist_path,
        sign_phrase=sign_phrase.replace('"', '\\"'),
        secret_name=secret_name,
    )


# ---- Content orchestration (PR-everywhere policy) -----------------------------
def compose_pr_body(action: str, reason: str) -> str:
    lines = [
        f"**CLA stub {action}**",
        "",
        f"- Reason: {reason}",
        f"- Managed by automation branch `{WORK_BRANCH}`",
        f"- Stub version: `{TARGET_STUB_VERSION}`",
        "",
        "This PR is generated by the org CLA manager to keep every repo aligned with the central CLA policy."
    ]
    return "\n".join(lines)

def ensure_stub_via_pr(owner: str, repo: str, token: str, base_branch: str,
                       reusable_ref: str, allowlist_branch: str, allowlist_path: str,
                       sign_phrase: str, secret_name: str) -> str:
    # Always refresh work branch from base
    ensure_branch(owner, repo, base_branch, WORK_BRANCH, token)

    desired = stub_template(reusable_ref, allowlist_branch, allowlist_path, sign_phrase, secret_name)
    existing_on_work, sha_work = get_file(owner, repo, STUB_PATH, WORK_BRANCH, token)

    # Write/Update on work branch
    put_file(owner, repo, STUB_PATH, WORK_BRANCH, token, desired, sha_work, "chore(cla): ensure trigger stub")

    # Open or update PR
    title = "chore(cla): add/ensure required CLA trigger stub"
    body = compose_pr_body("addition/update", "CLA required for this repository")
    open_or_update_pr(owner, repo, WORK_BRANCH, base_branch, title, body, token)
    return "pr_opened_or_updated_for_stub"

def remove_stub_via_pr(owner: str, repo: str, token: str, base_branch: str) -> str:
    # Only open a removal PR if base currently has the stub
    existing_base, sha_base = get_file(owner, repo, STUB_PATH, base_branch, token)
    if not existing_base:
        return "skipped_not_required"

    # Refresh work branch from base, then delete on work branch
    ensure_branch(owner, repo, base_branch, WORK_BRANCH, token)
    existing_work, sha_work = get_file(owner, repo, STUB_PATH, WORK_BRANCH, token)
    if existing_work and sha_work:
        delete_file(owner, repo, STUB_PATH, WORK_BRANCH, token, sha_work,
                    "chore(cla): remove trigger stub (CLA not required)")

    title = "chore(cla): remove CLA trigger stub (no longer required)"
    body = compose_pr_body("removal", "CLA not required for this repository")
    open_or_update_pr(owner, repo, WORK_BRANCH, base_branch, title, body, token)
    return "pr_opened_or_updated_for_removal"

# ---- Policy filters -----------------------------------------------------------
def globs_to_list(val: str | None) -> List[str]:
    return [g.strip() for g in (val or "").split(",") if g.strip()]

def allowed_by_globs(name: str, includes: List[str], excludes: List[str]) -> bool:
    if includes and not any(fnmatch.fnmatch(name, pat) for pat in includes):
        return False
    for pat in excludes:
        if fnmatch.fnmatch(name, pat):
            return False
    return True

# ---- Main ---------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", required=True)
    ap.add_argument("--reusable-ref", required=True)
    ap.add_argument("--allowlist-branch", required=True)
    ap.add_argument("--allowlist-path", required=True)
    ap.add_argument("--sign-phrase", required=True)
    ap.add_argument("--secret-name", default="CLA_ASSISTANT_PAT")
    ap.add_argument("--include-repos", default=os.environ.get("INCLUDE_REPOS",""))
    ap.add_argument("--exclude-repos", default=os.environ.get("EXCLUDE_REPOS",""))
    args = ap.parse_args()

    token = os.environ.get("ORG_PAT") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("ERROR: ORG_PAT/GITHUB_TOKEN not set", file=sys.stderr)
        sys.exit(2)

    includes = globs_to_list(args.include_repos)
    excludes = DEFAULT_EXCLUDES + globs_to_list(args.exclude_repos)

    repos = list_public_repos(args.org, token)
    for r in repos:
        name = r.get("name") or ""
        if not name:
            print("REPO=? STATUS=error DECISION=None MSG=missing repo name", file=sys.stderr)
            continue
        if not allowed_by_globs(name, includes, excludes):
            print(f"REPO={name} STATUS=skipped_filtered DECISION=None MSG=Filtered by include/exclude")
            continue

        try:
            try:
                decision = requires_cla.requires_CLA(f"{args.org}/{name}", token=token)
            except Exception:
                decision = None  # fail-safe: require CLA
            requires = True if decision is None else bool(decision)

            base_branch = get_default_branch(args.org, name, token)

            if requires:
                status = ensure_stub_via_pr(args.org, name, token, base_branch,
                                            args.reusable_ref, args.allowlist_branch, args.allowlist_path,
                                            args.sign_phrase, args.secret_name)
                print(f"REPO={name} STATUS={status} DECISION={requires} MSG=CLA required")
            else:
                status = remove_stub_via_pr(args.org, name, token, base_branch)
                print(f"REPO={name} STATUS={status} DECISION={requires} MSG=CLA not required")

        except Exception as e:
            print(f"REPO={name} STATUS=error DECISION=None MSG={e}", file=sys.stderr)

if __name__ == "__main__":
    main()
