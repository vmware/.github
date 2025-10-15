#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Org-wide CLA Stub Manager (requires_cla edition)

Purpose
-------
Reconcile per-repo CLA trigger stubs across all *public* repositories in an org.
This version delegates the "does this repo require CLA?" decision to your
`.github/scripts/requires_cla.py` module (and its helpers), eliminating any
license detection inside the workflow.

Behavior
--------
For each public repo (filtered by include/exclude globs):
  - decision = requires_cla.requires_CLA("<org>/<repo>", token)
  - If decision is True  or None (error/unknown): ensure stub PRESENT/UPDATED
  - If decision is False: ensure stub ABSENT (delete if present)

Outputs one machine-parsable line per repo:
  REPO=<name> STATUS=<status> DECISION=<True|False|None> MSG=<text>

Where STATUS ∈ {
  stub_created_or_updated, stub_ok, stub_removed_not_required,
  skipped_not_required, skipped_filtered, error
}

Usage (typical in GitHub Actions)
---------------------------------
python3 .github/scripts/check_and_install_stub.py \
  --org "<ORG>" \
  --reusable-ref "main" \
  --allowlist-branch "cla-config" \
  --allowlist-path "cla/allowlist.yml" \
  --sign-phrase "I have read the CLA Document and I hereby sign the CLA" \
  --secret-name "CLA_ASSISTANT_PAT" \
  --include-repos "" \
  --exclude-repos ""

Env / Secrets
-------------
- GITHUB_TOKEN or ORG_PAT : PAT with Content R/W across target repos,
  and read access to list org repositories.
- Optional env overrides for filters:
  INCLUDE_REPOS, EXCLUDE_REPOS (comma-separated globs)

Notes
-----
- Public repositories only (by policy).
- Fail-safe: if requires_CLA() returns None or raises -> treat as require CLA.
- The per-repo stub forwards the repo secret (default "CLA_ASSISTANT_PAT")
  to the reusable workflow as CONTRIBUTOR_ASSISTANT_PAT.
- Bump TARGET_STUB_VERSION to force an org-wide stub refresh.
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple


# ====== Configuration knobs ======

# Auto-managed per-repo stub location
STUB_PATH = ".github/workflows/cla-check-trigger.yml"

# Increment to force updates across all repos (compares against header in existing stub)
TARGET_STUB_VERSION = "7"

# Default excludes for discovery (special admin/security repos etc.)
DEFAULT_EXCLUDES = [".github", ".github-*", "security", "security-*", "admin", "admin-*"]

# Where to try importing your helper modules from (in Actions runner workspace)
CANDIDATE_MODULE_DIRS = [
    os.path.join(os.getcwd(), ".github", "scripts"),
    os.path.join(os.getcwd(), ".github-admin", "scripts"),
    os.getcwd(),
]


# ====== Utilities ======

def _prepare_import_path() -> None:
    for p in CANDIDATE_MODULE_DIRS:
        if os.path.isdir(p) and p not in sys.path:
            sys.path.insert(0, p)


_prepare_import_path()

try:
    # Your single source of truth for the decision.
    # May internally import detect_org_repo_licenses.py, license_detector.py, etc.
    import requires_cla  # type: ignore
except Exception as e:
    print(f"ERROR: Could not import requires_cla.py: {e}", file=sys.stderr)
    sys.exit(2)


def gh_api(
    url: str,
    token: str,
    method: str = "GET",
    body: Optional[bytes] = None,
    accept: str = "application/vnd.github+json",
) -> Dict:
    """Minimal GitHub API helper using urllib (stdlib only)."""
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", accept)
    if body is not None:
        req.add_header("Content-Type", "application/json")
        req.data = body
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return json.loads(raw.decode()) if raw else {}
    except urllib.error.HTTPError as e:
        # Surface HTTP error details for logs while letting caller decide behavior
        try:
            detail = e.read().decode()
        except Exception:
            detail = ""
        raise RuntimeError(f"GitHub API error {e.code} for {url}: {detail}") from e


def list_public_repos(org: str, token: str) -> List[Dict]:
    """List all public, non-archived, non-disabled repos in the org."""
    results: List[Dict] = []
    page = 1
    while True:
        url = f"https://api.github.com/orgs/{org}/repos?per_page=100&page={page}&type=public&sort=full_name&direction=asc"
        data = gh_api(url, token)
        if not isinstance(data, list) or not data:
            break
        results.extend(data)
        page += 1

    return [
        r
        for r in results
        if not (r.get("archived") or r.get("disabled")) and r.get("private") is False
    ]


def get_default_branch(owner: str, repo: str, token: str) -> str:
    data = gh_api(f"https://api.github.com/repos/{owner}/{repo}", token)
    return data.get("default_branch", "main")


def get_file(owner: str, repo: str, path: str, ref: str, token: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (content_str, sha) or (None, None) if not found."""
    try:
        data = gh_api(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}",
            token,
        )
        if isinstance(data, dict) and data.get("content"):
            content = base64.b64decode(data["content"]).decode()
            return content, data.get("sha")
    except Exception:
        pass
    return None, None


def put_file(
    owner: str,
    repo: str,
    path: str,
    ref: str,
    token: str,
    content: str,
    sha: Optional[str],
    message: str,
) -> Dict:
    body = {
        "message": message,
        "content": base64.b64encode(content.encode()).decode(),
        "branch": ref,
    }
    if sha:
        body["sha"] = sha
    return gh_api(
        f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
        token,
        method="PUT",
        body=json.dumps(body).encode(),
    )


def delete_file(
    owner: str,
    repo: str,
    path: str,
    ref: str,
    token: str,
    sha: str,
    message: str,
) -> Dict:
    body = {"message": message, "sha": sha, "branch": ref}
    return gh_api(
        f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
        token,
        method="DELETE",
        body=json.dumps(body).encode(),
    )


def globs_to_list(val: Optional[str]) -> List[str]:
    return [g.strip() for g in (val or "").split(",") if g.strip()]


def allowed_by_globs(name: str, includes: List[str], excludes: List[str]) -> bool:
    if includes:
        if not any(fnmatch.fnmatch(name, pat) for pat in includes):
            return False
    for pat in excludes:
        if fnmatch.fnmatch(name, pat):
            return False
    return True


# ====== Stub template (hardened) ======

STUB_TEMPLATE = """# Auto-managed; DO NOT EDIT MANUALLY
# Stub Version: {stub_version}
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
  group: ${{{{ github.workflow }}}}-${{{{ github.event.pull_request.number || github.run_id }}}}
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
          github-token: ${{{{ secrets.{secret_name} }}}}
          script: |
            let isMember = false;
            try {{
              await github.rest.orgs.checkMembershipForUser({{ org: context.repo.owner, username: context.payload.sender.login }});
              isMember = true;
            }} catch {{}}
            core.setOutput('is_member', isMember ? 'true' : 'false');

      - name: Skip if org member
        if: ${{{{ steps.member.outputs.is_member == 'true' }}}}
        run: echo "Org member — skipping CLA."

      - name: Call reusable CLA checker
        if: ${{{{ steps.member.outputs.is_member != 'true' }}}}
        uses: ${{{{ github.repository_owner }}}}/.github/.github/workflows/reusable-cla-check.yml@{reusable_ref}
        secrets:
          CONTRIBUTOR_ASSISTANT_PAT: ${{{{ secrets.{secret_name} }}}}}
        with:
          allowlist_branch: "{allowlist_branch}"
          allowlist_path: "{allowlist_path}"
          sign_comment_exact: "{sign_phrase}"
"""


def ensure_stub(
    owner: str,
    repo: str,
    token: str,
    default_branch: str,
    reusable_ref: str,
    allowlist_branch: str,
    allowlist_path: str,
    sign_phrase: str,
    secret_name: str,
) -> str:
    """Create or update the stub in a target repo; return status string."""
    desired = STUB_TEMPLATE.format(
        stub_version=TARGET_STUB_VERSION,
        reusable_ref=reusable_ref,
        allowlist_branch=allowlist_branch,
        allowlist_path=allowlist_path,
        sign_phrase=sign_phrase.replace('"', '\\"'),
        secret_name=secret_name,
    )

    existing, sha = get_file(owner, repo, STUB_PATH, default_branch, token)
    if existing:
        m = re.search(r"Stub Version:\s*(\d+)", existing)
        cur_ver = m.group(1) if m else "0"
        needs_update = (cur_ver != TARGET_STUB_VERSION) or (existing.strip() != desired.strip())
        if needs_update:
            put_file(
                owner,
                repo,
                STUB_PATH,
                default_branch,
                token,
                desired,
                sha,
                f"chore(cla): ensure trigger stub v{TARGET_STUB_VERSION}",
            )
            return "stub_created_or_updated"
        return "stub_ok"
    else:
        put_file(
            owner,
            repo,
            STUB_PATH,
            default_branch,
            token,
            desired,
            None,
            f"chore(cla): add trigger stub v{TARGET_STUB_VERSION}",
        )
        return "stub_created_or_updated"


# ====== Main ======

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Reconcile per-repo CLA trigger stubs for all public repos in an org.")
    p.add_argument("--org", required=True, help="GitHub organization login")
    p.add_argument("--reusable-ref", required=True, help="Ref in .github containing reusable-cla-check.yml (e.g., main)")
    p.add_argument("--allowlist-branch", required=True, help="Branch in .github where cla/allowlist.yml lives (e.g., cla-config)")
    p.add_argument("--allowlist-path", required=True, help="Path to allowlist YAML inside .github (e.g., cla/allowlist.yml)")
    p.add_argument("--sign-phrase", required=True, help="Exact phrase required to sign via comment")
    p.add_argument("--secret-name", default="CLA_ASSISTANT_PAT", help="Repo secret name forwarded as CONTRIBUTOR_ASSISTANT_PAT")
    p.add_argument("--include-repos", default=os.environ.get("INCLUDE_REPOS", ""), help="Comma-separated globs to include")
    p.add_argument("--exclude-repos", default=os.environ.get("EXCLUDE_REPOS", ""), help="Comma-separated globs to exclude (added to defaults)")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("ORG_PAT")
    if not token:
        print("ERROR: GITHUB_TOKEN/ORG_PAT not set", file=sys.stderr)
        sys.exit(2)

    includes = globs_to_list(args.include_repos)
    excludes = DEFAULT_EXCLUDES + globs_to_list(args.exclude_repos)

    try:
        repos = list_public_repos(args.org, token)
    except Exception as e:
        print(f"ERROR: failed to list public repos: {e}", file=sys.stderr)
        sys.exit(2)

    for r in repos:
        name = r.get("name") or ""
        if not name:
            # Very unlikely, but be defensive
            print("REPO=? STATUS=error DECISION=None MSG=missing repo name", file=sys.stderr)
            continue

        # Filter by include/exclude globs
        if not allowed_by_globs(name, includes, excludes):
            print(f"REPO={name} STATUS=skipped_filtered DECISION=None MSG=Filtered by include/exclude")
            continue

        full = f"{args.org}/{name}"
        try:
            # Single source of truth (your module)
            decision: Optional[bool] = None
            try:
                decision = requires_cla.requires_CLA(full, token=token)  # type: ignore[attr-defined]
            except Exception as e:
                # Fail-safe: treat unknown as require CLA
                decision = None

            requires = True if decision is None else bool(decision)

            default_branch = get_default_branch(args.org, name, token)
            existing, sha = get_file(args.org, name, STUB_PATH, default_branch, token)

            if requires:
                status = ensure_stub(
                    args.org,
                    name,
                    token,
                    default_branch,
                    args.reusable_ref,
                    args.allowlist_branch,
                    args.allowlist_path,
                    args.sign_phrase,
                    args.secret_name,
                )
                print(f"REPO={name} STATUS={status} DECISION={requires} MSG=CLA required")
            else:
                if existing and sha:
                    delete_file(
                        args.org,
                        name,
                        STUB_PATH,
                        default_branch,
                        token,
                        sha,
                        "chore(cla): remove trigger stub (CLA not required)",
                    )
                    print(f"REPO={name} STATUS=stub_removed_not_required DECISION={requires} MSG=Removed stub")
                else:
                    print(f"REPO={name} STATUS=skipped_not_required DECISION={requires} MSG=No stub (as expected)")

        except Exception as e:
            print(f"REPO={name} STATUS=error DECISION=None MSG={e}", file=sys.stderr)


if __name__ == "__main__":
    main()

