#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import asyncio
import base64
import datetime
import fnmatch
import inspect
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

# ----------------------------- Config -----------------------------------------
TARGET_STUB_VERSION = "14"
STUB_PATH = ".github/workflows/cla-check-trigger.yml"
WORK_BRANCH = "automation/cla-stub"
DEFAULT_EXCLUDES = [".github", ".github-*", "security", "security-*", "admin", "admin-*"]

# ----------------------------- Debug helper -----------------------------------
import re

_SECRET_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.=]+", re.I),
    re.compile(r"([?&]access_token=)[^&]+", re.I),
]

def _scrub(s: str) -> str:
    s = _SECRET_PATTERNS[0].sub("Bearer ***", str(s))
    s = _SECRET_PATTERNS[1].sub(r"\1***", s)
    return s

def log_debug(msg: str) -> None:
    print(f"DEBUG {datetime.datetime.utcnow().isoformat()}Z: {_scrub(msg)}", file=sys.stderr)

def log_debug(msg: str) -> None:
    """Structured debug printer with UTC timestamp (stderr)."""
    print(f"DEBUG {datetime.datetime.utcnow().isoformat()}Z: {msg}", file=sys.stderr)

# ----------------------------- Import requires_cla -----------------------------
CANDIDATE_MODULE_DIRS = [
    os.path.join(os.getcwd(), ".github", "scripts"),
    os.getcwd(),
]
for p in CANDIDATE_MODULE_DIRS:
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

try:
    import requires_cla  # must expose requires_CLA("<org>/<repo>", token=...) or gh_token=...
except ModuleNotFoundError as e:
    print(
        f"ERROR: requires_cla.py dependency missing: {e.name}. "
        f"Add it to .github/scripts/requirements.txt and install in the workflow.",
        file=sys.stderr,
    )
    sys.exit(2)
except Exception as e:
    print(f"ERROR: Could not import requires_cla.py: {e}", file=sys.stderr)
    sys.exit(2)

# ----------------------------- GitHub REST helpers ----------------------------
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
    log_debug(f"HTTP {method} {url}")
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return json.loads(raw.decode()) if raw else {}
    except urllib.error.HTTPError as e:
        try:
            err = e.read().decode()
        except Exception:
            err = ""
        log_debug(f"HTTP ERROR {e.code} {method} {url} body={err or '<no body>'}")
        raise

def gh_api(path: str, token: str, **kw) -> Dict:
    url = path if path.startswith("http") else "https://api.github.com" + path
    return _req(url, token, **kw)

def list_public_repos(org: str, token: str) -> List[Dict]:
    results, page = [], 1
    while True:
        data = gh_api(
            f"/orgs/{org}/repos?per_page=100&page={page}&type=public&sort=full_name&direction=asc",
            token
        )
        if not isinstance(data, list) or not data:
            break
        results.extend(data)
        page += 1
    # Filter client-side
    repos = [r for r in results if not (r.get("archived") or r.get("disabled")) and r.get("private") is False]
    log_debug(f"Discovered {len(repos)} public, active repos in org '{org}'")
    return repos

def get_repo(owner: str, repo: str, token: str) -> Dict:
    return gh_api(f"/repos/{owner}/{repo}", token)

def get_default_branch(owner: str, repo: str, token: str) -> str:
    data = get_repo(owner, repo, token)
    default_branch = data.get("default_branch", "main")
    log_debug(f"{owner}/{repo} default branch is '{default_branch}'")
    return default_branch

def get_file(owner: str, repo: str, path: str, ref: str, token: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        data = gh_api(
            f"/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}?ref={urllib.parse.quote(ref)}",
            token
        )
        if isinstance(data, dict) and data.get("content"):
            content = base64.b64decode(data["content"]).decode()
            sha = data.get("sha")
            log_debug(f"Fetched file '{path}' at '{ref}' ({'present' if content else 'empty'}), sha={sha}")
            return content, sha
    except Exception as e:
        log_debug(f"get_file error for {owner}/{repo}@{ref}:{path}: {e}")
    return None, None

def put_file(owner: str, repo: str, path: str, ref: str, token: str,
             content: str, sha: str | None, message: str) -> Dict:
    body = {"message": message, "content": base64.b64encode(content.encode()).decode(), "branch": ref}
    if sha:
        body["sha"] = sha
    log_debug(f"PUT file '{path}' on branch '{ref}' (sha={sha}) in {owner}/{repo}")
    return gh_api(f"/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}", token,
                  method="PUT", body=json.dumps(body).encode())

def delete_file(owner: str, repo: str, path: str, ref: str, token: str,
                sha: str, message: str) -> Dict:
    body = {"message": message, "sha": sha, "branch": ref}
    log_debug(f"DELETE file '{path}' on branch '{ref}' (sha={sha}) in {owner}/{repo}")
    return gh_api(f"/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}", token,
                  method="DELETE", body=json.dumps(body).encode())

def get_ref(owner: str, repo: str, ref: str, token: str) -> Optional[Dict]:
    try:
        return gh_api(f"/repos/{owner}/{repo}/git/ref/{urllib.parse.quote(ref, safe='')}", token)
    except Exception as e:
        log_debug(f"get_ref {owner}/{repo} {ref} -> {e}")
        return None

def create_ref(owner: str, repo: str, ref: str, sha: str, token: str) -> Dict:
    body = {"ref": f"refs/{ref}", "sha": sha}
    log_debug(f"CREATE ref '{ref}' at sha={sha} in {owner}/{repo}")
    return gh_api(f"/repos/{owner}/{repo}/git/refs", token, method="POST", body=json.dumps(body).encode())

def update_ref(owner: str, repo: str, ref: str, sha: str, token: str, force: bool = True) -> Dict:
    body = {"sha": sha, "force": force}
    log_debug(f"UPDATE ref '{ref}' to sha={sha} (force={force}) in {owner}/{repo}")
    return gh_api(f"/repos/{owner}/{repo}/git/refs/{urllib.parse.quote(ref, safe='')}", token,
                  method="PATCH", body=json.dumps(body).encode())

def ensure_branch(owner: str, repo: str, base_branch: str, work_branch: str, token: str) -> str:
    base = gh_api(f"/repos/{owner}/{repo}/git/ref/heads/{urllib.parse.quote(base_branch)}", token)
    base_sha = base["object"]["sha"]
    ref = f"heads/{work_branch}"
    existing = get_ref(owner, repo, ref, token)
    if existing and "object" in existing:
        update_ref(owner, repo, ref, base_sha, token, force=True)
        log_debug(f"Reset branch '{work_branch}' to '{base_branch}'@{base_sha[:7]}")
    else:
        create_ref(owner, repo, ref, base_sha, token)
        log_debug(f"Created branch '{work_branch}' from '{base_branch}'@{base_sha[:7]}")
    return work_branch

def find_existing_pr(owner: str, repo: str, head_branch: str, base_branch: str, token: str) -> Optional[Dict]:
    head = f"{owner}:{head_branch}"
    pulls = gh_api(
        f"/repos/{owner}/{repo}/pulls?state=open&head={urllib.parse.quote(head)}&base={urllib.parse.quote(base_branch)}&per_page=100",
        token
    )
    if isinstance(pulls, list) and pulls:
        log_debug(f"Found existing PR #{pulls[0]['number']} for head={head_branch} base={base_branch} in {owner}/{repo}")
        return pulls[0]
    return None

def comment_on_pr(owner: str, repo: str, pr_number: int, token: str, body: str) -> None:
    log_debug(f"Commenting on PR #{pr_number} in {owner}/{repo}")
    gh_api(f"/repos/{owner}/{repo}/issues/{pr_number}/comments", token,
           method="POST", body=json.dumps({"body": body}).encode())

def find_any_pr(owner: str, repo: str, head_branch: str, base_branch: str, token: str) -> Optional[Dict]:
    head = f"{owner}:{head_branch}"
    pulls = gh_api(
        f"/repos/{owner}/{repo}/pulls?state=all&head={urllib.parse.quote(head)}&base={urllib.parse.quote(base_branch)}&per_page=100",
        token
    )
    if isinstance(pulls, list) and pulls:
        # Prefer the most recent
        return sorted(pulls, key=lambda p: p.get("number", 0), reverse=True)[0]
    return None

def reopen_pr(owner: str, repo: str, number: int, title: str, body: str, token: str) -> Dict:
    log_debug(f"Reopening PR #{number} in {owner}/{repo}")
    return gh_api(
        f"/repos/{owner}/{repo}/pulls/{number}",
        token,
        method="PATCH",
        body=json.dumps({"state": "open", "title": title, "body": body}).encode()
    )

def open_or_update_pr(owner: str, repo: str, head_branch: str, base_branch: str,
                      title: str, body: str, token: str) -> Dict:
    log_debug(f"Opening or updating PR head={head_branch} base={base_branch} in {owner}/{repo}")
    pr = find_existing_pr(owner, repo, head_branch, base_branch, token)
    if pr:
        number = pr["number"]
        gh_api(f"/repos/{owner}/{repo}/pulls/{number}", token,
               method="PATCH", body=json.dumps({"title": title, "body": body}).encode())
        return pr
    payload = {"title": title, "head": head_branch, "base": base_branch, "body": body}
    try:
        pr = gh_api(f"/repos/{owner}/{repo}/pulls", token, method="POST", body=json.dumps(payload).encode())
        comment_on_pr(
            owner, repo, pr["number"], token,
            "🤖 **Org management automation:** This pull request was opened automatically to ensure "
            "that the required CLA trigger stub exists and is up to date. "
            "Merging this PR keeps the repository in compliance with the org-wide CLA policy."
        )
        log_debug(f"Posted automation comment on PR #{pr['number']} in {owner}/{repo}")
        return pr
    except urllib.error.HTTPError as e:
        # Fallback: try to reopen an existing closed PR with same head/base
        any_pr = find_any_pr(owner, repo, head_branch, base_branch, token)
        if any_pr and any_pr.get("state") == "closed":
            pr = reopen_pr(owner, repo, any_pr["number"], title, body, token)
            return pr
        # Surface a clearer error in the logs; caller will mark STATUS=error
        raise


# ----------------------------- Stub template ----------------------------------
def stub_template(owner: str, reusable_ref: str, allowlist_branch: str,
                  allowlist_path: str, sign_phrase: str,
                  secret_name: str) -> str:
    # NOTE: we purposely keep ALL GitHub expression delimiters as sentinel tokens
    # during .format(), then swap them at the end. This avoids any brace parsing.

    tmpl = """# Auto-managed; DO NOT EDIT MANUALLY
# Stub Version: {version}
name: CLA — Trigger

on:
  pull_request_target:
    types: [opened, synchronize, reopened, ready_for_review]
  issue_comment:
    types: [created, edited]

≈
jobs:
  cla:
    name: Call reusable CLA checker
    # run on PRs, or when a signing comment *or* recheck is posted
    if: >
      ${{
        github.event_name == 'pull_request_target' ||
        (
          github.event_name == 'issue_comment' &&
          github.event.issue.pull_request &&
          (
            contains(github.event.comment.body, {{ sign_comment_exact | tojson }}) ||
            startsWith(github.event.comment.body, 'recheck') ||
            startsWith(github.event.comment.body, '/recheck')
          )
        )
      }}
   permissions:
        contents: read
        pull-requests: write
        issues: write
        statuses: write
        actions: read
    uses: {owner}/.github/.github/workflows/reusable-cla-check.yml@{reusable_ref}
    with:
      allowlist_branch: "{allowlist_branch}"
      allowlist_path: "{allowlist_path}"
      sign_comment_exact: "{sign_phrase}"
    secrets:
      # preserve existing mapping: pass repo/org secret <secret_name> into the reusable as CONTRIBUTOR_ASSISTANT_PAT
      CONTRIBUTOR_ASSISTANT_PAT: __GHA_OPEN__ secrets.{secret_name} __GHA_CLOSE__
"""
    # 1) Do the safe .format() substitutions for our *own* variables only
    out = tmpl.format(
        version=TARGET_STUB_VERSION,
        owner=owner,
        reusable_ref=reusable_ref,
        allowlist_branch=allowlist_branch,
        allowlist_path=allowlist_path,
        sign_phrase=sign_phrase.replace('"', '\\"'),
        secret_name=secret_name
    )
    # 2) Now swap placeholders to real GitHub expression delimiters
    out = out.replace("__GHA_OPEN__", "${{").replace("__GHA_CLOSE__", "}}")
    return out

# ----------------------------- PR-everywhere ops ------------------------------
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
    log_debug(f"Ensuring stub via PR for {owner}/{repo}")
    ensure_branch(owner, repo, base_branch, WORK_BRANCH, token)
    try:
        desired = stub_template(owner, reusable_ref, allowlist_branch, allowlist_path, sign_phrase, secret_name)
    except Exception as e:
        log_debug(f"stub_template formatting error for {owner}/{repo}: {e}")
        raise                           
#    desired = stub_template(reusable_ref, allowlist_branch, allowlist_path, sign_phrase, secret_name)
    existing_on_work, sha_work = get_file(owner, repo, STUB_PATH, WORK_BRANCH, token)
    put_file(owner, repo, STUB_PATH, WORK_BRANCH, token, desired, sha_work, "chore(cla): ensure trigger stub")
    title = "chore(cla): add/ensure required CLA trigger stub"
    body = compose_pr_body("addition/update", "CLA required for this repository")
    open_or_update_pr(owner, repo, WORK_BRANCH, base_branch, title, body, token)
    return "pr_opened_or_updated_for_stub"

def remove_stub_via_pr(owner: str, repo: str, token: str, base_branch: str) -> str:
    log_debug(f"Removing stub via PR for {owner}/{repo}")
    existing_base, _ = get_file(owner, repo, STUB_PATH, base_branch, token)
    if not existing_base:
        log_debug(f"No stub on base branch for {owner}/{repo}; skipping removal PR")
        return "skipped_not_required"
    ensure_branch(owner, repo, base_branch, WORK_BRANCH, token)
    existing_work, sha_work = get_file(owner, repo, STUB_PATH, WORK_BRANCH, token)
    if existing_work and sha_work:
        delete_file(owner, repo, STUB_PATH, WORK_BRANCH, token, sha_work,
                    "chore(cla): remove trigger stub (CLA not required)")
    title = "chore(cla): remove CLA trigger stub (no longer required)"
    body = compose_pr_body("removal", "CLA not required for this repository")
    open_or_update_pr(owner, repo, WORK_BRANCH, base_branch, title, body, token)
    return "pr_opened_or_updated_for_removal"

# ----------------------------- Filtering & decision ---------------------------
def globs_to_list(val: str | None) -> List[str]:
    return [g.strip() for g in (val or "").split(",") if g.strip()]

def allowed_by_globs(name: str, includes: List[str], excludes: List[str]) -> bool:
    """
    Include overrides exclude. If 'includes' is empty, everything is included (subject to excludes).
    """
    inc_hit = any(fnmatch.fnmatch(name, pat) for pat in includes) if includes else True
    exc_hit = any(fnmatch.fnmatch(name, pat) for pat in excludes)
    allowed = (inc_hit and not exc_hit) or (includes and inc_hit)
    log_debug(f"Filter check for '{name}': inc_hit={inc_hit}, exc_hit={exc_hit}, allowed={allowed}")
    return allowed

def decide_requires_cla(org: str, repo: str, token: str) -> bool:
    """
    Calls requires_cla.requires_CLA('<org>/<repo>', token=...) and supports:
    - async function
    - kwarg name 'gh_token' instead of 'token'
    Returns: bool (True => CLA required)
    """
    target = f"{org}/{repo}"
    fn = getattr(requires_cla, "requires_CLA", None)
    if fn is None:
        raise RuntimeError("requires_cla.requires_CLA not found")

    def _coerce(v):
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        return s in ("1", "true", "yes", "require", "required", "needs", "needed")

    tries = [
        lambda: fn(target, token=token),
        lambda: fn(target, gh_token=token),
    ]
    for call in tries:
        try:
            if inspect.iscoroutinefunction(fn):
                log_debug(f"Calling async requires_CLA({target})")
                return _coerce(asyncio.run(call()))
            else:
                log_debug(f"Calling sync requires_CLA({target})")
                return _coerce(call())
        except TypeError as te:
            log_debug(f"Signature mismatch for requires_CLA({target}): {te} (trying next variant)")
            continue
    # Positional fallback
    if inspect.iscoroutinefunction(fn):
        return _coerce(asyncio.run(fn(target, token)))
    return _coerce(fn(target, token))

# ----------------------------- Main -------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", required=True)
    ap.add_argument("--reusable-ref", required=True)
    ap.add_argument("--allowlist-branch", required=True)
    ap.add_argument("--allowlist-path", required=True)
    ap.add_argument("--sign-phrase", required=True)
    ap.add_argument("--secret-name", default="CLA_ASSISTANT_PAT")
    ap.add_argument("--include-repos", default=os.environ.get("INCLUDE_REPOS", ""))
    ap.add_argument("--exclude-repos", default=os.environ.get("EXCLUDE_REPOS", ""))
    args = ap.parse_args()

    token = os.environ.get("ORG_PAT") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("ERROR: ORG_PAT/GITHUB_TOKEN not set", file=sys.stderr)
        sys.exit(2)

    log_debug(f"Python {sys.version.split()[0]} running cla_manager.py")
    log_debug(f"Inputs: org={args.org}, reusable_ref={args.reusable_ref}, allowlist={args.allowlist_branch}:{args.allowlist_path}")
    log_debug("Inputs received (sign phrase and secret name hidden)")

    includes = globs_to_list(args.include_repos)
    excludes = DEFAULT_EXCLUDES + globs_to_list(args.exclude_repos)
    log_debug(f"Scanning repos for org={args.org}, includes={includes or ['<all>']}, excludes={excludes}")

    repos = list_public_repos(args.org, token)
    for r in repos:
        name = r.get("name") or ""
        if not name:
            print("REPO=? STATUS=error DECISION=None MSG=missing repo name", file=sys.stderr)
            continue

        log_debug(f"Evaluating repo '{name}'")
        if not allowed_by_globs(name, includes, excludes):
            log_debug(f"Repo '{name}' filtered out (includes={includes}, excludes={excludes})")
            print(f"REPO={name} STATUS=skipped_filtered DECISION=None MSG=Filtered by include/exclude")
            continue

        try:
            log_debug(f"Calling requires_CLA for {args.org}/{name}")
            try:
                requires = decide_requires_cla(args.org, name, token)
                log_debug(f"requires_CLA({args.org}/{name}) => {requires}")
            except Exception as e:
                log_debug(f"requires_CLA failed for {args.org}/{name}: {e}")
                print(f"REPO={name} STATUS=decision_error DECISION=None MSG={e}", file=sys.stderr)
                requires = True  # fail-safe: require CLA

            base_branch = get_default_branch(args.org, name, token)

            if requires:
                status = ensure_stub_via_pr(
                    args.org, name, token, base_branch,
                    args.reusable_ref, args.allowlist_branch, args.allowlist_path,
                    args.sign_phrase, args.secret_name
                )
                print(f"REPO={name} STATUS={status} DECISION=True MSG=CLA required")
            else:
                status = remove_stub_via_pr(args.org, name, token, base_branch)
                print(f"REPO={name} STATUS={status} DECISION=False MSG=CLA not required")

        except Exception as e:
            log_debug(f"Unhandled error for {args.org}/{name}: {e}")
            print(f"REPO={name} STATUS=error DECISION=None MSG={e}", file=sys.stderr)

if __name__ == "__main__":
    main()
