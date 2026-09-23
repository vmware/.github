import os
import sys
import json
import urllib.request
import urllib.error
import time
import random
import yaml
import base64
import gzip
import io

# --- [INTEGRATION START] IMPORT CLA AUTHENTICATION MODULE ---
try:
    import cla_auth
except ImportError:
    print("::warning::[SETUP] 'cla_auth.py' module not found. Token upgrade checks may fail.")

try:
    import requires_cla
except ImportError:
    print("::warning::[SETUP] 'requires_cla' module not found. Assuming strict CLA policy.")
    class requires_cla_stub:
        @staticmethod
        def requires_CLA(repo, token=None, licenses_data=None, permissive_data=None, allowlist_data=None): return True
    requires_cla = requires_cla_stub
# --- [INTEGRATION END] -------------------------------------

# --- CONFIGURATION ---
# The context the org ruleset requires. MUST NOT match the job name in
# .github/workflows/required-compliance.yml — see the comment there for why
# letting them collide makes the gate fail open.
STATUS_CONTEXT = "Check CLA/DCO"
BOT_ALLOWLIST = ["dependabot[bot]", "github-actions[bot]", "renovate[bot]"]

# Appended to the status description when the contributor signed correctly but
# writing their consent record failed. The status stays SUCCESS on purpose —
# they did sign, and an infrastructure failure is not theirs to pay for — but
# this marker exempts the PR from the already-resolved short-circuit so the
# next sweep retries the write. Without it a failed write is invisible AND
# permanent: green status, no record, nothing ever coming back to fix it.
#
# Matched with a substring test rather than equality so the surrounding
# wording can change without silently disabling the retry.
RECORD_PENDING_MARKER = "record pending"


def has_pending_record(description):
    """True if a status description we painted marks its consent record as
    not yet written. Tolerates None, which is what the API returns for a
    status posted without a description."""
    return RECORD_PENDING_MARKER in (description or "").lower()

# Substrings that only ever appear in our own instruction comment, never in a
# sign-off. Needed because INSTRUCTION_MESSAGE_LINES *contains* the signature
# phrase verbatim, so matching on the phrase alone cannot tell a deliberate
# sign-off from a comment that merely reproduces the instructions.
# tests/test_policy_selector.py asserts these still appear in
# INSTRUCTION_MESSAGE, so rewording the message fails loudly rather than
# silently reopening the bypass.
INSTRUCTION_MARKERS = ("Sign via Comment", "Legal Compliance Check Failed")

# --- UPDATED TEXT: STANDING WARRANTY ---
INSTRUCTION_MESSAGE_LINES = [
    "### 🛑 Legal Compliance Check Failed",
    "Hi @{user}, thank you for your contribution!",
    "",
    "To merge this Pull Request, you must sign our **{doc_type}**.",
    "",
    "**Note:** Even if you signed off your commits locally (using `git commit -s`), you must post the comment below to register your signature with our automated system.",
    "**Note:** This is a one-time process. Once signed, future contributions to this repository will be verified automatically.",
    "",
    "**1. Read the Document:** [Click here to read the {doc_type}]({url})",
    "**2. Sign via Comment:** Copy and paste the exact line below into a new comment on this Pull Request:",
    "",
    "```text",
    "I have read the {doc_type} Document and I hereby sign the {doc_type} for this and all future contributions.",
    "```",
    "",
    "---",
    "**⏳ Processing Schedule:**",
    "Our 'Compliance Sweeper' runs automatically **approximately every 15-20 minutes**.",
    "After you post the comment, your status will update automatically during the next scheduled run.",
    "You do not need to take any further action."
]
INSTRUCTION_MESSAGE = "\n".join(INSTRUCTION_MESSAGE_LINES)

# --- TOKEN UPGRADE LOGIC ---
def ensure_valid_token():
    if os.environ.get("CLA_TOKEN_UPGRADED") == "true": return
    print("::warning::[AUTH] Checking for available credentials to upgrade token...")
    app_id = os.environ.get("CLA_APP_ID")
    private_key = os.environ.get("CLA_APP_PRIVATE_KEY")
    org_name = os.environ.get("CENTRAL_ORG") or "vmware"

    if not app_id or not private_key:
        print("::warning::[AUTH] CLA_APP_ID or CLA_APP_PRIVATE_KEY missing. Cannot perform token upgrade.")
        return

    try:
        fresh_token = cla_auth.get_installation_access_token(app_id, private_key, org_name)
        if fresh_token:
            os.environ["GH_TOKEN"] = fresh_token
            os.environ["GITHUB_TOKEN"] = fresh_token
            os.environ["CLA_TOKEN_UPGRADED"] = "true"
            print("::warning::[AUTH] ✅ Token Upgrade Successful!")
        else:
            print("::error::[AUTH] Token Upgrade Failed.")
    except Exception as e:
        print(f"::error::[AUTH CRASH] Unexpected error during token upgrade: {e}")

# Run upgrade immediately
ensure_valid_token()

def debug_log(message):
    print(f"::warning::{message}")

def is_org_member(api_root, org_name, user, token):
    url = f"{api_root}/orgs/{org_name}/members/{user}"
    debug_log(f"🕵️ Checking membership for @{user} in {org_name}...")
    try:
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CLA-Sweeper"
        })
        with urllib.request.urlopen(req) as response:
            if response.getcode() == 204: return True
    except urllib.error.HTTPError as e:
        debug_log(f"❌ GitHub API error: {e.code} - {e.reason}")
        if e.code == 404: debug_log("-> NOTE: 404 means 'Not Found'.")
        return False
    except Exception as e:
        debug_log(f"⚠️ Unexpected error: {e}")
        return False
    return False
        
def _sleep_until_rate_limit_reset(headers, context=""):
    """Sleeps until X-RateLimit-Reset if present. Mirrors the proven pattern
    already used by the batch reporting pipeline (detect_org_repo_licenses.py's
    _rate_limit_sleep), adapted for this module's sync urllib calls."""
    try:
        reset = int(headers.get("X-RateLimit-Reset", "0"))
    except (TypeError, ValueError):
        return
    if not reset:
        return
    sleep_for = max(0, reset - int(time.time()) + 2)
    if sleep_for:
        debug_log(f"⏳ Rate limit low{f' ({context})' if context else ''}. Sleeping {sleep_for}s until reset...")
        time.sleep(sleep_for)


def github_api(url, token, method="GET", data=None, _retry_on_rate_limit=True):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    try:
        req = urllib.request.Request(url, headers=headers, method=method)
        if data: req.data = json.dumps(data).encode("utf-8")
        with urllib.request.urlopen(req) as r:
            remaining = r.headers.get("X-RateLimit-Remaining")
            if remaining is not None and remaining.isdigit() and int(remaining) <= 1:
                _sleep_until_rate_limit_reset(r.headers, context=url)
            if method == "DELETE": return {}
            if r.status == 204: return {}
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        # A rate-limit 403 and a permissions 403 (e.g. this App isn't
        # installed on the target repo) look identical unless we check this
        # header — X-RateLimit-Remaining is only "0" for the former. Only
        # the rate-limit case is worth sleeping-and-retrying; a permissions
        # error would just fail the same way again.
        is_rate_limited = e.code in (403, 429) and e.headers and e.headers.get("X-RateLimit-Remaining") == "0"
        if is_rate_limited and _retry_on_rate_limit:
            debug_log(f"⏳ Rate limited (HTTP {e.code}) for {url}. Sleeping until reset, then retrying once...")
            _sleep_until_rate_limit_reset(e.headers, context=url)
            return github_api(url, token, method, data, _retry_on_rate_limit=False)
        if e.code != 404:
            if is_rate_limited:
                debug_log(f"❌ Still rate limited after retry for {url}.")
            else:
                debug_log(f"API Error {e.code} for {url}: {e.read().decode()}")
        return None
    except Exception as e:
        debug_log(f"Network Error: {e}")
        return None

# --- NEW: PAGINATION HELPER (Fixes 100 Item Limit) ---
def github_api_paginated(url, token):
    """Fetches ALL pages of results."""
    all_results = []
    page = 1
    
    while True:
        separator = "&" if "?" in url else "?"
        paged_url = f"{url}{separator}page={page}&per_page=100"
        
        data = github_api(paged_url, token)
        
        # Handle cases where API returns dict (like search results) vs list
        items = data.get("items") if isinstance(data, dict) and "items" in data else data
        
        if not items or not isinstance(items, list):
            break
            
        all_results.extend(items)
        if len(items) < 100:
            break
        page += 1
        
    return all_results

# --- UNIFIED RESOURCE LOADER ---
def fetch_mothership_file(api_root, file_path, token):
    central_org = os.environ.get("CENTRAL_ORG") or "vmware"
    mothership_repo = f"{central_org}/.github"
    url = f"{api_root}/repos/{mothership_repo}/contents/{file_path}"
    debug_log(f"📥 API Fetch: {mothership_repo}/{file_path}")
    
    data = github_api(url, token)
    content_b64 = None
    
    if data:
        if "content" in data and data["content"]:
            content_b64 = data["content"]
        elif "sha" in data:
            debug_log(f"📦 Large file detected ({data.get('size')} bytes). Fetching blob {data['sha']}...")
            blob_url = f"{api_root}/repos/{mothership_repo}/git/blobs/{data['sha']}"
            blob_data = github_api(blob_url, token)
            if blob_data and "content" in blob_data:
                content_b64 = blob_data["content"]
    
    if content_b64:
        try:
            decoded_bytes = base64.b64decode(content_b64)
            if file_path.endswith(".gz"):
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(decoded_bytes)) as gz:
                        return gz.read().decode("utf-8")
                except Exception as gz_e:
                    debug_log(f"❌ Gzip Decompression Failed: {gz_e}")
                    return None
            return decoded_bytes.decode("utf-8")
        except Exception as e:
            debug_log(f"❌ Failed to decode/read file {file_path}: {e}")
            return None
    return None

def fetch_json_with_fallback(api_root, primary_path, secondary_path, token):
    candidates = [primary_path, f"{primary_path}.gz", secondary_path, f"{secondary_path}.gz"]
    for path in candidates:
        raw = fetch_mothership_file(api_root, path, token)
        if raw:
            try:
                return json.loads(raw)
            except json.JSONDecodeError as e:
                debug_log(f"❌ JSON Parse Error for {path}: {e}")
                continue
    return None

def add_reaction_to_comment(api_root, repo, comment_id, token):
    if not comment_id: return
    reaction_url = f"{api_root}/repos/{repo}/issues/comments/{comment_id}/reactions"
    try:
        github_api(reaction_url, token, "POST", {"content": "rocket"})
    except:
        pass

def signature_candidate_text(body):
    """Returns the part of a comment body that may count as a sign-off, or None
    if the comment is a reproduction of our own instruction comment.

    Our instruction comment quotes the exact sentence a contributor has to
    post, so a comment can contain that sentence without anyone intending to
    sign. Two such cases, both confirmed against real comment bodies:

      * GitHub's "Quote reply" button prefixes every line with "> ", so
        quoting the bot reproduces the sentence verbatim.
      * Pasting the whole instruction comment does the same without any quote
        markers.

    Quoted lines are dropped, and anything still carrying an
    INSTRUCTION_MARKERS fingerprint is rejected outright: a sign-off is one
    sentence, while the instruction comment is a document. Content inside code
    fences is deliberately *kept* — the instructions tell contributors to copy
    a line that is itself shown inside a fence, so someone who copies the
    fence markers too is signing in good faith.
    """
    normalized = body.replace("\xa0", " ")
    kept = [ln for ln in normalized.splitlines() if not ln.strip().startswith(">")]
    remaining = "\n".join(kept).strip()
    if any(marker in remaining for marker in INSTRUCTION_MARKERS):
        return None
    return remaining


# --- UPDATED: Uses Pagination for Comments ---
def check_comments_for_signature(api_root, repo, pr_number, user, doc_type, token):
    """Returns (comment_id, signed_doc_type), or (None, None) if the PR author
    has not signed.

    `signed_doc_type` is the document the author actually signed, which is not
    necessarily the one this repo requires — the caller compares them. This
    used to return only a comment id and accept either phrase regardless of
    `doc_type`, so posting the DCO sentence on a CLA repo passed the gate and
    then recorded a CLA consent record for someone who never agreed to the CLA.
    """
    if not pr_number: return None, None
    # Fix: Use paginated fetch to see >100 comments
    url = f"{api_root}/repos/{repo}/issues/{pr_number}/comments"
    comments = github_api_paginated(url, token)

    if not comments: return None, None

    # Check the document this repo actually requires first, so a comment that
    # happens to contain both sentences is credited to the required one.
    possible_types = [doc_type] + [t for t in ("CLA", "DCO") if t != doc_type]
    base_phrase = "I have read the {doc_type} Document and I hereby sign the {doc_type}"
    suffix_check = "for this and all future contributions"

    for c in comments:
        body = c.get("body", "")
        comment_user = c.get("user", {}).get("login")
        if comment_user and user and comment_user.lower() == user.lower():
            normalized_body = signature_candidate_text(body)
            if normalized_body is None:
                # The author reproduced our instruction comment rather than
                # signing. Not an error, and not a signature.
                continue
            for current_type in possible_types:
                target_phrase = base_phrase.format(doc_type=current_type)

                if target_phrase in normalized_body:
                    if suffix_check in normalized_body:
                        debug_log(f"✅ Found matching {current_type} signature from {user}!")
                        # Only acknowledge a sign-off that satisfies this
                        # repo's policy — a 🚀 on a wrong-document comment
                        # would contradict the failure status we go on to set.
                        if current_type == doc_type:
                            add_reaction_to_comment(api_root, repo, c.get("id"), token)
                        return c.get("id"), current_type

    debug_log(f"❌ No matching CLA or DCO signature found in {len(comments)} comments.")
    return None, None

# --- NEW: DCO Commit Check (Fixes 100 Commit Limit) ---
def check_dco_commits(api_root, repo, pr_number, token):
    """Returns True if ALL commits are signed-off."""
    url = f"{api_root}/repos/{repo}/pulls/{pr_number}/commits"
    # Fix: Use paginated fetch for >100 commits
    commits = github_api_paginated(url, token)
    
    if not commits: return False
    
    for commit in commits:
        message = commit.get("commit", {}).get("message", "")
        if "Signed-off-by:" not in message:
            debug_log(f"❌ Commit {commit.get('sha')[:7]} missing DCO Sign-off.")
            return False
            
    debug_log(f"✅ All {len(commits)} commits have DCO Sign-off.")
    return True

def post_pr_comment(api_root, repo, pr_number, message, token):
    if not pr_number: return
    comments_url = f"{api_root}/repos/{repo}/issues/{pr_number}/comments"
    existing_comments = github_api(comments_url, token)
    if existing_comments:
        for c in existing_comments:
            if "I have read the" in c.get("body", "") and "Sign via Comment" in c.get("body", ""):
                return 
    payload = {"body": message}
    github_api(comments_url, token, "POST", payload)

def force_merge_check_refresh(api_root, repo, pr_number, token):
    url = f"{api_root}/repos/{repo}/pulls/{pr_number}"
    github_api(url, token)

def set_commit_status(api_root, repo, sha, state, description, target_url, token):
    url = f"{api_root}/repos/{repo}/statuses/{sha}"
    payload = {
        "state": state,
        "context": STATUS_CONTEXT,
        "description": description,
        "target_url": target_url
    }
    debug_log(f"⚡ Painting Commit {sha[:7]} as '{state}'...")
    github_api(url, token, "POST", payload)

def get_existing_status(api_root, repo, sha, token):
    """Returns (state, description) for our STATUS_CONTEXT on this commit, or
    (None, None) if we haven't posted one yet.

    Renamed from get_existing_status_state when the description became
    load-bearing. Deliberately a rename rather than a changed return type: a
    caller left comparing the old name's result to "success" would silently
    evaluate False against a tuple, the PR #67 short-circuit would stop firing,
    and the repaint loop it exists to prevent would come back. An AttributeError
    is the better failure.
    """
    url = f"{api_root}/repos/{repo}/commits/{sha}/status"
    data = github_api(url, token)
    if not data:
        return None, None
    for s in data.get("statuses", []):
        if s.get("context") == STATUS_CONTEXT:
            return s.get("state"), s.get("description")
    return None, None

from datetime import datetime

# --- UPDATED: Retry Loop for Database Contention ---
def record_signature(api_root, org_name, doc_type, user, repo_name, token, pr_number, head_sha, comment_id):
    target_repo = f"{org_name}/.github"
    file_path = f"signatures/{doc_type.lower()}.json"
    url = f"{api_root}/repos/{target_repo}/contents/{file_path}"
    
    debug_log(f"💾 Attempting to record signature via API...")

    user_details = github_api(f"{api_root}/users/{user}", token)
    user_id = user_details.get("id") if user_details else None

    # RETRY LOOP: Try up to 3 times to handle race conditions
    max_retries = 3
    for attempt in range(max_retries):
        data = github_api(url, token)
        if not data or "content" not in data:
            debug_log(f"❌ Failed to fetch signature file. Check permissions for {target_repo}.")
            return False

        try:
            file_content = base64.b64decode(data["content"]).decode("utf-8")
            json_data = json.loads(file_content)
            if "signedContributors" not in json_data: json_data["signedContributors"] = []
            contributors = json_data["signedContributors"]

            # Check duplication
            for c in contributors:
                if isinstance(c, dict):
                    if c.get("name", "").lower() == user.lower(): return True
                    if user_id and c.get("id") == user_id: return True
                elif isinstance(c, str) and c.lower() == user.lower(): return True

            # Create Entry
            new_entry = {
                "name": user,
                "id": user_id,
                "signedAt": datetime.utcnow().isoformat() + "Z",
                "org": org_name,
                "repo": repo_name,
                "pr_number": pr_number,      
                "head_sha": head_sha,        
                "comment_id": comment_id,    
                "agreement_version": "1.0"   
            }
            contributors.append(new_entry)
            
            updated_content = json.dumps(json_data, indent=2)
            commit_message = f"Sign {doc_type} for @{user} (PR #{pr_number})"
            put_payload = {
                "message": commit_message,
                "content": base64.b64encode(updated_content.encode("utf-8")).decode("utf-8"),
                "sha": data["sha"] # Vital: Must use SHA from *this* fetch
            }
            
            response = github_api(url, token, "PUT", put_payload)
            if response:
                return True
            else:
                debug_log(f"⚠️ Write conflict (Attempt {attempt+1}/{max_retries}). Retrying...")
                time.sleep(random.uniform(1, 3)) # Jitter to prevent lockstep

        except Exception as e:
            debug_log(f"❌ Error updating signature file: {e}")
            return False
            
    debug_log("❌ Failed to update signature file after retries.")
    return False
        
def fetch_shared_config(api_root, gh_token):
    """Fetches the 3 mothership config files (allowlist + both license
    catalogs) once. Callers that process many PRs in one run (e.g.
    cla_sweeper.py's sweep loop) should call this once and pass the result
    into every process_single_pr() call via shared_config=, instead of
    letting each PR refetch independently — one of these files is a
    multi-MB blob, and refetching it per PR doesn't scale past a handful
    of open PRs total."""
    # A. Allowlist (Try cla/ -> data/)
    raw_allowlist = fetch_mothership_file(api_root, "cla/allowlist.yml", gh_token)
    if not raw_allowlist:
        raw_allowlist = fetch_mothership_file(api_root, "data/allowlist.yml", gh_token)

    allowlist_repos = []
    allowlist_data = {}
    # False means "we could not read the policy", which is NOT the same as
    # "the policy is empty". Callers use it to fail closed rather than
    # silently enforcing a weaker document than the real allowlist requires.
    allowlist_ok = False

    if raw_allowlist:
        try:
            parsed = yaml.safe_load(raw_allowlist)
            if not isinstance(parsed, dict):
                # safe_load returns None for an empty/comments-only file and a
                # list for a top-level sequence. Assigning either to
                # allowlist_data before the .get() below would destroy the {}
                # default and poison every downstream consumer.
                raise ValueError(
                    f"allowlist must be a mapping, got {type(parsed).__name__}"
                )
            allowlist_data = parsed
            # Handle nesting under 'license_overrides' -> 'repos', falling back
            # to a top-level 'repos' for backwards compatibility.
            #
            # `or {}` rather than a .get() default on both lookups: a key that is
            # PRESENT but null (`license_overrides:` with nothing under it) yields
            # None, and the default only applies when the key is absent. The old
            # `.get("license_overrides", {}).get(...)` therefore raised
            # AttributeError on that file, which the except below swallowed into
            # "enforce CLA everywhere" — the whole allowlist lost to one empty key.
            nested_repos = (allowlist_data.get("license_overrides") or {}).get("repos") or {}
            legacy_repos = allowlist_data.get("repos") or {}
            repos_config = nested_repos or legacy_repos

            # The fallback is unreachable whenever the nested block has entries,
            # so a top-level 'repos' added alongside one silently does nothing.
            # Say so rather than letting someone conclude their entry is live.
            if nested_repos and legacy_repos:
                # `legacy_repos` is whatever YAML produced and may be a list,
                # an int, or a string. sorted() raises TypeError on a list of
                # dicts, and the except below would turn that into "enforce CLA
                # everywhere" — building a diagnostic must never be the thing
                # that discards the policy.
                ignored = sorted(legacy_repos) if isinstance(legacy_repos, dict) else repr(legacy_repos)
                debug_log(
                    "⚠️ Top-level 'repos:' is ignored because license_overrides.repos "
                    "is non-empty. Move those entries under license_overrides.repos; "
                    f"currently ignored: {ignored}"
                )

            if isinstance(repos_config, dict):
                for r_name, r_config in repos_config.items():
                    # One malformed entry must cost that entry, not the file.
                    # `r_config.get(...)` on a null or boolean value raised
                    # AttributeError, which the except below swallowed into
                    # enforcing CLA across every gated repo — org-wide blast
                    # radius from a single missing indent. Skipping instead
                    # leaves this repo on CLA (absence from the DCO-only list
                    # is the strict direction) and keeps the rest intact.
                    if not isinstance(r_config, dict):
                        debug_log(
                            f"⚠️ Ignoring repos[{r_name!r}]: expected a mapping, got "
                            f"{type(r_config).__name__}. That repo stays on CLA."
                        )
                        continue
                    if r_config.get("require_cla") is False:
                        allowlist_repos.append(r_name)

            extra = allowlist_data.get("repositories") or []
            if isinstance(extra, list):
                allowlist_repos.extend(extra)
            else:
                # A bare string here would be iterated character by character.
                debug_log(f"⚠️ 'repositories' must be a list, got {type(extra).__name__}; ignoring.")
            allowlist_ok = True
            debug_log(f"✅ Allowlist loaded via API. Found {len(allowlist_repos)} DCO-only repos.")
        except Exception as e:
            # Reset rather than leave a half-built or poisoned value behind.
            allowlist_data = {}
            allowlist_repos = []
            print(f"::error::Failed to parse cla/allowlist.yml: {e}. "
                  "Enforcing CLA for every repo until this is fixed.")
    else:
        print("::error::Could not fetch cla/allowlist.yml. "
              "Enforcing CLA for every repo until this is fixed.")

    # B. Licenses
    licenses_data = fetch_json_with_fallback(api_root, "data/licenses_all.json", "cla/licenses_all.json", gh_token) or []

    # C. Permissive Names
    permissive_data = fetch_json_with_fallback(api_root, "data/permissive_names.json", "cla/permissive_names.json", gh_token) or []

    return {
        "allowlist_data": allowlist_data,
        "allowlist_repos": allowlist_repos,
        "allowlist_ok": allowlist_ok,
        "licenses_data": licenses_data,
        "permissive_data": permissive_data,
    }


def process_single_pr(pr_number, pr_head_sha, pr_user, repo_full_name, gh_token, base_path, api_root, shared_config=None):
    gh_token = os.environ.get("GH_TOKEN") or gh_token
    debug_log(f"🔍 Checking PR #{pr_number} by @{pr_user}...")

    # 0. Already-Resolved Check
    # Posting a status bumps the PR's updated_at, which can put it right back
    # into the sweeper's lookback window — repeatedly re-confirming an
    # already-successful PR just repaints the same result and pushes
    # updated_at again, looping forever every sweep cycle. A new commit gets
    # a fresh SHA (no prior status), so this only skips true no-op re-checks.
    #
    # Exception: a success we painted while the consent record FAILED to write
    # carries RECORD_PENDING_MARKER in its description. Skipping that would
    # make the failed write permanently unretryable — the status is green, so
    # nothing ever comes back, and the contributor's consent is never durably
    # recorded. Those we deliberately re-process so the write is retried.
    existing_state, existing_desc = get_existing_status(
        api_root, repo_full_name, pr_head_sha, gh_token)
    if existing_state == "success" and not has_pending_record(existing_desc):
        debug_log(f"✅ PR #{pr_number} already has a successful '{STATUS_CONTEXT}' status on {pr_head_sha[:7]}. Skipping re-check.")
        return
    if existing_state == "success":
        debug_log(f"🔁 PR #{pr_number} is green but its consent record never landed "
                  f"({existing_desc!r}). Re-processing to retry the write.")

    # 1. Bot Check
    if pr_user in BOT_ALLOWLIST or pr_user.endswith("[bot]"):
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", "Bot Bypass", "", gh_token)
        return

    # 2. Org Member/Owner Check
    org_name = repo_full_name.split("/")[0]
    if is_org_member(api_root, org_name, pr_user, gh_token):
        debug_log(f"🛡️ User @{pr_user} is an Organization Member. Skipping check.")
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", "Member Bypass", "", gh_token)
        return

    # --- 1. FETCH CONFIGURATION ---
    # Reuse the caller's pre-fetched config if provided (e.g. a sweep run
    # fetching once for many PRs); otherwise fetch fresh — correct either
    # way, since required-compliance.yml only ever processes one PR per run.
    config = shared_config or fetch_shared_config(api_root, gh_token)
    allowlist_data = config["allowlist_data"]
    allowlist_repos = config["allowlist_repos"]
    licenses_data = config["licenses_data"]
    permissive_data = config["permissive_data"]

    # --- 2. DETERMINE POLICY ---
    is_strict = True
    try:
        is_strict = requires_cla.requires_CLA(
            repo_full_name, 
            token=gh_token, 
            licenses_data=licenses_data,
            permissive_data=permissive_data,
            allowlist_data=allowlist_data
        )
    except Exception as e:
        debug_log(f"⚠️ Logic Module Error: {e}. Defaulting to STRICT mode.")
        is_strict = True
        
    # An unreadable allowlist is not an empty one. Without its overrides a
    # non-permissive licence can look permissive — Broadcom Source Available
    # is listed as permissive in the base tables and is held at CLA only by
    # the override — so continuing would silently downgrade repos to DCO.
    # Default to strict instead, matching the Logic Module Error path above.
    # .get() default is True so a hand-built shared_config (tests, callers
    # that supply their own data) is treated as deliberate, not as a failure.
    if not config.get("allowlist_ok", True):
        debug_log("⚠️ Allowlist unavailable. Defaulting to STRICT mode.")
        is_strict = True
        allowlist_repos = []

    # Allowlist Override
    if repo_full_name in allowlist_repos:
        debug_log(f"ℹ️ Repo {repo_full_name} is in Allowlist. Enforcing DCO only.")
        is_strict = False

    debug_log(f"🧐 POLICY DECISION for {repo_full_name}: {'CLA' if is_strict else 'DCO'}")
    doc_type = "CLA" if is_strict else "DCO"
    
    # --- 3. CHECK SIGNATURES (Registry Check) ---
    has_signed_json = False
    sig_file_path = f"signatures/{doc_type.lower()}.json"
    raw_signatures = fetch_mothership_file(api_root, sig_file_path, gh_token)
    
    if raw_signatures:
        try:
            data = json.loads(raw_signatures)
            contributors = data.get("signedContributors", []) if isinstance(data, dict) else data
            for c in contributors:
                if isinstance(c, dict):
                    if c.get("name", "").lower() == pr_user.lower(): has_signed_json = True; break
                elif isinstance(c, str):
                    if c.lower() == pr_user.lower(): has_signed_json = True; break
        except Exception as e:
            debug_log(f"⚠️ Failed to parse Signatures JSON: {e}")
            
    # 4. Check Comments (Forensics Collection)
    comment_id = None
    signed_type = None
    if not has_signed_json:
        # Returns (ID, document actually signed), or (None, None)
        comment_id, signed_type = check_comments_for_signature(api_root, repo_full_name, pr_number, pr_user, doc_type, gh_token)

    # A sign-off only counts if it is for the document this repo requires.
    has_valid_signature = bool(comment_id) and signed_type == doc_type

    # 5. DCO Commit Check (Optional Override)
    # If using DCO, and not in registry, and no valid sign-off, we check
    # individual commits. If all commits are signed-off, we treat it as
    # compliant. Note this keys off has_valid_signature rather than comment_id:
    # someone who posted the *wrong* document's sentence may still have
    # properly signed-off commits, and shouldn't lose that fallback.
    dco_commits_valid = False
    if doc_type == "DCO" and not has_signed_json and not has_valid_signature:
        dco_commits_valid = check_dco_commits(api_root, repo_full_name, pr_number, gh_token)

    doc_url = os.environ.get("CLA_DOC_URL") if doc_type == "CLA" else os.environ.get("DCO_DOC_URL")

    if has_signed_json:
        debug_log(f"✅ User {pr_user} is COMPLIANT (Found in JSON).")
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", f"{doc_type} Signed", "", gh_token)
        
    elif has_valid_signature:
        debug_log(f"✅ User {pr_user} is COMPLIANT (Signature comment found).")
        # RECORD HYBRID METADATA.
        # The return value is the only signal that the durable consent record
        # actually landed. Discarding it painted the PR green with no record
        # and no way to tell — the signature comment is evidence of intent,
        # but signatures/<doc>.json is the record of record.
        recorded = record_signature(api_root, org_name, doc_type, pr_user, repo_full_name, gh_token, pr_number, pr_head_sha, comment_id)
        if recorded:
            description = f"{doc_type} Signed"
        else:
            description = f"{doc_type} Signed ({RECORD_PENDING_MARKER})"
            debug_log(f"⚠️ Consent record for @{pr_user} did not persist. Painting success "
                      f"with '{RECORD_PENDING_MARKER}' so the next sweep retries the write.")

        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", description, "", gh_token)
        time.sleep(1)
        force_merge_check_refresh(api_root, repo_full_name, pr_number, gh_token)

    elif dco_commits_valid:
        debug_log(f"✅ User {pr_user} is COMPLIANT (DCO Sign-off on commits).")
        set_commit_status(api_root, repo_full_name, pr_head_sha, "success", f"{doc_type} Signed", "", gh_token)

    else:
        # Say which document was posted when the author signed the wrong one —
        # otherwise a good-faith contributor sees an unchanged failure and has
        # no idea the text they pasted was for the other document.
        if signed_type and signed_type != doc_type:
            debug_log(f"❌ User {pr_user} posted the {signed_type} sentence, but this repo requires the {doc_type}.")
            description = f"{doc_type} Missing ({signed_type} text posted)"
        else:
            debug_log(f"❌ User {pr_user} is NOT compliant.")
            description = f"{doc_type} Missing"
        set_commit_status(api_root, repo_full_name, pr_head_sha, "failure", description, doc_url or "", gh_token)
        formatted_message = INSTRUCTION_MESSAGE.format(user=pr_user, doc_type=doc_type, url=doc_url or "#")
        post_pr_comment(api_root, repo_full_name, pr_number, formatted_message, gh_token)

def main():
    debug_log("--- STARTING COMPLIANCE ENGINE (EVENT MODE) ---")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_path = os.path.dirname(script_dir)
    
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    repo_full_name = os.environ.get("GITHUB_REPOSITORY")
    gh_token = os.environ.get("GITHUB_TOKEN")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    if event_path and os.path.exists(event_path):
        with open(event_path, 'r') as f:
            event = json.load(f)
            pr_data = event.get("pull_request", {})
            pr_number = pr_data.get("number")
            pr_head_sha = pr_data.get("head", {}).get("sha", "")
            pr_user = pr_data.get("user", {}).get("login")
            
            if pr_number:
                process_single_pr(pr_number, pr_head_sha, pr_user, repo_full_name, gh_token, base_path, api_root)

if __name__ == "__main__":
    ensure_valid_token()
    main()
    
