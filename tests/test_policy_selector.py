"""Regression tests for the CLA/DCO compliance engine.

Run from the repo root:

    python -m unittest discover tests

Why these tests exist: `policy_selector.py` and `cla_sweeper.py` run in
production against every gated repo in the org, on a 5-minute cron, with both
workflows checking the scripts out at `ref: main`. There is no staging
environment, so until now the only verification available was a live
`workflow_dispatch` against real PRs. These tests cover the parts that can be
checked deterministically, so a live run only has to confirm the things that
genuinely need real GitHub semantics.

These live in `tests/` rather than `scripts/tests/` on purpose: both
production workflows sparse-checkout the whole `scripts` directory, so
anything under it gets downloaded onto the runner on every sweep. Keeping
the tests out means production pulls exactly what it did before.

Test seams (see the import block below for why the env setup comes first):

  * Almost every HTTP call in `policy_selector` funnels through `github_api`
    and `github_api_paginated`, so faking those two covers most of the module.
  * `is_org_member` is the exception — it builds its own `urllib.request` call
    instead of going through `github_api`, so it has to be stubbed separately.
  * `process_single_pr` accepts `shared_config=`, which lets a test supply the
    allowlist/license data directly instead of fetching the multi-MB catalog.
"""
import json
import os
import re
import sys
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

# --- Import setup. Must happen before `import policy_selector`. ---
#
# Three import-time side effects to neutralise:
#
# 1. `policy_selector` calls `ensure_valid_token()` at module level. With
#    CLA_APP_ID / CLA_APP_PRIVATE_KEY absent it warns and returns without
#    making any network call, which is what we want in a test process.
# 2. `license_detector` (reached via `requires_cla`) mkdirs CACHE_DIR at import,
#    resolved against the *current working directory* — so without this it
#    litters a `.github/tools/.cache/` into wherever the tests were run from.
# 3. `cla_auth` shells out to `pip install` at import if fewer than three of
#    jwt/cryptography/requests are importable. Nothing we can do from here
#    except require them; the CI workflow installs them explicitly.
for _var in ("CLA_APP_ID", "CLA_APP_PRIVATE_KEY"):
    os.environ.pop(_var, None)
_CACHE_TMP = tempfile.mkdtemp(prefix="cla-test-cache-")
os.environ["CACHE_DIR"] = _CACHE_TMP

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "scripts"))

import policy_selector  # noqa: E402

# policy_selector wraps this import in try/except and substitutes a stub, so a
# missing optional dep (aiohttp, rapidfuzz) degrades rather than breaking. Match
# that: an unguarded import here turns one absent dep into a collection error
# that erases the whole suite instead of skipping the tests that need it.
try:
    import requires_cla  # noqa: E402
except Exception:  # pragma: no cover - exercised only on a degraded runner
    requires_cla = None

# cla_sweeper imports policy_selector, so it must come after the env setup
# above. Guarded for the same reason requires_cla is.
try:
    import cla_sweeper  # noqa: E402
except Exception:  # pragma: no cover
    cla_sweeper = None


SIGNED_SUFFIX = "for this and all future contributions"


def signature_body(doc_type, suffix=True):
    """The exact string the bot instructs contributors to post."""
    body = "I have read the {d} Document and I hereby sign the {d}".format(d=doc_type)
    if suffix:
        body += " " + SIGNED_SUFFIX
    return body + "."


def comment(body, login="contributor", user_type="User", comment_id=1):
    return {"body": body, "user": {"login": login, "type": user_type}, "id": comment_id}


def instruction_comment(doc_type="CLA", comment_id=999):
    """A copy of what `post_pr_comment` actually posts, so dedup tests match
    on real text rather than a hand-written approximation."""
    body = policy_selector.INSTRUCTION_MESSAGE.format(
        user="contributor", doc_type=doc_type, url="https://example.invalid/doc"
    )
    return comment(body, login="legal-compliance-bot[bot]", user_type="Bot", comment_id=comment_id)


class FakeGitHub(object):
    """Routes `github_api` / `github_api_paginated` calls by URL substring.

    Records every call so tests can assert on writes — the thing we most need
    to be sure about is that the engine does not post comments or repaint
    statuses when it shouldn't.
    """

    def __init__(self, routes=None, paginated_routes=None):
        self.routes = routes or {}
        self.paginated_routes = paginated_routes or {}
        self.calls = []

    def _match(self, table, url):
        for fragment, value in table.items():
            if fragment in url:
                return value
        return None

    def github_api(self, url, token, method="GET", data=None, _retry_on_rate_limit=True):
        self.calls.append((method, url, data))
        return self._match(self.routes, url)

    def github_api_paginated(self, url, token):
        self.calls.append(("GET-paginated", url, None))
        return self._match(self.paginated_routes, url) or []

    # --- assertion helpers ---

    def writes(self):
        return [c for c in self.calls if c[0] in ("POST", "PUT", "PATCH", "DELETE")]

    def posted_comments(self):
        return [c for c in self.calls if c[0] == "POST" and "/issues/" in c[1] and c[1].endswith("/comments")]

    def statuses(self):
        out = []
        for method, url, data in self.calls:
            if method == "POST" and "/statuses/" in url:
                out.append(data)
        return out


class PolicySelectorTestCase(unittest.TestCase):
    """Installs the fake and restores the real functions afterwards."""

    def install(self, routes=None, paginated_routes=None):
        fake = FakeGitHub(routes, paginated_routes)
        self._saved = (policy_selector.github_api, policy_selector.github_api_paginated)
        policy_selector.github_api = fake.github_api
        policy_selector.github_api_paginated = fake.github_api_paginated
        self.addCleanup(self._restore)
        return fake

    def _restore(self):
        policy_selector.github_api, policy_selector.github_api_paginated = self._saved


# ---------------------------------------------------------------------------
# check_comments_for_signature
# ---------------------------------------------------------------------------
class TestCheckCommentsForSignature(PolicySelectorTestCase):
    def call(self, comments, user="contributor", doc_type="CLA"):
        fake = self.install(paginated_routes={"/issues/5/comments": comments})
        result = policy_selector.check_comments_for_signature(
            "https://api.invalid", "vmware/repo", 5, user, doc_type, "tok"
        )
        return result, fake

    def test_exact_signature_matches(self):
        result, _ = self.call([comment(signature_body("CLA"), comment_id=42)])
        self.assertEqual(result, (42, "CLA"))

    def test_signature_without_suffix_is_rejected(self):
        # The phrase alone is not a signature; the "and all future
        # contributions" suffix is what makes it a standing warranty.
        result, _ = self.call([comment(signature_body("CLA", suffix=False))])
        self.assertEqual(result, (None, None))

    def test_comment_from_another_user_is_ignored(self):
        result, _ = self.call([comment(signature_body("CLA"), login="someone-else")])
        self.assertEqual(result, (None, None))

    def test_login_match_is_case_insensitive(self):
        result, _ = self.call(
            [comment(signature_body("CLA"), login="ConTributor", comment_id=7)], user="contributor"
        )
        self.assertEqual(result, (7, "CLA"))

    def test_non_breaking_spaces_are_normalised(self):
        # Copy-pasting the phrase out of a rendered web page can bring
        # U+00A0 along with it.
        body = signature_body("CLA").replace(" ", "\xa0")
        result, _ = self.call([comment(body, comment_id=11)])
        self.assertEqual(result, (11, "CLA"))

    def test_signature_is_found_beyond_the_first_page(self):
        # This function paginates, so a signature buried under a long
        # discussion must still register.
        comments = [comment("just a normal comment", comment_id=i) for i in range(60)]
        comments.append(comment(signature_body("CLA"), comment_id=12345))
        result, _ = self.call(comments)
        self.assertEqual(result, (12345, "CLA"))

    def test_reaction_is_added_to_the_signing_comment(self):
        _, fake = self.call([comment(signature_body("CLA"), comment_id=42)])
        reactions = [c for c in fake.calls if c[0] == "POST" and "/reactions" in c[1]]
        self.assertEqual(len(reactions), 1)
        self.assertEqual(reactions[0][2], {"content": "rocket"})

    def test_no_comments_returns_none(self):
        result, fake = self.call([])
        self.assertEqual(result, (None, None))
        self.assertEqual(fake.writes(), [])

    def test_signature_in_a_code_fence_still_counts(self):
        # The instruction comment shows the sentence inside a ```text fence
        # and says "copy and paste the exact line below", so a contributor who
        # brings the fence markers along is signing in good faith.
        body = "```text\n" + signature_body("CLA") + "\n```"
        result, _ = self.call([comment(body, comment_id=21)])
        self.assertEqual(result, (21, "CLA"))

    def test_signature_with_surrounding_chat_still_counts(self):
        body = signature_body("CLA") + "\n\nThanks for the quick review!"
        result, _ = self.call([comment(body, comment_id=22)])
        self.assertEqual(result, (22, "CLA"))


# ---------------------------------------------------------------------------
# Signature validation: reproducing the instructions is not signing
# ---------------------------------------------------------------------------
class TestSignatureIsNotManufacturedFromAQuote(PolicySelectorTestCase):
    """The instruction comment contains the signature sentence verbatim, so
    matching on the sentence alone let a contributor pass the gate — and get a
    durable consent record written — just by quoting the bot. Both vectors
    below were confirmed against the real matcher before being fixed."""

    def call(self, body, doc_type="CLA"):
        self.install(paginated_routes={
            "/issues/5/comments": [comment(body, comment_id=99)]
        })
        return policy_selector.check_comments_for_signature(
            "https://api.invalid", "vmware/repo", 5, "contributor", doc_type, "tok"
        )

    def _bot_message(self, doc_type="CLA"):
        return policy_selector.INSTRUCTION_MESSAGE.format(
            user="contributor", doc_type=doc_type, url="https://example.invalid/doc"
        )

    def test_quote_reply_to_the_bot_is_not_a_signature(self):
        # GitHub's "Quote reply" button prefixes every line with "> ".
        quoted = "\n".join("> " + ln for ln in self._bot_message().splitlines())
        self.assertEqual(self.call(quoted + "\n\nwhat do I do here?"), (None, None))

    def test_verbatim_paste_of_the_instructions_is_not_a_signature(self):
        self.assertEqual(self.call(self._bot_message()), (None, None))

    def test_quoted_signature_sentence_alone_is_not_a_signature(self):
        self.assertEqual(self.call("> " + signature_body("CLA")), (None, None))

    def test_instruction_markers_really_are_in_the_message(self):
        # The rejection above keys off these markers. If the instruction
        # message is ever reworded without updating them, the bypass silently
        # reopens — so fail here instead.
        msg = self._bot_message()
        for marker in policy_selector.INSTRUCTION_MARKERS:
            self.assertIn(marker, msg)

    def test_a_genuine_signature_quoting_nothing_is_unaffected(self):
        self.assertEqual(self.call(signature_body("CLA")), (99, "CLA"))


# ---------------------------------------------------------------------------
# Signature validation: the document signed must be the one required
# ---------------------------------------------------------------------------
class TestDocTypeMustMatch(PolicySelectorTestCase):
    def call(self, body, doc_type):
        fake = self.install(paginated_routes={
            "/issues/5/comments": [comment(body, comment_id=31)]
        })
        result = policy_selector.check_comments_for_signature(
            "https://api.invalid", "vmware/repo", 5, "contributor", doc_type, "tok"
        )
        return result, fake

    def test_cla_repo_cla_sentence(self):
        result, _ = self.call(signature_body("CLA"), "CLA")
        self.assertEqual(result, (31, "CLA"))

    def test_dco_repo_dco_sentence(self):
        result, _ = self.call(signature_body("DCO"), "DCO")
        self.assertEqual(result, (31, "DCO"))

    def test_cla_repo_dco_sentence_reports_the_mismatch(self):
        # Previously this passed the gate and wrote a CLA consent record for
        # someone who only ever agreed to the DCO text.
        result, _ = self.call(signature_body("DCO"), "CLA")
        self.assertEqual(result, (31, "DCO"))

    def test_no_rocket_reaction_on_a_mismatched_document(self):
        # A 🚀 reads as "accepted" and would contradict the failure status.
        _, fake = self.call(signature_body("DCO"), "CLA")
        self.assertEqual([c for c in fake.calls if "/reactions" in c[1]], [])

    def test_both_sentences_present_credits_the_required_one(self):
        body = signature_body("DCO") + "\n\n" + signature_body("CLA")
        result, _ = self.call(body, "CLA")
        self.assertEqual(result, (31, "CLA"))


# ---------------------------------------------------------------------------
# post_pr_comment
# ---------------------------------------------------------------------------
class TestPostPrComment(PolicySelectorTestCase):
    def call(self, existing):
        fake = self.install(
            routes={"/issues/5/comments": existing},
            paginated_routes={"/issues/5/comments": existing},
        )
        policy_selector.post_pr_comment(
            "https://api.invalid", "vmware/repo", 5, "the instruction message", "tok"
        )
        return fake

    def test_posts_when_no_prior_instruction_comment(self):
        fake = self.call([comment("unrelated chatter")])
        self.assertEqual(len(fake.posted_comments()), 1)

    def test_does_not_repost_when_instruction_comment_already_present(self):
        fake = self.call([instruction_comment()])
        self.assertEqual(fake.posted_comments(), [])

    def test_no_pr_number_is_a_no_op(self):
        fake = self.install()
        policy_selector.post_pr_comment("https://api.invalid", "vmware/repo", None, "msg", "tok")
        self.assertEqual(fake.calls, [])


# ---------------------------------------------------------------------------
# get_existing_status_state  (protects the PR #67 short-circuit)
# ---------------------------------------------------------------------------
class TestGetExistingStatusState(PolicySelectorTestCase):
    def call(self, payload):
        fake = self.install(routes={"/commits/abc123/status": payload})
        return policy_selector.get_existing_status(
            "https://api.invalid", "vmware/repo", "abc123", "tok"
        ), fake

    def test_returns_our_context_state(self):
        (state, _desc), _ = self.call({"statuses": [{"context": policy_selector.STATUS_CONTEXT, "state": "success"}]})
        self.assertEqual(state, "success")

    def test_ignores_other_contexts(self):
        (state, _desc), _ = self.call({"statuses": [{"context": "Some Other CI", "state": "failure"}]})
        self.assertIsNone(state)

    def test_picks_our_context_out_of_a_crowd(self):
        (state, _desc), _ = self.call({"statuses": [
            {"context": "lint", "state": "success"},
            {"context": policy_selector.STATUS_CONTEXT, "state": "failure"},
            {"context": "build", "state": "success"},
        ]})
        self.assertEqual(state, "failure")

    def test_no_statuses_returns_none(self):
        (state, _desc), _ = self.call({"statuses": []})
        self.assertIsNone(state)

    def test_api_failure_returns_none(self):
        (state, _desc), _ = self.call(None)
        self.assertIsNone(state)


# ---------------------------------------------------------------------------
# check_dco_commits
# ---------------------------------------------------------------------------
class TestCheckDcoCommits(PolicySelectorTestCase):
    def call(self, commits):
        self.install(paginated_routes={"/pulls/5/commits": commits})
        return policy_selector.check_dco_commits("https://api.invalid", "vmware/repo", 5, "tok")

    def _commit(self, message, sha="abcdef1234"):
        return {"sha": sha, "commit": {"message": message}}

    def test_all_commits_signed_off(self):
        self.assertTrue(self.call([
            self._commit("fix: thing\n\nSigned-off-by: A <a@example.com>"),
            self._commit("fix: other\n\nSigned-off-by: A <a@example.com>"),
        ]))

    def test_one_unsigned_commit_fails_the_whole_pr(self):
        self.assertFalse(self.call([
            self._commit("fix: thing\n\nSigned-off-by: A <a@example.com>"),
            self._commit("fix: forgot the sign-off"),
        ]))

    def test_no_commits_is_not_compliant(self):
        self.assertFalse(self.call([]))


# ---------------------------------------------------------------------------
# process_single_pr  — the decision table
# ---------------------------------------------------------------------------
class ProcessSinglePrHarness(PolicySelectorTestCase):
    """Fixtures for driving process_single_pr. Carries no tests of its own:
    subclassing a populated TestCase re-runs every parent test under the
    child's name, which inflated the suite by 34 duplicates and 9 seconds
    the first time this was written."""

    SHARED_CONFIG = {
        "allowlist_data": {},
        "allowlist_repos": [],
        "licenses_data": [],
        "permissive_data": [],
    }

    def setUp(self):
        # `requires_cla.requires_CLA` always opens a network session, so pin the
        # policy decision explicitly rather than letting it reach out.
        self._saved_requires = policy_selector.requires_cla.requires_CLA
        self._saved_is_member = policy_selector.is_org_member
        policy_selector.requires_cla.requires_CLA = lambda *a, **k: True
        # `is_org_member` does not route through `github_api` — it builds its own
        # urllib request — so it needs its own stub.
        policy_selector.is_org_member = lambda *a, **k: False
        # The compliant path sleeps a real second before force_merge_check_refresh,
        # and record_signature's retry loop sleeps 1-3s per attempt. Neither
        # affects any assertion here, and paying them per test made the suite
        # take 9 seconds instead of 2.
        self._saved_sleep = policy_selector.time.sleep
        policy_selector.time.sleep = lambda *_a, **_k: None
        self.addCleanup(self._restore_helpers)

    def _restore_helpers(self):
        policy_selector.requires_cla.requires_CLA = self._saved_requires
        policy_selector.is_org_member = self._saved_is_member
        policy_selector.time.sleep = self._saved_sleep

    def run_pr(self, routes=None, paginated_routes=None, user="contributor", config=None):
        fake = self.install(routes or {}, paginated_routes or {})
        policy_selector.process_single_pr(
            5, "abc123", user, "vmware/repo", "tok", "/tmp", "https://api.invalid",
            shared_config=self.SHARED_CONFIG if config is None else config,
        )
        return fake

    def _status(self, state, description=None):
        return {"statuses": [{"context": policy_selector.STATUS_CONTEXT,
                              "state": state, "description": description}]}

    def _registry(self, names):
        import base64
        payload = json.dumps({"signedContributors": [{"name": n} for n in names]})
        # "sha" matters: without it record_signature bails at "failed to fetch
        # signature file" before attempting a write, which silently makes any
        # "no consent record written" assertion vacuous.
        return {"content": base64.b64encode(payload.encode()).decode(), "sha": "filesha"}

    def _writable_registry_routes(self):
        """Routes that let record_signature get all the way to its PUT, so a
        test asserting that no record was written can actually fail."""
        return {
            "/users/": {"id": 4242},
            "/contents/signatures/cla.json": self._registry([]),
            "/contents/signatures/dco.json": self._registry([]),
        }


class TestProcessSinglePr(ProcessSinglePrHarness):
    def test_already_successful_status_short_circuits_with_no_writes(self):
        # This is the PR #67 fix. Repainting an already-green PR bumps its
        # updated_at, which puts it back in the sweeper's lookback window.
        fake = self.run_pr(routes={"/commits/abc123/status": self._status("success")})
        self.assertEqual(fake.writes(), [])

    def test_failure_status_is_reprocessed(self):
        fake = self.run_pr(
            routes={"/commits/abc123/status": self._status("failure")},
            paginated_routes={"/issues/5/comments": []},
        )
        self.assertTrue(len(fake.writes()) > 0)

    def test_pending_status_is_reprocessed(self):
        fake = self.run_pr(
            routes={"/commits/abc123/status": self._status("pending")},
            paginated_routes={"/issues/5/comments": []},
        )
        self.assertTrue(len(fake.writes()) > 0)

    def test_bot_author_is_bypassed(self):
        fake = self.run_pr(user="dependabot[bot]")
        self.assertEqual([s["state"] for s in fake.statuses()], ["success"])
        self.assertEqual(fake.statuses()[0]["description"], "Bot Bypass")

    def test_unlisted_bot_suffix_is_also_bypassed(self):
        fake = self.run_pr(user="some-new-app[bot]")
        self.assertEqual(fake.statuses()[0]["description"], "Bot Bypass")

    def test_org_member_is_bypassed(self):
        policy_selector.is_org_member = lambda *a, **k: True
        fake = self.run_pr()
        self.assertEqual(fake.statuses()[0]["description"], "Member Bypass")

    def test_user_in_registry_passes_without_checking_comments(self):
        fake = self.run_pr(routes={"/contents/signatures/cla.json": self._registry(["contributor"])})
        self.assertEqual([s["state"] for s in fake.statuses()], ["success"])
        self.assertEqual(fake.statuses()[0]["description"], "CLA Signed")

    def test_registry_match_is_case_insensitive(self):
        fake = self.run_pr(routes={"/contents/signatures/cla.json": self._registry(["ConTributor"])})
        self.assertEqual([s["state"] for s in fake.statuses()], ["success"])

    def test_unsigned_user_gets_failure_and_instructions(self):
        fake = self.run_pr(paginated_routes={"/issues/5/comments": []})
        self.assertEqual([s["state"] for s in fake.statuses()], ["failure"])
        self.assertEqual(fake.statuses()[0]["description"], "CLA Missing")
        self.assertEqual(len(fake.posted_comments()), 1)

    def test_dco_policy_accepts_signed_off_commits(self):
        policy_selector.requires_cla.requires_CLA = lambda *a, **k: False
        fake = self.run_pr(paginated_routes={
            "/issues/5/comments": [],
            "/pulls/5/commits": [{"sha": "a" * 10, "commit": {"message": "x\n\nSigned-off-by: A <a@b.c>"}}],
        })
        self.assertEqual([s["state"] for s in fake.statuses()], ["success"])
        self.assertEqual(fake.statuses()[0]["description"], "DCO Signed")

    def test_unreadable_allowlist_forces_cla_not_dco(self):
        """The behaviour that matters. requires_CLA says permissive (DCO) and
        the repo is in allowlist_repos (DCO), but the allowlist could not be
        read — so neither signal is trustworthy and the gate must ask for the
        stronger document rather than the weaker one."""
        policy_selector.requires_cla.requires_CLA = lambda *a, **k: False
        fake = self.run_pr(
            paginated_routes={"/issues/5/comments": [], "/pulls/5/commits": []},
            config=dict(self.SHARED_CONFIG, allowlist_ok=False,
                        allowlist_repos=["vmware/repo"]))
        self.assertEqual(fake.statuses()[0]["description"], "CLA Missing")

    def test_fail_closed_guard_does_not_corrupt_a_shared_config(self):
        """cla_sweeper fetches the config ONCE and threads the same dict
        through every PR in the sweep. The guard clears allowlist_repos, so if
        it mutated the list in place instead of rebinding the local name, the
        first PR to hit it would strip the DCO downgrade from every repo
        processed afterwards in that sweep.
        """
        shared = dict(self.SHARED_CONFIG, allowlist_ok=False,
                      allowlist_repos=["vmware/repo", "vmware/other"])
        before = list(shared["allowlist_repos"])
        policy_selector.requires_cla.requires_CLA = lambda *a, **k: False
        self.run_pr(paginated_routes={"/issues/5/comments": [], "/pulls/5/commits": []},
                    config=shared)
        self.assertEqual(shared["allowlist_repos"], before,
                         "the guard must rebind, not mutate the caller's list")

    def test_hand_built_config_without_the_flag_is_treated_as_readable(self):
        """Back-compat: a caller supplying its own data deliberately (tests,
        license_report.py) has no allowlist_ok key and must not be forced
        strict by its absence."""
        policy_selector.requires_cla.requires_CLA = lambda *a, **k: False
        fake = self.run_pr(
            paginated_routes={"/issues/5/comments": [], "/pulls/5/commits": []},
            config=dict(self.SHARED_CONFIG))  # no allowlist_ok key at all
        self.assertEqual(fake.statuses()[0]["description"], "DCO Missing")

    def test_allowlisted_repo_is_downgraded_to_dco(self):
        config = dict(self.SHARED_CONFIG, allowlist_repos=["vmware/repo"])
        fake = self.run_pr(paginated_routes={"/issues/5/comments": [], "/pulls/5/commits": []}, config=config)
        self.assertEqual(fake.statuses()[0]["description"], "DCO Missing")

    def test_correct_sentence_passes_and_is_recorded(self):
        # Writable registry routes matter: without them record_signature fails,
        # and before the record-pending marker existed this test asserted the
        # clean description and passed anyway — the failed write was invisible
        # even here. That is the defect this suite now covers.
        fake = self.run_pr(routes=self._writable_registry_routes(), paginated_routes={
            "/issues/5/comments": [comment(signature_body("CLA"), comment_id=61)],
        })
        self.assertEqual([s["state"] for s in fake.statuses()], ["success"])
        self.assertEqual(fake.statuses()[0]["description"], "CLA Signed")

    def test_wrong_document_sentence_fails_with_a_diagnostic_description(self):
        fake = self.run_pr(paginated_routes={
            "/issues/5/comments": [comment(signature_body("DCO"), comment_id=62)],
        })
        self.assertEqual([s["state"] for s in fake.statuses()], ["failure"])
        self.assertEqual(fake.statuses()[0]["description"], "CLA Missing (DCO text posted)")

    def test_correct_sentence_does_write_a_consent_record(self):
        # Positive control for the test below. Without this, "no record
        # written" could pass simply because the fake never made a write
        # possible — which is exactly how that assertion was once vacuous.
        fake = self.run_pr(
            routes=self._writable_registry_routes(),
            paginated_routes={"/issues/5/comments": [comment(signature_body("CLA"), comment_id=61)]},
        )
        puts = [c for c in fake.calls if c[0] == "PUT" and "signatures/" in c[1]]
        self.assertEqual(len(puts), 1)

    def test_wrong_document_sentence_writes_no_consent_record(self):
        fake = self.run_pr(
            routes=self._writable_registry_routes(),
            paginated_routes={"/issues/5/comments": [comment(signature_body("DCO"), comment_id=62)]},
        )
        puts = [c for c in fake.calls if c[0] == "PUT" and "signatures/" in c[1]]
        self.assertEqual(puts, [])

    def test_quoting_the_bot_does_not_pass_the_gate(self):
        bot_msg = policy_selector.INSTRUCTION_MESSAGE.format(
            user="contributor", doc_type="CLA", url="https://example.invalid/doc"
        )
        quoted = "\n".join("> " + ln for ln in bot_msg.splitlines())
        fake = self.run_pr(paginated_routes={
            "/issues/5/comments": [comment(quoted, comment_id=63)],
        })
        self.assertEqual([s["state"] for s in fake.statuses()], ["failure"])
        self.assertEqual([c for c in fake.calls if c[0] == "PUT" and "signatures/" in c[1]], [])

    def test_wrong_sentence_does_not_cost_a_dco_repo_its_commit_fallback(self):
        # Keying the fallback off comment_id rather than a *valid* signature
        # would silently strand someone who pasted the CLA sentence on a DCO
        # repo but whose commits are properly signed off.
        policy_selector.requires_cla.requires_CLA = lambda *a, **k: False
        fake = self.run_pr(paginated_routes={
            "/issues/5/comments": [comment(signature_body("CLA"), comment_id=64)],
            "/pulls/5/commits": [{"sha": "a" * 10, "commit": {"message": "x\n\nSigned-off-by: A <a@b.c>"}}],
        })
        self.assertEqual([s["state"] for s in fake.statuses()], ["success"])
        self.assertEqual(fake.statuses()[0]["description"], "DCO Signed")


# ---------------------------------------------------------------------------
# record_signature
# ---------------------------------------------------------------------------
class TestRecordSignature(PolicySelectorTestCase):
    def _existing(self, contributors):
        import base64
        payload = json.dumps({"signedContributors": contributors})
        return {"content": base64.b64encode(payload.encode()).decode(), "sha": "filesha"}

    def call(self, contributors, user="contributor", user_id=4242, put_fails=False):
        """`put_fails` simulates the contended-write case: `github_api` returns
        None for the PUT, which is what record_signature's retry loop treats as
        a write conflict."""
        fake = FakeGitHub({
            "/users/": {"id": user_id},
            "/contents/signatures/cla.json": self._existing(contributors),
        })
        get_only = fake.github_api

        def routed(url, token, method="GET", data=None, _retry_on_rate_limit=True):
            if method == "PUT":
                fake.calls.append((method, url, data))
                return None if put_fails else {"commit": {"sha": "newsha"}}
            return get_only(url, token, method, data)

        self._saved = (policy_selector.github_api, policy_selector.github_api_paginated)
        policy_selector.github_api = routed
        policy_selector.github_api_paginated = fake.github_api_paginated
        self.addCleanup(self._restore)

        # The retry loop sleeps 1-3s with jitter between attempts; skip the wait.
        saved_sleep = policy_selector.time.sleep
        policy_selector.time.sleep = lambda _s: None
        self.addCleanup(lambda: setattr(policy_selector.time, "sleep", saved_sleep))

        ok = policy_selector.record_signature(
            "https://api.invalid", "vmware", "CLA", user, "vmware/repo", "tok", 5, "abc123", 77
        )
        return ok, fake

    def test_already_recorded_by_name_is_a_no_op(self):
        ok, fake = self.call([{"name": "contributor", "id": 1}])
        self.assertTrue(ok)
        self.assertEqual([c for c in fake.calls if c[0] == "PUT"], [])

    def test_name_dedup_is_case_insensitive(self):
        ok, fake = self.call([{"name": "ConTributor", "id": 1}])
        self.assertTrue(ok)
        self.assertEqual([c for c in fake.calls if c[0] == "PUT"], [])

    def test_already_recorded_by_id_is_a_no_op(self):
        # Covers a contributor who renamed their GitHub account.
        ok, fake = self.call([{"name": "old-username", "id": 4242}])
        self.assertTrue(ok)
        self.assertEqual([c for c in fake.calls if c[0] == "PUT"], [])

    def test_new_signature_is_appended_with_full_provenance(self):
        ok, fake = self.call([])
        self.assertTrue(ok)
        puts = [c for c in fake.calls if c[0] == "PUT"]
        self.assertEqual(len(puts), 1)
        import base64
        written = json.loads(base64.b64decode(puts[0][2]["content"]).decode())
        entry = written["signedContributors"][-1]
        self.assertEqual(entry["name"], "contributor")
        self.assertEqual(entry["id"], 4242)
        self.assertEqual(entry["repo"], "vmware/repo")
        self.assertEqual(entry["pr_number"], 5)
        self.assertEqual(entry["head_sha"], "abc123")
        self.assertEqual(entry["comment_id"], 77)
        # The file's own sha must come from the same fetch, or the write races.
        self.assertEqual(puts[0][2]["sha"], "filesha")

    def test_write_failure_is_reported_to_the_caller(self):
        # The return value is what tells process_single_pr whether the consent
        # record actually landed.
        ok, fake = self.call([], put_fails=True)
        self.assertFalse(ok)
        # Three attempts, per the retry loop's max_retries.
        self.assertEqual(len([c for c in fake.calls if c[0] == "PUT"]), 3)


# ---------------------------------------------------------------------------
# fetch_shared_config  (protects the PR #66 per-sweep caching contract)
# ---------------------------------------------------------------------------
class TestFetchSharedConfig(PolicySelectorTestCase):
    def test_returns_all_keys_process_single_pr_indexes(self):
        # process_single_pr indexes these directly, so a missing key is a
        # KeyError mid-sweep rather than a soft failure.
        self.install()
        config = policy_selector.fetch_shared_config("https://api.invalid", "tok")
        self.assertEqual(
            sorted(config.keys()),
            ["allowlist_data", "allowlist_ok", "allowlist_repos",
             "licenses_data", "permissive_data"],
        )

    def test_missing_config_degrades_to_empty_rather_than_raising(self):
        self.install()
        config = policy_selector.fetch_shared_config("https://api.invalid", "tok")
        self.assertEqual(config["licenses_data"], [])
        self.assertEqual(config["permissive_data"], [])
        # allowlist_data was previously omitted here — it is the one key that
        # could come back poisoned (None, or a list) rather than empty.
        self.assertEqual(config["allowlist_data"], {})
        self.assertIs(config["allowlist_ok"], False,
                      "an unfetchable allowlist must be reported as not-ok, not as empty")
        self.assertEqual(config["allowlist_repos"], [])


# ---------------------------------------------------------------------------
# Instruction message
# ---------------------------------------------------------------------------
class TestInstructionMessage(unittest.TestCase):
    def test_renders_doc_type_user_and_url(self):
        msg = policy_selector.INSTRUCTION_MESSAGE.format(
            user="alice", doc_type="CLA", url="https://example.invalid/cla"
        )
        self.assertIn("@alice", msg)
        self.assertIn("https://example.invalid/cla", msg)
        # The exact phrase a contributor must post has to appear verbatim,
        # since check_comments_for_signature matches on it.
        self.assertIn(
            "I have read the CLA Document and I hereby sign the CLA for this and all future contributions.",
            msg,
        )

    def test_dedup_markers_are_present(self):
        # post_pr_comment recognises its own previous comment by these two
        # substrings; if the message is reworded without updating that
        # predicate, the bot starts re-posting on every sweep.
        msg = policy_selector.INSTRUCTION_MESSAGE.format(user="a", doc_type="CLA", url="u")
        self.assertIn("I have read the", msg)
        self.assertIn("Sign via Comment", msg)


@unittest.skipIf(requires_cla is None, "requires_cla unavailable (optional dep missing)")
class TestAllowlistFile(unittest.TestCase):
    """Parse the REAL cla/allowlist.yml.

    Every other test in this file monkeypatches `requires_cla.requires_CLA`
    away in setUp, so none of them exercise the shipped file — the suite
    passes whether it is valid, emptied, or absent. That gap let a change to
    this file reach a PR with the full suite green and nothing reading it.

    (Note the seam is the monkeypatch, not `allowlist_data={}`: `_load_allowlist`
    gates on a truthiness check, so an empty dict falls through to the disk
    read and would pick up the real file anyway.)

    Both production workflows fetch this file from `ref: main` with no pinned
    ref, so a malformed version is live org-wide the moment it merges.
    """

    # The only top-level keys any live code reads: `license_overrides` via
    # requires_cla, and `repos`/`repositories` via
    # policy_selector.fetch_shared_config. Asserting a subset rather than
    # denying a list of known-dead names catches keys nobody has thought of —
    # including `temp_exemptions`, the spelling the retired workflow actually
    # read, which an earlier denylist here missed while blocking the inert
    # `temporary_exemptions`.
    READ_BY_LIVE_CODE = {"license_overrides", "repos", "repositories"}

    @classmethod
    def setUpClass(cls):
        import yaml
        # Reuse production's own path constant so moving the file fails loudly
        # here instead of leaving the test reading a stale location.
        cls.path = requires_cla._ALLOWLIST_PATH
        # encoding= matters: _load_allowlist opens utf-8 explicitly, and this
        # file contains non-ASCII. Without it a non-UTF-8 locale raises in
        # setUpClass and silently erases all of these tests from the report.
        cls.data = yaml.safe_load(cls.path.read_text(encoding="utf-8"))

    def mapping(self):
        """Fail fast with a message naming the file, rather than letting a
        non-mapping surface as AttributeError/TypeError in four places."""
        self.assertIsInstance(
            self.data, dict,
            f"{self.path} must parse to a mapping; got {type(self.data).__name__}",
        )
        return self.data

    def test_file_parses_to_a_mapping(self):
        self.mapping()

    def test_only_keys_live_code_reads(self):
        extra = set(self.mapping()) - self.READ_BY_LIVE_CODE
        self.assertEqual(
            extra, set(),
            f"{sorted(extra)} is read by no live code. Enforcement bypasses live in "
            "policy_selector.process_single_pr(); a key here that looks like one "
            "but does nothing is how a departed employee stayed apparently "
            "allowlisted after the workflow honouring it was retired.",
        )

    # Nested keys live code reads, in addition to the top-level ones above:
    # requires_cla._override_requires_cla reads require_cla and allow_dco,
    # fetch_shared_config reads require_cla inside each repo entry.
    NESTED_KEYS_READ_BY_LIVE_CODE = {"require_cla", "allow_dco"}

    # Declared once and used by both the check and its guard below.
    # Duplicating it meant the guard validated a copy, so editing the
    # real pattern would not have tripped it.
    COMMENTED_KEY_RE = re.compile(r"\s*#\s*([a-z][a-z0-9_]*):")

    def test_commented_out_keys_are_also_read_by_live_code(self):
        """The check above sees live keys only, so a dead knob parked in a
        comment is invisible to it.

        Two were: a per-repo `force_spdx` and a top-level `spdx_aliases`, both
        written as ready-to-uncomment examples, neither read by any code. A
        commented example is a promise — someone uncomments it, sees no error,
        and concludes it took effect. That is worse than no documentation,
        because the file itself is the most authoritative-looking source here.

        Matches only `<lowercase_identifier>:` after a `#`, so prose, bullet
        lines, quoted map keys and `owner/repo:` names are all left alone.
        """
        allowed = self.READ_BY_LIVE_CODE | self.NESTED_KEYS_READ_BY_LIVE_CODE
        found = set()
        for line in self.path.read_text(encoding="utf-8").splitlines():
            m = self.COMMENTED_KEY_RE.match(line)
            if m:
                found.add(m.group(1))
        extra = found - allowed
        self.assertEqual(
            extra, set(),
            f"{sorted(extra)} appears as a commented-out key but is read by no "
            "code, so uncommenting it is a silent no-op. Either implement it or "
            "describe it in prose that cannot be mistaken for working config.",
        )

    def test_commented_key_guard_can_actually_see_a_commented_key(self):
        """Guards the guard. The regex above is narrow by design, so a change
        that made it match nothing would leave the test passing vacuously on
        an empty set.
        """
        pattern = self.COMMENTED_KEY_RE
        self.assertEqual(pattern.match("#  allow_dco:").group(1), "allow_dco")
        self.assertEqual(pattern.match("      # force_spdx: \"MIT\"").group(1), "force_spdx")
        self.assertIsNone(pattern.match("#    vmware/docs-site:"),
                          "owner/repo keys must not be treated as config knobs")
        self.assertIsNone(pattern.match("# The left side is what the detector finds"),
                          "prose must not be treated as config")
        self.assertIsNone(pattern.match('#    "LicenseRef-BSA": "x"'),
                          "quoted map values must not be treated as config knobs")
        # And it must still find the real ones in the shipped file.
        live = {m.group(1) for m in
                (pattern.match(l) for l in self.path.read_text(encoding="utf-8").splitlines())
                if m}
        self.assertIn("allow_dco", live,
                      "the shipped file documents a commented allow_dco; if that "
                      "went away, this guard is no longer exercised by real input")

    def test_license_overrides_shaped_as_requires_cla_expects(self):
        overrides = self.mapping().get("license_overrides")
        self.assertIsInstance(overrides, dict)
        self.assertIsInstance(overrides.get("require_cla"), list)

    def test_repo_overrides_shaped_as_policy_selector_expects(self):
        """`license_overrides.repos` decides CLA-vs-DCO for a whole repo, and
        fetch_shared_config swallows a malformed shape into a debug log."""
        repos = (self.mapping().get("license_overrides") or {}).get("repos")
        self.assertIsInstance(repos, dict, "repos must be a mapping, not a list or null")
        for name, cfg in repos.items():
            self.assertIsInstance(cfg, dict, f"repos[{name}] must be a mapping, not null")
            self.assertIsInstance(cfg.get("require_cla"), bool,
                                  f"repos[{name}].require_cla must be a bool")
            self.assertIn("/", name,
                          f"repos[{name}] must be '<owner>/<repo>' — process_single_pr "
                          "compares against the full name, so a bare repo never matches")

    def test_dotgithub_stays_on_dco(self):
        """Pins a deliberate policy decision rather than the file's shape.

        Deleting the repos block, emptying it, dropping this entry, or flipping
        it to true all leave the previous shape-only assertions green while
        silently moving this repo from DCO back to CLA. Changing that is a
        legitimate decision — it just has to be a deliberate one, so it fails
        here first.
        """
        repos = (self.mapping().get("license_overrides") or {}).get("repos") or {}
        self.assertIs(
            repos.get("vmware/.github", {}).get("require_cla"), False,
            "vmware/.github is intentionally on DCO; if that changed on purpose, "
            "update this test in the same commit",
        )

    def test_broadcom_wildcard_entry_is_present(self):
        """Pins the entry itself, not just the matcher. Deleting
        `LicenseRef-Broadcom*` from this file silently returns every Broadcom
        licence except the one spelled out to the base tables, where they are
        listed as permissive — i.e. back to DCO."""
        req = (self.mapping().get("license_overrides") or {}).get("require_cla") or []
        self.assertTrue(
            any("*" in str(x) and "roadcom" in str(x) for x in req),
            f"expected a LicenseRef-Broadcom* wildcard in require_cla, got {req}",
        )

    def test_broadcom_source_available_still_forces_cla(self):
        """Broadcom Source Available is listed as permissive in the base
        tables, so without this override it would fall through to DCO. Feed
        the raw ID through production's own normaliser rather than a
        hand-normalised literal, so a change to that normaliser fails here."""
        norm = requires_cla._norm_license_name("LicenseRef-Broadcom_Source_Available")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):  # keeps ::warning:: out of CI annotations
            decision = requires_cla._override_requires_cla(norm, self.mapping())
        self.assertIs(decision, True)



# ---------------------------------------------------------------------------
# Allowlist robustness: a policy we cannot read must not read as a policy
# that permits everything.
# ---------------------------------------------------------------------------
class TestAllowlistFailClosed(PolicySelectorTestCase):
    """cla/allowlist.yml is fetched from `ref: main` on every run.

    Before this, `allowlist_data = yaml.safe_load(...)` was assigned before
    the `.get()` that can raise, so a comments-only file left allowlist_data
    as None, the AttributeError was swallowed into a debug_log, and every
    licence override silently disappeared org-wide. That direction is
    dangerous: Broadcom Source Available is listed as permissive in the base
    tables and is held at CLA *only* by the override, so losing it downgrades
    those repos to DCO.
    """

    def _config(self, body):
        self.install(routes={"/contents/cla/allowlist.yml": self._file(body)})
        return policy_selector.fetch_shared_config("https://api.invalid", "tok")

    @staticmethod
    def _file(text):
        import base64
        return {"content": base64.b64encode(text.encode()).decode()}

    def test_valid_allowlist_is_ok_and_parsed(self):
        cfg = self._config(
            "license_overrides:\n"
            "  require_cla: [LicenseRef-Broadcom_Source_Available]\n"
            "  repos:\n"
            "    vmware/x:\n"
            "      require_cla: false\n"
        )
        self.assertIs(cfg["allowlist_ok"], True)
        self.assertEqual(cfg["allowlist_repos"], ["vmware/x"])

    def test_comments_only_file_is_not_ok_and_data_stays_a_dict(self):
        cfg = self._config("# nothing but a comment\n")
        self.assertIs(cfg["allowlist_ok"], False)
        self.assertEqual(cfg["allowlist_data"], {},
                         "must not leak yaml.safe_load's None into callers")

    def test_top_level_list_is_not_ok(self):
        cfg = self._config("- one\n- two\n")
        self.assertIs(cfg["allowlist_ok"], False)
        self.assertEqual(cfg["allowlist_data"], {})

    def test_malformed_yaml_is_not_ok(self):
        cfg = self._config("license_overrides: [unclosed\n")
        self.assertIs(cfg["allowlist_ok"], False)
        self.assertEqual(cfg["allowlist_data"], {})
        self.assertEqual(cfg["allowlist_repos"], [])

    def test_repositories_scalar_does_not_explode_into_characters(self):
        cfg = self._config("repositories: vmware/foo\n")
        self.assertEqual(cfg["allowlist_repos"], [],
                         "a bare string must be rejected, not iterated per character")


class TestOverrideMatchesTheRealCatalogue(unittest.TestCase):
    """Guard the seam between two files that must agree but are spelled
    differently.

    cla/allowlist.yml says `LicenseRef-Broadcom_Source_Available`
    (underscores); data/licenses_all.json's canonical spdx_id is
    `LicenseRef-Broadcom-Source-Available` (hyphens). They match ONLY because
    _norm_license_name collapses [\\s_]+ to '-'. Change that normaliser, or
    regenerate the catalogue with a different spelling, and production stops
    forcing CLA on 48 repos while a test that normalises both sides itself
    would stay green. So this drives the lookup from the catalogue's own
    value, not from a literal.
    """

    @classmethod
    def setUpClass(cls):
        import yaml
        cls.allowlist = yaml.safe_load(
            requires_cla._ALLOWLIST_PATH.read_text(encoding="utf-8"))
        cls.catalogue = json.loads(
            (Path(__file__).resolve().parents[1] / "data" / "licenses_all.json").read_text())

    def override_for(self, catalogue_key):
        entry = self.catalogue[catalogue_key]
        spdx = entry.get("spdx_id") or catalogue_key
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            return requires_cla._override_requires_cla(
                requires_cla._norm_license_name(spdx), self.allowlist)

    def test_allowlist_and_catalogue_spellings_converge(self):
        """Assert the convergence directly, not through the matcher.

        Going via _override_requires_cla cannot detect a broken normaliser,
        because the LicenseRef-Broadcom* wildcard matches the catalogue form
        either way and masks it. The two files genuinely disagree on spelling
        — underscores here, hyphens there — and only _norm_license_name makes
        them meet. That property is what has to hold.
        """
        entry = self.catalogue["Broadcom_Source_Available"]
        from_catalogue = requires_cla._norm_license_name(entry["spdx_id"])
        from_allowlist = requires_cla._norm_license_name(
            "LicenseRef-Broadcom_Source_Available")
        self.assertEqual(
            from_catalogue, from_allowlist,
            f"catalogue spells it {entry['spdx_id']!r} and the allowlist spells it "
            "'LicenseRef-Broadcom_Source_Available'; _norm_license_name is the only "
            "thing making them match, so 48 repos depend on this rule",
        )

    def test_broadcom_source_available_resolves_to_cla_from_catalogue_id(self):
        self.assertIs(self.override_for("Broadcom_Source_Available"), True)

    def test_broadcom_proprietary_resolves_to_cla_via_the_wildcard(self):
        """Without the wildcard this falls through to the base tables, which
        list Broadcom_Proprietary as permissive, and the repo gets DCO."""
        self.assertIs(self.override_for("Broadcom_Proprietary"), True)


class TestOverrideWildcards(unittest.TestCase):
    """`cla/allowlist.yml` has always documented "simple '*' wildcards", and
    ships `LicenseRef-Broadcom*` on that basis, but matching was plain set
    membership so that entry matched nothing."""

    ALLOWLIST = {"license_overrides": {
        "require_cla": ["LicenseRef-Broadcom_Source_Available", "LicenseRef-Broadcom*"],
        "allow_dco": ["LicenseRef-Sample*"],
    }}

    def check(self, license_id):
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            return requires_cla._override_requires_cla(
                requires_cla._norm_license_name(license_id), self.ALLOWLIST)

    def test_exact_entry_still_matches(self):
        self.assertIs(self.check("LicenseRef-Broadcom_Source_Available"), True)

    def test_exact_entries_match_when_no_wildcard_covers_them(self):
        """Pins the non-glob branch of _matches_any independently.

        Every other fixture here pairs an exact entry with a wildcard over the
        same namespace (`LicenseRef-Broadcom_Source_Available` alongside
        `LicenseRef-Broadcom*`), so the wildcard masks a broken exact branch.
        Verified: with the exact branch removed, an exact-only allowlist stops
        matching and every one of those tests still passed. This fixture has
        no wildcard, so the exact path has to work on its own.
        """
        exact_only = {"license_overrides": {"require_cla": ["MIT", "GPL-2.0"],
                                            "allow_dco": ["Apache-2.0"]}}
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIs(requires_cla._override_requires_cla("mit", exact_only), True)
            self.assertIs(requires_cla._override_requires_cla("gpl-2.0", exact_only), True)
            self.assertIs(requires_cla._override_requires_cla("apache-2.0", exact_only), False)
            self.assertIsNone(requires_cla._override_requires_cla("bsd-3-clause", exact_only))

    def test_wildcard_catches_other_broadcom_licences(self):
        """The gap this closes: without it, LicenseRef-Broadcom-Proprietary
        falls through to the base tables, where the canonical matcher strips
        the LicenseRef- prefix and finds Broadcom_Proprietary listed as
        permissive — so a proprietary licence resolved to DCO."""
        for lic in ("LicenseRef-Broadcom-Proprietary",
                    "LicenseRef-Broadcom_Enterprise",
                    "LicenseRef-BroadcomAnything"):
            self.assertIs(self.check(lic), True, lic)

    def test_wildcard_does_not_over_match(self):
        for lic in ("MIT", "Apache-2.0", "LicenseRef-Other", "Broadcom-Without-Prefix"):
            self.assertIsNone(self.check(lic), lic)

    def test_allow_dco_wildcards_work_too(self):
        self.assertIs(self.check("LicenseRef-Sample-Thing"), False)

    def test_matching_is_case_sensitive_on_already_normalised_input(self):
        """Both sides are lowercased by _norm_license_name before matching, so
        fnmatchcase is correct and fnmatch's platform-dependent case folding
        is not wanted. An upper-case pattern must therefore NOT match."""
        upper = {"license_overrides": {"require_cla": ["LICENSEREF-ZZZ*"]}}
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            # the pattern is normalised (lowercased) too, so this still matches
            self.assertIs(requires_cla._override_requires_cla("licenseref-zzz-a", upper), True)
            # but a raw, un-normalised upper-case subject must not
            self.assertIsNone(requires_cla._override_requires_cla("LICENSEREF-ZZZ-A", upper))

    def test_require_cla_wins_over_allow_dco(self):
        both = {"license_overrides": {"require_cla": ["LicenseRef-X*"],
                                      "allow_dco": ["LicenseRef-X*"]}}
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            d = requires_cla._override_requires_cla("licenseref-xyz", both)
        self.assertIs(d, True, "require_cla must take precedence")


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# The gate workflow may only reference paths it actually checks out.
# ---------------------------------------------------------------------------
class TestGateWorkflowPaths(unittest.TestCase):
    """`required-compliance.yml` sparse-checks-out part of this repo, then
    hands filesystem paths to the job through `env:`. A path pointing outside
    that subset names a file that does not exist on the runner.

    This shipped: `LICENSES_JSON` pointed at
    `.github-tools/data/licenses_all.json` while the checkout pulled only
    `scripts`. It was inert purely by luck — `license_detector` consults that
    variable only when handed no `catalog_data`, and production always passes
    both catalogues in memory from the API fetch. Ruleset 12239008 pins this
    workflow to `refs/heads/main`, so a future caller that omitted
    `catalog_data` would have found the missing file in production, with no
    pre-merge signal anywhere.
    """

    WORKFLOW = (Path(__file__).resolve().parents[1]
                / ".github" / "workflows" / "required-compliance.yml")

    @classmethod
    def setUpClass(cls):
        import yaml
        cls.text = cls.WORKFLOW.read_text(encoding="utf-8")
        cls.doc = yaml.safe_load(cls.text)

    def checkout_step(self):
        for job in (self.doc.get("jobs") or {}).values():
            for step in job.get("steps", []):
                if str(step.get("uses", "")).startswith("actions/checkout"):
                    return step
        self.fail(f"no actions/checkout step found in {self.WORKFLOW}")

    def sparse_dirs(self):
        raw = (self.checkout_step().get("with") or {}).get("sparse-checkout")
        self.assertIsNotNone(
            raw, "the checkout step declares no sparse-checkout; if that is "
                 "deliberate, this test's premise no longer holds")
        return {ln.strip().strip("/") for ln in str(raw).splitlines() if ln.strip()}

    def test_sparse_checkout_is_declared_and_non_empty(self):
        self.assertTrue(self.sparse_dirs())

    def test_every_tools_path_in_env_is_actually_checked_out(self):
        """Generic on purpose. Pinning the absence of `LICENSES_JSON` by name
        would fail a legitimate future change that reinstated it *and* added
        `data` to the sparse-checkout; this passes exactly when the paths and
        the checkout agree, which is the property that matters."""
        import re
        allowed = self.sparse_dirs()
        referenced = {}
        for m in re.finditer(
            r"([A-Z][A-Z0-9_]*):\s*\$\{\{\s*github\.workspace\s*\}\}/\.github-tools/(\S+)",
            self.text,
        ):
            referenced[m.group(1)] = m.group(2).split("/")[0]
        self.assertTrue(
            referenced,
            "expected at least one .github-tools/<dir> path in env; if the "
            "workflow stopped using them this test should be retired, not left "
            "passing vacuously",
        )
        bad = {var: top for var, top in referenced.items() if top not in allowed}
        self.assertEqual(
            bad, {},
            f"{bad} point outside the sparse-checkout {sorted(allowed)}, so the "
            "path will not exist on the runner. Either drop the variable or add "
            "the directory to sparse-checkout in the same change.",
        )


# ---------------------------------------------------------------------------
# Top-level `repos:` is a fallback, not a supplement.
# ---------------------------------------------------------------------------
class TestTopLevelReposFallback(PolicySelectorTestCase):
    """`fetch_shared_config` reads `license_overrides.repos`, and only falls
    back to a top-level `repos:` when that is absent or empty.

    Worth pinning because the fallback is invisible in the shipped file:
    `license_overrides.repos` is populated, so a top-level `repos:` added
    beside it does nothing at all. Whoever added it would see a valid-looking
    entry and no effect.
    """

    def _config(self, body):
        self.install(routes={"/contents/cla/allowlist.yml": self._file(body)})
        return policy_selector.fetch_shared_config("https://api.invalid", "tok")

    @staticmethod
    def _file(text):
        import base64
        return {"content": base64.b64encode(text.encode()).decode()}

    NESTED = ("license_overrides:\n"
              "  repos:\n"
              "    vmware/nested:\n"
              "      require_cla: false\n")
    LEGACY = ("repos:\n"
              "  vmware/legacy:\n"
              "    require_cla: false\n")

    def test_top_level_repos_is_used_when_nested_is_absent(self):
        cfg = self._config(self.LEGACY)
        self.assertIs(cfg["allowlist_ok"], True)
        self.assertEqual(cfg["allowlist_repos"], ["vmware/legacy"])

    def test_top_level_repos_is_used_when_nested_is_empty(self):
        cfg = self._config("license_overrides:\n  repos: {}\n" + self.LEGACY)
        self.assertEqual(cfg["allowlist_repos"], ["vmware/legacy"])

    def test_nested_repos_shadows_top_level_entirely(self):
        """Not a merge. The legacy entry is dropped, not appended."""
        cfg = self._config(self.NESTED + self.LEGACY)
        self.assertEqual(
            cfg["allowlist_repos"], ["vmware/nested"],
            "top-level repos must be ignored, not merged, when the nested "
            "block has entries",
        )

    def test_shadowing_is_reported_rather_than_silent(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._config(self.NESTED + self.LEGACY)
        out = buf.getvalue()
        self.assertIn("Top-level 'repos:' is ignored", out)
        self.assertIn("vmware/legacy", out,
                      "the warning must name what is being ignored, or it "
                      "cannot be acted on")

    def test_no_warning_when_only_one_source_is_present(self):
        for label, body in (("nested only", self.NESTED), ("legacy only", self.LEGACY)):
            with self.subTest(label):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self._config(body)
                self.assertNotIn("Top-level 'repos:' is ignored", buf.getvalue())

    def test_null_license_overrides_does_not_discard_the_whole_allowlist(self):
        """`license_overrides:` present but empty parses to None. A `.get()`
        default does not apply to a key that exists with a null value, so
        `.get("license_overrides", {}).get("repos")` raised AttributeError,
        which the caller swallowed into "enforce CLA for every repo". One
        empty key cost the entire policy.
        """
        cfg = self._config("license_overrides:\n" + self.LEGACY)
        self.assertIs(cfg["allowlist_ok"], True,
                      "a null license_overrides must not read as an unparseable file")
        self.assertEqual(cfg["allowlist_repos"], ["vmware/legacy"])


# ---------------------------------------------------------------------------
# The CI paths filter must cover everything this suite depends on.
# ---------------------------------------------------------------------------
class TestTestsWorkflowPathsFilter(unittest.TestCase):
    """`tests.yml` only runs on a paths filter, so a file this suite reads but
    the filter omits can be changed with CI green and nothing checking it.

    That has now happened three times: `cla/**` was missing when the tests
    that parse the allowlist were added (#74), `data/**` was missing while
    TestOverrideMatchesTheRealCatalogue parsed the real catalogue (#76), and
    `required-compliance.yml` was missing when TestGateWorkflowPaths was added
    to guard it. Each time the guard existed and simply never ran.

    Derives its expectations from the same constants the tests use, rather
    than a hand-kept list that would drift out of date in the same way.
    """

    WORKFLOW = (Path(__file__).resolve().parents[1]
                / ".github" / "workflows" / "tests.yml")

    @classmethod
    def setUpClass(cls):
        import yaml
        cls.doc = yaml.safe_load(cls.WORKFLOW.read_text(encoding="utf-8"))
        # PyYAML parses a bare `on:` key as the boolean True.
        cls.triggers = cls.doc.get("on", cls.doc.get(True))

    @staticmethod
    def _covered(path, globs):
        """GitHub path-filter semantics, narrowed to the forms we use:
        `dir/**` covers anything beneath dir, and a literal path matches
        itself."""
        for g in globs:
            if g.endswith("/**"):
                if path.startswith(g[:-2]):
                    return True
            elif g == path:
                return True
        return False

    def repo_relative(self, p):
        return str(Path(p).resolve().relative_to(Path(__file__).resolve().parents[1]))

    def required_paths(self):
        """Files the suite genuinely reads, taken from production constants."""
        root = Path(__file__).resolve().parents[1]
        return {
            self.repo_relative(requires_cla._ALLOWLIST_PATH),
            self.repo_relative(root / "data" / "licenses_all.json"),
            self.repo_relative(TestGateWorkflowPaths.WORKFLOW),
            self.repo_relative(Path(policy_selector.__file__)),
            self.repo_relative(Path(__file__)),
        }

    def test_both_triggers_declare_the_same_filter(self):
        pr = self.triggers["pull_request"]["paths"]
        push = self.triggers["push"]["paths"]
        self.assertEqual(
            pr, push,
            "pull_request and push must agree, or a change can pass pre-merge "
            "and go unverified on main, or vice versa",
        )

    def test_filter_covers_every_file_the_suite_reads(self):
        globs = self.triggers["pull_request"]["paths"]
        missing = sorted(p for p in self.required_paths() if not self._covered(p, globs))
        self.assertEqual(
            missing, [],
            f"{missing} are read by this suite but not matched by the tests.yml "
            f"paths filter {globs}, so changing them runs no tests.",
        )

    def test_coverage_check_rejects_a_path_outside_the_filter(self):
        """Guards the guard: _covered must be capable of returning False."""
        globs = ["scripts/**", ".github/workflows/tests.yml"]
        self.assertTrue(self._covered("scripts/policy_selector.py", globs))
        self.assertTrue(self._covered(".github/workflows/tests.yml", globs))
        self.assertFalse(self._covered("data/licenses_all.json", globs))
        self.assertFalse(self._covered(".github/workflows/required-compliance.yml", globs),
                         "a literal glob must not match a sibling file")


# ---------------------------------------------------------------------------
# A malformed entry must cost that entry, not the whole policy.
# ---------------------------------------------------------------------------
class TestMalformedRepoEntriesAreContained(PolicySelectorTestCase):
    """`fetch_shared_config` wraps the whole parse in one try/except whose
    failure mode is "Enforcing CLA for every repo". Anything that raises in
    there — including while building a log line — therefore has an org-wide
    blast radius from a single bad indent.

    Two separate faults lived here. `r_config.get("require_cla")` on a null or
    boolean value raised AttributeError. And the shadowing warning added in
    this change called `sorted()` on a top-level `repos:` of arbitrary YAML
    shape, so a list of dicts raised TypeError — a regression caught by
    re-probing malformed shapes against origin/main rather than by review.
    """

    def _config(self, body):
        self.install(routes={"/contents/cla/allowlist.yml": self._file(body)})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cfg = policy_selector.fetch_shared_config("https://api.invalid", "tok")
        return cfg, buf.getvalue()

    @staticmethod
    def _file(text):
        import base64
        return {"content": base64.b64encode(text.encode()).decode()}

    NESTED = ("license_overrides:\n  repos:\n    vmware/nested:\n"
              "      require_cla: false\n")

    # A top-level `repos:` of each shape YAML can produce. Only dicts are
    # meaningful; the rest must be inert, never fatal.
    LEGACY_SHAPES = {
        "list of dicts": "repos:\n  - vmware/a: true\n  - vmware/b: true\n",
        "list of strings": "repos:\n  - vmware/a\n  - vmware/b\n",
        "scalar string": "repos: vmware/a\n",
        "integer": "repos: 5\n",
        "null": "repos:\n",
    }

    def test_odd_top_level_repos_shape_never_discards_the_allowlist(self):
        for label, legacy in self.LEGACY_SHAPES.items():
            with self.subTest(label):
                cfg, _ = self._config(self.NESTED + legacy)
                self.assertIs(
                    cfg["allowlist_ok"], True,
                    f"a top-level repos: of type {label} must not cost the whole "
                    "policy — the except in fetch_shared_config enforces CLA "
                    "org-wide",
                )
                self.assertEqual(cfg["allowlist_repos"], ["vmware/nested"])

    NESTED_BAD_VALUES = {"null": "", "boolean": " true", "string": " hello", "integer": " 7"}

    def test_malformed_nested_entry_is_skipped_not_fatal(self):
        for label, value in self.NESTED_BAD_VALUES.items():
            with self.subTest(label):
                cfg, _ = self._config(
                    f"license_overrides:\n  repos:\n    vmware/x:{value}\n")
                self.assertIs(cfg["allowlist_ok"], True,
                              f"a repo entry of type {label} must not discard the file")
                self.assertEqual(cfg["allowlist_repos"], [])

    def test_a_good_entry_survives_alongside_a_malformed_one(self):
        """The property that matters: blast radius is the bad entry, not the file."""
        cfg, _ = self._config(
            "license_overrides:\n"
            "  repos:\n"
            "    vmware/good:\n"
            "      require_cla: false\n"
            "    vmware/bad:\n"
        )
        self.assertIs(cfg["allowlist_ok"], True)
        self.assertEqual(
            cfg["allowlist_repos"], ["vmware/good"],
            "one unparseable entry must not take the readable ones with it",
        )

    def test_malformed_entry_stays_on_cla_rather_than_being_let_through(self):
        """Skipping must not be mistaken for permitting. allowlist_repos is the
        DCO-only set, so absence from it means CLA — the strict direction."""
        cfg, _ = self._config("license_overrides:\n  repos:\n    vmware/bad:\n")
        self.assertNotIn("vmware/bad", cfg["allowlist_repos"])

    def test_skipped_entry_is_reported(self):
        _, out = self._config("license_overrides:\n  repos:\n    vmware/bad:\n")
        self.assertIn("vmware/bad", out)
        self.assertIn("expected a mapping", out)

    def test_warning_renders_a_non_dict_legacy_block_without_raising(self):
        """Direct pin on the regression: the diagnostic itself must be safe.

        TWO dicts, deliberately. `sorted()` on a single-element list never
        performs a comparison, so a one-entry version of this test passes even
        with the broken `sorted(legacy_repos)` in place — it cannot fail for
        the scenario its own name describes. Found by mutation testing, which
        is the only reason this reads as it does.
        """
        cfg, out = self._config(
            self.NESTED + "repos:\n  - vmware/a: true\n  - vmware/b: true\n")
        self.assertIs(cfg["allowlist_ok"], True)
        self.assertIn("Top-level 'repos:' is ignored", out)


# ---------------------------------------------------------------------------
# A consent record that did not persist must be visible AND retryable.
# ---------------------------------------------------------------------------
class TestRecordPendingMarker(unittest.TestCase):
    """`has_pending_record` decides whether a green PR gets re-processed, so
    it is the hinge the whole retry depends on."""

    def test_marker_is_detected(self):
        self.assertTrue(policy_selector.has_pending_record("CLA Signed (record pending)"))

    def test_detection_is_case_insensitive(self):
        self.assertTrue(policy_selector.has_pending_record("DCO Signed (RECORD PENDING)"))

    def test_clean_description_is_not_marked(self):
        self.assertFalse(policy_selector.has_pending_record("CLA Signed"))

    def test_none_is_tolerated(self):
        """The API returns no description for a status posted without one, and
        `None in str` would raise rather than return False."""
        self.assertFalse(policy_selector.has_pending_record(None))

    def test_empty_is_not_marked(self):
        self.assertFalse(policy_selector.has_pending_record(""))

    def test_the_description_we_paint_is_the_one_we_detect(self):
        """Ties the writer to the reader. Reword one without the other and the
        retry silently stops happening, with everything still green."""
        painted = f"CLA Signed ({policy_selector.RECORD_PENDING_MARKER})"
        self.assertTrue(policy_selector.has_pending_record(painted))


class TestFailedConsentRecordIsMarkedAndRetried(ProcessSinglePrHarness):
    """Before this, `record_signature`'s return value was discarded and the PR
    was painted a clean success regardless. Combined with the PR #67
    short-circuit — which skips any commit already carrying a successful
    status — a failed write became both invisible and permanent: green PR, no
    consent record, nothing ever coming back to fix it.
    """

    SIGNED = {"/issues/5/comments": [comment(signature_body("CLA"), comment_id=61)]}

    def _broken_registry_routes(self):
        """Readable signature file, but the PUT returns nothing, so
        record_signature exhausts its retries and returns False."""
        routes = dict(self._writable_registry_routes())
        routes["/contents/signatures/cla.json"] = self._registry([])
        return routes

    def run_with_failed_write(self):
        saved = policy_selector.record_signature
        policy_selector.record_signature = lambda *a, **k: False
        self.addCleanup(lambda: setattr(policy_selector, "record_signature", saved))
        return self.run_pr(routes=self._writable_registry_routes(),
                           paginated_routes=self.SIGNED)

    def run_with_successful_write(self):
        saved = policy_selector.record_signature
        policy_selector.record_signature = lambda *a, **k: True
        self.addCleanup(lambda: setattr(policy_selector, "record_signature", saved))
        return self.run_pr(routes=self._writable_registry_routes(),
                           paginated_routes=self.SIGNED)

    # --- defect 7: the failure must be recorded in the status ---

    def test_successful_write_paints_a_clean_description(self):
        fake = self.run_with_successful_write()
        self.assertEqual([s["state"] for s in fake.statuses()], ["success"])
        self.assertEqual(fake.statuses()[0]["description"], "CLA Signed")
        self.assertFalse(policy_selector.has_pending_record(fake.statuses()[0]["description"]))

    def test_failed_write_is_marked_in_the_description(self):
        fake = self.run_with_failed_write()
        self.assertTrue(
            policy_selector.has_pending_record(fake.statuses()[0]["description"]),
            f"expected the record-pending marker, got {fake.statuses()[0]['description']!r}",
        )

    def test_failed_write_still_passes_the_contributor(self):
        """They signed. An infrastructure failure on our side is not theirs to
        pay for, and blocking them would be outward-facing on a real PR."""
        fake = self.run_with_failed_write()
        self.assertEqual([s["state"] for s in fake.statuses()], ["success"])

    # --- defect 8: the marked status must be re-processed ---

    def test_plain_success_is_still_skipped(self):
        """The #67 short-circuit must survive intact, or the repaint loop it
        exists to prevent comes straight back."""
        fake = self.run_pr(routes={"/commits/abc123/status": self._status("success", "CLA Signed")})
        self.assertEqual(fake.writes(), [], "a clean green PR must not be touched")

    def test_success_with_pending_record_is_reprocessed(self):
        fake = self.run_pr(
            routes=dict(self._writable_registry_routes(),
                        **{"/commits/abc123/status": self._status("success", "CLA Signed (record pending)")}),
            paginated_routes=self.SIGNED,
        )
        self.assertTrue(fake.writes(),
                        "a green PR whose consent record never landed must be retried")

    def test_a_successful_retry_clears_the_marker(self):
        """The end state that matters: the PR converges on a clean status, so
        it stops being re-processed once the record exists."""
        saved = policy_selector.record_signature
        policy_selector.record_signature = lambda *a, **k: True
        self.addCleanup(lambda: setattr(policy_selector, "record_signature", saved))
        fake = self.run_pr(
            routes=dict(self._writable_registry_routes(),
                        **{"/commits/abc123/status": self._status("success", "CLA Signed (record pending)")}),
            paginated_routes=self.SIGNED,
        )
        self.assertEqual(fake.statuses()[-1]["description"], "CLA Signed")
        self.assertFalse(policy_selector.has_pending_record(fake.statuses()[-1]["description"]))

    def test_missing_description_on_a_green_status_is_still_skipped(self):
        """A status posted before this change carries no description. Treating
        None as 'pending' would re-process every historically-green PR in the
        org on the next sweep."""
        fake = self.run_pr(routes={"/commits/abc123/status": self._status("success", None)})
        self.assertEqual(fake.writes(), [])

    def test_failure_and_pending_states_are_unaffected(self):
        for state in ("failure", "pending"):
            with self.subTest(state):
                fake = self.run_pr(
                    routes=dict(self._writable_registry_routes(),
                                **{"/commits/abc123/status": self._status(state, "whatever")}),
                    paginated_routes=self.SIGNED,
                )
                self.assertTrue(fake.writes(), f"a {state} status must still be re-checked")


# ---------------------------------------------------------------------------
# A sweep that failed must not look like a sweep that worked.
# ---------------------------------------------------------------------------
@unittest.skipIf(cla_sweeper is None, "cla_sweeper unavailable on this runner")
class TestSweeperExitCode(unittest.TestCase):
    """Every PR is processed inside a try/except that logs and continues, so
    a sweep where all of them failed still exited 0. On a 5-minute cron with
    nobody reading logs, that made failure indistinguishable from success
    indefinitely — including a consent record that never persisted.

    First tests this script has ever had.
    """

    REPOS = [{"full_name": "vmware/a"}, {"full_name": "vmware/b"}]

    def setUp(self):
        self._saved = {
            "paginated": cla_sweeper.github_api_paginated,
            "fetch": policy_selector.fetch_shared_config,
            "process": policy_selector.process_single_pr,
            "token": getattr(policy_selector, "ensure_valid_token", None),
        }
        self._saved_env = {k: os.environ.get(k) for k in ("GH_TOKEN", "SWEEPER_STRICT_EXIT", "HOURS_BACK")}
        os.environ["GH_TOKEN"] = "tok"
        os.environ.pop("SWEEPER_STRICT_EXIT", None)
        os.environ["HOURS_BACK"] = "24"
        policy_selector.fetch_shared_config = lambda *a, **k: {}
        if self._saved["token"]:
            policy_selector.ensure_valid_token = lambda *a, **k: None
        cla_sweeper.time.sleep = lambda *_a, **_k: None
        self.addCleanup(self._restore)

    def _restore(self):
        cla_sweeper.github_api_paginated = self._saved["paginated"]
        policy_selector.fetch_shared_config = self._saved["fetch"]
        policy_selector.process_single_pr = self._saved["process"]
        if self._saved["token"]:
            policy_selector.ensure_valid_token = self._saved["token"]
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _pr(self, number):
        return {"number": number, "updated_at": "2099-01-01T00:00:00Z",
                "head": {"sha": f"sha{number}"}, "user": {"login": "someone"},
                "draft": False}

    def install(self, repos=None, prs_per_repo=2, fail_on=()):
        repos = self.REPOS if repos is None else repos

        def paginated(url, token):
            if "/installation/repositories" in url:
                return repos
            return [self._pr(i) for i in range(1, prs_per_repo + 1)]

        self.processed = []

        def process(pr_number, *a, **k):
            self.processed.append(pr_number)
            if pr_number in fail_on:
                raise RuntimeError(f"boom on {pr_number}")

        cla_sweeper.github_api_paginated = paginated
        policy_selector.process_single_pr = process

    def run_sweep(self):
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = cla_sweeper.main()
        return rc, buf.getvalue()

    # --- the exit code itself ---

    def test_clean_sweep_returns_zero(self):
        self.install()
        rc, _ = self.run_sweep()
        self.assertEqual(rc, 0)

    def test_any_failed_pr_returns_nonzero(self):
        self.install(fail_on=(2,))
        rc, _ = self.run_sweep()
        self.assertEqual(rc, 1, "one failed PR must redden the sweep")

    def test_failure_does_not_abort_the_rest_of_the_sweep(self):
        """The try/except stays: one bad PR must not cost the other repos
        their status updates."""
        self.install(prs_per_repo=3, fail_on=(1,))
        rc, _ = self.run_sweep()
        self.assertEqual(rc, 1)
        self.assertEqual(len(self.processed), 6, "all PRs across both repos should still be attempted")

    def test_failures_are_named_in_the_log(self):
        self.install(fail_on=(1,))
        _, out = self.run_sweep()
        self.assertIn("vmware/a#1", out)
        self.assertIn("boom on 1", out)

    # --- the kill switch ---

    def test_kill_switch_suppresses_the_nonzero_exit(self):
        os.environ["SWEEPER_STRICT_EXIT"] = "false"
        self.install(fail_on=(1,))
        rc, out = self.run_sweep()
        self.assertEqual(rc, 0)
        self.assertIn("SWEEPER_STRICT_EXIT is off", out)

    def test_kill_switch_still_logs_the_failures(self):
        """Quieting the exit code must not quieten the diagnosis."""
        os.environ["SWEEPER_STRICT_EXIT"] = "false"
        self.install(fail_on=(1,))
        _, out = self.run_sweep()
        self.assertIn("vmware/a#1", out)

    def test_kill_switch_accepts_the_usual_spellings(self):
        for v in ("false", "FALSE", "0", "no", "off", " False "):
            with self.subTest(v):
                os.environ["SWEEPER_STRICT_EXIT"] = v
                self.assertFalse(cla_sweeper.strict_exit_enabled())

    def test_anything_else_leaves_strict_exit_on(self):
        for v in ("true", "1", "yes", "", "banana"):
            with self.subTest(v):
                os.environ["SWEEPER_STRICT_EXIT"] = v
                self.assertTrue(cla_sweeper.strict_exit_enabled(),
                                "an unrecognised value must fail safe to strict")

    def test_default_is_strict(self):
        os.environ.pop("SWEEPER_STRICT_EXIT", None)
        self.assertTrue(cla_sweeper.strict_exit_enabled())

    # --- the early-return path ---

    def test_no_repositories_is_a_failure_not_a_quiet_success(self):
        """An empty installation list means the token or the App install is
        broken. Returning 0 there reported a sweep that examined nothing as
        a clean sweep."""
        self.install(repos=[])
        rc, out = self.run_sweep()
        self.assertEqual(rc, 1)
        self.assertIn("No repositories", out)

    def test_no_repositories_respects_the_kill_switch(self):
        os.environ["SWEEPER_STRICT_EXIT"] = "false"
        self.install(repos=[])
        rc, _ = self.run_sweep()
        self.assertEqual(rc, 0)
