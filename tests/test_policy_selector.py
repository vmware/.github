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
        return policy_selector.get_existing_status_state(
            "https://api.invalid", "vmware/repo", "abc123", "tok"
        ), fake

    def test_returns_our_context_state(self):
        state, _ = self.call({"statuses": [{"context": policy_selector.STATUS_CONTEXT, "state": "success"}]})
        self.assertEqual(state, "success")

    def test_ignores_other_contexts(self):
        state, _ = self.call({"statuses": [{"context": "Some Other CI", "state": "failure"}]})
        self.assertIsNone(state)

    def test_picks_our_context_out_of_a_crowd(self):
        state, _ = self.call({"statuses": [
            {"context": "lint", "state": "success"},
            {"context": policy_selector.STATUS_CONTEXT, "state": "failure"},
            {"context": "build", "state": "success"},
        ]})
        self.assertEqual(state, "failure")

    def test_no_statuses_returns_none(self):
        state, _ = self.call({"statuses": []})
        self.assertIsNone(state)

    def test_api_failure_returns_none(self):
        state, _ = self.call(None)
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
class TestProcessSinglePr(PolicySelectorTestCase):
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
        self.addCleanup(self._restore_helpers)

    def _restore_helpers(self):
        policy_selector.requires_cla.requires_CLA = self._saved_requires
        policy_selector.is_org_member = self._saved_is_member

    def run_pr(self, routes=None, paginated_routes=None, user="contributor", config=None):
        fake = self.install(routes or {}, paginated_routes or {})
        policy_selector.process_single_pr(
            5, "abc123", user, "vmware/repo", "tok", "/tmp", "https://api.invalid",
            shared_config=self.SHARED_CONFIG if config is None else config,
        )
        return fake

    def _status(self, state):
        return {"statuses": [{"context": policy_selector.STATUS_CONTEXT, "state": state}]}

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
        fake = self.run_pr(paginated_routes={
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
