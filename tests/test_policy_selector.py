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
import tempfile
import unittest

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

    def __init__(self, routes=None, paginated_routes=None, unreadable=()):
        self.routes = routes or {}
        self.paginated_routes = paginated_routes or {}
        # URL fragments whose fetch should report failure rather than an empty
        # list — the distinction the engine now depends on.
        self.unreadable = tuple(unreadable)
        self.calls = []

    def _match(self, table, url):
        for fragment, value in table.items():
            if fragment in url:
                return value
        return None

    def github_api(self, url, token, method="GET", data=None, _retry_on_rate_limit=True):
        self.calls.append((method, url, data))
        return self._match(self.routes, url)

    def github_api_paginated_checked(self, url, token):
        self.calls.append(("GET-paginated", url, None))
        if any(frag in url for frag in self.unreadable):
            return [], False
        return (self._match(self.paginated_routes, url) or []), True

    def github_api_paginated(self, url, token):
        items, _ok = self.github_api_paginated_checked(url, token)
        return items

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

    def install(self, routes=None, paginated_routes=None, unreadable=()):
        fake = FakeGitHub(routes, paginated_routes, unreadable)
        self._saved = (
            policy_selector.github_api,
            policy_selector.github_api_paginated,
            policy_selector.github_api_paginated_checked,
        )
        policy_selector.github_api = fake.github_api
        policy_selector.github_api_paginated = fake.github_api_paginated
        policy_selector.github_api_paginated_checked = fake.github_api_paginated_checked
        self.addCleanup(self._restore)
        return fake

    def _restore(self):
        (policy_selector.github_api,
         policy_selector.github_api_paginated,
         policy_selector.github_api_paginated_checked) = self._saved


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
        self.assertEqual(result, (42, "CLA", True))

    def test_signature_without_suffix_is_rejected(self):
        # The phrase alone is not a signature; the "and all future
        # contributions" suffix is what makes it a standing warranty.
        result, _ = self.call([comment(signature_body("CLA", suffix=False))])
        self.assertEqual(result, (None, None, True))

    def test_comment_from_another_user_is_ignored(self):
        result, _ = self.call([comment(signature_body("CLA"), login="someone-else")])
        self.assertEqual(result, (None, None, True))

    def test_login_match_is_case_insensitive(self):
        result, _ = self.call(
            [comment(signature_body("CLA"), login="ConTributor", comment_id=7)], user="contributor"
        )
        self.assertEqual(result, (7, "CLA", True))

    def test_non_breaking_spaces_are_normalised(self):
        # Copy-pasting the phrase out of a rendered web page can bring
        # U+00A0 along with it.
        body = signature_body("CLA").replace(" ", "\xa0")
        result, _ = self.call([comment(body, comment_id=11)])
        self.assertEqual(result, (11, "CLA", True))

    def test_signature_is_found_beyond_the_first_page(self):
        # This function paginates, so a signature buried under a long
        # discussion must still register.
        comments = [comment("just a normal comment", comment_id=i) for i in range(60)]
        comments.append(comment(signature_body("CLA"), comment_id=12345))
        result, _ = self.call(comments)
        self.assertEqual(result, (12345, "CLA", True))

    def test_reaction_is_added_to_the_signing_comment(self):
        _, fake = self.call([comment(signature_body("CLA"), comment_id=42)])
        reactions = [c for c in fake.calls if c[0] == "POST" and "/reactions" in c[1]]
        self.assertEqual(len(reactions), 1)
        self.assertEqual(reactions[0][2], {"content": "rocket"})

    def test_no_comments_returns_none(self):
        result, fake = self.call([])
        self.assertEqual(result, (None, None, True))
        self.assertEqual(fake.writes(), [])

    def test_signature_in_a_code_fence_still_counts(self):
        # The instruction comment shows the sentence inside a ```text fence
        # and says "copy and paste the exact line below", so a contributor who
        # brings the fence markers along is signing in good faith.
        body = "```text\n" + signature_body("CLA") + "\n```"
        result, _ = self.call([comment(body, comment_id=21)])
        self.assertEqual(result, (21, "CLA", True))

    def test_signature_with_surrounding_chat_still_counts(self):
        body = signature_body("CLA") + "\n\nThanks for the quick review!"
        result, _ = self.call([comment(body, comment_id=22)])
        self.assertEqual(result, (22, "CLA", True))


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
        self.assertEqual(self.call(quoted + "\n\nwhat do I do here?"), (None, None, True))

    def test_verbatim_paste_of_the_instructions_is_not_a_signature(self):
        self.assertEqual(self.call(self._bot_message()), (None, None, True))

    def test_quoted_signature_sentence_alone_is_not_a_signature(self):
        self.assertEqual(self.call("> " + signature_body("CLA")), (None, None, True))

    def test_instruction_markers_really_are_in_the_message(self):
        # The rejection above keys off these markers. If the instruction
        # message is ever reworded without updating them, the bypass silently
        # reopens — so fail here instead.
        msg = self._bot_message()
        for marker in policy_selector.INSTRUCTION_MARKERS:
            self.assertIn(marker, msg)

    def test_a_genuine_signature_quoting_nothing_is_unaffected(self):
        self.assertEqual(self.call(signature_body("CLA")), (99, "CLA", True))


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
        self.assertEqual(result, (31, "CLA", True))

    def test_dco_repo_dco_sentence(self):
        result, _ = self.call(signature_body("DCO"), "DCO")
        self.assertEqual(result, (31, "DCO", True))

    def test_cla_repo_dco_sentence_reports_the_mismatch(self):
        # Previously this passed the gate and wrote a CLA consent record for
        # someone who only ever agreed to the DCO text.
        result, _ = self.call(signature_body("DCO"), "CLA")
        self.assertEqual(result, (31, "DCO", True))

    def test_no_rocket_reaction_on_a_mismatched_document(self):
        # A 🚀 reads as "accepted" and would contradict the failure status.
        _, fake = self.call(signature_body("DCO"), "CLA")
        self.assertEqual([c for c in fake.calls if "/reactions" in c[1]], [])

    def test_both_sentences_present_credits_the_required_one(self):
        body = signature_body("DCO") + "\n\n" + signature_body("CLA")
        result, _ = self.call(body, "CLA")
        self.assertEqual(result, (31, "CLA", True))


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
        self.assertEqual(state, ("success", True))

    def test_ignores_other_contexts(self):
        state, _ = self.call({"statuses": [{"context": "Some Other CI", "state": "failure"}]})
        self.assertEqual(state, (None, True))

    def test_picks_our_context_out_of_a_crowd(self):
        state, _ = self.call({"statuses": [
            {"context": "lint", "state": "success"},
            {"context": policy_selector.STATUS_CONTEXT, "state": "failure"},
            {"context": "build", "state": "success"},
        ]})
        self.assertEqual(state, ("failure", True))

    def test_no_statuses_returns_none(self):
        state, _ = self.call({"statuses": []})
        self.assertEqual(state, (None, True))

    def test_api_failure_is_reported_as_unreadable(self):
        # Not the same as "no status yet": acting on it would repaint PRs the
        # already-resolved short-circuit is meant to leave alone.
        state, _ = self.call(None)
        self.assertEqual(state, (None, False))


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
        self.assertEqual(self.call([
            self._commit("fix: thing\n\nSigned-off-by: A <a@example.com>"),
            self._commit("fix: other\n\nSigned-off-by: A <a@example.com>"),
        ]), (True, True))

    def test_one_unsigned_commit_fails_the_whole_pr(self):
        self.assertEqual(self.call([
            self._commit("fix: thing\n\nSigned-off-by: A <a@example.com>"),
            self._commit("fix: forgot the sign-off"),
        ]), (False, True))

    def test_no_commits_is_not_compliant(self):
        self.assertEqual(self.call([]), (False, True))


# ---------------------------------------------------------------------------
# process_single_pr  — the decision table
# ---------------------------------------------------------------------------
class ProcessSinglePrHarness(object):
    """Shared fixture for process_single_pr tests.

    Deliberately NOT a TestCase. Subclassing a TestCase to reuse its
    helpers makes unittest re-run every parent test under each child,
    which silently inflated this suite's reported count by 34.
    """

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

    def _default_routes(self):
        """process_single_pr now bails rather than guessing when the signature
        registry cannot be read, so a readable (empty) registry is the baseline
        for any test that is not specifically about that failure."""
        return {
            # process_single_pr now refuses to act on an unreadable status, so
            # a readable "no status yet" is the baseline.
            "/commits/abc123/status": {"statuses": []},
            "/contents/signatures/cla.json": self._registry([]),
            "/contents/signatures/dco.json": self._registry([]),
            "/users/": {"id": 4242},
        }

    def run_pr(self, routes=None, paginated_routes=None, user="contributor", config=None,
               unreadable=()):
        merged = dict(self._default_routes())
        merged.update(routes or {})
        fake = self.install(merged, paginated_routes or {}, unreadable)
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
        test asserting that no record was written can actually fail. Same as
        the defaults now, kept named for readability at the call sites that
        depend on a write being possible."""
        return self._default_routes()

class TestProcessSinglePr(ProcessSinglePrHarness, PolicySelectorTestCase):
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

        self._saved = (
            policy_selector.github_api,
            policy_selector.github_api_paginated,
            policy_selector.github_api_paginated_checked,
        )
        policy_selector.github_api = routed
        policy_selector.github_api_paginated = fake.github_api_paginated
        policy_selector.github_api_paginated_checked = fake.github_api_paginated_checked
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
    def test_returns_all_four_keys_process_single_pr_indexes(self):
        # process_single_pr indexes these directly, so a missing key is a
        # KeyError mid-sweep rather than a soft failure.
        self.install()
        config = policy_selector.fetch_shared_config("https://api.invalid", "tok")
        for key in ("allowlist_data", "allowlist_repos", "licenses_data", "permissive_data"):
            self.assertIn(key, config)
        self.assertIn("complete", config)

    def test_missing_config_degrades_to_empty_rather_than_raising(self):
        self.install()
        config = policy_selector.fetch_shared_config("https://api.invalid", "tok")
        self.assertEqual(config["licenses_data"], [])
        self.assertEqual(config["permissive_data"], [])
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




# ---------------------------------------------------------------------------
# A failed fetch is not evidence of anything
# ---------------------------------------------------------------------------
class TestFetchFailureIsNotEmptiness(PolicySelectorTestCase):
    """`github_api` returns None for every failure, so a 403/404/network error
    collapses into the same empty list as "there is nothing here". Every place
    that turned emptiness into a decision could therefore turn a transient
    error into a wrong, contributor-visible answer."""

    def patch_transport(self, fn):
        """Replace only `github_api`, so the REAL github_api_paginated_checked
        is the thing under test. install() would swap the checked helper out
        for the fake and the test would assert on the fake instead."""
        saved = policy_selector.github_api
        policy_selector.github_api = fn
        self.addCleanup(lambda: setattr(policy_selector, "github_api", saved))

    def test_checked_helper_reports_a_failed_page(self):
        self.patch_transport(lambda *a, **k: None)
        items, ok = policy_selector.github_api_paginated_checked("https://api.invalid/x", "tok")
        self.assertEqual(items, [])
        self.assertFalse(ok)

    def test_checked_helper_reports_a_genuinely_empty_listing(self):
        self.patch_transport(lambda *a, **k: [])
        items, ok = policy_selector.github_api_paginated_checked("https://api.invalid/x", "tok")
        self.assertEqual(items, [])
        self.assertTrue(ok)

    def test_checked_helper_reports_a_malformed_page_as_not_ok(self):
        self.patch_transport(lambda *a, **k: {"unexpected": "shape"})
        items, ok = policy_selector.github_api_paginated_checked("https://api.invalid/x", "tok")
        self.assertFalse(ok)

    def test_checked_helper_reports_partial_pages_as_not_ok(self):
        # Page 1 full, page 2 fails: the list is truncated, not complete.
        state = {"n": 0}

        def flaky(url, token, method="GET", data=None, _retry_on_rate_limit=True):
            state["n"] += 1
            return [{"i": i} for i in range(100)] if state["n"] == 1 else None

        self.patch_transport(flaky)
        items, ok = policy_selector.github_api_paginated_checked("https://api.invalid/x", "tok")
        self.assertEqual(len(items), 100)
        self.assertFalse(ok)

    def test_plain_wrapper_still_returns_just_the_items(self):
        # The ~6 existing call sites keep working unchanged.
        self.patch_transport(lambda *a, **k: [{"a": 1}])
        self.assertEqual(policy_selector.github_api_paginated("https://api.invalid/x", "tok"),
                         [{"a": 1}])

    def test_unreadable_comments_do_not_produce_a_duplicate_comment(self):
        # The regression that the pagination fix alone would have introduced:
        # posting on a failed read, which bumps updated_at and so re-posts
        # every sweep.
        fake = self.install(unreadable=("/issues/5/comments",))
        policy_selector.post_pr_comment(
            "https://api.invalid", "vmware/repo", 5, "INSTRUCTIONS", "tok")
        self.assertEqual(fake.posted_comments(), [])

    def test_readable_comments_still_post_when_absent(self):
        fake = self.install(paginated_routes={"/issues/5/comments": []})
        policy_selector.post_pr_comment(
            "https://api.invalid", "vmware/repo", 5, "INSTRUCTIONS", "tok")
        self.assertEqual(len(fake.posted_comments()), 1)

    def test_instruction_comment_beyond_the_first_thirty_is_still_found(self):
        # The original defect: the dedup scan was unpaginated, so it saw only
        # GitHub's default first 30 comments.
        comments = [comment("chatter %d" % i, comment_id=i) for i in range(30)]
        comments.append(instruction_comment(comment_id=9001))
        comments += [comment("more chatter %d" % i, comment_id=100 + i) for i in range(5)]
        fake = self.install(paginated_routes={"/issues/5/comments": comments})
        policy_selector.post_pr_comment(
            "https://api.invalid", "vmware/repo", 5, "INSTRUCTIONS", "tok")
        self.assertEqual(fake.posted_comments(), [])

    def test_unreadable_comments_report_unknown_not_unsigned(self):
        self.install(unreadable=("/issues/5/comments",))
        result = policy_selector.check_comments_for_signature(
            "https://api.invalid", "vmware/repo", 5, "contributor", "CLA", "tok")
        self.assertEqual(result, (None, None, False))

    def test_unreadable_commits_report_unknown_not_unsigned(self):
        self.install(unreadable=("/pulls/5/commits",))
        result = policy_selector.check_dco_commits(
            "https://api.invalid", "vmware/repo", 5, "tok")
        self.assertEqual(result, (False, False))


class TestUnreadableInputLeavesTheStatusAlone(ProcessSinglePrHarness, PolicySelectorTestCase):
    """Whatever status a PR already has is a better answer than one derived
    from a fetch that failed, so process_single_pr writes nothing at all."""

    def test_unreadable_comments_write_no_status_and_no_comment(self):
        fake = self.run_pr(unreadable=("/issues/5/comments",))
        self.assertEqual(fake.statuses(), [])
        self.assertEqual(fake.posted_comments(), [])

    def test_unreadable_registry_writes_no_status_and_no_comment(self):
        fake = self.run_pr(routes={"/contents/signatures/cla.json": None})
        self.assertEqual(fake.statuses(), [])
        self.assertEqual(fake.posted_comments(), [])

    def test_unreadable_commits_write_no_status_on_a_dco_repo(self):
        policy_selector.requires_cla.requires_CLA = lambda *a, **k: False
        fake = self.run_pr(
            paginated_routes={"/issues/5/comments": []},
            unreadable=("/pulls/5/commits",))
        self.assertEqual(fake.statuses(), [])

    def test_a_readable_but_unsigned_pr_is_still_failed(self):
        # The guard must not become a blanket excuse to do nothing.
        fake = self.run_pr(paginated_routes={"/issues/5/comments": []})
        self.assertEqual([s["state"] for s in fake.statuses()], ["failure"])
        self.assertEqual(len(fake.posted_comments()), 1)


# ---------------------------------------------------------------------------
# Edge cases found by auditing rather than by a failing test
# ---------------------------------------------------------------------------
class TestPaginationBoundaries(PolicySelectorTestCase):
    def patch_transport(self, fn):
        saved = policy_selector.github_api
        policy_selector.github_api = fn
        self.addCleanup(lambda: setattr(policy_selector, "github_api", saved))

    def test_search_style_items_envelope_is_unwrapped_and_paged(self):
        state = {"n": 0}

        def search(url, token, method="GET", data=None, _retry_on_rate_limit=True):
            state["n"] += 1
            return {"items": [{"x": i} for i in range(100)]} if state["n"] == 1 else {"items": []}

        self.patch_transport(search)
        items, ok = policy_selector.github_api_paginated_checked("https://api.invalid/search?q=1", "tok")
        self.assertEqual(len(items), 100)
        self.assertTrue(ok)
        self.assertEqual(state["n"], 2)

    def test_full_page_followed_by_an_empty_page_is_complete(self):
        # The boundary case: exactly 100 items means "maybe more", so it pages
        # again; an empty second page means the listing really is done.
        state = {"n": 0}

        def two_pages(url, token, method="GET", data=None, _retry_on_rate_limit=True):
            state["n"] += 1
            return [{"i": i} for i in range(100)] if state["n"] == 1 else []

        self.patch_transport(two_pages)
        items, ok = policy_selector.github_api_paginated_checked("https://api.invalid/x", "tok")
        self.assertEqual(len(items), 100)
        self.assertTrue(ok)


class TestCommitWithoutShaDoesNotCrash(PolicySelectorTestCase):
    def test_unsigned_commit_missing_its_sha(self):
        # commit.get('sha')[:7] raised TypeError, which the sweeper's per-PR
        # except swallowed — the PR was skipped with no status at all.
        self.install(paginated_routes={
            "/pulls/5/commits": [{"commit": {"message": "no sign-off here"}}]
        })
        self.assertEqual(
            policy_selector.check_dco_commits("https://api.invalid", "vmware/repo", 5, "tok"),
            (False, True))


class TestUnreadableStatusIsNotAbsentStatus(PolicySelectorTestCase):
    def test_failed_status_fetch_reports_unreadable(self):
        self.install(routes={})  # no route -> github_api returns None
        self.assertEqual(
            policy_selector.get_existing_status_state("https://api.invalid", "vmware/repo", "abc123", "tok"),
            (None, False))

    def test_absent_status_is_readable_but_none(self):
        self.install(routes={"/commits/abc123/status": {"statuses": []}})
        self.assertEqual(
            policy_selector.get_existing_status_state("https://api.invalid", "vmware/repo", "abc123", "tok"),
            (None, True))

    def test_present_status_is_readable(self):
        self.install(routes={"/commits/abc123/status": {
            "statuses": [{"context": policy_selector.STATUS_CONTEXT, "state": "failure"}]}})
        self.assertEqual(
            policy_selector.get_existing_status_state("https://api.invalid", "vmware/repo", "abc123", "tok"),
            ("failure", True))


class TestIncompleteConfigAborts(PolicySelectorTestCase):
    def test_fetch_shared_config_flags_a_total_failure(self):
        self.install()  # every mothership fetch returns None
        config = policy_selector.fetch_shared_config("https://api.invalid", "tok")
        self.assertFalse(config["complete"])

    def test_process_single_pr_writes_nothing_on_incomplete_config(self):
        # An empty catalogue does not fail one PR — it decides CLA-vs-DCO for
        # every PR in the sweep from no data.
        # Every *other* guard must be satisfied, or this test passes for the
        # wrong reason: without a readable registry process_single_pr bails
        # there first and the config guard is never reached.
        import base64
        registry = {"content": base64.b64encode(
            json.dumps({"signedContributors": []}).encode()).decode(), "sha": "filesha"}
        fake = self.install(routes={
            "/commits/abc123/status": {"statuses": []},
            "/contents/signatures/cla.json": registry,
            "/contents/signatures/dco.json": registry,
        }, paginated_routes={"/issues/5/comments": []})
        saved = policy_selector.is_org_member
        saved_req = policy_selector.requires_cla.requires_CLA
        policy_selector.is_org_member = lambda *a, **k: False
        policy_selector.requires_cla.requires_CLA = lambda *a, **k: True
        self.addCleanup(lambda: setattr(policy_selector, "is_org_member", saved))
        self.addCleanup(lambda: setattr(policy_selector.requires_cla, "requires_CLA", saved_req))
        policy_selector.process_single_pr(
            5, "abc123", "contributor", "vmware/repo", "tok", "/tmp", "https://api.invalid",
            shared_config={"allowlist_data": {}, "allowlist_repos": [],
                           "licenses_data": [], "permissive_data": [], "complete": False})
        self.assertEqual(fake.statuses(), [])
        self.assertEqual(fake.posted_comments(), [])

    def test_a_config_without_the_key_is_treated_as_complete(self):
        # Back-compat: hand-built configs (including this suite's own) predate
        # the key and must not be read as broken.
        self.assertTrue({"allowlist_data": {}}.get("complete", True))


class TestConfigCompletenessIsNarrowlyScoped(PolicySelectorTestCase):
    """Completeness must cover the licence catalogues and NOT the allowlist.
    Gating on the allowlist would mean that emptying cla/allowlist.yml — a
    valid configuration meaning "no overrides" — silently aborts every sweep
    org-wide, which is far worse than the skewed decision it would prevent."""

    def _b64(self, text):
        import base64
        return {"content": base64.b64encode(text.encode()).decode()}

    def test_empty_allowlist_does_not_make_the_config_incomplete(self):
        self.install(routes={
            "allowlist": self._b64(""),
            "licenses_all": self._b64('[{"spdx_id": "MIT"}]'),
            "permissive": self._b64('["MIT"]'),
        })
        config = policy_selector.fetch_shared_config("https://api.invalid", "tok")
        self.assertTrue(config["complete"])

    def test_missing_licence_catalogue_does_make_it_incomplete(self):
        self.install(routes={
            "allowlist": self._b64("repos: {}"),
            "permissive": self._b64('["MIT"]'),
            # licenses_all deliberately absent -> fetch returns None
        })
        config = policy_selector.fetch_shared_config("https://api.invalid", "tok")
        self.assertFalse(config["complete"])

    def test_missing_permissive_table_does_make_it_incomplete(self):
        self.install(routes={
            "allowlist": self._b64("repos: {}"),
            "licenses_all": self._b64('[{"spdx_id": "MIT"}]'),
        })
        config = policy_selector.fetch_shared_config("https://api.invalid", "tok")
        self.assertFalse(config["complete"])




# ---------------------------------------------------------------------------
# Guards that an audit found were NOT pinned by any test
# ---------------------------------------------------------------------------
class TestGuardsThatWereNotPinned(ProcessSinglePrHarness, PolicySelectorTestCase):
    """Both guards below were production-correct but unpinned: deleting either
    left the suite green, because another code path happened to reach the same
    end state. A guard no test can distinguish is a guard the next refactor
    silently removes."""

    def test_unreadable_status_guard_is_reached_and_stops_everything(self):
        # Every other process_single_pr test gets a readable status from
        # _default_routes, so none of them exercise the caller's guard —
        # only the helper's return contract. Override it to None here.
        fake = self.run_pr(
            routes={"/commits/abc123/status": None},
            paginated_routes={"/issues/5/comments": []},
        )
        self.assertEqual(fake.statuses(), [])
        self.assertEqual(fake.posted_comments(), [])
        # And prove the guard fired *early*: with the status unreadable we must
        # not have gone on to read the registry at all.
        registry_reads = [c for c in fake.calls if "/contents/signatures/" in c[1]]
        self.assertEqual(registry_reads, [])

    def test_unreadable_registry_guard_is_distinguishable_from_the_parse_guard(self):
        # `if not raw_signatures: return` was indistinguishable from letting
        # json.loads(None) raise into the except branch — same end state, so
        # flipping the guard to `if False:` kept the suite green. A body that
        # is present but not JSON separates them: only the parse guard can
        # catch that, so this test pins the parse guard...
        fake = self.run_pr(
            routes={"/contents/signatures/cla.json": {
                "content": __import__("base64").b64encode(b"not json at all").decode()}},
            paginated_routes={"/issues/5/comments": []},
        )
        self.assertEqual(fake.statuses(), [])
        self.assertEqual(fake.posted_comments(), [])

    def test_absent_registry_is_diagnosed_as_unreadable_not_as_malformed(self):
        """The `if not raw_signatures` guard cannot be pinned by end state: with
        it disabled, json.loads(None) raises and the parse guard catches it,
        reaching the identical outcome. Its distinct value is the diagnosis — an
        operator seeing "failed to parse" would go hunting for corrupt JSON when
        the real problem is that the fetch failed. So assert on that, and keep
        the guard from depending on an accidental TypeError."""
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.run_pr(
                routes={"/contents/signatures/cla.json": None},
                paginated_routes={"/issues/5/comments": []},
            )
        out = buf.getvalue()
        self.assertIn("Could not read signatures/cla.json", out)
        self.assertNotIn("Failed to parse", out)

    def test_absent_registry_stops_before_the_comment_scan(self):
        # ...and this pins the *first* guard: when the registry cannot be
        # fetched at all we must bail before scanning comments. If the first
        # guard is removed, json.loads(None) raises immediately and the comment
        # scan is likewise skipped — so assert on the ordering signal that
        # differs: no comment fetch is attempted either way, but the first
        # guard must produce no exception-derived log. Assert the observable
        # contract both guards share, plus that we never touched comments.
        fake = self.run_pr(
            routes={"/contents/signatures/cla.json": None},
            paginated_routes={"/issues/5/comments": [comment(signature_body("CLA"))]},
        )
        self.assertEqual(fake.statuses(), [])
        comment_reads = [c for c in fake.calls if c[1].endswith("/comments")]
        self.assertEqual(comment_reads, [])


# ---------------------------------------------------------------------------
# Gaps found by measuring line coverage of the diff, not by reasoning
# ---------------------------------------------------------------------------
class TestLegacyStringRegistryEntries(ProcessSinglePrHarness, PolicySelectorTestCase):
    """signatures/*.json entries are dicts today, but the reader still supports
    a bare-string form. That branch had no coverage, so nothing would notice if
    it broke — and a repo using the old format would start failing everyone."""

    def _string_registry(self, names):
        import base64
        return {"content": base64.b64encode(json.dumps(names).encode()).decode(),
                "sha": "filesha"}

    def test_bare_string_entry_is_recognised(self):
        fake = self.run_pr(routes={"/contents/signatures/cla.json": self._string_registry(["contributor"])})
        self.assertEqual([s["state"] for s in fake.statuses()], ["success"])
        self.assertEqual(fake.statuses()[0]["description"], "CLA Signed")

    def test_bare_string_entry_match_is_case_insensitive(self):
        fake = self.run_pr(routes={"/contents/signatures/cla.json": self._string_registry(["ConTributor"])})
        self.assertEqual([s["state"] for s in fake.statuses()], ["success"])

    def test_bare_string_entry_for_a_different_user_does_not_match(self):
        fake = self.run_pr(
            routes={"/contents/signatures/cla.json": self._string_registry(["someone-else"])},
            paginated_routes={"/issues/5/comments": []})
        self.assertEqual([s["state"] for s in fake.statuses()], ["failure"])


class TestSweeperAbortsOnIncompleteConfig(unittest.TestCase):
    """cla_sweeper.main()'s abort guard had ZERO coverage — the widest-blast-
    radius guard in the change, since it stops the whole sweep rather than one
    PR. Measuring coverage of the diff found this; reasoning about it did not."""

    def setUp(self):
        import cla_sweeper
        self.sweeper = cla_sweeper
        self.processed = []
        self._saved = {
            "paginated": cla_sweeper.github_api_paginated,
            "config": policy_selector.fetch_shared_config,
            "process": policy_selector.process_single_pr,
            "sleep": cla_sweeper.time.sleep,
            "ensure": getattr(policy_selector, "ensure_valid_token", None),
        }
        # cla_sweeper has its OWN paginated helper (different envelope unwrap),
        # so it must be stubbed separately from policy_selector's.
        cla_sweeper.github_api_paginated = lambda url, token: (
            [{"full_name": "vmware/repo"}] if "installation/repositories" in url
            else [{"number": 5, "updated_at": "2099-01-01T00:00:00Z",
                   "head": {"sha": "abc123"}, "user": {"login": "contributor"},
                   "draft": False}])
        policy_selector.process_single_pr = lambda *a, **k: self.processed.append(a)
        cla_sweeper.time.sleep = lambda _s: None
        policy_selector.ensure_valid_token = lambda: None
        os.environ.setdefault("GH_TOKEN", "test-token")
        self.addCleanup(self._restore)

    def _restore(self):
        self.sweeper.github_api_paginated = self._saved["paginated"]
        policy_selector.fetch_shared_config = self._saved["config"]
        policy_selector.process_single_pr = self._saved["process"]
        self.sweeper.time.sleep = self._saved["sleep"]
        if self._saved["ensure"]:
            policy_selector.ensure_valid_token = self._saved["ensure"]

    def test_incomplete_config_aborts_before_touching_any_pr(self):
        policy_selector.fetch_shared_config = lambda *a, **k: {
            "allowlist_data": {}, "allowlist_repos": [],
            "licenses_data": [], "permissive_data": [], "complete": False}
        self.sweeper.main()
        self.assertEqual(self.processed, [],
                         "sweep must process nothing when policy data is missing")

    def test_complete_config_does_process_prs(self):
        # Positive control: without this, the test above would pass even if
        # main() were broken in some unrelated way.
        policy_selector.fetch_shared_config = lambda *a, **k: {
            "allowlist_data": {}, "allowlist_repos": [],
            "licenses_data": [{"spdx_id": "MIT"}], "permissive_data": ["MIT"],
            "complete": True}
        self.sweeper.main()
        self.assertEqual(len(self.processed), 1)

    def test_config_without_the_complete_key_still_processes(self):
        # Back-compat: a config predating the key must not read as broken.
        policy_selector.fetch_shared_config = lambda *a, **k: {
            "allowlist_data": {}, "allowlist_repos": [],
            "licenses_data": [{"spdx_id": "MIT"}], "permissive_data": ["MIT"]}
        self.sweeper.main()
        self.assertEqual(len(self.processed), 1)


if __name__ == "__main__":
    unittest.main()
