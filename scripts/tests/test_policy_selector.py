"""Regression tests for the CLA/DCO compliance engine.

Run from the repo root:

    python -m unittest discover scripts/tests

Why these tests exist: `policy_selector.py` and `cla_sweeper.py` run in
production against every gated repo in the org, on a 5-minute cron, with both
workflows checking the scripts out at `ref: main`. There is no staging
environment, so until now the only verification available was a live
`workflow_dispatch` against real PRs. These tests cover the parts that can be
checked deterministically, so a live run only has to confirm the things that
genuinely need real GitHub semantics.

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

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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
        self.assertEqual(result, 42)

    def test_signature_without_suffix_is_rejected(self):
        # The phrase alone is not a signature; the "and all future
        # contributions" suffix is what makes it a standing warranty.
        result, _ = self.call([comment(signature_body("CLA", suffix=False))])
        self.assertIsNone(result)

    def test_comment_from_another_user_is_ignored(self):
        result, _ = self.call([comment(signature_body("CLA"), login="someone-else")])
        self.assertIsNone(result)

    def test_login_match_is_case_insensitive(self):
        result, _ = self.call(
            [comment(signature_body("CLA"), login="ConTributor", comment_id=7)], user="contributor"
        )
        self.assertEqual(result, 7)

    def test_non_breaking_spaces_are_normalised(self):
        # Copy-pasting the phrase out of a rendered web page can bring
        # U+00A0 along with it.
        body = signature_body("CLA").replace(" ", "\xa0")
        result, _ = self.call([comment(body, comment_id=11)])
        self.assertEqual(result, 11)

    def test_signature_is_found_beyond_the_first_page(self):
        # This function paginates, so a signature buried under a long
        # discussion must still register.
        comments = [comment("just a normal comment", comment_id=i) for i in range(60)]
        comments.append(comment(signature_body("CLA"), comment_id=12345))
        result, _ = self.call(comments)
        self.assertEqual(result, 12345)

    def test_reaction_is_added_to_the_signing_comment(self):
        _, fake = self.call([comment(signature_body("CLA"), comment_id=42)])
        reactions = [c for c in fake.calls if c[0] == "POST" and "/reactions" in c[1]]
        self.assertEqual(len(reactions), 1)
        self.assertEqual(reactions[0][2], {"content": "rocket"})

    def test_no_comments_returns_none(self):
        result, fake = self.call([])
        self.assertIsNone(result)
        self.assertEqual(fake.writes(), [])


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
        return {"content": base64.b64encode(payload.encode()).decode()}

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
    def test_returns_all_four_keys_process_single_pr_indexes(self):
        # process_single_pr indexes these directly, so a missing key is a
        # KeyError mid-sweep rather than a soft failure.
        self.install()
        config = policy_selector.fetch_shared_config("https://api.invalid", "tok")
        self.assertEqual(
            sorted(config.keys()),
            ["allowlist_data", "allowlist_repos", "licenses_data", "permissive_data"],
        )

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


if __name__ == "__main__":
    unittest.main()
