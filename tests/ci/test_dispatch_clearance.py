import copy
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("review_gate", ROOT / ".github/scripts/review_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
SHA = "a" * 40
BOT = {"login": gate.BOT, "id": gate.BOT_ID, "type": "Bot"}


def setUpModule():
    # Simulated CLI calls must not inherit the real runner's ref or write its
    # output file. Tests of the Actions context supply their own environment.
    environment = patch.dict(gate.os.environ, {"GITHUB_ACTIONS": "false", "GITHUB_OUTPUT": ""})
    environment.start()
    unittest.addModuleCleanup(environment.stop)


def fixture():
    repo = {"full_name": "owner/repo"}
    return {
        "pr": {"state": "open", "draft": False, "mergeable": True, "head": {"sha": SHA, "ref": "feature", "repo": repo},
               "base": {"repo": repo, "sha": "b" * 40}},
        "summary": {"user": BOT, "body": gate.SUMMARY_MARKER + '''
| Review | Status | Commit | Review trigger |
| --- | --- | --- | --- |
| 📝 **Code Review** | ✅ **Completed** <relative-time datetime="2026-10-14T07:00:00Z">now</relative-time> | `aaaaaaa` | New commits |
''', "updated_at": "2026-10-14T07:00:01Z"},
        "reactions": [{"user": BOT, "content": "+1", "created_at": "2026-10-14T07:00:02Z"}],
        "reviews": [], "threads": [{"isResolved": True}],
    }


class ClearanceTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        resolver = patch.object(gate, "gh_api", return_value={"sha": SHA})
        self.api = resolver.start()
        self.addCleanup(resolver.stop)

    def blocked(self, message):
        with self.assertRaisesRegex(gate.Blocked, message):
            gate.evaluate(**self.data)

    def test_fresh_clean_review_of_latest_head_passes(self):
        self.assertEqual(gate.evaluate(**self.data, expected_sha=SHA), SHA)

    def test_stale_review_does_not_clear_new_commits(self):
        self.data["pr"]["head"]["sha"] = "b" * 40
        self.blocked("latest PR commit")

    def test_dispatch_sha_must_still_match(self):
        with self.assertRaisesRegex(gate.Blocked, "changed after clearance"):
            gate.evaluate(**self.data, expected_sha="b" * 40)

    def test_draft_and_closed_prs_are_blocked(self):
        for field, value in (("draft", True), ("state", "closed")):
            with self.subTest(field=field):
                self.data = fixture()
                self.data["pr"][field] = value
                self.blocked("open and ready")

    def test_forks_are_not_dispatched_to_an_untrusted_repository(self):
        self.data["pr"]["head"]["repo"] = {"full_name": "other/repo"}
        self.blocked("same repository")

    def test_unresolved_threads_block_even_if_outdated(self):
        self.data["threads"].append({"isResolved": False, "isOutdated": True})
        self.blocked("Unresolved")

    def test_changes_requested_survives_a_later_comment_only_review(self):
        self.data["reviews"] = [
            {"id": 1, "user": {"login": "owner", "id": 1}, "state": "CHANGES_REQUESTED"},
            {"id": 2, "user": {"login": "owner", "id": 1}, "state": "COMMENTED"},
        ]
        self.blocked("changes-requested")

    def test_approval_or_dismissal_clears_a_changes_request(self):
        self.data["reviews"] = [
            {"id": 1, "user": {"login": "owner", "id": 1}, "state": "CHANGES_REQUESTED"},
            {"id": 2, "user": {"login": "owner", "id": 1}, "state": "APPROVED"},
        ]
        self.assertEqual(gate.evaluate(**self.data), SHA)
        self.data["reviews"] = [{"id": 1, "user": {"login": "owner", "id": 1}, "state": "DISMISSED"}]
        self.assertEqual(gate.evaluate(**self.data), SHA)

    def test_running_failed_and_unknown_summary_formats_fail_closed(self):
        for status in ("🔄 **Running**", "❌ **Failed**", "Completed"):
            with self.subTest(status=status):
                self.data = fixture()
                self.data["summary"]["body"] = self.data["summary"]["body"].replace("✅ **Completed**", status)
                self.blocked("pending, running, or incomplete")

    def test_security_review_must_also_finish(self):
        self.data["summary"]["body"] += '| 🔐 **Security Review** | 🔄 **Running** | `aaaaaaa` | Manual |\n'
        self.blocked("pending, running, or incomplete")

    def test_completed_security_review_must_cover_current_commit(self):
        self.data["summary"]["body"] += (
            '| 🔐 **Security Review** | ✅ **Completed** '
            '<relative-time datetime="2026-10-14T07:05:00Z">now</relative-time> | `bbbbbbb` | Manual |\n'
        )
        self.blocked("latest PR commit")

    def test_summary_without_code_review_does_not_count(self):
        self.data["summary"]["body"] = self.data["summary"]["body"].replace("Code Review", "Security Review")
        self.blocked("No completed Code Review")

    def test_missing_or_spoofed_summary_does_not_count(self):
        self.data["summary"] = None
        self.blocked("No Codex review summary")
        self.data = fixture()
        self.data["summary"]["user"] = {"login": "someone-else"}
        self.blocked("authenticated")

    def test_completed_review_with_findings_is_not_sign_off(self):
        self.data["reactions"] = []
        self.blocked("No fresh Codex thumbs-up")

    def test_old_or_human_thumbs_up_does_not_count(self):
        for reaction in (
            {"user": BOT, "content": "+1", "created_at": "2026-10-13T07:00:00Z"},
            {"user": {"login": "owner", "id": 1}, "content": "+1", "created_at": "2026-10-14T07:00:02Z"},
        ):
            with self.subTest(reaction=reaction):
                self.data["reactions"] = [reaction]
                self.blocked("No fresh Codex thumbs-up")

    def test_active_review_blocks_even_with_thumbs_up(self):
        self.data["reactions"].append({"user": BOT, "content": "eyes", "created_at": "2026-10-14T07:00:03Z"})
        with self.assertRaisesRegex(gate.AwaitingSignoff, "still indicates"):
            gate.evaluate(**self.data)

    def test_old_eyes_do_not_block_a_completed_clean_review(self):
        for created_at in ("2026-10-13T07:00:00Z", "2026-10-14T07:00:00Z"):
            with self.subTest(created_at=created_at):
                self.data = fixture()
                self.data["reactions"].append({"user": BOT, "content": "eyes", "created_at": created_at})
                self.assertEqual(gate.evaluate(**self.data), SHA)

    def test_newer_codex_review_invalidates_sign_off(self):
        self.data["reviews"] = [{"id": 1, "user": BOT, "state": "COMMENTED", "submitted_at": "2026-10-14T07:00:05Z"}]
        self.blocked("newer Codex review")


class RequestReactionTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.data["summary"]["body"] += (
            '| 🔐 **Security Review** | ✅ **Completed** '
            '<relative-time datetime="2026-10-14T07:05:00Z">now</relative-time> | `aaaaaaa` | Manual |\n'
        )
        # Code Review found issues; resolving its threads does not sign it off.
        self.data["reviews"] = [{"id": 1, "user": BOT, "state": "COMMENTED",
                                 "submitted_at": "2026-10-14T07:00:01Z"}]
        self.request = {"id": 2, "user": {"login": "owner", "id": 1}, "body": "@codex security review",
                        "created_at": "2026-10-14T06:59:00Z", "updated_at": "2026-10-14T06:59:00Z"}
        self.request_reactions = [{"user": BOT, "content": "+1", "created_at": "2026-10-14T07:05:02Z"}]
        self.data["reactions"] = []

    def assert_dispatch(self, allowed, reason=None):
        responses = {
            "repos/owner/repo/issues/1/comments?per_page=100": [self.data["summary"], self.request],
            "repos/owner/repo/issues/1/reactions?per_page=100": self.data["reactions"],
            "repos/owner/repo/issues/comments/2/reactions?per_page=100": self.request_reactions,
            "repos/owner/repo/pulls/1/reviews?per_page=100": self.data["reviews"],
        }
        api_responses = {
            "repos/owner/repo": {"default_branch": "main"},
            "repos/owner/repo/pulls/1": self.data["pr"],
            "repos/owner/repo/commits/aaaaaaa": {"sha": SHA},
            "repos/owner/repo/actions/workflows/reviewed-ci.yml/runs?event=workflow_dispatch&branch=main&per_page=100": [{"total_count": 0, "workflow_runs": []}],
            "repos/owner/repo/actions/workflows/review-clearance.yml/runs?event=workflow_dispatch&branch=main&per_page=100": [{"total_count": 0, "workflow_runs": []}],
        }
        with patch.object(gate, "gh_api", side_effect=lambda endpoint, **kwargs: api_responses[endpoint]), \
             patch.object(gate, "list_api", side_effect=lambda endpoint: copy.deepcopy(responses[endpoint])), \
             patch.object(gate, "review_threads", return_value=self.data["threads"]), \
             patch.object(gate.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run, \
             patch.object(gate.sys, "stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(gate.main(["--repo", "owner/repo", "--pr", "1", "--dispatch", "--once"]), 0 if allowed else 1)
            if allowed:
                run.assert_called_once()
            else:
                run.assert_not_called()
                self.assertIn(reason, stderr.getvalue())

    def test_security_or_mixed_request_signoff_cannot_clear_code_findings(self):
        for body in ("@codex security review", "@CoDeX \n SeCuRiTy\t review",
                     "@codex review\n@codex security review"):
            with self.subTest(body=body):
                self.request["body"] = body
                self.assert_dispatch(False, "No fresh Codex thumbs-up")

    def test_fresh_code_review_request_signoff_clears_resolved_findings(self):
        self.data["summary"]["body"] = self.data["summary"]["body"].replace("07:00:00Z", "07:05:00Z")
        for body in ("@codex review", "@CoDeX \n ReViEw"):
            with self.subTest(body=body):
                self.request["body"] = body
                self.assert_dispatch(True)

    def test_later_security_completion_preserves_earlier_code_signoff(self):
        for source in ("pr", "code_request"):
            with self.subTest(source=source):
                # Code Review signs off at 07:00:02, before Security Review
                # completes at 07:05:00. Both reviews cover the same commit.
                if source == "pr":
                    self.data["reactions"] = fixture()["reactions"]
                else:
                    self.data["reactions"] = []
                    self.request["body"] = "@codex review"
                    self.request_reactions = fixture()["reactions"]
                self.assert_dispatch(True)

    def test_security_review_eyes_still_block_clean_code_review(self):
        self.data["summary"]["body"] = self.data["summary"]["body"].replace("07:00:00Z", "07:05:00Z")
        self.data["reactions"] = copy.deepcopy(self.request_reactions)
        self.request_reactions[0]["content"] = "eyes"
        self.assert_dispatch(False, "still indicates a review is running")

    def test_old_security_eyes_do_not_block_after_security_completion(self):
        self.data["reactions"] = fixture()["reactions"]
        self.request_reactions = [{"user": BOT, "content": "eyes", "created_at": "2026-10-14T07:02:00Z"}]
        self.assert_dispatch(True)

    def test_later_security_completion_does_not_hide_a_new_code_review(self):
        self.data["reactions"] = fixture()["reactions"]
        self.request["body"] = "@codex review"
        self.request_reactions = [{"user": BOT, "content": "eyes", "created_at": "2026-10-14T07:02:00Z"}]
        self.assert_dispatch(False, "still indicates a review is running")

    def test_reaction_before_or_at_request_edit_cannot_be_reclassified(self):
        self.request['body'] = '@codex review'
        for edited in ['2026-10-14T07:05:03Z', '2026-10-14T07:05:02Z',
                       '2026-10-14T07:05:02.100Z', '2026-10-14T08:05:02+01:00']:
            with self.subTest(edited=edited):
                self.request['updated_at'] = edited
                self.assert_dispatch(False, 'No fresh Codex thumbs-up')

    def test_same_second_fractional_reaction_is_not_fresh(self):
        self.request['body'] = '@codex review'
        self.request['updated_at'] = '2026-10-14T07:05:02.100Z'
        self.request_reactions[0]['created_at'] = '2026-10-14T07:05:02.900Z'
        self.assert_dispatch(False, 'No fresh Codex thumbs-up')

    def test_fresh_signoff_strictly_after_edit_is_accepted(self):
        self.request['body'] = '@codex review'
        self.request['updated_at'] = '2026-10-14T08:05:01+01:00'
        self.assert_dispatch(True)

    def test_unedited_request_also_requires_reaction_after_creation(self):
        self.request['body'] = '@codex review'
        self.request['created_at'] = self.request['updated_at'] = '2026-10-14T07:05:02Z'
        self.assert_dispatch(False, 'No fresh Codex thumbs-up')
        self.request_reactions[0]['created_at'] = '2026-10-14T07:05:03Z'
        self.assert_dispatch(True)

    def test_invalid_request_timestamps_never_supply_signoff(self):
        self.request['body'] = '@codex review'
        baseline = copy.deepcopy(self.request)
        for field in ['created_at', 'updated_at']:
            for value in [None, '', 123, 'not-a-date', '2026-02-30T07:00:00Z',
                          '2026-10-14T07:00:00', '2026-10-14', '2026-10-14T07:00:00+00:99']:
                with self.subTest(field=field, value=value):
                    self.request = dict(baseline, **{field: value})
                    self.assert_dispatch(False, 'No fresh Codex thumbs-up')
            self.request = dict(baseline)
            del self.request[field]
            self.assert_dispatch(False, 'No fresh Codex thumbs-up')
        self.request = dict(baseline, created_at='2026-10-14T07:05:01Z',
                            updated_at='2026-10-14T07:05:00Z')
        self.assert_dispatch(False, 'No fresh Codex thumbs-up')

    def test_invalid_reaction_timestamp_never_supplies_signoff(self):
        self.request['body'] = '@codex review'
        for value in [None, '', 123, 'invalid', '2026-10-14T07:05:02']:
            with self.subTest(value=value):
                self.request_reactions[0]['created_at'] = value
                self.assert_dispatch(False, 'No fresh Codex thumbs-up')
        del self.request_reactions[0]['created_at']
        self.assert_dispatch(False, 'No fresh Codex thumbs-up')

    def test_eyes_blockers_survive_later_edits_and_invalid_request_dates(self):
        self.request['body'] = '@codex review'
        self.data['reactions'] = fixture()['reactions']
        self.request_reactions[0]['content'] = 'eyes'
        for edited in ['2026-10-14T07:05:03Z', None, 'invalid']:
            with self.subTest(edited=edited):
                self.request['updated_at'] = edited
                self.assert_dispatch(False, 'still indicates a review is running')

    def test_pr_signoff_does_not_depend_on_edited_comment_freshness(self):
        self.data['reactions'] = fixture()['reactions']
        self.request['body'] = '@codex review'
        self.request['updated_at'] = '2026-10-14T07:05:03Z'
        self.assert_dispatch(True)

    def test_fresh_request_reaction_still_requires_current_sha_and_completed_review(self):
        self.request['body'] = '@codex review'
        original = self.data['summary']['body']
        self.data['summary']['body'] = original.replace('`aaaaaaa`', '`bbbbbbb`')
        self.assert_dispatch(False, 'latest PR commit')
        self.data['summary']['body'] = original.replace('✅ **Completed**', '🔄 **Running**')
        self.assert_dispatch(False, 'pending, running, or incomplete')
        self.data['summary']['body'] = original.replace('07:00:00Z', '07:06:00Z')
        self.assert_dispatch(False, 'No fresh Codex thumbs-up')


class ApiAndDispatchTests(unittest.TestCase):
    def test_dispatch_uses_trusted_default_branch_with_reviewed_sha_as_data(self):
        with patch.object(gate, "check", return_value=fixture()["pr"]), \
             patch.object(gate, "gh_api", side_effect=[{"default_branch": "main"}, [{"total_count": 0, "workflow_runs": []}], [{"total_count": 0, "workflow_runs": []}]]), \
             patch.object(gate.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(gate.main(["--repo", "owner/repo", "--pr", "1", "--dispatch", "--once"]), 0)
            self.assertEqual(json.loads(run.call_args.kwargs["input"]), {
                "ref": "refs/heads/main", "inputs": {"pr_number": "1", "reviewed_sha": SHA, "dispatch_mode": "once"}})

    def test_same_prefix_replacement_commit_cannot_reuse_review(self):
        data = fixture()
        data["pr"]["head"]["sha"] = "a" * 7 + "b" * 33
        with patch.object(gate, "gh_api", return_value={"sha": SHA}):
            with self.assertRaisesRegex(gate.Blocked, "latest PR commit"):
                gate.evaluate(**data)

    def test_review_abbreviation_is_resolved_once_for_both_review_types(self):
        data = fixture()
        data["summary"]["body"] += (
            '| 🔐 **Security Review** | ✅ **Completed** '
            '<relative-time datetime="2026-10-14T07:05:00Z">now</relative-time> | `aaaaaaa` | Manual |\n'
        )
        with patch.object(gate, "gh_api", return_value={"sha": SHA}) as api:
            self.assertEqual(gate.evaluate(**data), SHA)
            api.assert_called_once_with("repos/owner/repo/commits/aaaaaaa")

    def test_ambiguous_or_unavailable_commit_resolution_blocks_dispatch(self):
        data = fixture()
        for problem in ("Ambiguous commit", "Commit not found", "GitHub API unavailable"):
            with self.subTest(problem=problem), \
                 patch.object(gate, "gh_api", side_effect=[data["pr"], gate.Blocked(problem)]), \
                 patch.object(gate, "list_api", side_effect=[[data["summary"]], data["reactions"], []]), \
                 patch.object(gate, "review_threads", return_value=[]), \
                 patch.object(gate.subprocess, "run") as run:
                self.assertEqual(gate.main(["--repo", "owner/repo", "--pr", "1", "--dispatch", "--once"]), 1)
                run.assert_not_called()

    def test_full_summary_sha_compares_exactly_without_abbreviation_lookup(self):
        data = fixture()
        data["summary"]["body"] = data["summary"]["body"].replace("`aaaaaaa`", f"`{SHA}`")
        with patch.object(gate, "gh_api") as api:
            self.assertEqual(gate.evaluate(**data), SHA)
            api.assert_not_called()

    def test_invalid_commit_resolution_never_clears_review(self):
        for resolved in ("aaaaaaa", None, "b" * 40):
            with self.subTest(resolved=resolved), patch.object(gate, "gh_api", return_value={"sha": resolved}):
                with self.assertRaisesRegex(gate.Blocked, "latest PR commit"):
                    gate.evaluate(**fixture())

    def test_completed_summary_can_be_followed_by_a_delayed_clean_reaction(self):
        with patch.object(gate, "check", side_effect=[gate.AwaitingSignoff("Waiting"), fixture()["pr"]]), patch.object(gate.time, "sleep") as sleep:
            self.assertEqual(gate.main(["--repo", "owner/repo", "--pr", "1", "--wait-for-signoff"]), 0)
            sleep.assert_called_once_with(5)

    def test_reaction_wait_is_bounded_and_never_dispatches_when_still_missing(self):
        with patch.object(gate, "check", side_effect=gate.AwaitingSignoff("Waiting")) as check, \
             patch.object(gate.time, "sleep") as sleep, patch.object(gate.subprocess, "run") as run:
            self.assertEqual(gate.main(["--repo", "owner/repo", "--pr", "1", "--wait-for-signoff", "--dispatch", "--once"]), 1)
            self.assertEqual(check.call_count, 3)
            self.assertEqual(sleep.call_count, 2)
            run.assert_not_called()

    def test_automatic_events_do_not_repeat_ci_for_the_same_commit(self):
        prior = {"id": 1, "head_sha": "b" * 40, "head_branch": "main", "event": "workflow_dispatch",
                 "display_title": f"Reviewed CI / PR #1 / {SHA}"}
        with patch.object(gate, "check", return_value=fixture()["pr"]), \
             patch.object(gate, "gh_api", side_effect=[{"default_branch": "main"}, [{"total_count": 1, "workflow_runs": [prior]}], [{"total_count": 0, "workflow_runs": []}]]), \
             patch.object(gate.subprocess, "run") as run:
            self.assertEqual(gate.main(["--repo", "owner/repo", "--pr", "1", "--dispatch", "--once"]), 0)
            run.assert_not_called()

    def test_automatic_event_dispatches_when_no_prior_run_exists(self):
        with patch.object(gate, "check", return_value=fixture()["pr"]), \
             patch.object(gate, "gh_api", side_effect=[{"default_branch": "main"}, [{"total_count": 0, "workflow_runs": []}], [{"total_count": 0, "workflow_runs": []}]]), \
             patch.object(gate.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(gate.main(["--repo", "owner/repo", "--pr", "1", "--dispatch", "--once"]), 0)
            run.assert_called_once()

    def test_unrelated_runs_cannot_suppress_reviewed_ci(self):
        for prior in (
            {"head_branch": "feature", "event": "workflow_dispatch", "display_title": f"Reviewed CI / PR #1 / {SHA}"},
            {"head_branch": "main", "event": "workflow_dispatch", "display_title": f"Reviewed CI / PR #2 / {SHA}"},
            {"head_branch": "main", "event": "workflow_dispatch", "display_title": "Reviewed CI / PR #1 / " + "b" * 40},
            {"head_branch": "main", "event": "push", "display_title": f"Reviewed CI / PR #1 / {SHA}"},
        ):
            with self.subTest(prior=prior), patch.object(gate, "check", return_value=fixture()["pr"]), \
                 patch.object(gate, "gh_api", side_effect=[{"default_branch": "main"}, [{"total_count": 1, "workflow_runs": [dict(prior, id=1)]}], [{"total_count": 0, "workflow_runs": []}]]), \
                 patch.object(gate.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
                self.assertEqual(gate.main(["--repo", "owner/repo", "--pr", "1", "--dispatch", "--once"]), 0)
                run.assert_called_once()

    def test_older_gh_consecutive_page_output_is_supported(self):
        with patch.object(gate.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout='[1,2]\n[3]\n')) as run:
            self.assertEqual(gate.list_api("endpoint"), [1, 2, 3])
            self.assertNotIn("--slurp", run.call_args.args[0])

    def test_rest_pagination_does_not_drop_later_pages(self):
        with patch.object(gate, "gh_api", return_value=[[1, 2], [3]]) as api:
            self.assertEqual(gate.list_api("endpoint"), [1, 2, 3])
            api.assert_called_once_with("endpoint", paginate=True)

    def test_graphql_pagination_includes_unresolved_threads_on_second_page(self):
        def response(nodes, more, cursor):
            return SimpleNamespace(returncode=0, stdout=json.dumps({"data": {"repository": {"pullRequest": {
                "headRefOid": SHA, "baseRefOid": "b" * 40, "reviewDecision": None,
                "reviewThreads": {"nodes": nodes, "pageInfo": {"hasNextPage": more, "endCursor": cursor}}
            }}}}))
        with patch.object(gate.subprocess, "run", side_effect=[
            response([{"isResolved": True}], True, "cursor"),
            response([{"isResolved": False}], False, None),
        ]) as run:
            self.assertEqual(gate.review_threads("owner/repo", 1, SHA, "b" * 40), [{"isResolved": True}, {"isResolved": False}])
            self.assertEqual(json.loads(run.call_args.kwargs["input"])["variables"]["after"], "cursor")

    def test_api_failures_block_dispatch(self):
        with patch.object(gate.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout="")):
            self.assertEqual(gate.main(["--repo", "owner/repo", "--pr", "1", "--dispatch", "--once"]), 1)

    def test_blocked_review_never_dispatches(self):
        with patch.object(gate, "check", side_effect=gate.Blocked("Unresolved threads")), patch.object(gate.subprocess, "run") as run:
            self.assertEqual(gate.main(["--repo", "owner/repo", "--pr", "1", "--dispatch", "--once"]), 1)
            run.assert_not_called()

    def test_check_only_never_dispatches(self):
        with patch.object(gate, "check", return_value=fixture()["pr"]), patch.object(gate.subprocess, "run") as run:
            self.assertEqual(gate.main(["--repo", "owner/repo", "--pr", "1"]), 0)
            run.assert_not_called()

    def test_push_during_api_reads_invalidates_clearance(self):
        data = fixture()
        newer = copy.deepcopy(data["pr"])
        newer["head"]["sha"] = "b" * 40
        with patch.object(gate, "gh_api", side_effect=[data["pr"], {"sha": SHA}, newer]), \
             patch.object(gate, "list_api", side_effect=[[data["summary"]], data["reactions"], []]), \
             patch.object(gate, "review_threads", return_value=[]):
            with self.assertRaisesRegex(gate.Blocked, "changed while checking"):
                gate.check("owner/repo", 1)

    def test_workflow_must_run_on_trusted_default_branch(self):
        with patch.dict(gate.os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/feature"}), \
             patch.object(gate, "gh_api", return_value={"default_branch": "main"}), patch.object(gate, "check") as check:
            self.assertEqual(gate.main(["--repo", "owner/repo", "--pr", "1", "--expected-sha", SHA]), 1)
            check.assert_not_called()

    def test_trusted_workflow_sha_is_separate_from_verified_checkout_sha(self):
        with patch.dict(gate.os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "b" * 40}), \
             patch.object(gate, "gh_api", return_value={"default_branch": "main"}), \
             patch.object(gate, "check", return_value=fixture()["pr"]) as check:
            self.assertEqual(gate.main(["--repo", "owner/repo", "--pr", "1", "--expected-sha", SHA]), 0)
            check.assert_called_once_with("owner/repo", 1, SHA)

class MigrationSecurityTests(unittest.TestCase):
    def test_bot_id_type_and_login_are_all_required(self):
        for field, value in [('id', 123), ('type', 'User'), ('login', 'other')]:
            for location in ['summary', 'reaction']:
                data = copy.deepcopy(fixture())
                user = data['summary']['user'] if location == 'summary' else data['reactions'][0]['user']
                user[field] = value
                with self.subTest(field=field, location=location), patch.object(gate, 'gh_api', return_value={'sha': SHA}):
                    with self.assertRaises(gate.Blocked):
                        gate.evaluate(**data)

    def test_missing_thread_state_and_unknown_mergeability_fail_closed(self):
        for field in ['thread', 'mergeable']:
            data = fixture()
            if field == 'thread':
                data['threads'] = [{}]
            else:
                data['pr']['mergeable'] = None
            with self.subTest(field=field), self.assertRaises(gate.Blocked):
                gate.evaluate(**data)

    def test_native_review_requirements_and_graphql_head_are_enforced(self):
        for decision, head, base in [('REVIEW_REQUIRED', SHA, 'b'*40), ('CHANGES_REQUESTED', SHA, 'b'*40), (None, 'c'*40, 'b'*40), (None, SHA, 'c'*40)]:
            payload = {'data': {'repository': {'pullRequest': {
                'headRefOid': head, 'baseRefOid': base, 'reviewDecision': decision,
                'reviewThreads': {'nodes': [], 'pageInfo': {'hasNextPage': False, 'endCursor': None}}
            }}}}
            with self.subTest(decision=decision, head=head, base=base), patch.object(gate.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(payload))):
                with self.assertRaises(gate.Blocked):
                    gate.review_threads('owner/repo', 1, SHA, 'b'*40)

    def test_repeated_graphql_cursor_fails_closed(self):
        payload = {'data': {'repository': {'pullRequest': {
            'headRefOid': SHA, 'baseRefOid': 'b'*40, 'reviewDecision': None,
            'reviewThreads': {'nodes': [], 'pageInfo': {'hasNextPage': True, 'endCursor': 'same'}}
        }}}}
        with patch.object(gate.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(payload))):
            with self.assertRaisesRegex(gate.Blocked, 'cursor'):
                gate.review_threads('owner/repo', 1, SHA, 'b'*40)

    def test_late_clearance_change_prevents_dispatch(self):
        with patch.object(gate, 'check', side_effect=[fixture()['pr'], gate.Blocked('Changed')]) as check, patch.object(gate, 'gh_api', side_effect=[{'default_branch': 'main'}, [{'total_count': 0, 'workflow_runs': []}], [{"total_count": 0, "workflow_runs": []}]]), patch.object(gate.subprocess, 'run') as run:
            self.assertEqual(gate.main(['--repo','owner/repo','--pr','1','--dispatch','--once']), 1)
            self.assertEqual(check.call_args.args, ('owner/repo', 1, SHA))
            run.assert_not_called()

    def test_native_rerun_control_never_dispatches(self):
        with patch.dict(gate.os.environ, {'GITHUB_ACTIONS':'true', 'GITHUB_REF':'refs/heads/main', 'GITHUB_RUN_ATTEMPT':'2'}), patch.object(gate, 'gh_api', return_value={'default_branch':'main'}), patch.object(gate, 'check') as check, patch.object(gate.subprocess, 'run') as run:
            self.assertEqual(gate.main(['--repo','owner/repo','--pr','1','--dispatch', '--once']), 1)
            check.assert_not_called()
            run.assert_not_called()

    def test_malformed_security_row_cannot_be_ignored(self):
        data = fixture()
        data['summary']['body'] += '| **Security Review** | Running | too few cells |\n'
        with patch.object(gate, 'gh_api', return_value={'sha': SHA}):
            with self.assertRaisesRegex(gate.Blocked, 'Unrecognized'):
                gate.evaluate(**data)


if __name__ == "__main__":
    unittest.main()
