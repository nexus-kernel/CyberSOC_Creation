import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('retry_gate', ROOT / '.github/scripts/review_gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
SHA = 'a' * 40


class ManualRetryTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(gate.os.environ, {'GITHUB_ACTIONS': 'false', 'GITHUB_OUTPUT': ''})
        env.start()
        self.addCleanup(env.stop)

    def prior(self, **updates):
        run = {'id': 10, 'run_attempt': 1, 'head_branch': 'main', 'event': 'workflow_dispatch',
               'display_title': f'Reviewed CI / PR #1 / {SHA}',
               'status': 'completed', 'conclusion': 'failure'}
        run.update(updates)
        return run

    def invoke(self, pages, *, mode='--retry-failed', check_error=None, late_error=None):
        pr = {'head': {'sha': SHA}}
        checks = [check_error or pr, late_error or pr]
        with patch.object(gate, 'check', side_effect=checks) as check, \
             patch.object(gate, 'gh_api', side_effect=[{'default_branch': 'main'}, [{'total_count': 0, 'workflow_runs': []}], pages]) as api, \
             patch.object(gate.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as post:
            result = gate.main(['--repo', 'owner/repo', '--pr', '1', '--dispatch', mode])
        return result, check, post, api

    def test_manual_failed_cancelled_and_timed_out_same_sha_retry(self):
        for conclusion in ['failure', 'cancelled', 'timed_out']:
            with self.subTest(conclusion=conclusion):
                result, check, post, api = self.invoke([{'total_count': 1, 'workflow_runs': [self.prior(conclusion=conclusion)]}])
                self.assertEqual(result, 0)
                post.assert_called_once()
                self.assertEqual(check.call_count, 2)
                self.assertEqual(check.call_args.args, ('owner/repo', 1, SHA))
                self.assertEqual(json.loads(post.call_args.kwargs['input']), {
                    'ref': 'refs/heads/main', 'inputs': {'pr_number': '1', 'reviewed_sha': SHA, 'dispatch_mode': 'retry-failed'}})
                self.assertTrue(api.call_args.kwargs['paginate'])

    def test_automatic_failed_or_cancelled_run_is_not_retried(self):
        for conclusion in ['failure', 'cancelled', 'timed_out', 'success']:
            with self.subTest(conclusion=conclusion):
                result, _, post, _ = self.invoke([{'total_count': 1, 'workflow_runs': [self.prior(conclusion=conclusion)]}], mode='--once')
                self.assertEqual(result, 0)
                post.assert_not_called()

    def test_native_rerun_cannot_launder_success_into_retryable_failure(self):
        prior = self.prior(conclusion='success')
        prior.update(run_attempt=2, conclusion='failure')
        for mode in ['--once', '--retry-failed']:
            result, _, post, _ = self.invoke(
                [{'total_count': 1, 'workflow_runs': [prior]}], mode=mode)
            self.assertEqual(result, 1)
            post.assert_not_called()

    def test_uncertain_attempt_history_blocks_launch(self):
        for attempt in [None, True, False, '1', 0, -1, 1.0, 2, 1000]:
            for mode in ['--once', '--retry-failed']:
                with self.subTest(attempt=attempt, mode=mode):
                    prior = self.prior(run_attempt=attempt)
                    if attempt is None:
                        prior.pop('run_attempt')
                    result, _, post, _ = self.invoke(
                        [{'total_count': 1, 'workflow_runs': [prior]}], mode=mode)
                    self.assertEqual(result, 1)
                    post.assert_not_called()

    def test_manual_first_run_is_allowed(self):
        result, check, post, _ = self.invoke([{'total_count': 0, 'workflow_runs': []}])
        self.assertEqual(result, 0)
        self.assertEqual(check.call_count, 2)
        post.assert_called_once()

    def test_manual_retry_does_not_duplicate_any_active_same_sha_run(self):
        for status in ['queued', 'in_progress', 'waiting', 'pending', 'requested', 'unknown']:
            pages = [{'total_count': 2, 'workflow_runs': [self.prior(id=20)]},
                     {'total_count': 2, 'workflow_runs': [self.prior(id=10, status=status, conclusion=None)]}]
            with self.subTest(status=status):
                result, _, post, _ = self.invoke(pages)
                self.assertEqual(result, 0)
                post.assert_not_called()

    def test_latest_completed_success_suppresses_retry_of_older_failure(self):
        for order in [[self.prior(id=20, conclusion='success'), self.prior(id=10)],
                      [self.prior(id=10), self.prior(id=20, conclusion='success')]]:
            result, _, post, _ = self.invoke([{'total_count': 2, 'workflow_runs': order}])
            self.assertEqual(result, 0)
            post.assert_not_called()

    def test_later_failed_admission_cannot_erase_older_success(self):
        result, _, post, _ = self.invoke([{'total_count': 2, 'workflow_runs': [self.prior(id=10, conclusion='success')]},
                                         {'total_count': 2, 'workflow_runs': [self.prior(id=20)]}])
        self.assertEqual(result, 0)
        post.assert_not_called()

    def test_unrelated_run_cannot_suppress_manual_retry(self):
        for unrelated in [self.prior(head_branch='feature'), self.prior(event='push'),
                          self.prior(display_title=f'Reviewed CI / PR #2 / {SHA}'),
                          self.prior(display_title='Reviewed CI / PR #1 / ' + 'b'*40)]:
            unrelated.update(id=1, status='queued', conclusion=None)
            result, _, post, _ = self.invoke([{'total_count': 2, 'workflow_runs': [unrelated, self.prior()]}])
            self.assertEqual(result, 0)
            post.assert_called_once()

    def test_unknown_run_evidence_fails_closed(self):
        cases = [None, [], [{}], [{'total_count': 1, 'workflow_runs': None}],
                 [{'total_count': 1, 'workflow_runs': [self.prior(status=None)]}],
                 [{'total_count': 1, 'workflow_runs': [self.prior(id=None)]}],
                 [{'total_count': 1, 'workflow_runs': [self.prior(conclusion=None)]}],
                 [{'total_count': 1, 'workflow_runs': [self.prior(conclusion='skipped')]}],
                 gate.Blocked('Run lookup unavailable')]
        for pages in cases:
            with self.subTest(pages=pages):
                result, _, post, _ = self.invoke(pages)
                self.assertEqual(result, 1)
                post.assert_not_called()

    def test_fresh_clearance_failure_and_late_head_change_prevent_retry(self):
        for reason in ['Draft PR', 'No fresh thumbs-up', 'Stale SHA', 'Unresolved thread', 'Native review required']:
            result, _, post, _ = self.invoke([{'total_count': 1, 'workflow_runs': [self.prior()]}], check_error=gate.Blocked(reason))
            self.assertEqual(result, 1)
            post.assert_not_called()
        result, check, post, _ = self.invoke([{'total_count': 1, 'workflow_runs': [self.prior()]}], late_error=gate.Blocked('Head changed'))
        self.assertEqual(result, 1)
        self.assertEqual(check.call_args.args, ('owner/repo', 1, SHA))
        post.assert_not_called()

    def test_invalid_mode_combinations_are_rejected(self):
        for arguments in [['--once', '--retry-failed', '--dispatch'], ['--retry-failed']]:
            with patch.object(gate, 'check') as check, self.assertRaises(SystemExit):
                gate.main(['--repo', 'owner/repo', '--pr', '1', *arguments])
            check.assert_not_called()

    def history(self, runs, total=None):
        count = len(runs) if total is None else total
        return [{'total_count': count, 'workflow_runs': runs[i:i + 100]}
                for i in range(0, len(runs), 100)] or [{'total_count': count, 'workflow_runs': []}]

    def test_capped_history_never_dispatches_in_either_mode(self):
        # Reproduce 1,000 returned runs with an omitted older same-PR/SHA
        # success. Also reject a saturated count that itself reports only 1,000.
        runs = [self.prior(id=i, display_title='Unrelated run') for i in range(1, 1001)]
        for total in [1000, 1001, 5000]:
            for mode in ['--once', '--retry-failed']:
                with self.subTest(total=total, mode=mode):
                    result, check, post, _ = self.invoke(self.history(runs, total), mode=mode)
                    self.assertEqual(result, 1)
                    self.assertEqual(check.call_count, 1)
                    post.assert_not_called()

    def test_complete_history_below_cap_can_authorize_first_run(self):
        runs = [self.prior(id=i, display_title='Unrelated run') for i in range(1, 1000)]
        for mode in ['--once', '--retry-failed']:
            with self.subTest(mode=mode):
                result, check, post, _ = self.invoke(self.history(runs), mode=mode)
                self.assertEqual(result, 0)
                self.assertEqual(check.call_count, 2)
                post.assert_called_once()

    def test_later_page_success_suppresses_both_modes(self):
        runs = [self.prior(id=i, display_title='Unrelated run') for i in range(1, 101)]
        runs.append(self.prior(id=101, conclusion='success'))
        for mode in ['--once', '--retry-failed']:
            result, _, post, _ = self.invoke(self.history(runs), mode=mode)
            self.assertEqual(result, 0)
            post.assert_not_called()

    def test_complete_history_retains_manual_retry_only_for_failure(self):
        runs = [self.prior(id=i, display_title='Unrelated run') for i in range(1, 101)]
        runs.append(self.prior(id=101, conclusion='failure'))
        for mode in ['--once', '--retry-failed']:
            result, _, post, _ = self.invoke(self.history(runs), mode=mode)
            self.assertEqual(result, 0)
            self.assertEqual(post.call_count, int(mode == '--retry-failed'))

    def test_missing_or_malformed_history_count_blocks_both_modes(self):
        cases = [{'workflow_runs': []}]
        cases += [{'total_count': value, 'workflow_runs': []}
                  for value in [None, True, False, -1, 0.0, '0', [], {}]]
        for page in cases:
            for mode in ['--once', '--retry-failed']:
                with self.subTest(page=page, mode=mode):
                    result, _, post, _ = self.invoke([page], mode=mode)
                    self.assertEqual(result, 1)
                    post.assert_not_called()

    def test_inconsistent_history_blocks_both_modes(self):
        cases = [
            self.history([self.prior()], total=2),  # Missing a returned run.
            self.history([self.prior()], total=0),  # More runs than reported.
            [{'total_count': 2, 'workflow_runs': [self.prior(id=1)]},
             {'total_count': 3, 'workflow_runs': [self.prior(id=2)]}],
            self.history([self.prior(), self.prior()]),  # Same-page duplication.
            [{'total_count': 2, 'workflow_runs': [self.prior()]},
             {'total_count': 2, 'workflow_runs': [self.prior()]}],
            [{'total_count': 0, 'workflow_runs': []}, {'total_count': 0, 'workflow_runs': []}],
            [{'total_count': 101, 'workflow_runs': [self.prior(id=i) for i in range(1, 102)]}],
        ]
        for pages in cases:
            for mode in ['--once', '--retry-failed']:
                with self.subTest(pages=pages, mode=mode):
                    result, _, post, _ = self.invoke(pages, mode=mode)
                    self.assertEqual(result, 1)
                    post.assert_not_called()

    def test_malformed_run_records_cannot_hide_prior_runs(self):
        cases = [None, 'run', {}, self.prior(id=True), self.prior(id=0), self.prior(id='1')]
        for key in ['display_title', 'head_branch', 'event']:
            for value in [None, '', 1]:
                cases.append(self.prior(**{key: value}))
        for run in cases:
            for mode in ['--once', '--retry-failed']:
                with self.subTest(run=run, mode=mode):
                    result, _, post, _ = self.invoke(self.history([run]), mode=mode)
                    self.assertEqual(result, 1)
                    post.assert_not_called()

    def test_actual_workflow_selects_manual_and_automatic_modes(self):
        from workflow_support import parse_workflow
        workflow = parse_workflow((ROOT / '.github/workflows/review-clearance.yml').read_text())
        step = workflow['jobs']['clearance']['steps'][-1]
        self.assertEqual(step['env']['TRIGGER_EVENT'], '${{ github.event_name }}')
        self.assertFalse(workflow['concurrency']['cancel-in-progress'])
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            stub = directory / 'python3'
            stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE_ARGS"\n')
            stub.chmod(0o755)
            capture = directory / 'args'
            for event, mode, absent in [('workflow_dispatch', '--retry-failed', '--once'),
                                        ('issue_comment', '--once', '--retry-failed')]:
                env = dict(os.environ, PATH=str(directory)+os.pathsep+os.environ['PATH'],
                           TRIGGER_EVENT=event, REVIEWED_SHA='', DISPATCH_MODE='', GITHUB_REPOSITORY='owner/repo', PR_NUMBER='1',
                           CAPTURE_ARGS=str(capture), GITHUB_STEP_SUMMARY=str(directory/'summary'))
                result = subprocess.run(['bash', '-e', '-c', step['run']], env=env,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                args = capture.read_text().splitlines()
                self.assertIn(mode, args)
                self.assertNotIn(absent, args)
                self.assertIn('--dispatch', args)
                self.assertIn('--wait-for-signoff', args)


if __name__ == '__main__':
    unittest.main()
