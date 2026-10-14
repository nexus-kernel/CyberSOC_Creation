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
        if hasattr(gate, 'require_legacy_disabled'):
            isolation = patch.object(gate, 'require_legacy_disabled')
            self.isolation = isolation.start()
            self.addCleanup(isolation.stop)

    def prior(self, **updates):
        run = {'id': 10, 'head_branch': 'main', 'event': 'workflow_dispatch',
               'display_title': f'Reviewed CI / PR #1 / {SHA}',
               'status': 'completed', 'conclusion': 'failure'}
        run.update(updates)
        return run

    def invoke(self, pages, *, mode='--retry-failed', check_error=None, late_error=None):
        pr = {'head': {'sha': SHA}}
        checks = [check_error or pr, late_error or pr]
        with patch.object(gate, 'check', side_effect=checks) as check, \
             patch.object(gate, 'gh_api', side_effect=[{'default_branch': 'main'}, pages]) as api, \
             patch.object(gate.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as post:
            result = gate.main(['--repo', 'owner/repo', '--pr', '1', '--dispatch', mode])
        return result, check, post, api

    def test_manual_failed_cancelled_and_timed_out_same_sha_retry(self):
        for conclusion in ['failure', 'cancelled', 'timed_out']:
            with self.subTest(conclusion=conclusion):
                result, check, post, api = self.invoke([{'workflow_runs': [self.prior(conclusion=conclusion)]}])
                self.assertEqual(result, 0)
                post.assert_called_once()
                self.assertEqual(check.call_count, 2)
                self.assertEqual(check.call_args.args, ('owner/repo', 1, SHA))
                self.assertEqual(json.loads(post.call_args.kwargs['input']), {
                    'ref': 'refs/heads/main', 'inputs': {'pr_number': '1', 'reviewed_sha': SHA}})
                self.assertTrue(api.call_args.kwargs['paginate'])

    def test_automatic_failed_or_cancelled_run_is_not_retried(self):
        for conclusion in ['failure', 'cancelled', 'timed_out', 'success']:
            with self.subTest(conclusion=conclusion):
                result, _, post, _ = self.invoke([{'workflow_runs': [self.prior(conclusion=conclusion)]}], mode='--once')
                self.assertEqual(result, 0)
                post.assert_not_called()

    def test_manual_first_run_is_allowed(self):
        result, check, post, _ = self.invoke([{'workflow_runs': []}])
        self.assertEqual(result, 0)
        self.assertEqual(check.call_count, 2)
        post.assert_called_once()

    def test_manual_retry_does_not_duplicate_any_active_same_sha_run(self):
        for status in ['queued', 'in_progress', 'waiting', 'pending', 'requested', 'unknown']:
            pages = [{'workflow_runs': [self.prior(id=20)]},
                     {'workflow_runs': [self.prior(id=10, status=status, conclusion=None)]}]
            with self.subTest(status=status):
                result, _, post, _ = self.invoke(pages)
                self.assertEqual(result, 0)
                post.assert_not_called()

    def test_latest_completed_success_suppresses_retry_of_older_failure(self):
        for order in [[self.prior(id=20, conclusion='success'), self.prior(id=10)],
                      [self.prior(id=10), self.prior(id=20, conclusion='success')]]:
            result, _, post, _ = self.invoke([{'workflow_runs': order}])
            self.assertEqual(result, 0)
            post.assert_not_called()

    def test_latest_failure_can_retry_after_older_success(self):
        result, _, post, _ = self.invoke([{'workflow_runs': [self.prior(id=10, conclusion='success')]},
                                         {'workflow_runs': [self.prior(id=20)]}])
        self.assertEqual(result, 0)
        post.assert_called_once()

    def test_unrelated_run_cannot_suppress_manual_retry(self):
        for unrelated in [self.prior(head_branch='feature'), self.prior(event='push'),
                          self.prior(display_title=f'Reviewed CI / PR #2 / {SHA}'),
                          self.prior(display_title='Reviewed CI / PR #1 / ' + 'b'*40)]:
            unrelated.update(status='queued', conclusion=None)
            result, _, post, _ = self.invoke([{'workflow_runs': [unrelated, self.prior()]}])
            self.assertEqual(result, 0)
            post.assert_called_once()

    def test_unknown_run_evidence_fails_closed(self):
        cases = [None, [], [{}], [{'workflow_runs': None}],
                 [{'workflow_runs': [self.prior(status=None)]}],
                 [{'workflow_runs': [self.prior(id=None)]}],
                 [{'workflow_runs': [self.prior(conclusion=None)]}],
                 [{'workflow_runs': [self.prior(conclusion='skipped')]}],
                 gate.Blocked('Run lookup unavailable')]
        for pages in cases:
            with self.subTest(pages=pages):
                result, _, post, _ = self.invoke(pages)
                self.assertEqual(result, 1)
                post.assert_not_called()

    def test_fresh_clearance_failure_and_late_head_change_prevent_retry(self):
        for reason in ['Draft PR', 'No fresh thumbs-up', 'Stale SHA', 'Unresolved thread', 'Native review required']:
            result, _, post, _ = self.invoke([{'workflow_runs': [self.prior()]}], check_error=gate.Blocked(reason))
            self.assertEqual(result, 1)
            post.assert_not_called()
        result, check, post, _ = self.invoke([{'workflow_runs': [self.prior()]}], late_error=gate.Blocked('Head changed'))
        self.assertEqual(result, 1)
        self.assertEqual(check.call_args.args, ('owner/repo', 1, SHA))
        post.assert_not_called()

    def test_manual_mode_does_not_bypass_void_isolation(self):
        if not hasattr(gate, 'require_legacy_disabled'):
            return  # Rapid7/Sentinel have no Void-specific isolation prerequisite.
        self.isolation.side_effect = gate.Blocked('Legacy workflow active')
        result, check, post, _ = self.invoke([{'workflow_runs': [self.prior()]}])
        self.assertEqual(result, 1)
        check.assert_not_called()
        post.assert_not_called()

    def test_invalid_mode_combinations_are_rejected(self):
        for arguments in [['--once', '--retry-failed', '--dispatch'], ['--retry-failed']]:
            with patch.object(gate, 'check') as check, self.assertRaises(SystemExit):
                gate.main(['--repo', 'owner/repo', '--pr', '1', *arguments])
            check.assert_not_called()

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
                           TRIGGER_EVENT=event, GITHUB_REPOSITORY='owner/repo', PR_NUMBER='1',
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
