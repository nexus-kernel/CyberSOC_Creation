import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('admission_gate', ROOT / '.github/scripts/review_gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
SHA = 'a' * 40


class AdmissionTests(unittest.TestCase):
    def run_record(self, run_id=20, **values):
        record = dict(id=run_id, run_attempt=1, display_title=f'Reviewed CI / PR #1 / {SHA}',
                      head_branch='main', event='workflow_dispatch', status='in_progress', conclusion=None)
        record.update(values)
        return record

    def invoke(self, *, previous=(), current=None, mode='--retry-failed', context=None,
               check_error=None, late_error=None, controller_pages=None, legacy_previous=()):
        current = [self.run_record()] if current is None else current
        records = list(previous) + current
        pages = controller_pages if controller_pages is not None else [
            dict(total_count=len(records), workflow_runs=records)]
        env = dict(GITHUB_ACTIONS='true', GITHUB_REF='refs/heads/main', GITHUB_RUN_ATTEMPT='1',
                   GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ID='20',
                   GITHUB_WORKFLOW_REF='owner/repo/.github/workflows/review-clearance.yml@refs/heads/main')
        env.update(context or {})
        pr = {'head': {'sha': SHA}}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            env['GITHUB_OUTPUT'] = str(output)
            with patch.dict(gate.os.environ, env), \
                 patch.object(gate, 'gh_api', side_effect=[{'default_branch': 'main'},
                     [{'total_count': len(legacy_previous), 'workflow_runs': list(legacy_previous)}], pages]), \
                 patch.object(gate, 'check', side_effect=[check_error or pr, late_error or pr]) as check, \
                 patch.object(gate.subprocess, 'run') as post, \
                 patch.object(gate.sys, 'stderr', new_callable=io.StringIO):
                result = gate.main(['--repo', 'owner/repo', '--pr', '1', '--expected-sha', SHA,
                                    '--admit-run', mode])
                content = output.read_text() if output.exists() else ''
            return result, content, check.call_count, post.call_count

    def denied(self, **kwargs):
        result, content, _, posts = self.invoke(**kwargs)
        self.assertEqual(result, 1)
        self.assertEqual(content, '')  # No SHA can reach tests or status reporter.
        self.assertEqual(posts, 0)

    def test_genuine_controller_first_run_passes_both_modes(self):
        for mode in ['--once', '--retry-failed']:
            self.assertEqual(self.invoke(mode=mode), (0, f'sha={SHA}\n', 2, 0))

    def test_direct_execution_cannot_repeat_any_success(self):
        success = self.run_record(10, status='completed', conclusion='success')
        denied_retry = self.run_record(15, status='completed', conclusion='failure')
        for mode in ['--once', '--retry-failed']:
            self.denied(previous=[success], mode=mode)
            self.denied(previous=[success, denied_retry], mode=mode)

    def test_prior_success_under_old_workflow_still_blocks(self):
        self.denied(legacy_previous=[self.run_record(10, status='completed', conclusion='success')])

    def test_direct_execution_cannot_duplicate_active_run(self):
        for status in ['in_progress', 'queued', 'pending', 'waiting', 'requested']:
            self.denied(previous=[self.run_record(10, status=status)])

    def test_normal_failed_cancelled_timed_out_retry_requires_manual_mode(self):
        for conclusion in ['failure', 'cancelled', 'timed_out']:
            prior = self.run_record(10, status='completed', conclusion=conclusion)
            self.assertEqual(self.invoke(previous=[prior]), (0, f'sha={SHA}\n', 2, 0))
            self.denied(previous=[prior], mode='--once')

    def test_direct_retry_does_not_bypass_fresh_or_exact_sha_clearance(self):
        for reason in ['stale SHA', 'no fresh signoff', 'draft', 'unresolved threads', 'request edited']:
            self.denied(check_error=gate.Blocked(reason))
        self.denied(late_error=gate.Blocked('head changed after admission history'))

    def test_native_rerun_cannot_reuse_admission(self):
        self.denied(context={'GITHUB_RUN_ATTEMPT': '2'})

    def test_success_then_rejected_native_rerun_cannot_authorize_new_execution(self):
        # GitHub retains the run ID but replaces its conclusion on attempt 2.
        prior = self.run_record(10, status='completed', conclusion='success')
        prior.update(run_attempt=2, conclusion='failure')
        for mode in ['--once', '--retry-failed']:
            self.denied(previous=[prior], mode=mode)
            self.denied(legacy_previous=[prior], mode=mode)

    def test_current_run_attempt_must_be_verified_before_exclusion(self):
        for attempt in [None, True, '1', 0, 2]:
            self.denied(current=[self.run_record(run_attempt=attempt)])

    def test_cannot_supply_or_spoof_current_run_identity(self):
        for context in [{'GITHUB_RUN_ID': ''}, {'GITHUB_RUN_ID': '10'},
                        {'GITHUB_EVENT_NAME': 'push'}, {'GITHUB_ACTIONS': 'false'},
                        {'GITHUB_REF': 'refs/heads/feature'},
                        {'GITHUB_WORKFLOW_REF': 'owner/repo/.github/workflows/evil.yml@refs/heads/main'},
                        {'GITHUB_WORKFLOW_REF': 'owner/repo/.github/workflows/review-clearance.yml@refs/heads/feature'}]:
            self.denied(context=context)
        self.denied(current=[])
        self.denied(current=[self.run_record(status='completed', conclusion='failure')])
        self.denied(current=[self.run_record(display_title='Other PR')])

    def test_capped_or_inconsistent_controller_history_blocks_admission(self):
        for total in [None, 2, 1000, 1001]:
            self.denied(controller_pages=[{'total_count': total, 'workflow_runs': [self.run_record()]}])

    def test_current_id_from_retired_workflow_cannot_be_excluded(self):
        run = dict(self.run_record(), history_workflow='reviewed-ci.yml')
        env = dict(GITHUB_ACTIONS='true', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ID='20',
                   GITHUB_WORKFLOW_REF='owner/repo/.github/workflows/review-clearance.yml@refs/heads/main')
        with patch.dict(gate.os.environ, env), self.assertRaises(gate.Blocked):
            gate.exclude_admission_run([run], 'owner/repo', 'main')

    def test_launcher_dispatch_targets_controller_and_carries_mode(self):
        for mode, value in [('--once', 'once'), ('--retry-failed', 'retry-failed')]:
            with patch.dict(gate.os.environ, {'GITHUB_ACTIONS': 'false', 'GITHUB_OUTPUT': ''}), \
                 patch.object(gate, 'check', return_value={'head': {'sha': SHA}}), \
                 patch.object(gate, 'gh_api', side_effect=[{'default_branch': 'main'},
                     [{'total_count': 0, 'workflow_runs': []}], [{'total_count': 0, 'workflow_runs': []}]]), \
                 patch.object(gate.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as post:
                self.assertEqual(gate.main(['--repo', 'owner/repo', '--pr', '1', '--dispatch', mode]), 0)
                self.assertIn('repos/owner/repo/actions/workflows/review-clearance.yml/dispatches', post.call_args.args[0])
                self.assertEqual(json.loads(post.call_args.kwargs['input'])['inputs']['dispatch_mode'], value)

    def test_no_unguarded_dispatch_or_admission_mode(self):
        for args in [['--dispatch'], ['--admit-run'], ['--admit-run', '--once'],
                     ['--admit-run', '--dispatch', '--once', '--expected-sha', SHA]]:
            with patch.object(gate, 'check') as check, self.assertRaises(SystemExit):
                gate.main(['--repo', 'owner/repo', '--pr', '1', *args])
            check.assert_not_called()


if __name__ == '__main__':
    unittest.main()
