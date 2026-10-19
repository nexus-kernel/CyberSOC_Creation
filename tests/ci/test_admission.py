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
               check_error=None, late_error=None, controller_pages=None, job_pages=None):
        current = [self.run_record()] if current is None else current
        records = list(previous) + current
        pages = controller_pages if controller_pages is not None else [
            dict(total_count=len(records), workflow_runs=records)]
        env = dict(GITHUB_ACTIONS='true', GITHUB_REF='refs/heads/main', GITHUB_RUN_ATTEMPT='1',
                   GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ID='20',
                   GITHUB_WORKFLOW_REF='owner/repo/.github/workflows/review-clearance.yml@refs/heads/main')
        env.update(context or {})
        pr = {'head': {'sha': SHA}}
        def api(endpoint, **kwargs):
            if endpoint == 'repos/owner/repo':
                return {'default_branch': 'main'}
            if '/actions/workflows/reviewed-ci.yml/' in endpoint:
                return [{'total_count': 0, 'workflow_runs': []}]
            if '/actions/workflows/' in endpoint:
                return pages
            run_id = int(endpoint.split('/runs/')[1].split('/')[0])
            if '/jobs' in endpoint:
                if job_pages is not None and run_id in job_pages:
                    result = job_pages[run_id]
                    if isinstance(result, Exception):
                        raise result
                    return result
                return [{'total_count': 0, 'jobs': []}] if run_id > 20 else [
                    {'total_count': 1, 'jobs': [{'id': 1, 'run_id': run_id, 'run_attempt': 1,
                                               'started_at': '2026-10-19T00:00:00Z'}]}]
            return next(dict(run) for page in pages for run in page['workflow_runs'] if run['id'] == run_id)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            env['GITHUB_OUTPUT'] = str(output)
            with patch.dict(gate.os.environ, env), \
                 patch.object(gate, 'gh_api', side_effect=api), \
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

    def test_three_or_more_deliveries_do_not_poison_running_winner(self):
        for canceled_ids in [[30], [30, 40, 50]]:
            others = [self.run_record(i, status='completed', conclusion='cancelled') for i in canceled_ids]
            others.append(self.run_record(60, status='queued'))
            jobs = {i: [{'total_count': 0, 'jobs': []}] for i in canceled_ids}
            self.assertEqual(self.invoke(previous=others, job_pages=jobs, mode='--once'),
                             (0, f'sha={SHA}\n', 2, 0))

    def test_older_never_started_canceled_or_queued_run_does_not_block(self):
        for status, conclusion in [('completed', 'cancelled'), ('queued', None)]:
            older = self.run_record(10, status=status, conclusion=conclusion)
            self.assertEqual(self.invoke(previous=[older], mode='--once',
                                        job_pages={10: [{'total_count': 0, 'jobs': []}]}),
                             (0, f'sha={SHA}\n', 2, 0))

    def test_canceled_with_any_job_is_not_discarded(self):
        for run_id in [10, 30]:
            canceled = self.run_record(run_id, status='completed', conclusion='cancelled')
            jobs = {run_id: [{'total_count': 1, 'jobs': [
                {'id': 99, 'run_id': run_id, 'run_attempt': 1, 'started_at': None}]}]}
            self.denied(previous=[canceled], job_pages=jobs, mode='--once')
            # Explicit manual retry of a completed canceled execution remains allowed.
            self.assertEqual(self.invoke(previous=[canceled], job_pages=jobs),
                             (0, f'sha={SHA}\n', 2, 0))

    def test_missing_incomplete_or_failed_job_provenance_blocks_both_modes(self):
        cases = [None, [], [{}], [{'total_count': True, 'jobs': []}],
                 [{'total_count': 1, 'jobs': []}],
                 [{'total_count': 0, 'jobs': []}, {'total_count': 0, 'jobs': []}],
                 [{'total_count': 1, 'jobs': [{'id': 1, 'run_id': 999, 'run_attempt': 1}]}],
                 gate.Blocked('Job API unavailable')]
        canceled = self.run_record(30, status='completed', conclusion='cancelled')
        for mode in ['--once', '--retry-failed']:
            for pages in cases:
                self.denied(previous=[canceled], job_pages={30: pages}, mode=mode)

    def test_stable_job_provenance_is_required(self):
        run = self.run_record(30, status='completed', conclusion='cancelled')
        for changed in [dict(run, run_attempt=2), dict(run, conclusion='success'),
                        dict(run, status='in_progress'), dict(run, head_branch='other')]:
            with patch.object(gate, 'gh_api', side_effect=[run, [{'total_count': 0, 'jobs': []}], changed]), \
                 self.assertRaises(gate.Blocked):
                gate.has_no_jobs('owner/repo', run)

    def test_started_job_on_later_page_cannot_be_hidden(self):
        run = self.run_record(30, status='completed', conclusion='cancelled')
        pages = [{'total_count': 2, 'jobs': [{'id': i, 'run_id': 30, 'run_attempt': 1}]} for i in [1, 2]]
        self.denied(previous=[run], job_pages={30: pages}, mode='--once')

    def test_three_event_winner_history_suppresses_survivor(self):
        canceled = self.run_record(30, status='completed', conclusion='cancelled')
        for conclusion in ['success', 'failure', 'cancelled', 'timed_out']:
            winner = self.run_record(20, status='completed', conclusion=conclusion)
            self.denied(previous=[winner, canceled], current=[self.run_record(40)],
                        context={'GITHUB_RUN_ID': '40'}, mode='--once')

    def test_no_jobs_never_bypasses_final_live_review(self):
        canceled = self.run_record(30, status='completed', conclusion='cancelled')
        self.denied(previous=[canceled], mode='--once', late_error=gate.Blocked('Head changed'))

    def test_direct_execution_cannot_repeat_any_success(self):
        success = self.run_record(10, status='completed', conclusion='success')
        denied_retry = self.run_record(15, status='completed', conclusion='failure')
        for mode in ['--once', '--retry-failed']:
            self.denied(previous=[success], mode=mode)
            self.denied(previous=[success, denied_retry], mode=mode)

    def test_direct_execution_cannot_duplicate_active_run(self):
        for status in ['in_progress', 'queued', 'pending', 'waiting', 'requested']:
            self.denied(previous=[self.run_record(10, status=status)])

    def test_current_admission_wins_over_later_queued_duplicate(self):
        for mode in ['--once', '--retry-failed']:
            for status in ['queued', 'pending', 'requested']:
                duplicate = self.run_record(30, status=status)
                self.assertEqual(self.invoke(previous=[duplicate], mode=mode),
                                 (0, f'sha={SHA}\n', 2, 0))

    def test_duplicate_deliveries_allow_one_automatic_execution(self):
        first = self.run_record(20)
        second = self.run_record(30, status='queued')
        self.assertEqual(self.invoke(previous=[second], mode='--once'),
                         (0, f'sha={SHA}\n', 2, 0))
        # After the winner finishes, the queued duplicate must not run tests,
        # whether the winner passed or failed. Automatic mode never retries.
        for conclusion in ['success', 'failure', 'cancelled', 'timed_out']:
            self.denied(previous=[dict(first, status='completed', conclusion=conclusion)],
                        current=[dict(second, status='in_progress')],
                        context={'GITHUB_RUN_ID': '30'}, mode='--once')

    def test_later_duplicate_does_not_mask_prior_success_or_active_run(self):
        duplicate = self.run_record(30, status='queued')
        for mode in ['--once', '--retry-failed']:
            for earlier in [self.run_record(10),
                            self.run_record(10, status='completed', conclusion='success')]:
                self.denied(previous=[duplicate, earlier], mode=mode)

    def test_later_running_completed_or_ambiguous_run_still_blocks(self):
        for mode in ['--once', '--retry-failed']:
            for status, conclusion in [('in_progress', None), ('waiting', None),
                                       ('completed', 'success'), ('unknown', None),
                                       ('queued', 'success')]:
                self.denied(previous=[self.run_record(30, status=status, conclusion=conclusion)], mode=mode)

    def test_manual_retry_with_queued_duplicate_retains_failed_history_policy(self):
        failed = self.run_record(10, status='completed', conclusion='failure')
        duplicate = self.run_record(30, status='queued')
        self.assertEqual(self.invoke(previous=[failed, duplicate]), (0, f'sha={SHA}\n', 2, 0))
        self.denied(previous=[failed, duplicate], mode='--once')

    def test_later_queued_native_rerun_or_missing_attempt_is_not_ignored(self):
        for attempt in [None, 2]:
            self.denied(previous=[self.run_record(30, status='queued', run_attempt=attempt)], mode='--once')

    def test_duplicate_election_is_independent_of_history_page_order(self):
        current = self.run_record(20)
        duplicate = self.run_record(30, status='queued')
        for order in [(current, duplicate), (duplicate, current)]:
            pages = [dict(total_count=2, workflow_runs=[run]) for run in order]
            self.assertEqual(self.invoke(controller_pages=pages, mode='--once'),
                             (0, f'sha={SHA}\n', 2, 0))

    def test_election_requires_running_current_and_explicit_unstarted_evidence(self):
        for status in ['queued', 'pending', 'requested', 'waiting']:
            self.denied(current=[self.run_record(status=status)], mode='--once')
        duplicate = self.run_record(30, status='queued')
        del duplicate['conclusion']
        self.denied(previous=[duplicate], mode='--once')

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

    def test_current_id_from_other_workflow_cannot_be_excluded(self):
        run = dict(self.run_record(), history_workflow='other.yml')
        env = dict(GITHUB_ACTIONS='true', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ID='20',
                   GITHUB_WORKFLOW_REF='owner/repo/.github/workflows/review-clearance.yml@refs/heads/main')
        with patch.dict(gate.os.environ, env), self.assertRaises(gate.Blocked):
            gate.exclude_admission_run([run], 'owner/repo', 'main')

    def test_launcher_dispatch_targets_controller_and_carries_mode(self):
        for mode, value in [('--once', 'once'), ('--retry-failed', 'retry-failed')]:
            with patch.dict(gate.os.environ, {'GITHUB_ACTIONS': 'false', 'GITHUB_OUTPUT': ''}), \
                 patch.object(gate, 'check', return_value={'head': {'sha': SHA}}), \
                 patch.object(gate, 'gh_api', side_effect=[{'default_branch': 'main'}, [{'total_count': 0, 'workflow_runs': []}],
                     [{'total_count': 0, 'workflow_runs': []}]]), \
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
