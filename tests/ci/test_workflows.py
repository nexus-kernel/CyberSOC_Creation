from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from workflow_support import parse_workflow

ROOT = Path(__file__).resolve().parents[2]


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflows = {p.stem: parse_workflow(p.read_text()) for p in
                          (ROOT / '.github/workflows').glob('*.yml')}
        self.ci = self.workflows['reviewed-ci']
        self.control = self.workflows['review-clearance']

    def test_inventory_triggers_and_runner_free_cancellation(self):
        self.assertEqual(set(self.workflows), {'reviewed-ci', 'review-clearance', 'cancel-ci'})
        self.assertEqual(set(self.ci['on']), {'workflow_dispatch'})
        self.assertEqual(set(self.control['on']), {'workflow_dispatch', 'issue_comment'})
        cancel = self.workflows['cancel-ci']
        self.assertEqual(cancel['on'], {'pull_request_target': {'types': ['synchronize', 'converted_to_draft', 'closed']}})
        self.assertEqual(cancel['permissions'], {})
        self.assertEqual(cancel['jobs']['cancel-only']['if'], "github.event_name != 'pull_request_target'")
        self.assertEqual(cancel['concurrency']['group'], 'reviewed-ci-${{ github.event.pull_request.number }}')
        self.assertEqual(self.ci['concurrency']['group'], 'reviewed-ci-${{ inputs.pr_number || github.sha }}')
        self.assertTrue(cancel['concurrency']['cancel-in-progress'])
        self.assertFalse(self.control['concurrency']['cancel-in-progress'])

    def test_trusted_control_and_read_only_tests(self):
        self.assertEqual(self.ci['permissions'], {'contents': 'read'})
        test = self.ci['jobs']['test']
        self.assertNotIn('permissions', test)
        self.assertEqual(test['needs'], 'review-clearance')
        self.assertIn("needs.review-clearance.result == 'success'", test['if'])
        checkout = next(s for s in test['steps'] if s.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with'], {'ref': '${{ needs.review-clearance.outputs.sha }}', 'persist-credentials': False})
        for job in [self.control['jobs']['clearance'], self.ci['jobs']['review-clearance']]:
            self.assertIn('github.event.repository.default_branch', job['if'])
            self.assertEqual(job['steps'][0]['with'], {'ref': '${{ github.sha }}', 'persist-credentials': False})
        self.assertEqual(self.control['permissions'], {'contents': 'read', 'pull-requests': 'read', 'issues': 'read', 'actions': 'write'})
        self.assertEqual(self.ci['jobs']['review-clearance']['permissions'], {'contents': 'read', 'pull-requests': 'read', 'issues': 'read', 'statuses': 'write'})
        for workflow in self.workflows.values():
            for job in workflow['jobs'].values():
                for step in job['steps']:
                    if 'uses' in step:
                        self.assertRegex(step['uses'], r'@[0-9a-f]{40}$')
                    self.assertNotIn('secrets.', str(step))

    def test_separate_reporter_and_native_rerun_rejection(self):
        report = self.ci['jobs']['report-reviewed-ci']
        self.assertEqual(report['permissions'], {'statuses': 'write'})
        self.assertEqual(report['needs'], ['review-clearance', 'test'])
        self.assertEqual(len(report['steps']), 1)
        self.assertTrue(report['steps'][0]['uses'].startswith('actions/github-script@'))
        script = report['steps'][0]['with']['script']
        self.assertIn("process.env.RUN_ATTEMPT === '1'", script)
        self.assertIn("process.env.TEST_RESULT === 'success'", script)
        self.assertIn("process.env.CLEARANCE_RESULT === 'success'", script)
        first = self.ci['jobs']['test']['steps'][0]
        for attempt, code in [('1', 0), ('2', 1)]:
            result = subprocess.run(['bash', '-e', '-c', first['run']], env=dict(os.environ, CI_RUN_ATTEMPT=attempt), capture_output=True)
            self.assertEqual(result.returncode, code)

    def test_ebr_suites_require_node_and_pester(self):
        steps = self.ci['jobs']['test']['steps']
        text = '\n'.join(s.get('run', '') for s in steps)
        self.assertIn('npm ci', text)
        self.assertIn('node --test tests/*.test.cjs', text)
        self.assertIn("$config.Run.Path = './tests'", text)
        self.assertIn('Get-Command node -ErrorAction Stop', text)
        self.assertIn('$result.SkippedCount -gt 0', text)
        self.assertIn('-RequiredVersion 5.9.1', text)
        for unused in ['Az.Accounts', 'PSScriptAnalyzer', 'Chromium', 'ExchangeOnlineManagement']:
            self.assertNotIn(unused, text)

    def test_unknown_events_and_failed_gate_are_fail_closed(self):
        script = self.control['jobs']['clearance']['steps'][-1]['run']
        with tempfile.TemporaryDirectory() as directory:
            stub = Path(directory) / 'python3'
            stub.write_text('#!/bin/sh\nexit 1\n')
            stub.chmod(0o755)
            for event in ['push', 'pull_request', '', 'workflow_dispatch', 'issue_comment']:
                env = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'],
                           TRIGGER_EVENT=event, GITHUB_REPOSITORY='owner/repo', PR_NUMBER='1',
                           GITHUB_STEP_SUMMARY=str(Path(directory) / 'summary'))
                self.assertNotEqual(subprocess.run(['bash', '-e', '-c', script], env=env, capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
