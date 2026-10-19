"""CyberSOC routing and migration regressions; no network or tenant access."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from test_admission import gate, SHA
from workflow_support import parse_workflow

ROOT = Path(__file__).resolve().parents[2]


class CyberSocPortTests(unittest.TestCase):
    def test_retired_identity_still_blocks_success_and_incomplete_history(self):
        prior = dict(id=10, run_attempt=1, head_branch='main', event='workflow_dispatch',
                     display_title=f'Reviewed CI / PR #1 / {SHA}', status='completed', conclusion='success')
        with patch.object(gate, 'gh_api', side_effect=[
                [{'total_count': 1, 'workflow_runs': [prior]}],
                [{'total_count': 0, 'workflow_runs': []}]]) as api:
            runs = gate.matching_runs('owner/repo', 'main', 1, SHA)
            self.assertFalse(gate.retry_is_allowed(runs))
            self.assertIn('reviewed-ci.yml', api.call_args_list[0].args[0])
            self.assertIn('review-clearance.yml', api.call_args_list[1].args[0])
        with patch.object(gate, 'gh_api', return_value=[]), self.assertRaises(gate.Blocked):
            gate.matching_runs('owner/repo', 'main', 1, SHA)

    def test_retired_workflow_cannot_execute_or_cancel(self):
        workflow = parse_workflow((ROOT / '.github/workflows/reviewed-ci.yml').read_text())
        self.assertEqual(workflow['permissions'], {})
        self.assertNotIn('concurrency', workflow)
        self.assertEqual(workflow['jobs']['retired']['if'], '${{ false }}')

    def test_target_metadata_and_disabled_budget(self):
        config = json.loads((ROOT / '.github/review-budget.json').read_text())
        self.assertEqual(config['repository'], 'nexus-kernel/CyberSOC_Creation')
        self.assertIs(config['enabled'], False)
        self.assertIsNone(config['activation_after'])
        self.assertIs(config['independent_code_triggers_disabled'], False)
        self.assertIs(config['security_review_required'], True)
        self.assertIs(config['native_merge_policy_verified'], False)
        self.assertIsNone(config['merge_queue_required'])
        self.assertEqual(config['ordinary_completed_rounds'], 3)
        package = json.loads((ROOT / 'package.json').read_text())
        lock = json.loads((ROOT / 'package-lock.json').read_text())
        self.assertEqual(package['name'], 'cybersoc-creation')
        self.assertEqual(package['name'], lock['name'])
        self.assertEqual(package['name'], lock['packages']['']['name'])
        self.assertTrue((ROOT / '.idea/CyberSOC_Creation.iml').is_file())
        self.assertNotIn('EBR_Creation', (ROOT / '.idea/modules.xml').read_text())

    def test_setup_routes_before_any_dependency_operation(self):
        source = (ROOT / '.codex/setup-cloud.sh').read_text()
        # Execute only routing; stop before prerequisites/downloads, with mocked git.
        routing = source.split('test "$(uname -s)')[0] + '\nprintf "%s" "$PWD"\n'
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            checkout = base / 'CyberSOC checkout'
            (checkout / '.codex').mkdir(parents=True)
            script = checkout / '.codex/setup-cloud.sh'
            script.write_text(routing)
            stub = base / 'git'
            stub.write_text('#!/bin/sh\nprintf "%s" "$MOCK_REMOTE"\n')
            stub.chmod(0o755)
            env = dict(os.environ, PATH=temp + os.pathsep + os.environ['PATH'],
                       EBR_REPO_DIR='/never/use/EBR', MOCK_REMOTE='https://github.com/nexus-kernel/CyberSOC_Creation.git')
            env.pop('CYBERSOC_REPO_DIR', None)
            result = subprocess.run(['bash', str(script)], cwd=temp, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, str(checkout))
            env['CYBERSOC_REPO_DIR'] = temp
            result = subprocess.run(['bash', str(script)], env=env, capture_output=True, text=True)
            self.assertEqual(result.stdout, temp)
            env['MOCK_REMOTE'] = 'https://github.com/nexus-kernel/EBR_Creation.git'
            result = subprocess.run(['bash', str(script)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Refusing setup', result.stderr)
