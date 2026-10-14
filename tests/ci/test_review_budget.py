"""Offline adversarial tests for the inactive budget policy and writer protocol."""
import importlib.util
from dataclasses import replace
from pathlib import Path
import sys
import unittest

SPEC = importlib.util.spec_from_file_location('review_budget', Path(__file__).parents[2] / '.github/scripts/review_budget.py')
budget = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = budget
SPEC.loader.exec_module(budget)


def snapshot(count=3):
    return budget.Snapshot(
        'nexus-kernel/EBR_Creation', 99, 'a' * 40, 'b' * 40, 'c' * 64,
        True, True, True, True, False, False,
        tuple(budget.Round(str(i), 'Code Review', 'a' * 40, 'completed') for i in range(count)),
        (budget.Finding('finding-1', 'https://github.com/nexus-kernel/EBR_Creation/pull/99#discussion_r123',
                        'P2', False, 'Code Review', 'Fix a lower-priority defect'),))


class BudgetTests(unittest.TestCase):
    def test_initial_counts_and_new_heads_do_not_reset(self):
        for count in range(6):
            with self.subTest(count=count):
                self.assertEqual(budget.request_allowed(snapshot(count)), count < 3)
                self.assertEqual(budget.request_allowed(replace(snapshot(count), head='d' * 40)), count < 3)

    def test_security_round_does_not_consume_code_budget(self):
        s = snapshot(2)
        s = replace(s, rounds=s.rounds + (budget.Round('security', 'Security Review', s.head, 'completed'),))
        self.assertTrue(budget.request_allowed(s))
        with self.assertRaises(budget.Blocked):
            budget.deferral_candidates(s)

    def test_unknown_and_running_history_blocks_requests_and_deferral(self):
        s = snapshot()
        variants = [replace(s, complete=False), replace(s, open_ready=False), replace(s, mergeable=None),
                    replace(s, rounds=s.rounds + (s.rounds[0],)),
                    replace(s, rounds=s.rounds + (budget.Round('new', 'Code Review', s.head, 'running'),)),
                    replace(s, findings=(replace(s.findings[0], priority='unknown'),))]
        for variant in variants:
            for operation in (budget.request_allowed, budget.deferral_candidates):
                with self.subTest(variant=variant, operation=operation), self.assertRaises(budget.Blocked):
                    operation(variant)

    def test_all_history_severity_blocks_every_deferral(self):
        s = snapshot()
        for priority in ('P0', 'P1', '', 'P4'):
            old = replace(s.findings[0], identity='old', source=s.findings[0].source + '4', priority=priority)
            with self.subTest(priority=priority), self.assertRaises(budget.Blocked):
                budget.deferral_candidates(replace(s, findings=s.findings + (old,)))

    def test_resolved_critical_finding_is_not_deferred(self):
        s = snapshot()
        critical = replace(s.findings[0], identity='old', source=s.findings[0].source + '4', priority='P1', resolved=True)
        self.assertEqual(budget.deferral_candidates(replace(s, findings=s.findings + (critical,))), s.findings)

    def test_unreviewed_head_and_human_requirements_fail_closed(self):
        for s in (replace(snapshot(), head='d' * 40), replace(snapshot(), human_requirements_met=False)):
            with self.assertRaises(budget.Blocked):
                budget.deferral_candidates(s)

    def test_security_requires_its_own_current_clearance(self):
        s = replace(snapshot(), security_required=True)
        for variant in (s, replace(s, security_cleared=True)):
            with self.assertRaises(budget.Blocked):
                budget.deferral_candidates(variant)
        s = replace(s, security_cleared=True, rounds=s.rounds + (budget.Round('security', 'Security Review', s.head, 'completed'),))
        self.assertEqual(budget.deferral_candidates(s), s.findings)
        with self.assertRaises(budget.Blocked):
            budget.deferral_candidates(replace(s, findings=(replace(s.findings[0], kind='Security Review'),)))

    def test_identity_and_source_dedup_in_all_states(self):
        s = snapshot()
        for state in ('open', 'closed'):
            for body in (budget.marker(s, s.findings[0]), f'Tracked from ({s.findings[0].source}).',
                         f'Original finding: {s.findings[0].source}.',
                         f'Original finding: {s.findings[0].source}. More context',
                         f'Source: `{s.findings[0].source}`',
                         f'<a href="{s.findings[0].source}">Finding</a>'):
                inventory = budget.IssueInventory(True, (budget.Issue(4, state, body),))
                self.assertEqual(budget.existing_issue(s, s.findings[0], inventory), 4)
        inventory = budget.IssueInventory(True, (budget.Issue(4, 'open', s.findings[0].source + '4'),))
        self.assertIsNone(budget.existing_issue(s, s.findings[0], inventory))

    def test_incomplete_inventory_or_multiple_matches_blocks(self):
        s = snapshot()
        for inventory in (budget.IssueInventory(False, ()), budget.IssueInventory(True, (
                budget.Issue(4, 'closed', s.findings[0].source), budget.Issue(5, 'open', s.findings[0].source)))):
            with self.assertRaises(budget.Blocked):
                budget.existing_issue(s, s.findings[0], inventory)

    def test_uncertain_success_is_read_back_and_never_retried(self):
        s, issues, calls = snapshot(), [], []
        def inventory():
            return budget.IssueInventory(True, tuple(issues))
        def create(title, body):
            calls.append(title)
            issues.append(budget.Issue(7, 'open', body))
            raise TimeoutError('response lost after write')
        result = budget.defer(lambda: s, inventory, create)
        self.assertEqual(result, budget.Deferral('capped-deferral', s.head, (7,)))
        self.assertEqual(budget.defer(lambda: s, inventory, create), result)
        self.assertEqual(len(calls), 1)

    def test_unconfirmed_write_blocks_without_retry(self):
        calls = []
        def create(title, body):
            calls.append(title)
            raise TimeoutError()
        with self.assertRaises(budget.Blocked):
            budget.defer(snapshot, lambda: budget.IssueInventory(True, ()), create)
        self.assertEqual(len(calls), 1)

    def test_same_head_new_evidence_blocks_before_write(self):
        s, calls, reads = snapshot(), [], []
        def read():
            reads.append(1)
            return s if len(reads) == 1 else replace(s, revision='d' * 64)
        with self.assertRaises(budget.Blocked):
            budget.defer(read, lambda: budget.IssueInventory(True, ()), lambda *args: calls.append(args))
        self.assertEqual(calls, [])

    def test_revocation_after_write_never_produces_deferral(self):
        s, issues = snapshot(), []
        def read():
            return s if not issues else replace(s, human_requirements_met=False)
        with self.assertRaises(budget.Blocked):
            budget.defer(read, lambda: budget.IssueInventory(True, tuple(issues)),
                         lambda title, body: issues.append(budget.Issue(7, 'open', body)))
        self.assertEqual(len(issues), 1)  # Keep issue for reconciliation; no rollback/duplicate.


if __name__ == '__main__':
    unittest.main()
