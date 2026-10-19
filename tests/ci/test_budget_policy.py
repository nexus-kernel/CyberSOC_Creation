import copy
import unittest
from unittest.mock import patch
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / '.github/scripts'))
import budget_policy as p


def snapshot():
    heads = ['a' * 40, 'b' * 40, 'c' * 40]
    return dict(repo=p.REPO, pr=2, head=heads[-1], base='d' * 40,
                complete=True, ledger_from_start=True, open=True, draft=False,
                same_repo=True, mergeable=True, native_reviews_satisfied=True,
                security_clear=True, no_newer_review_activity=True,
                rounds=[dict(ordinal=i, request_id=i, head=head, state='completed',
                             actor=p.BOT.copy(), completion_id=f'completion-{i}')
                        for i, head in enumerate(heads, 1)],
                unresolved_thread_root_ids=[101], unresolved_findings=[dict(
                    id=101, review_id=201, head=heads[-1], actor=p.BOT.copy(),
                    stream='code', review_link_verified=True,
                    body='**<sub><sub>![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)</sub></sub>  Fix this**\n\n' + p.MARKER)])


def receipts(s):
    return [dict(item, number=i, repo=p.REPO, is_issue=True, open=True,
                 publisher_verified=True) for i, item in enumerate(p.handoff_plan(s), 1)]


class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.s = snapshot()

    def test_third_completed_round_across_heads_can_handoff_then_clear(self):
        with patch('subprocess.run', side_effect=AssertionError('No IO')):
            result = p.clearance(self.s, receipts(self.s))
        self.assertEqual(result['basis'], 'p2-budget')
        self.assertEqual(result['head'], 'c' * 40)

    def test_no_issues_means_no_clearance(self):
        with self.assertRaises(p.Blocked):
            p.clearance(self.s, [])

    def test_first_two_rounds_and_incomplete_third_never_defer(self):
        for n in (0, 1, 2):
            s = snapshot(); s['rounds'] = s['rounds'][:n]
            with self.subTest(n=n), self.assertRaises(p.Blocked): p.handoff_plan(s)
        for state in ('reserved', 'running', 'failed'):
            s = snapshot(); s['rounds'][-1]['state'] = state
            with self.subTest(state=state), self.assertRaises(p.Blocked): p.handoff_plan(s)

    def test_ineligible_and_unknown_snapshot_blocks(self):
        for key, value in dict(repo='owner/other', complete=False, ledger_from_start=False,
                               open=False, draft=True, same_repo=False, mergeable=None,
                               native_reviews_satisfied=False, security_clear=False,
                               no_newer_review_activity=False).items():
            s = snapshot(); s[key] = value
            with self.subTest(key=key), self.assertRaises(p.Blocked): p.handoff_plan(s)

    def test_push_or_old_latest_completion_blocks(self):
        self.s['head'] = 'e' * 40
        with self.assertRaises(p.Blocked): p.handoff_plan(self.s)

    def test_duplicate_request_completion_and_gap_block(self):
        for key, value in [('request_id', 1), ('completion_id', 'completion-1'), ('ordinal', 8)]:
            s = snapshot(); s['rounds'][-1][key] = value
            with self.subTest(key=key), self.assertRaises(p.Blocked): p.handoff_plan(s)

    def test_human_summary_cannot_count(self):
        self.s['rounds'][0]['actor']['id'] = 100
        with self.assertRaises(p.Blocked): p.handoff_plan(self.s)

    def test_p0_p1_unknown_security_human_and_unlinked_findings_block(self):
        for change in [dict(body=self.s['unresolved_findings'][0]['body'].replace('P2', level))
                       for level in ('P0', 'P1', 'P3')]+[
                           dict(stream='security'), dict(review_link_verified=False),
                           dict(actor=dict(p.BOT, id=999)), dict(body='quoted [P2] text')]:
            s = snapshot(); s['unresolved_findings'][0].update(change)
            with self.subTest(change=change), self.assertRaises(p.Blocked): p.handoff_plan(s)

    def test_outdated_findings_still_require_handoff(self):
        self.s['unresolved_findings'][0]['head'] = 'a' * 40
        self.assertEqual(len(p.handoff_plan(self.s)), 1)
        self.s['unresolved_thread_root_ids'].append(999)
        with self.assertRaises(p.Blocked): p.handoff_plan(self.s)

    def test_issue_key_stable_digest_changes_on_edit(self):
        old = p.handoff_plan(self.s)[0]
        self.s['unresolved_findings'][0]['body'] = self.s['unresolved_findings'][0]['body'].replace('Fix this', 'Fix that')
        new = p.handoff_plan(self.s)[0]
        self.assertEqual(old['key'], new['key'])
        self.assertNotEqual(old['source_digest'], new['source_digest'])

    def test_spoofed_closed_cross_repo_pr_stale_or_edited_issue_blocks(self):
        for key, value in dict(repo='owner/other', publisher_verified=False, open=False,
                               is_issue=False, head='b'*40, source_digest='bad', key='bad').items():
            r = receipts(self.s); r[0][key] = value
            with self.subTest(key=key), self.assertRaises(p.Blocked): p.clearance(self.s, r)
        r = receipts(self.s)
        with self.assertRaises(p.Blocked): p.clearance(self.s, r + r)

    def test_reservation_cap_includes_failed_requests_and_active_blocks(self):
        for state in ('reserved', 'running'):
            s = snapshot(); s['rounds'][-1]['state'] = state
            with self.subTest(state=state), self.assertRaises(p.Blocked): p.request_decision(s)
        self.s['rounds'][-1]['state'] = 'failed'
        with self.assertRaises(p.Blocked): p.request_decision(self.s)
        self.s['rounds'].pop()
        self.assertEqual(p.request_decision(self.s), 'reserve-normal-round')

    def test_only_authenticated_p1_permits_fourth_reservation(self):
        with self.assertRaises(p.Blocked): p.request_decision(self.s)
        self.s['unresolved_findings'][0]['body'] = self.s['unresolved_findings'][0]['body'].replace('P2', 'P1')
        self.assertEqual(p.request_decision(self.s), 'reserve-p1-exception')
        self.s['unresolved_findings'][0]['body'] = self.s['unresolved_findings'][0]['body'].replace('P1', 'P0')
        with self.assertRaises(p.Blocked): p.request_decision(self.s)

    def test_fourth_round_needs_prior_verified_exception(self):
        row = dict(self.s['rounds'][-1], ordinal=4, request_id=4, completion_id='completion-4', p1_exception=False)
        self.s['rounds'].append(row)
        with self.assertRaises(p.Blocked): p.handoff_plan(self.s)
        row.update(p1_exception=True, p1_finding_id=99)
        self.assertEqual(len(p.handoff_plan(self.s)), 1)

    def test_clean_reviews_use_existing_gate(self):
        self.s.update(unresolved_findings=[], unresolved_thread_root_ids=[])
        with self.assertRaises(p.Blocked): p.handoff_plan(self.s)

    def test_merge_requires_same_evidence_and_trusted_ci_and_native_requirements(self):
        r = receipts(self.s); ticket = p.clearance(self.s, r)
        ci = dict(head=self.s['head'], base=self.s['base'], trusted_workflow=True,
                  attempt=1, conclusion='success', required_checks_satisfied=True,
                  protections_satisfied=True)
        self.assertEqual(p.merge_preflight(self.s, r, ticket, ci)['expected_head_sha'], self.s['head'])
        for key, value in dict(head='b'*40, base='a'*40, trusted_workflow=False,
                               attempt=2, conclusion='skipped', required_checks_satisfied=False,
                               protections_satisfied=False).items():
            bad = dict(ci); bad[key] = value
            with self.subTest(key=key), self.assertRaises(p.Blocked): p.merge_preflight(self.s, r, ticket, bad)
        changed = copy.deepcopy(self.s)
        changed['unresolved_findings'][0]['body'] = changed['unresolved_findings'][0]['body'].replace('Fix this', 'Fix that')
        with self.assertRaises(p.Blocked): p.merge_preflight(changed, receipts(changed), ticket, ci)


if __name__ == '__main__':
    unittest.main()
