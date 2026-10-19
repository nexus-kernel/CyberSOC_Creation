"""Regression cases reproduced during independent local adversarial review."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_dispatch_clearance import gate, fixture, BOT, SHA


class AdversarialTests(unittest.TestCase):
    def test_same_second_running_reaction_is_not_provably_old(self):
        for value in ['2026-10-14T07:00:00Z', '2026-10-14T07:00:00.001Z']:
            data = fixture()
            data['reactions'].append(dict(user=BOT, content='eyes', created_at=value))
            with patch.object(gate, 'gh_api', return_value={'sha': SHA}), self.assertRaises(gate.Blocked):
                gate.evaluate(**data)

    def test_same_second_bot_review_or_missing_date_blocks(self):
        for value in ['2026-10-14T07:00:02Z', '2026-10-14T07:00:02.001Z', None, '']:
            data = fixture()
            data['reviews'] = [dict(id=1, user=BOT, state='COMMENTED', submitted_at=value)]
            with patch.object(gate, 'gh_api', return_value={'sha': SHA}), self.assertRaises(gate.Blocked):
                gate.evaluate(**data)

    def test_dismissed_unrelated_review_does_not_clear_changes_request(self):
        data = fixture()
        user = {'id': 123, 'login': 'reviewer'}
        data['reviews'] = [dict(id=1, user=user, state='CHANGES_REQUESTED'),
                           dict(id=2, user=user, state='DISMISSED')]
        with self.assertRaisesRegex(gate.Blocked, 'changes-requested'):
            gate.evaluate(**data)

    def test_review_timestamps_require_explicit_timezone(self):
        for value in [None, '', '2026-10-14T07:00:00', '2026-10-14', 123]:
            with self.subTest(value=value), self.assertRaises(gate.Blocked):
                gate.timestamp(value)

    def test_missing_or_malformed_rest_pages_fail_closed(self):
        for pages in [None, [], {}, [None], [{}]]:
            with patch.object(gate, 'gh_api', return_value=pages), self.assertRaises(gate.Blocked):
                gate.list_api('endpoint')
        with patch.object(gate, 'gh_api', return_value=[[]]):
            self.assertEqual(gate.list_api('endpoint'), [])

    def test_unknown_graphql_pagination_is_not_terminal(self):
        for more in [None, 0, '', 'false']:
            payload = {'data': {'repository': {'pullRequest': {
                'headRefOid': SHA, 'baseRefOid': 'b' * 40, 'reviewDecision': None,
                'reviewThreads': {'nodes': [], 'pageInfo': {'hasNextPage': more, 'endCursor': None}}
            }}}}
            with patch.object(gate.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout=json.dumps(payload))), self.assertRaises(gate.Blocked):
                gate.review_threads('owner/repo', 1, SHA, 'b' * 40)


if __name__ == '__main__':
    unittest.main()
