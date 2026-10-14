"""Transport fixtures for disabled budget controller: no network or credentials."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).parents[2] / '.github/scripts'
sys.path.insert(0, str(SCRIPTS))
import review_budget as budget
import review_budget_history as history
import review_budget_runtime as runtime
import review_budget_store as store
import review_gate as gate
from test_review_budget import snapshot

BOT = history.BOT
HUMAN = {'id': 4, 'login': 'human', 'type': 'User'}
REQUESTER = {'id': 9, 'login': 'controller', 'type': 'Bot'}
REPO = 'nexus-kernel/EBR_Creation'
SHA = 'a' * 40


def pr(draft=False):
    return {'number': 99, 'created_at': '2026-10-14T01:00:00Z', 'state': 'open',
            'draft': draft, 'mergeable': True, 'head': {'sha': SHA, 'repo': {'full_name': REPO}},
            'base': {'sha': 'b' * 40, 'repo': {'full_name': REPO}}}


def summary(status='completed', stamp='2026-10-14T02:00:00Z', commit=SHA):
    value = (f'✅ **Completed** <relative-time datetime="{stamp}">{stamp}</relative-time>'
             if status == 'completed' else f'**{status.capitalize()}**')
    return f'{history.SUMMARY}\n| Code Review | {value} | `{commit}` | Manual request |'


def event(identity, kind='issue_comment', action='created', body=None, old=None, user=BOT):
    payload = {'repository': {'full_name': REPO, 'id': 777}, 'sender': user, 'action': action}
    if kind == 'pull_request':
        payload['pull_request'] = pr(True)
    else:
        payload['issue'] = {'number': 99}
        payload['comment'] = {'id': 42, 'body': body or summary(), 'user': user}
        if old is not None:
            payload['changes'] = {'body': {'from': old}}
    return {'id': identity, 'guid': str(identity), 'event': kind, 'action': action, 'payload': payload}


class DeliveryAPI:
    def __init__(self):
        self.hook = {'id': 1, 'created_at': '2026-10-14T00:00:00Z',
                     'updated_at': '2026-10-14T00:00:00Z', 'active': True, 'events': sorted(history.EVENTS)}
        self.events = [event(1, 'pull_request', 'opened')]
        self.commits = {}
        self.calls = []

    def __call__(self, endpoint, method='GET', payload=None, paginate=False):
        self.calls.append(endpoint)
        prefix = f'repos/{REPO}/hooks/1'
        if endpoint == prefix:
            return deepcopy(self.hook)
        def metadata(e):
            return {**{k: e[k] for k in ('id', 'guid', 'event', 'action')}, 'repository_id': 777, 'redelivery': e.get('redelivery', False)}
        if endpoint == prefix + '/deliveries?per_page=100':
            values = [metadata(e) for e in reversed(self.events)]
            return [values[i:i+100] for i in range(0, len(values), 100)] or [[]]
        if endpoint.startswith(prefix + '/deliveries/'):
            e = next(e for e in self.events if e['id'] == int(endpoint.split('/')[-1]))
            return {**metadata(e), 'request': {'headers': {'X-GitHub-Delivery': e['guid'],
                    'X-GitHub-Event': e['event'], 'X-GitHub-Hook-ID': '1'}, 'payload': deepcopy(e['payload'])}}
        if endpoint.startswith(f'repos/{REPO}/commits/') and endpoint.rsplit('/', 1)[1] in self.commits:
            return deepcopy(self.commits[endpoint.rsplit('/', 1)[1]])
        raise AssertionError(endpoint)


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.api = DeliveryAPI()
        self.history = history.History(REPO, 1, REQUESTER, self.api)
        self.state = self.history.sync(pr(True))

    def test_opening_redelivery_uses_one_guid_and_latest_raw_watermark(self):
        duplicate = deepcopy(self.api.events[0])
        duplicate['id'] = 3
        duplicate['redelivery'] = True
        self.api.events.append(duplicate)
        state = self.history.sync(pr(True))
        self.assertEqual(len(state['events']), 1)
        self.assertEqual(state['anchor'], 3)
        self.assertEqual(self.history.sync(pr(True), state), state)

    def test_missing_original_opening_cannot_enroll_from_redelivery(self):
        duplicate = deepcopy(self.api.events[0])
        duplicate.update(id=3, redelivery=True)
        for earlier in ([], [event(2, 'pull_request_review')]):
            self.api.events = earlier + [duplicate]
            with self.subTest(earlier=earlier), self.assertRaises(budget.Blocked):
                self.history.sync(pr(True))

    def test_activity_before_apparent_original_opening_blocks(self):
        opening = deepcopy(self.api.events[0])
        opening['id'] = 3
        self.api.events = [event(2), opening]
        with self.assertRaises(budget.Blocked):
            self.history.sync(pr(True))

    def test_conflicting_or_distinct_openings_block(self):
        for change in ('payload', 'guid', 'action'):
            duplicate = deepcopy(self.api.events[0])
            duplicate['id'] = 3
            if change == 'payload':
                duplicate['payload']['pull_request']['draft'] = False
            else:
                duplicate[change] = 'different'
            self.api.events = [self.api.events[0], duplicate]
            with self.subTest(change=change), self.assertRaises(budget.Blocked):
                self.history.sync(pr(True))

    def test_opening_redelivery_cannot_skip_intervening_review(self):
        duplicate = deepcopy(self.api.events[0])
        duplicate['id'] = 3
        self.api.events += [event(2, 'pull_request_review'), duplicate]
        self.api.events[1]['payload']['pull_request'] = pr(True)
        with self.assertRaises(budget.Blocked):
            self.history.sync(pr(True))

    def test_prospective_only_and_missing_anchor(self):
        with self.assertRaises(budget.Blocked):
            self.history.sync(pr(False))
        self.api.events = []
        with self.assertRaises(budget.Blocked):
            self.history.sync(pr(False), self.state)

    def test_no_backfill_from_completed_summary(self):
        self.api.events.append(event(2))
        with self.assertRaises(budget.Blocked):
            self.history.sync(pr(True))

    def test_authenticated_complete_initial_round_and_idempotent_sync(self):
        self.state['pending'] = {'kind': 'Code Review', 'head': SHA, 'nonce': 'n', 'comment': 12}
        self.api.events.append(event(2))
        state = self.history.sync(pr(), self.state)
        self.assertEqual(len(history.rounds(state)), 1)
        self.assertEqual(self.history.sync(pr(), state), state)

    def test_same_head_rounds_count_separately(self):
        state = self.state
        old = None
        for i in range(3):
            state['pending'] = {'kind': 'Code Review', 'head': SHA, 'nonce': str(i), 'comment': 12+i}
            body = summary(stamp=f'2026-10-14T02:0{i}:00Z')
            self.api.events.append(event(i+2, action='edited' if old else 'created', body=body, old=old))
            state = self.history.sync(pr(), state)
            old = body
        self.assertEqual(len(history.rounds(state)), 3)

    def test_forgery_missing_edit_and_external_completion_block(self):
        for change in ('forged', 'missing-edit', 'no-reservation'):
            with self.subTest(change=change):
                api = DeliveryAPI()
                h = history.History(REPO, 1, REQUESTER, api)
                state = h.sync(pr(True))
                if change != 'no-reservation':
                    state['pending'] = {'kind': 'Code Review', 'head': SHA, 'nonce': 'n', 'comment': 12}
                api.events.append(event(2, action='edited' if change == 'missing-edit' else 'created',
                                        user=HUMAN if change == 'forged' else BOT))
                with self.assertRaises(budget.Blocked):
                    h.sync(pr(), state)

    def test_summary_findings_unknown_text_and_result_cells_block(self):
        for body in (summary() + '\n[P0] Critical summary finding',
                     summary() + '\nUnclassified finding',
                     summary().replace('Manual request', 'Manual request [P1] Critical'),
                     summary().replace('Code Review |', 'Code Review [P2] hidden |'),
                     summary().replace('</relative-time>', '</relative-time> [P3] ignored')):
            with self.subTest(body=body), self.assertRaises(budget.Blocked):
                history.summary_rows(body, REPO)

    def test_hook_change_and_running_review_fail_closed(self):
        self.api.hook['active'] = False
        with self.assertRaises(budget.Blocked):
            self.history.sync(pr(), self.state)
        state = deepcopy(self.state)
        state['latest']['Code Review'] = {'state': 'running'}
        with self.assertRaises(budget.Blocked):
            history.rounds(state)

    def test_inventory_spans_pages_and_rejects_duplicate_ids(self):
        for i in range(2, 104):
            e = event(i, 'pull_request', 'synchronize')
            e['payload']['pull_request']['number'] = 100
            self.api.events.append(e)
        state = self.history.sync(pr(), self.state)
        self.assertEqual(state['anchor'], 103)
        self.api.events.append(self.api.events[-1])
        with self.assertRaises(budget.Blocked):
            self.history.sync(pr(), state)

    def test_abbreviated_commit_binds_to_resolved_full_sha_once(self):
        self.api.commits[SHA[:7]] = {'sha': SHA}
        self.state['pending'] = {'kind': 'Code Review', 'head': SHA, 'nonce': 'n', 'comment': 12}
        self.api.events.append(event(2, body=summary(commit=SHA[:7])))
        state = self.history.sync(pr(), self.state)
        self.assertEqual([r.head for r in history.rounds(state)], [SHA])
        self.assertEqual(self.api.calls.count(f'repos/{REPO}/commits/{SHA[:7]}'), 1)
        self.assertEqual(self.history.sync(pr(), state), state)

    def test_full_sha_rows_skip_resolution(self):
        self.state['pending'] = {'kind': 'Code Review', 'head': SHA, 'nonce': 'n', 'comment': 12}
        self.api.events.append(event(2))
        self.history.sync(pr(), self.state)
        self.assertFalse([call for call in self.api.calls if '/commits/' in call])

    def test_same_named_ref_cannot_rebind_review_to_reserved_head(self):
        other = 'c' * 40
        for status in ('completed', 'Running', 'Pending', 'Queued'):
            with self.subTest(status=status):
                api = DeliveryAPI()
                api.commits[other[:7]] = {'sha': SHA}
                h = history.History(REPO, 1, REQUESTER, api)
                state = h.sync(pr(True))
                state['pending'] = {'kind': 'Code Review', 'head': SHA, 'nonce': 'n', 'comment': 12}
                api.events.append(event(2, body=summary(status, commit=other[:7])))
                with self.assertRaises(budget.Blocked):
                    h.sync(pr(), state)

    def test_resolution_must_extend_abbreviation_in_every_row_state(self):
        other = 'c' * 40
        responses = ({'sha': SHA}, {'sha': other[:6] + 'd' * 34}, {'sha': other[:7]}, {'sha': other.upper()},
                     {'sha': other + '0'}, {'sha': 7}, {'sha': None}, {}, None, [], other)
        for status in ('completed', 'Running', 'Pending', 'Queued'):
            body = summary(status, commit=other[:7])
            for response in responses:
                with self.subTest(status=status, response=response), self.assertRaises(budget.Blocked):
                    history.summary_rows(body, REPO, lambda endpoint, **_: response)
            rows = history.summary_rows(body, REPO, lambda endpoint, **_: {'sha': other})
            self.assertEqual(rows['Code Review']['head'], other)

    def test_resolution_api_failure_remains_blocked(self):
        def failing(endpoint, **_):
            raise budget.Blocked('GitHub API failed; operation may be uncertain: ' + endpoint)
        with self.assertRaises(budget.Blocked):
            history.summary_rows(summary(commit=SHA[:7]), REPO, failing)

    def test_recorded_abbreviation_binding_survives_summary_edits(self):
        collision = SHA[:7] + 'c' * 33
        self.api.commits[SHA[:7]] = {'sha': SHA}
        self.state['pending'] = {'kind': 'Code Review', 'head': SHA, 'nonce': 'n', 'comment': 12}
        first = summary(commit=SHA[:7])
        self.api.events.append(event(2, body=first))
        state = self.history.sync(pr(), self.state)
        self.assertEqual(state['commits'], {SHA[:7]: SHA})
        # A same-named ref now points at a crafted prefix collision that holds the next reservation.
        self.api.commits[SHA[:7]] = {'sha': collision}
        state['pending'] = {'kind': 'Code Review', 'head': collision, 'nonce': 'm', 'comment': 13}
        edited = first + f'\n| Security Review | **Running** | `{SHA[:7]}` | Manual request |'
        self.api.events.append(event(3, action='edited', body=edited, old=first))
        state = self.history.sync(pr(), state)
        self.assertEqual([row['head'] for row in state['rounds'].values()], [SHA])
        self.assertEqual(state['pending']['head'], collision)
        self.assertEqual(state['latest']['Security Review']['head'], SHA)
        self.assertEqual(self.api.calls.count(f'repos/{REPO}/commits/{SHA[:7]}'), 1)

    def test_corrupt_persisted_binding_blocks_without_resolution(self):
        for bound in ('c' * 40, SHA[:7], SHA.upper(), 7):
            with self.subTest(bound=bound), self.assertRaises(budget.Blocked):
                history.summary_rows(summary(commit=SHA[:7]), REPO, self.api, {SHA[:7]: bound})
        self.assertFalse([call for call in self.api.calls if '/commits/' in call])


class MemoryJournal:
    def __init__(self, state=None):
        self.version = 0
        self.state = state or {'version': 1, 'prs': {'99': {'writes': {}}}, 'locks': {}}
        self.saves = []

    def read(self):
        return str(self.version), deepcopy(self.state)

    def compare_swap(self, expected, state):
        if expected != str(self.version):
            raise budget.Blocked('conflict')
        self.version += 1
        self.state = deepcopy(state)
        self.saves.append(deepcopy(state))
        return str(self.version)

    transaction = store.GitJournal.transaction


class FakeLive:
    def __init__(self):
        self.issues = []
        self.posts = []
        self.fail = None
        self.current = snapshot()
        self.change_after_post = False

    def pr(self):
        return pr()

    def snapshot(self, state):
        return self.current, pr()

    def inventory(self):
        return budget.IssueInventory(True, tuple(self.issues), ((9, 'controller'),))

    def call(self, endpoint, method='GET', payload=None):
        self.posts.append(payload)
        if self.fail != 'before':
            self.issues.append(budget.Issue(len(self.issues)+1, 'open', payload['body'], title=payload['title'], author=(9, 'controller')))
        if self.change_after_post:
            self.current = replace(self.current, revision='e'*64)
        if self.fail:
            raise budget.Blocked('response lost')


class FakeHistory:
    requester = REQUESTER
    def sync(self, pr, previous=None):
        return deepcopy(previous)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.journal, self.live = MemoryJournal(), FakeLive()
        self.controller = runtime.Controller(REPO, 99, self.journal, FakeHistory(), self.live)

    def test_uncertain_issue_write_reconciles_and_receipt_admits(self):
        self.live.fail = 'after'
        self.controller.defer()
        self.assertEqual(len(self.live.posts), 1)
        self.assertEqual(self.controller.admit(SHA)['clearance_basis'], 'capped-deferral')
        self.controller.defer()
        self.assertEqual(len(self.live.posts), 1)
        self.assertTrue(any(next(iter(s['prs']['99']['writes'].values()), {}).get('state') == 'intent'
                            for s in self.journal.saves))

    def test_uncertain_write_rejects_downgraded_readback_without_resend(self):
        original = self.live.call
        def changed(*args, **kwargs):
            original(*args, **kwargs)
            issue = self.live.issues[0]
            self.live.issues[0] = replace(issue, body=self.live.current.findings[0].source)
            raise TimeoutError('lost response')
        self.live.call = changed
        for _ in range(2):
            with self.assertRaises(budget.Blocked):
                self.controller.defer()
        self.assertEqual(len(self.live.posts), 1)
        self.assertEqual(next(iter(self.journal.state['prs']['99']['writes'].values()))['state'], 'intent')

    def test_uncertain_absent_write_is_not_retried_after_restart(self):
        self.live.fail = 'before'
        with self.assertRaises(budget.Blocked):
            self.controller.defer()
        restarted = runtime.Controller(REPO, 99, self.journal, FakeHistory(), self.live)
        with self.assertRaises(budget.Blocked):
            restarted.defer()
        self.assertEqual(len(self.live.posts), 1)
        with self.assertRaises(budget.Blocked):
            restarted.admit(SHA)

    def test_shared_source_distinct_findings_create_and_reuse_distinct_issues(self):
        s = self.live.current
        self.live.current = replace(s, findings=s.findings+(replace(s.findings[0], identity='finding-2'),))
        self.controller.defer()
        self.assertEqual(len(self.live.posts), 2)
        self.controller.defer()
        self.assertEqual(len(self.live.posts), 2)
        self.assertEqual(self.controller.admit(SHA)['clearance_basis'], 'capped-deferral')

    def test_shared_source_legacy_issue_is_not_ambiguous_reuse(self):
        s = self.live.current
        self.live.current = replace(s, findings=s.findings+(replace(s.findings[0], identity='finding-2'),))
        self.live.issues.append(budget.Issue(10, 'closed', s.findings[0].source))
        with self.assertRaises(budget.Blocked):
            self.controller.defer()
        self.assertEqual(len(self.live.posts), 0)

    def test_revocation_after_write_blocks_receipt(self):
        self.live.change_after_post = True
        with self.assertRaises(budget.Blocked):
            self.controller.defer()
        self.assertNotIn('deferral', self.journal.state['prs']['99'])

    def test_stale_receipt_head_and_deleted_issue_block_admission(self):
        self.controller.defer()
        with self.assertRaises(budget.Blocked):
            self.controller.admit('e'*40)
        self.live.issues.clear()
        with self.assertRaises(budget.Blocked):
            self.controller.admit(SHA)

    def test_locks_do_not_expire_and_serialize(self):
        with self.journal.transaction(99):
            with self.assertRaises(budget.Blocked):
                with self.journal.transaction(99):
                    self.fail('second writer acquired lock')
            with self.assertRaises(budget.Blocked):
                self.controller.admit(SHA)
        self.journal.state['locks']['99'] = 'crashed-owner'
        with self.assertRaises(budget.Blocked):
            self.controller.defer()

    def test_critical_or_unknown_history_prevents_any_write(self):
        for change in (dict(complete=False), dict(head='e'*40), dict(human_requirements_met=False),
                       dict(findings=(replace(snapshot().findings[0], priority='P1'),)),
                       dict(findings=(replace(snapshot().findings[0], priority='unknown'),))):
            self.live.current = replace(snapshot(), **change)
            with self.assertRaises(budget.Blocked):
                self.controller.defer()
        self.assertEqual(self.live.posts, [])

    def test_request_reservation_blocks_same_head_revocation_before_post(self):
        self.live.current = snapshot(2)
        original_swap = self.journal.compare_swap
        def swap(expected, state):
            result = original_swap(expected, state)
            if state['prs']['99'].get('pending'):
                self.live.current = replace(self.live.current, human_requirements_met=False)
            return result
        self.journal.compare_swap = swap
        with self.assertRaises(budget.Blocked):
            self.controller.request()
        self.assertEqual(self.live.posts, [])
        self.assertIsNotNone(self.journal.state['prs']['99']['pending'])

    def test_request_intent_survives_uncertain_post_and_readback(self):
        self.live.current = snapshot(2)
        comments = []
        def call(endpoint, method='GET', payload=None, paginate=False):
            if method == 'POST':
                comments.append({'id': 17, 'body': payload['body'], 'user': REQUESTER})
                raise budget.Blocked('lost response')
            return [comments]
        self.live.call = call
        self.controller.request()
        self.assertEqual(self.journal.state['prs']['99']['pending']['comment'], 17)
        self.assertEqual(len(comments), 1)

    def test_cap_suppresses_controlled_request(self):
        with self.assertRaises(budget.Blocked):
            self.controller.request()
        self.assertEqual(self.live.posts, [])


class ActivationTests(unittest.TestCase):
    def test_cli_disabled_before_any_api_call(self):
        with patch.object(runtime, 'api', side_effect=AssertionError('no network before opt-in')):
            for operation in ('enroll', 'sync', 'request', 'reconcile-request', 'defer', 'check'):
                self.assertEqual(runtime.main(['--repo', REPO, '--pr', '99', operation]), 1)

    def test_clean_gate_unchanged_and_budget_disabled(self):
        with patch.object(gate, 'check_clean', return_value=pr()), patch.object(runtime, 'check') as fallback:
            self.assertEqual(gate.check(REPO, 99), pr())
            fallback.assert_not_called()
        with patch.object(gate, 'check_clean', side_effect=gate.Blocked('no thumbs up')):
            with self.assertRaises(gate.Blocked):
                gate.check(REPO, 99)

    def test_opted_in_gate_delegates_exact_sha_and_does_not_forge_approval(self):
        with patch.object(gate, 'CAPPED_DEFERRAL_ENABLED', True), \
                patch.object(gate, 'check_clean', side_effect=gate.Blocked('findings')), \
                patch.object(runtime, 'check', return_value={**pr(), 'clearance_basis': 'capped-deferral'}) as fallback:
            self.assertEqual(gate.check(REPO, 99, SHA)['clearance_basis'], 'capped-deferral')
            fallback.assert_called_once_with(REPO, 99, SHA)

    def test_findings_in_one_body_have_distinct_identity_and_unknown_priority_blocks(self):
        findings = runtime.finding_sections('[P2] First\nDetails\n[P3] Second\nDetails',
                                            'review:4', 'url', False)
        self.assertEqual([f.identity for f in findings], ['review:4:0', 'review:4:1'])
        for body in ('[P4] Unknown', '[P2] One\n[P1] Bad with P2 text', 'unclassified text'):
            with self.assertRaises(budget.Blocked):
                runtime.finding_sections(body, 'review:4', 'url', False)

class LiveAPI:
    def __init__(self):
        self.current_pr = pr()
        self.comments = [{'id': 42, 'body': summary(), 'user': BOT,
                          'html_url': f'https://github.com/{REPO}/pull/99#issuecomment-42'}]
        self.inline = [{'id': 101, 'body': '[P2] A real inline finding\nDetails', 'user': BOT,
                        'html_url': f'https://github.com/{REPO}/pull/99#discussion_r101'}]
        self.issues = []
        self.resolved = False
        self.reactions = []
        self.reviews = []
        self.review_decision = 'APPROVED'
        self.state = {'hook': {}, 'anchor': 1, 'events': [
            {'event': 'issue_comment', 'payload': {'comment': self.comments[0]}},
            {'event': 'pull_request_review_comment', 'payload': {'comment': self.inline[0]}}],
            'guids': {}, 'summaries': {'42': summary()}, 'requests': {}, 'pending': None,
            'writes': {}, 'latest': {'Code Review': {'state': 'completed'}},
            'rounds': {str(i): {'kind': 'Code Review', 'head': SHA, 'state': 'completed'} for i in range(3)}}
        self.state = deepcopy(self.state)

    def __call__(self, endpoint, method='GET', payload=None, paginate=False):
        prefix = f'repos/{REPO}'
        if endpoint == prefix + '/pulls/99':
            return deepcopy(self.current_pr)
        if endpoint == 'graphql':
            return {'data': {'repository': {'pullRequest': {
                'headRefOid': SHA, 'baseRefOid': 'b'*40, 'reviewDecision': self.review_decision,
                'reviewThreads': {'nodes': [{'id': 'thread101', 'isResolved': self.resolved,
                                            'comments': {'nodes': [{'databaseId': 101}]}}],
                                  'pageInfo': {'hasNextPage': False, 'endCursor': None}}}}}}
        values = {
            prefix + '/issues/99/comments?per_page=100': self.comments,
            prefix + '/pulls/99/comments?per_page=100': self.inline,
            prefix + '/pulls/99/reviews?per_page=100': self.reviews,
            prefix + '/issues/99/reactions?per_page=100': self.reactions,
            prefix + '/issues?state=all&per_page=100': self.issues,
        }
        if endpoint in values:
            return [deepcopy(values[endpoint])]
        if endpoint == prefix + '/issues' and method == 'POST':
            number = len(self.issues)+1
            self.issues.append({'id': number, 'number': number, 'state': 'open', 'body': payload['body'], 'title': payload['title'], 'user': REQUESTER})
            return self.issues[-1]
        raise AssertionError(endpoint)


class LiveIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.api = LiveAPI()
        self.journal = MemoryJournal({'version': 1, 'prs': {'99': self.api.state}, 'locks': {}})
        self.live = runtime.Live(REPO, 99, self.api, issue_author=REQUESTER)
        self.controller = runtime.Controller(REPO, 99, self.journal, FakeHistory(), self.live)

    def test_tracking_issue_requires_author_and_complete_association(self):
        snap, _ = self.live.snapshot(self.api.state)
        finding = snap.findings[0]
        for state in ('open', 'closed'):
            for author, body in ((HUMAN, budget.tracking_body(snap, finding)),
                                 (HUMAN, finding.source),
                                 (REQUESTER, budget.marker(snap, finding))):
                self.api.issues = [{'id': 1, 'number': 1, 'state': state, 'user': author,
                                    'title': budget.tracking_title(finding), 'body': body}]
                with self.subTest(state=state, author=author, body=body), self.assertRaises(budget.Blocked):
                    self.controller.defer()
                self.assertEqual(len(self.api.issues), 1)

    def test_confirmed_issue_edits_block_admission_and_reuse(self):
        self.controller.defer()
        original = deepcopy(self.api.issues[0])
        snap, _ = self.live.snapshot(self.api.state)
        finding = snap.findings[0]
        for body in (budget.marker(snap, finding), finding.source,
                     original['body'] + '\nChanged association'):
            self.api.issues[0] = {**original, 'body': body}
            for operation in (lambda: self.controller.admit(SHA), self.controller.defer):
                with self.subTest(body=body), self.assertRaises(budget.Blocked):
                    operation()
            self.assertEqual(len(self.api.issues), 1)
        self.api.issues[0] = {**original, 'state': 'closed'}
        self.assertEqual(self.controller.admit(SHA)['clearance_basis'], 'capped-deferral')

    def test_trusted_legacy_association_is_pinned_after_adoption(self):
        source = self.api.inline[0]['html_url']
        self.api.issues = [{'id': 1, 'number': 1, 'state': 'closed', 'user': REQUESTER,
                            'title': 'Existing tracking issue', 'body': 'Context: ' + source}]
        self.controller.defer()
        self.assertEqual(len(self.api.issues), 1)
        self.controller.admit(SHA)
        self.api.issues[0]['body'] = source
        for operation in (lambda: self.controller.admit(SHA), self.controller.defer):
            with self.assertRaises(budget.Blocked):
                operation()
        self.assertEqual(len(self.api.issues), 1)

    def test_native_null_preserves_ebr_policy_but_missing_or_required_blocks(self):
        self.api.review_decision = None
        self.controller.defer()
        self.controller.admit(SHA)
        for decision in ('REVIEW_REQUIRED', 'CHANGES_REQUESTED'):
            self.api.review_decision = decision
            with self.subTest(decision=decision), self.assertRaises(budget.Blocked):
                self.controller.defer()
        original = self.live.call
        def missing(endpoint, *args, **kwargs):
            result = original(endpoint, *args, **kwargs)
            if endpoint == 'graphql':
                del result['data']['repository']['pullRequest']['reviewDecision']
            return result
        self.live.call = missing
        with self.assertRaises(budget.Blocked):
            self.controller.defer()

    def test_native_decision_must_be_consistent_across_thread_pages(self):
        original = self.live.call
        calls = []
        def changing(endpoint, *args, **kwargs):
            result = original(endpoint, *args, **kwargs)
            if endpoint == 'graphql':
                calls.append(1)
                node = result['data']['repository']['pullRequest']
                if len(calls) == 1:
                    node['reviewThreads']['pageInfo'] = {'hasNextPage': True, 'endCursor': 'next'}
                else:
                    node['reviewDecision'] = None
                    node['reviewThreads']['nodes'] = []
            return result
        self.live.call = changing
        with self.assertRaises(budget.Blocked):
            self.controller.defer()
        self.assertEqual(self.api.issues, [])

    def test_real_snapshot_journal_receipt_survives_own_bookkeeping(self):
        receipt = self.controller.defer()
        self.assertEqual(receipt['head'], SHA)
        self.assertEqual(len(self.api.issues), 1)
        self.assertEqual(self.controller.admit(SHA)['clearance_basis'], 'capped-deferral')
        self.controller.defer()
        self.assertEqual(len(self.api.issues), 1)

    def test_deleted_or_edited_historical_critical_finding_blocks(self):
        self.api.inline[0]['body'] = '[P3] A changed finding'
        with self.assertRaises(budget.Blocked):
            self.controller.defer()
        self.assertEqual(self.api.issues, [])
        self.api.inline.clear()
        with self.assertRaises(budget.Blocked):
            self.controller.defer()

    def test_live_running_review_or_unknown_priority_blocks(self):
        self.api.reactions = [{'id': 8, 'content': 'eyes', 'user': BOT}]
        with self.assertRaises(budget.Blocked):
            self.controller.defer()
        self.assertEqual(self.api.issues, [])

    def test_same_head_new_thread_resolution_invalidates_receipt(self):
        self.controller.defer()
        self.api.resolved = True
        with self.assertRaises(budget.Blocked):
            self.controller.admit(SHA)

    def test_undeferred_human_thread_blocks(self):
        self.api.inline[0]['user'] = HUMAN
        self.journal.state['prs']['99']['events'][1]['payload']['comment']['user'] = HUMAN
        with self.assertRaises(budget.Blocked):
            self.controller.defer()

    def test_human_commented_priority_and_unknown_body_block_all_deferral(self):
        for body in ('[P1] Critical human finding', '[P0] Critical', 'Unknown-priority finding'):
            review = {'id': 55, 'user': HUMAN, 'state': 'COMMENTED', 'body': body,
                      'html_url': f'https://github.com/{REPO}/pull/99#pullrequestreview-55'}
            self.api.reviews = [review]
            self.journal.state['prs']['99']['events'].append(
                {'event': 'pull_request_review', 'payload': {'review': deepcopy(review)}})
            with self.subTest(body=body), self.assertRaises(budget.Blocked):
                self.controller.defer()
            self.assertEqual(self.api.issues, [])

    def test_historical_human_p1_cannot_be_erased_by_editing_current_body(self):
        for kind in ('review', 'comment'):
            self.setUp()
            original = {'id': 55, 'user': HUMAN, 'state': 'COMMENTED', 'body': '[P1] Old critical finding',
                        'html_url': f'https://github.com/{REPO}/pull/99#pullrequestreview-55'}
            current = {**original, 'body': ''}
            if kind == 'review':
                self.api.reviews = [current]
            else:
                self.api.comments.append(current)
            self.journal.state['prs']['99']['events'].append({
                'event': 'pull_request_review' if kind == 'review' else 'issue_comment',
                'payload': {kind: original}})
            with self.subTest(kind=kind), self.assertRaises(budget.Blocked):
                self.controller.defer()
            self.assertEqual(self.api.issues, [])


class GitCASTests(unittest.TestCase):
    def test_ref_update_nonforce_uses_exact_parent_and_reads_back_uncertain_write(self):
        calls = []
        desired = {'version': 1, 'prs': {}, 'locks': {}}
        def call(endpoint, method='GET', payload=None):
            calls.append((endpoint, method, payload))
            if endpoint.endswith('/blobs'):
                return {'sha': 'blob'}
            if endpoint.endswith('/trees'):
                return {'sha': 'tree'}
            if endpoint.endswith('/commits'):
                self.assertEqual(payload['parents'], ['old'])
                return {'sha': 'new'}
            self.assertEqual(payload, {'sha': 'new', 'force': False})
            raise budget.Blocked('response lost')
        journal = store.GitJournal(REPO, call=call)
        with patch.object(journal, 'read', return_value=('new', desired)):
            self.assertEqual(journal.compare_swap('old', desired), 'new')
        self.assertEqual(len([c for c in calls if c[1] == 'PATCH']), 1)
        with patch.object(journal, 'read', return_value=('competitor', desired)):
            with self.assertRaises(budget.Blocked):
                journal.compare_swap('old', desired)

class CapDispatchTests(unittest.TestCase):
    def invoke(self, operation, prior=None, late=False):
        import io
        import tempfile
        from types import SimpleNamespace
        policy_pr = {**pr(), 'clearance_basis': 'capped-deferral'}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'output'
            environment = {'GITHUB_ACTIONS': 'true', 'GITHUB_REF': 'refs/heads/main',
                           'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                           'GITHUB_RUN_ID': '20', 'GITHUB_OUTPUT': str(output),
                           'GITHUB_WORKFLOW_REF': f'{REPO}/.github/workflows/review-clearance.yml@refs/heads/main'}
            current = {'id': 20, 'history_workflow': 'review-clearance.yml', 'status': 'in_progress'}
            records = ([prior] if prior else []) + ([current] if operation == '--admit-run' else [])
            results = [policy_pr, budget.Blocked('revoked') if late else policy_pr]
            with patch.dict(gate.os.environ, environment), \
                    patch.object(gate, 'CAPPED_DEFERRAL_ENABLED', True), \
                    patch.object(gate, 'check_clean', side_effect=gate.Blocked('lower priority findings')), \
                    patch.object(runtime, 'check', side_effect=results) as policy, \
                    patch.object(gate, 'get_default_branch', return_value='main'), \
                    patch.object(gate, 'matching_runs', return_value=records), \
                    patch.object(gate.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as post, \
                    patch.object(gate.sys, 'stderr', new_callable=io.StringIO):
                args = ['--repo', REPO, '--pr', '99', '--expected-sha', SHA]
                if operation:
                    args += [operation, '--retry-failed']
                code = gate.main(args)
            return code, output.read_text() if output.exists() else '', policy.call_count, post.call_count

    def test_capped_basis_still_uses_launch_admission_and_downstream_rechecks(self):
        self.assertEqual(self.invoke('--dispatch'), (0, f'sha={SHA}\n', 2, 1))
        self.assertEqual(self.invoke('--admit-run'), (0, f'sha={SHA}\n', 2, 0))
        self.assertEqual(self.invoke(''), (0, f'sha={SHA}\n', 1, 0))

    def test_capped_basis_does_not_bypass_prior_success_or_late_revocation(self):
        prior = {'id': 10, 'status': 'completed', 'conclusion': 'success'}
        self.assertEqual(self.invoke('--dispatch', prior=prior)[1:], ('', 1, 0))
        self.assertEqual(self.invoke('--admit-run', prior=prior), (1, '', 1, 0))
        self.assertEqual(self.invoke('--dispatch', late=True), (1, '', 2, 0))
        self.assertEqual(self.invoke('--admit-run', late=True), (1, '', 2, 0))

class RecordedCodexFormatTests(unittest.TestCase):
    def setUp(self):
        self.recorded = json.loads((Path(__file__).parent/'fixtures/codex_recorded_formats.json').read_text())

    def test_recorded_badge_formats_preserve_priority_title_and_stable_ids(self):
        for index, item in enumerate(self.recorded['inline']):
            finding, = runtime.finding_sections(item['body'], f'inline:{index+1}', 'source', False)
            self.assertEqual((finding.priority, finding.title, finding.identity),
                             ('P2', f'Synthetic finding {index+1}', f'inline:{index+1}:0'))

    def test_badge_critical_priorities_remain_blockers(self):
        for priority in ('P0', 'P1'):
            body = self.recorded['inline'][0]['body'].replace('P2', priority)
            finding, = runtime.finding_sections(body, 'inline:1', snapshot().findings[0].source, False)
            with self.assertRaises(budget.Blocked):
                budget.deferral_candidates(replace(snapshot(), findings=(finding,)))

    def test_later_badge_sections_are_classified_or_blocked_never_swallowed(self):
        first, second = [item['body'] for item in self.recorded['inline']]
        findings = runtime.finding_sections(first+'\n\n'+second, 'review:1', 'source', False)
        self.assertEqual([f.identity for f in findings], ['review:1:0', 'review:1:1'])
        for malformed in (second.replace('img.shields.io', 'example.invalid'),
                          second.replace('?style=flat', '?unknown=flat'),
                          second.replace('<sub>', '<sup>')):
            with self.subTest(body=malformed), self.assertRaises(budget.Blocked):
                runtime.finding_sections(first+'\n\n'+malformed, 'review:1', 'source', False)

    def test_unknown_or_conflicting_badges_and_unknown_prose_fail_closed(self):
        body = self.recorded['inline'][0]['body']
        for mutated in (body.replace('P2', 'P4'), body.replace('/badge/P2-', '/badge/P1-'),
                        body.replace('img.shields.io', 'example.invalid'),
                        body.replace('?style=flat', '?unknown=flat'),
                        'Unclassified review prose\n'+body, body+'\n[P9] Unknown priority'):
            with self.subTest(body=mutated), self.assertRaises(budget.Blocked):
                runtime.finding_sections(mutated, 'inline:1', 'source', False)

    def test_submission_notice_is_exact_and_never_approval(self):
        notice = self.recorded['review']
        self.assertTrue(runtime.is_codex_review_notice(notice['body'], notice['commit_id']))
        for body in (notice['body']+'\n[P1] Hidden finding', 'Unknown prose\n'+notice['body'],
                     notice['body'].replace('Here are some automated review suggestions for this pull request.',
                                            'Unclassified review result.'),
                     notice['body'].replace('aaaaaaaaa', 'bbbbbbbbb')):
            self.assertFalse(runtime.is_codex_review_notice(body, notice['commit_id']))
        self.assertFalse(runtime.is_codex_review_notice(notice['body'], None))
        with self.assertRaises(budget.Blocked):
            runtime.finding_sections(notice['body'], 'inline:1', 'source', False)

    def setup_live(self, user=BOT):
        api = LiveAPI()
        api.inline[0]['body'] = self.recorded['inline'][0]['body']
        api.state['events'][1]['payload']['comment'] = deepcopy(api.inline[0])
        review = {'id': 55, 'state': 'COMMENTED', 'user': user,
                  'html_url': f'https://github.com/{REPO}/pull/99#pullrequestreview-55',
                  **self.recorded['review']}
        api.reviews = [review]
        api.state['events'].append({'event': 'pull_request_review', 'payload': {'review': deepcopy(review)}})
        journal = MemoryJournal({'version': 1, 'prs': {'99': api.state}, 'locks': {}})
        live = runtime.Live(REPO, 99, api, issue_author=REQUESTER)
        return api, runtime.Controller(REPO, 99, journal, FakeHistory(), live)

    def test_authenticated_recorded_submission_and_badge_pass_live_deferral_and_admission(self):
        api, controller = self.setup_live()
        controller.defer()
        self.assertEqual(len(api.issues), 1)
        self.assertEqual(controller.admit(SHA)['clearance_basis'], 'capped-deferral')

    def test_human_cannot_reuse_boilerplate_exemption(self):
        api, controller = self.setup_live(HUMAN)
        with self.assertRaises(budget.Blocked):
            controller.defer()
        self.assertEqual(api.issues, [])

    def test_changed_historical_boilerplate_cannot_hide_old_findings(self):
        api, controller = self.setup_live()
        controller.journal.state['prs']['99']['events'][-1]['payload']['review']['body'] += '\n[P1] Old finding'
        with self.assertRaises(budget.Blocked):
            controller.defer()
        self.assertEqual(api.issues, [])

class CappedSignoffWaitTests(unittest.TestCase):
    def invoke(self, clean, fallback, *, wait=True):
        import io
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'output'
            with patch.dict(gate.os.environ, {'GITHUB_ACTIONS': 'false', 'GITHUB_OUTPUT': str(output)}), \
                    patch.object(gate, 'CAPPED_DEFERRAL_ENABLED', True), \
                    patch.object(gate, 'check_clean', side_effect=clean) as normal, \
                    patch.object(runtime, 'check', side_effect=fallback) as capped, \
                    patch.object(gate.time, 'sleep') as sleep, \
                    patch.object(gate.sys, 'stderr', new_callable=io.StringIO):
                result = gate.main(['--repo', REPO, '--pr', '99', '--expected-sha', SHA]
                                   + (['--wait-for-signoff'] if wait else []))
                return result, normal.call_count, capped.call_count, sleep.call_args_list, \
                    output.read_text() if output.exists() else ''

    def test_below_cap_or_missing_receipt_preserves_original_awaiting_exception(self):
        for reason in ('Code Review budget has not been exhausted.', 'Deferral receipt stale or absent.'):
            waiting = gate.AwaitingSignoff('Waiting for current-head thumbs-up')
            with patch.object(gate, 'CAPPED_DEFERRAL_ENABLED', True), \
                    patch.object(gate, 'check_clean', side_effect=waiting), \
                    patch.object(runtime, 'check', side_effect=budget.Blocked(reason)), \
                    self.assertRaises(gate.AwaitingSignoff) as raised:
                gate.check(REPO, 99, SHA)
            self.assertIs(raised.exception, waiting)

    def test_fallback_denial_retries_until_clean_signoff_arrives(self):
        for reason in ('below cap', 'missing receipt'):
            result, normal, capped, sleeps, output = self.invoke(
                [gate.AwaitingSignoff('waiting'), pr()], budget.Blocked(reason))
            self.assertEqual((result, normal, capped, output), (0, 2, 1, f'sha={SHA}\n'))
            self.assertEqual([c.args for c in sleeps], [(5,)])

    def test_wait_is_bounded_and_no_wait_is_one_attempt(self):
        for wait, attempts in ((True, 3), (False, 1)):
            result, normal, capped, sleeps, output = self.invoke(
                gate.AwaitingSignoff('waiting'), budget.Blocked('missing receipt'), wait=wait)
            self.assertEqual((result, normal, capped, output), (1, attempts, attempts, ''))
            self.assertEqual([c.args for c in sleeps], [(5,)] * (attempts-1))

    def test_valid_capped_clearance_returns_immediately_without_waiting(self):
        result, normal, capped, sleeps, output = self.invoke(
            gate.AwaitingSignoff('waiting'), [{**pr(), 'clearance_basis': 'capped-deferral'}])
        self.assertEqual((result, normal, capped, sleeps, output), (0, 1, 1, [], f'sha={SHA}\n'))

    def test_ordinary_failures_remain_terminal(self):
        result, normal, capped, sleeps, output = self.invoke(
            gate.Blocked('unresolved threads'), budget.Blocked('critical finding'))
        self.assertEqual((result, normal, capped, sleeps, output), (1, 1, 1, [], ''))
        # Malformed fallback evidence is not reclassified as a sign-off delay.
        result, normal, capped, sleeps, output = self.invoke(
            gate.AwaitingSignoff('waiting'), ValueError('invalid fallback data'))
        self.assertEqual((result, normal, capped, sleeps, output), (1, 1, 1, [], ''))


if __name__ == '__main__':
    unittest.main()
