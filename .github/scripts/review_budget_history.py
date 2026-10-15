"""Authenticated, prospective GitHub delivery history adapter.

Delivery payloads come from GitHub's authenticated REST API, never workflow input
or PR artifacts. A configured repository hook must precede PR creation. The full
retained delivery inventory is checked twice and must retain our previous anchor.
The summary edit chain catches missed/out-of-order transitions. No backfill from
current mutable summaries is permitted.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re

from review_budget import Blocked, Round
from review_budget_store import api, all_items

BOT = {'id': 199175422, 'login': 'chatgpt-codex-connector[bot]', 'type': 'Bot'}
SUMMARY = '<!-- codex-pull-request-review-summary -->'
EVENTS = {'pull_request', 'issue_comment', 'pull_request_review', 'pull_request_review_comment'}


def is_bot(user):
    return all(user.get(key) == value for key, value in BOT.items())


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def date(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise Blocked('Naive event timestamp.')
    return parsed.astimezone(timezone.utc)


def resolve_commit(commit, repo, call=api):
    """Resolve an authenticated summary commit cell to exactly one full SHA.

    GitHub's commits endpoint also accepts branch and tag names, so a ref named
    like an abbreviation could resolve to an unrelated commit. The response must
    be a full lowercase hexadecimal SHA that starts with the abbreviation; a full
    SHA needs no call. API failures and malformed responses fail closed. Recorded
    completions are never resolved again; see summary_rows.
    """
    if not isinstance(commit, str) or not re.fullmatch('[0-9a-f]{7,40}', commit):
        raise Blocked('Missing review commit.')
    if len(commit) == 40:
        return commit
    response = call(f'repos/{repo}/commits/{commit}')
    sha = response.get('sha') if isinstance(response, dict) else None
    if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{40}', sha) or not sha.startswith(commit):
        raise Blocked('Resolved commit does not match the authenticated review abbreviation.')
    return sha


def summary_rows(body, repo, call=api, recorded=None):
    """Parse authenticated summary rows.

    ``recorded`` maps (kind, completion time) of every recorded completion to its
    full SHA. Such a row is bound to that SHA without resolution, whatever
    abbreviation length is rendered, and a commit cell inconsistent with it
    blocks, so a recorded completion can never be rebound to another commit.
    """
    recorded = {} if recorded is None else recorded
    allowed_prose = {
        SUMMARY, '## Codex Review Summary',
        'This comment shows the latest Codex review activity on this pull request.',
        '<details> <summary>ℹ️ About Codex in GitHub</summary>', '<br/>', '</details>',
        '[Your team has set up Codex to review pull requests in this repo](https://chatgpt.com/codex/cloud/settings/general). Reviews are triggered when you',
        '- Open a pull request for review', '- Mark a draft as ready',
        '- Comment "@codex review" or "@codex security review".',
        'Codex reacts with 👀 while any review is running, comments if it has suggestions, and reacts with 👍 once all reviews finish with no findings.',
    }
    rows = {}
    for line in body.splitlines():
        if not line.startswith('|'):
            if line.strip() and line.strip() not in allowed_prose:
                raise Blocked('Unclassified summary content, including possible findings.')
            continue
        cells = [c.strip() for c in line.strip('|').split('|')]
        if cells == ['Review', 'Status', 'Commit', 'Review trigger']:
            continue
        if len(cells) == 4 and all(cell and set(cell) <= {'-', ':', ' '} for cell in cells):
            continue
        kinds = [kind for kind in ('Code Review', 'Security Review') if kind in cells[0]]
        if len(cells) != 4 or len(kinds) != 1 or kinds[0] in rows:
            raise Blocked('Unknown review summary schema.')
        if (cells[0] not in ('Code Review', 'Security Review', '📝 **Code Review**', '🛡️ **Security Review**')
                or cells[3] != 'Manual request'):
            raise Blocked('Unclassified summary label/trigger/result cell.')
        commit = re.fullmatch(r'`([0-9a-f]{7,40})`', cells[2])
        if not commit:
            raise Blocked('Missing review commit.')
        completed = re.fullmatch(r'✅ \*\*Completed\*\* <relative-time datetime="([^"]+)">([^<]+)</relative-time>', cells[1])
        if not completed and not re.fullmatch(r'(?:[🔄⏳] )?\*\*(?:Running|Pending|Queued)\*\*', cells[1]):
            raise Blocked('Unclassified summary status/result content.')
        if completed and completed[1] != completed[2]:
            raise Blocked('Inconsistent summary completion timestamps.')
        stamp = re.search(r'datetime="([^"]+)"', cells[1])
        if completed and not stamp:
            raise Blocked('Missing review completion time.')
        if stamp:
            date(stamp[1])
        head = recorded.get((kinds[0], stamp[1])) if completed else None
        if head is None:
            sha = resolve_commit(commit[1], repo, call)
        elif head.startswith(commit[1]):
            sha = head
        else:
            raise Blocked('Recorded completion rebound to another commit.')
        rows[kinds[0]] = {'head': sha, 'state': 'completed' if completed else 'running',
                         'completed_at': stamp[1] if completed else None}
    if not rows:
        raise Blocked('Empty review summary.')
    return rows


class History:
    def __init__(self, repo, hook_id, requester, call=api):
        self.repo, self.hook_id, self.requester, self.call = repo, hook_id, requester, call
        self.prefix = f'repos/{repo}/hooks/{hook_id}'

    def batch(self):
        hook = self.call(self.prefix)
        if (hook.get('active') is not True or not EVENTS <= set(hook.get('events', []))
                or hook.get('id') != self.hook_id):
            raise Blocked('History hook inactive, changed or missing required events.')
        binding = {key: hook[key] for key in ('id', 'created_at', 'updated_at', 'events', 'active')}
        items = all_items(self.prefix + '/deliveries?per_page=100', self.call)
        details = []
        for item in sorted(items, key=lambda value: value['id']):
            detail = self.call(f"{self.prefix}/deliveries/{item['id']}")
            if any(detail.get(key) != item.get(key) for key in ('id', 'guid', 'event', 'action', 'repository_id', 'redelivery')):
                raise Blocked('Delivery metadata changed while reading.')
            headers = {key.lower(): value for key, value in detail['request']['headers'].items()}
            payload = detail['request']['payload']
            if (headers.get('x-github-delivery') != item['guid']
                    or headers.get('x-github-event') != item['event']
                    or str(headers.get('x-github-hook-id')) != str(self.hook_id)
                    or payload['repository']['full_name'] != self.repo
                    or payload['repository']['id'] != item['repository_id']):
                raise Blocked('Delivery authentication/context mismatch.')
            details.append({'id': item['id'], 'guid': item['guid'], 'event': item['event'],
                            'action': item['action'], 'redelivery': item['redelivery'], 'payload': payload})
        second = all_items(self.prefix + '/deliveries?per_page=100', self.call)
        if [i['id'] for i in items] != [i['id'] for i in second] or self.call(self.prefix) != hook:
            raise Blocked('Delivery history changed; retry without mutation.')
        return binding, details

    def sync(self, pr, previous=None):
        hook, deliveries = self.batch()
        number = pr['number']
        if previous is None:
            openings_by_guid = {}
            for delivery in deliveries:
                if (delivery['event'] != 'pull_request' or delivery['action'] != 'opened'
                        or delivery['payload']['pull_request']['number'] != number):
                    continue
                previous_opening = openings_by_guid.get(delivery['guid'])
                if previous_opening is not None:
                    if any(delivery[key] != previous_opening[key] for key in ('event', 'action', 'payload')):
                        raise Blocked('Conflicting opening-event redelivery.')
                    # Keep the earliest raw delivery as the enrollment boundary.
                    if previous_opening['id'] < delivery['id']:
                        continue
                openings_by_guid[delivery['guid']] = delivery
            openings = list(openings_by_guid.values())
            # Initial enrollment is prospective, while still a pristine draft.
            if (len(openings) != 1 or openings[0].get('redelivery') is not False
                    or pr.get('draft') is not True or pr['state'] != 'open'
                    or openings[0]['payload']['pull_request']['draft'] is not True
                    or openings[0]['payload']['pull_request']['created_at'] != pr['created_at']
                    or date(hook['created_at']) >= date(pr['created_at'])):
                raise Blocked('No prospective opening evidence; historical PRs cannot enroll.')
            start = openings[0]['id']
            if any(d['id'] < start and
                   d['payload'].get('pull_request', d['payload'].get('issue', {})).get('number') == number
                   for d in deliveries):
                raise Blocked('Scoped activity precedes original opening evidence.')
            state = {'hook': hook, 'anchor': start, 'events': [], 'guids': {}, 'summaries': {},
                     'rounds': {}, 'latest': {}, 'requests': {}, 'writes': {}, 'pending': None,
                     'created_at': pr['created_at']}
        else:
            state = deepcopy(previous)
            start = state['anchor']
            if hook != state['hook'] or pr['created_at'] != state['created_at']:
                raise Blocked('History enrollment binding changed.')
        if start not in {d['id'] for d in deliveries}:
            raise Blocked('History watermark expired/missing; cannot prove delivery continuity.')
        for delivery in deliveries:
            if delivery['id'] < start or (previous is not None and delivery['id'] == start):
                continue
            payload = delivery['payload']
            scoped = payload.get('pull_request', payload.get('issue', {})).get('number') == number
            if not scoped:
                continue
            signature = digest({'event': delivery['event'], 'action': delivery['action'], 'payload': payload})
            if delivery['guid'] in state['guids']:
                if state['guids'][delivery['guid']] != signature:
                    raise Blocked('Conflicting webhook redelivery.')
                continue
            state['guids'][delivery['guid']] = signature
            self.apply(state, delivery)
            state['events'].append(delivery)
        if previous is None and (state['summaries'] or state['rounds'] or state['requests']
                                 or any(d['event'].startswith('pull_request_review') for d in state['events'])):
            raise Blocked('Review activity predates prospective enrollment.')
        if deliveries:
            state['anchor'] = max(d['id'] for d in deliveries)
        return state

    def apply(self, state, delivery):
        payload, action = delivery['payload'], delivery['action']
        if delivery['event'] != 'issue_comment':
            return
        comment = payload['comment']
        body, identity = comment.get('body', ''), str(comment['id'])
        if body.startswith(SUMMARY) or identity in state['summaries']:
            if not is_bot(comment['user']) or not is_bot(payload['sender']):
                raise Blocked('Unauthenticated summary change.')
            old = state['summaries'].get(identity)
            if ((old is None and action != 'created') or (old is not None and action != 'edited')
                    or (old is not None and payload.get('changes', {}).get('body', {}).get('from') != old)):
                raise Blocked('Missing, deleted or out-of-order summary revision.')
            if not body.startswith(SUMMARY):
                raise Blocked('Summary marker removed.')
            recorded = {(r['kind'], r['completed_at']): r['head'] for r in state['rounds'].values()}
            rows = summary_rows(body, self.repo, self.call, recorded)
            for kind, row in rows.items():
                if row['state'] == 'completed':
                    key = digest([kind, row['head'], row['completed_at']])
                    if key not in state['rounds']:
                        pending = state['pending']
                        if not pending or pending['kind'] != kind or pending['head'] != row['head']:
                            raise Blocked('Completion has no unique controlled request reservation.')
                        if pending.get('comment') is None:
                            raise Blocked('Request write not reconciled before completion.')
                        state['rounds'][key] = dict(row, kind=kind, request=pending['nonce'])
                        state['pending'] = None
                    elif state['latest'].get(kind, {}).get('state') == 'running':
                        raise Blocked('Ambiguous repeated completion identity.')
                state['latest'][kind] = row
            state['summaries'][identity] = body
        elif re.search(r'@codex\s+(?:security\s+)?review\b', body, re.I):
            pending = state['pending']
            expected = state['requests'].get(identity)
            if expected is None and pending and pending.get('comment') == comment['id']:
                expected = pending['body']
            if (comment['user'].get('id') != self.requester['id']
                    or comment['user'].get('login') != self.requester['login']
                    or expected != body or action != 'created'):
                raise Blocked('External or edited request breaks controlled-request history.')
            state['requests'][identity] = body
        elif identity in state['requests']:
            raise Blocked('Controlled request was edited or deleted.')


def rounds(state):
    if state['pending'] or any(row['state'] != 'completed' for row in state['latest'].values()):
        raise Blocked('Review reservation or running review remains.')
    return tuple(Round(key, row['kind'], row['head'], row['state']) for key, row in state['rounds'].items())
