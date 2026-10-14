"""Disabled trusted-default controller for prospective review budgets.

No workflows invoke this writer. Enabling requires a reviewed source change,
approved isolated permissions, and controlled external-integration cutover.
"""
import argparse
from dataclasses import asdict
import json
import os
import re
import sys
import uuid

from review_budget import (Blocked, Finding, Snapshot, Issue, IssueInventory,
                           deferral_candidates, existing_issue, marker, request_allowed,
                           tracking_body, tracking_title)
from review_budget_store import GitJournal, api, all_items
from review_budget_history import History, digest, is_bot, rounds, SUMMARY

ENABLED = False
HOOK_ID = None
REQUESTER = None  # Verified {'id': integer, 'login': string}; never PR input.
LEDGER_REPOSITORY = None  # Separately provisioned controller-only state repository.


def issue_association(inventory, number):
    issue, = (issue for issue in inventory.issues if issue.number == number)
    # State is deliberately excluded: closing a genuine tracking issue is valid.
    return digest([issue.number, issue.author, issue.title, issue.body])


def require_enabled(repo):
    if (not ENABLED or not HOOK_ID or not REQUESTER
            or not LEDGER_REPOSITORY or LEDGER_REPOSITORY == repo):
        raise Blocked('Review budget activation and isolated permissions have not been approved.')
    branch = api(f'repos/{repo}')['default_branch']
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('GITHUB_REPOSITORY') != repo
            or os.environ.get('GITHUB_REF') != f'refs/heads/{branch}'
            or os.environ.get('GITHUB_RUN_ATTEMPT') != '1'):
        raise Blocked('Budget controller requires first-attempt trusted-default execution.')


def finding_sections(body, identity, source, resolved, kind='Code Review'):
    """Known explicit priority headings only. Multiple sections keep distinct IDs.

    Review bodies lack provider subfinding IDs: use immutable source-object ID
    plus section ordinal. The live adapter rejects all substantive finding edits,
    so ordinal identity cannot silently be rebound to edited/reordered text.
    """
    if not body.strip():
        return []
    # Recorded Codex Markdown badge envelope. The alt priority and URL priority
    # must agree; an unknown host/query/wrapper is not a recognized heading.
    # Normalization changes presentation only, never the source-object identity.
    badge_heading = re.compile(
        r'\*\*<sub><sub>!\[(P[0-3]) Badge\]'
        r'\(https://img\.shields\.io/badge/\1-[A-Za-z0-9]+\?style=flat\)'
        r'</sub></sub>  ([^\n]+)\*\*[ \t]*')
    lines = []
    for line in body.splitlines():
        if 'Badge]' in line or '<sub>' in line or re.search(r'!\[P[^\]]*\]', line):
            match = badge_heading.fullmatch(line)
            if not match:
                raise Blocked('Unknown badge heading envelope; cannot classify every finding.')
            line = f'[{match[1]}] {match[2]}'
        lines.append(line)
    body = '\n'.join(lines)
    headings = list(re.finditer(r'(?m)^\s*(?:#{1,6}\s+)?(?:\*\*)?\[(P[0-3])\]\s+([^\n]+)', body))
    if not headings or body[:headings[0].start()].strip():
        raise Blocked('Unclassified review text or unknown priority; manual classification required.')
    result = []
    for index, match in enumerate(headings):
        section = body[match.start():headings[index+1].start() if index+1 < len(headings) else len(body)]
        priorities = set(re.findall(r'\bP[0-9]+\b', section))
        if priorities != {match[1]}:
            raise Blocked('Conflicting or unknown priority in finding.')
        result.append(Finding(f'{identity}:{index}', source, match[1], resolved, kind,
                              match[2].strip('* ')))
    return result


def is_codex_review_notice(body, commit_id):
    """Exact recorded submission boilerplate, not approval or a review round.

    Allow only whitespace-only line differences and the declared commit prefix.
    Never apply this exemption to an inline/issue comment or unauthenticated user.
    """
    if not isinstance(commit_id, str) or not re.fullmatch(r'[0-9a-f]{40}', commit_id):
        return False
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    if len(lines) != 12:
        return False
    commit = re.fullmatch(r'\*\*Reviewed commit:\*\* `([0-9a-f]{7,40})`', lines[2])
    if not commit or not commit_id.startswith(commit[1]):
        return False
    expected = [
        '### 💡 Codex Review',
        'Here are some automated review suggestions for this pull request.',
        lines[2],
        '<details> <summary>ℹ️ About Codex in GitHub</summary>',
        '<br/>',
        '[Your team has set up Codex to review pull requests in this repo](https://chatgpt.com/codex/cloud/settings/general). Reviews are triggered when you',
        '- Open a pull request for review',
        '- Mark a draft as ready',
        '- Comment "@codex review".',
        'If Codex has suggestions, it will comment; otherwise it will react with 👍.',
        'Codex can also answer questions or update the PR. Try commenting "@codex address that feedback".',
        '</details>',
    ]
    return lines == expected


class Live:
    def __init__(self, repo, number, call=api, issue_author=None):
        self.repo, self.number, self.call = repo, number, call
        self.prefix = f'repos/{repo}'
        self.issue_author = issue_author

    def pr(self):
        return self.call(f'{self.prefix}/pulls/{self.number}')

    def inventory(self):
        endpoint = f'{self.prefix}/issues?state=all&per_page=100'
        first = all_items(endpoint, self.call)
        if first != all_items(endpoint, self.call):
            raise Blocked('Issue inventory changed while paginating.')
        trusted = () if self.issue_author is None else ((self.issue_author['id'], self.issue_author['login']),)
        return IssueInventory(True, tuple(Issue(i['number'], i['state'], i.get('body') or '',
                                               'pull_request' in i, i.get('title', ''),
                                               (i['user']['id'], i['user']['login'])) for i in first), trusted)

    def threads(self, pr):
        owner, name = self.repo.split('/')
        query = '''query($owner:String!, $name:String!, $number:Int!, $after:String) {
          repository(owner:$owner,name:$name) { pullRequest(number:$number) {
            headRefOid baseRefOid reviewDecision reviewThreads(first:100,after:$after) {
              nodes { id isResolved comments(first:1) { nodes { databaseId } } }
              pageInfo { hasNextPage endCursor }
            }
          } }
        }'''
        cursor, seen, result, decisions = None, set(), {}, set()
        for _ in range(1000):
            response = self.call('graphql', 'POST', {'query': query, 'variables': {
                'owner': owner, 'name': name, 'number': self.number, 'after': cursor}})
            if response.get('errors'):
                raise Blocked('Incomplete review-thread data.')
            node = response['data']['repository']['pullRequest']
            if 'reviewDecision' not in node:
                raise Blocked('Native review decision is missing.')
            decisions.add(node['reviewDecision'])
            if (node['headRefOid'] != pr['head']['sha'] or node['baseRefOid'] != pr['base']['sha']
                    or node['reviewDecision'] not in (None, 'APPROVED') or len(decisions) != 1):
                raise Blocked('Human review requirements or PR references changed.')
            page = node['reviewThreads']
            for thread in page['nodes']:
                roots = thread['comments']['nodes']
                if len(roots) != 1 or roots[0]['databaseId'] in result or type(thread['isResolved']) is not bool:
                    raise Blocked('Unclassifiable review thread.')
                result[roots[0]['databaseId']] = thread['isResolved']
            if page['pageInfo']['hasNextPage'] is False:
                return result, node['reviewDecision']
            cursor = page['pageInfo']['endCursor']
            if not cursor or cursor in seen:
                raise Blocked('Broken review-thread cursor.')
            seen.add(cursor)
        raise Blocked('Review-thread pagination limit.')

    def snapshot(self, state):
        pr = self.pr()
        comments = all_items(f'{self.prefix}/issues/{self.number}/comments?per_page=100', self.call)
        reviews = all_items(f'{self.prefix}/pulls/{self.number}/reviews?per_page=100', self.call)
        inline = all_items(f'{self.prefix}/pulls/{self.number}/comments?per_page=100', self.call)
        threads, native_decision = self.threads(pr)
        if (pr['state'] != 'open' or pr.get('draft') is not False or pr.get('mergeable') is not True
                or not pr['head'].get('repo') or pr['head']['repo']['full_name'] != self.repo
                or pr['base']['repo']['full_name'] != self.repo):
            raise Blocked('PR is not open/ready/mergeable in this repository.')
        summaries = {str(c['id']): c['body'] for c in comments if is_bot(c['user']) and c['body'].startswith(SUMMARY)}
        if summaries != state['summaries'] or len(summaries) > 1:
            raise Blocked('Live summary is not exactly covered by authenticated history.')
        live_requests = {str(c['id']): c['body'] for c in comments
                         if not is_bot(c['user']) and re.search(r'@codex\s+(?:security\s+)?review\b', c['body'], re.I)}
        if live_requests != state['requests']:
            raise Blocked('Live requests are not exactly covered by the ledger.')
        # Every current review object must occur in captured history and vice
        # versa. Deletions and substantive edits fail closed instead of erasing
        # historical severe findings or rebinding body-section identities.
        objects = {(kind, obj['id']): obj for kind, collection in
                   (('comment', comments), ('review', reviews), ('inline', inline)) for obj in collection}
        historical = {}
        for event in state['events']:
            field = {'issue_comment': 'comment', 'pull_request_review': 'review',
                     'pull_request_review_comment': 'comment'}.get(event['event'])
            if field is None:
                continue
            obj = event['payload'][field]
            kind = 'inline' if event['event'] == 'pull_request_review_comment' else field
            key = (kind, obj['id'])
            if key not in objects:
                raise Blocked('Deleted review evidence is unresolved/uncertain.')
            current = objects[key]
            old_body = obj.get('body') or ''
            historical_finding = (is_bot(obj['user']) or kind in ('review', 'inline')
                                  or re.search(r'\bP[0-9]+\b', old_body))
            authenticated_summary = is_bot(obj['user']) and old_body.startswith(SUMMARY)
            if historical_finding and not authenticated_summary:
                if obj.get('body', '') != current.get('body', ''):
                    raise Blocked('Historical finding text changed; cannot prove stable identity/severity.')
            historical[key] = obj
        if any(key not in historical for key in objects
               if key[0] != 'comment' or is_bot(objects[key]['user'])):
            raise Blocked('Live review evidence is missing from delivery history.')
        decisions = {}
        for review in sorted(reviews, key=lambda r: r['id']):
            if review['state'] in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'):
                decisions[review['user']['id']] = review['state']
            elif review['state'] not in ('COMMENTED',):
                raise Blocked('Pending or unknown review state.')
        if 'CHANGES_REQUESTED' in decisions.values():
            raise Blocked('Outstanding human or bot changes request.')
        # EBR retains its original native-review policy: explicit null is not
        # proof of human approval, but is permitted when GitHub reports no native
        # decision. Repositories mandating a human approval need an extra rule.
        human_requirements_met = native_decision in (None, 'APPROVED')
        findings = []
        # Security findings cannot be guessed from identical inline formatting:
        # if Security Review exists, require the original strict clean gate.
        security = any(r.kind == 'Security Review' for r in rounds(state))
        for (kind, ident), obj in objects.items():
            body = obj.get('body') or ''
            if body.startswith(SUMMARY) and is_bot(obj['user']):
                continue
            if (kind == 'review' and is_bot(obj['user']) and obj.get('state') == 'COMMENTED'
                    and is_codex_review_notice(body, obj.get('commit_id'))):
                continue
            if kind == 'inline':
                root = obj.get('in_reply_to_id', ident)
                if root not in threads:
                    raise Blocked('Inline comment not covered by a complete thread.')
                resolved = threads[root]
                if not is_bot(obj['user']):
                    if not resolved:
                        raise Blocked('Non-Codex unresolved thread remains.')
                    continue
            else:
                resolved = False
                if not is_bot(obj['user']):
                    if kind == 'review' and body.strip():
                        raise Blocked('Human review-body findings/priority cannot be waived or inferred resolved.')
                    if kind == 'comment' and re.search(r'\bP[0-9]+\b', body):
                        raise Blocked('Priority-bearing human conversation requires explicit reconciliation.')
                    continue
            findings += finding_sections(body, f'{kind}:{ident}', obj['html_url'], resolved)
        reactions = all_items(f'{self.prefix}/issues/{self.number}/reactions?per_page=100', self.call)
        for comment in comments:
            if str(comment['id']) in state['requests']:
                reactions += all_items(f"{self.prefix}/issues/comments/{comment['id']}/reactions?per_page=100", self.call)
        # Conservative: any remaining bot eyes blocks, even on old requests.
        if any(is_bot(r['user']) and r['content'] == 'eyes' for r in reactions):
            raise Blocked('Running-review reaction remains.')
        if security:
            raise Blocked('Security Review present: use separate strict clean-review clearance; no security deferral.')
        # Journal bookkeeping must not invalidate its own receipt. Review event
        # history and request reservations remain part of the evidence digest.
        evidence_state = {k: v for k, v in state.items() if k not in ('writes', 'deferral', 'anchor')}
        evidence = {'pr': pr, 'comments': comments, 'reviews': reviews, 'inline': inline,
                    'threads': threads, 'native_decision': native_decision,
                    'reactions': reactions, 'state': evidence_state}
        if self.pr() != pr:
            raise Blocked('PR changed during snapshot.')
        return Snapshot(self.repo, self.number, pr['head']['sha'], pr['base']['sha'], digest(evidence),
                        True, True, True, human_requirements_met, security, False, rounds(state), tuple(findings)), pr


class Controller:
    def __init__(self, repo, number, journal, history, live):
        self.repo, self.number, self.journal, self.history, self.live = repo, number, journal, history, live
        self.key = str(number)

    def sync(self, tx):
        _, document = tx.read()
        state = self.history.sync(self.live.pr(), document['prs'].get(self.key))
        tx.update(lambda d: d['prs'].__setitem__(self.key, state))
        return state

    def read_snapshot(self, tx):
        _, document = tx.read()
        state = self.history.sync(self.live.pr(), document['prs'][self.key])
        snapshot, pr = self.live.snapshot(state)
        return snapshot, pr

    def defer(self):
        with self.journal.transaction(self.number) as tx:
            self.sync(tx)
            original, _ = self.read_snapshot(tx)
            candidates = deferral_candidates(original)
            def unchanged():
                current, _ = self.read_snapshot(tx)
                if current != original:
                    raise Blocked('Evidence changed before/during issue transaction.')
            # The comparison excludes write intents; they are bookkeeping only.
            for finding in candidates:
                unchanged()
                identity = marker(original, finding)
                inventory = self.live.inventory()
                _, document = tx.read()
                intent = document['prs'][self.key]['writes'].get(identity)
                number = existing_issue(original, finding, inventory,
                                        require_marked=bool(intent and intent.get('marked', True)))
                if (number is not None and intent and intent.get('state') == 'confirmed'
                        and issue_association(inventory, number) != intent.get('association')):
                    raise Blocked('Previously confirmed tracking association changed.')
                if number is None:
                    if intent is not None:
                        raise Blocked('Uncertain prior issue intent: read-only reconciliation required; never resend.')
                    intent = {'state': 'intent', 'source': finding.source, 'head': original.head}
                    tx.update(lambda d: d['prs'][self.key]['writes'].__setitem__(identity, intent))
                    unchanged()
                    body = tracking_body(original, finding)
                    try:
                        self.live.call(f'repos/{self.repo}/issues', 'POST',
                                       {'title': tracking_title(finding), 'body': body})
                    except Exception:
                        pass
                    inventory = self.live.inventory()
                    number = existing_issue(original, finding, inventory, require_marked=True)
                    if number is None:
                        raise Blocked('Issue write unconfirmed; durable intent prevents resend after restart.')
                tx.update(lambda d: d['prs'][self.key]['writes'].__setitem__(identity,
                          {'state': 'confirmed', 'number': number, 'source': finding.source, 'head': original.head,
                           'marked': any(marker(original, finding) in i.body for i in inventory.issues if i.number == number),
                           'association': issue_association(inventory, number)}))
            unchanged()
            # Record evidence only after all issues read back and final live check.
            receipt = {'head': original.head, 'base': original.base, 'revision': original.revision,
                       'findings': [marker(original, f) for f in candidates]}
            tx.update(lambda d: d['prs'][self.key].__setitem__('deferral', receipt))
            return receipt

    def request(self):
        with self.journal.transaction(self.number) as tx:
            self.sync(tx)
            snapshot, _ = self.read_snapshot(tx)
            if not request_allowed(snapshot):
                raise Blocked('Three completed Code Reviews already consumed; request suppressed.')
            nonce = str(uuid.uuid4())
            body = f'@codex review\n\n<!-- codex-budget-request:{nonce} -->\nHead: `{snapshot.head}`'
            pending = {'nonce': nonce, 'kind': 'Code Review', 'head': snapshot.head,
                       'body': body, 'comment': None}
            # Reservation is durable BEFORE POST, and blocks every later request.
            tx.update(lambda d: d['prs'][self.key].__setitem__('pending', pending))
            _, document = tx.read()
            fresh_state = self.history.sync(self.live.pr(), document['prs'][self.key])
            if fresh_state['pending'] != pending:
                raise Blocked('Request reservation changed; reconcile without sending.')
            # Exclude only our own newly persisted reservation for comparison.
            # Every review, PR state, approval and request remains live evidence.
            fresh_state['pending'] = None
            current, _ = self.live.snapshot(fresh_state)
            if current != snapshot:
                raise Blocked('Eligibility changed after reservation; reconcile without sending.')
            try:
                self.live.call(f'repos/{self.repo}/issues/{self.number}/comments', 'POST', {'body': body})
            except Exception:
                pass
            self.reconcile_request(tx)

    def reconcile_request(self, tx):
        _, document = tx.read()
        pending = document['prs'][self.key]['pending']
        if not pending:
            raise Blocked('No request intent to reconcile.')
        comments = all_items(f'repos/{self.repo}/issues/{self.number}/comments?per_page=100', self.live.call)
        matches = [c for c in comments if c['body'] == pending['body']
                   and c['user']['id'] == self.history.requester['id']
                   and c['user']['login'] == self.history.requester['login']]
        if len(matches) != 1:
            raise Blocked('Request write uncertain; reservation retained and no automatic resend.')
        pending['comment'] = matches[0]['id']
        tx.update(lambda d: d['prs'][self.key].__setitem__('pending', pending))

    def admit(self, expected_sha=None):
        before, document = self.journal.read()
        if document.get('locks', {}).get(self.key) or self.key not in document['prs']:
            raise Blocked('Journal locked or PR not prospectively enrolled.')
        state = self.history.sync(self.live.pr(), document['prs'][self.key])
        snapshot, pr = self.live.snapshot(state)
        candidates = deferral_candidates(snapshot)
        receipt = state.get('deferral')
        expected = {'head': snapshot.head, 'base': snapshot.base, 'revision': snapshot.revision,
                    'findings': [marker(snapshot, f) for f in candidates]}
        if receipt != expected or (expected_sha and snapshot.head != expected_sha):
            raise Blocked('Deferral receipt stale or absent; no exact-head admission.')
        inventory = self.live.inventory()
        for finding in candidates:
            recorded = state['writes'].get(marker(snapshot, finding), {})
            if (recorded.get('state') != 'confirmed' or
                    existing_issue(snapshot, finding, inventory,
                                   require_marked=recorded.get('marked', True)) != recorded.get('number') or
                    issue_association(inventory, recorded['number']) != recorded.get('association')):
                raise Blocked('Linked issue missing, changed or unconfirmed.')
        fresh_state = self.history.sync(self.live.pr(), document['prs'][self.key])
        fresh, fresh_pr = self.live.snapshot(fresh_state)
        if fresh != snapshot or self.journal.read()[0] != before:
            raise Blocked('Evidence/journal changed during admission.')
        fresh_pr['clearance_basis'] = 'capped-deferral'
        return fresh_pr


def controller(repo, number):
    require_enabled(repo)
    return Controller(repo, number, GitJournal(LEDGER_REPOSITORY, source_repo=repo),
                      History(repo, HOOK_ID, REQUESTER), Live(repo, number, issue_author=REQUESTER))


def check(repo, number, expected_sha=None):
    return controller(repo, number).admit(expected_sha)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--pr', required=True, type=int)
    parser.add_argument('operation', choices=['enroll', 'sync', 'request', 'reconcile-request', 'defer', 'check'])
    args = parser.parse_args(argv)
    try:
        c = controller(args.repo, args.pr)
        if args.operation in ('enroll', 'sync'):
            with c.journal.transaction(args.pr) as tx:
                c.sync(tx)
        elif args.operation == 'reconcile-request':
            with c.journal.transaction(args.pr) as tx:
                c.reconcile_request(tx)
        else:
            result = {'request': c.request, 'defer': c.defer, 'check': c.admit}[args.operation]()
            if result:
                print(json.dumps(result))
        return 0
    except (Blocked, KeyError, TypeError, ValueError, OSError) as exc:
        print(f'Review budget blocked: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
