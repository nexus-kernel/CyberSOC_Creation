#!/usr/bin/env python3
"""CyberSOC-only trusted controller. All writes require a persisted prepared artifact."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import zipfile

import review_gate as gate
import budget_policy as policy

REPO = policy.REPO
WORKFLOW = 'review-budget.yml'
PREFIX = f'repos/{REPO}'
ACTIONS_BOT = {'id': 41898282, 'login': 'github-actions[bot]', 'type': 'Bot'}
ROOT = Path(__file__).resolve().parents[2]
CONTROL_FILES = ('.github/scripts/review_budget.py', '.github/scripts/budget_policy.py',
                 '.github/scripts/review_gate.py', '.github/workflows/review-budget.yml')


class Blocked(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Blocked(message)


def api(path, method='GET', data=None):
    need(path.startswith(PREFIX + '/') or path == 'graphql', 'Unexpected API repository')
    command = ['gh', 'api', path, '--method', method]
    if data is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=None if data is None else json.dumps(data),
                            text=True, capture_output=True)
    need(result.returncode == 0, f'API {method} failed: {path}; do not retry writes blindly')
    return json.loads(result.stdout) if result.stdout else None


def pages(path, key=None, identity='id'):
    """Counted collections must match totals; simple REST lists need a terminal page."""
    output, seen, total = [], set(), None
    for page in range(1, 1001):
        data = api(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
        items = data if key is None else data[key]
        need(isinstance(items, list) and len(items) <= 100, 'Malformed collection')
        if key is not None:
            count = data.get('total_count')
            need(type(count) is int and count >= 0, 'Missing collection count')
            need(total in (None, count), 'Collection changed during pagination')
            total = count
        for item in items:
            ident = item.get(identity)
            valid = (type(ident) is int and ident > 0) if identity == 'id' else (isinstance(ident,str) and bool(ident))
            need(valid and ident not in seen, 'Duplicate/invalid API identity')
            seen.add(ident); output.append(item)
        if len(items) < 100:
            need(total is None or len(output) == total, 'Incomplete collection')
            return output
    raise Blocked('Collection exceeds verified pagination limit')


def config():
    value = json.loads((ROOT / '.github/review-budget.json').read_text())
    need(value.get('enabled') is True and value.get('repository') == REPO,
         'Budget activation is disabled or outside CyberSOC')
    gate.timestamp(value['activation_after'])
    need(value.get('ordinary_completed_rounds') == 3, 'Unsupported budget')
    need(value.get('independent_code_triggers_disabled') is True,
         'Sole-reviewer setup has not been verified')
    need(type(value.get('security_review_required')) is bool, 'Unknown security coverage')
    need(value.get('native_merge_policy_verified') is True
         and value.get('merge_queue_required') is False,
         'Native merge policy/queue setup not verified')
    return value


def trusted_context():
    need(os.environ.get('GITHUB_REPOSITORY') == REPO, 'CyberSOC only')
    need(os.environ.get('GITHUB_ACTIONS') == 'true'
         and os.environ.get('GITHUB_RUN_ATTEMPT') == '1', 'Trusted first attempt required')
    branch = gate.get_default_branch(REPO)
    need(os.environ.get('GITHUB_REF') == f'refs/heads/{branch}', 'Default branch only')
    return branch


def same_control(ref):
    """History must have executed this exact controller protocol, never PR code."""
    policy.sha(ref)
    for name in CONTROL_FILES:
        blob = api(f'{PREFIX}/contents/{name}?ref={ref}')
        need(blob.get('encoding') == 'base64', 'Missing historical control source')
        need(base64.b64decode(blob['content']) == (ROOT / name).read_bytes(),
             'Controller revision changed; audited ledger migration required')


def verify_run(run, branch):
    need(run.get('event') == 'workflow_dispatch' and run.get('head_branch') == branch
         and run.get('path') == f'.github/workflows/{WORKFLOW}'
         and type(run.get('run_attempt')) is int and run['run_attempt'] == 1,
         'Untrusted controller run')
    need(run.get('repository', {}).get('full_name') == REPO
         and run.get('head_repository', {}).get('full_name') == REPO, 'Foreign controller run')
    ref = policy.sha(run['head_sha'])
    comparison = api(f'{PREFIX}/compare/{ref}...{branch}')
    need(comparison.get('status') in ('ahead', 'identical'), 'Control revision is not trusted default ancestry')
    same_control(ref)


def artifact(run, phase, number):
    name = f'mxdr-budget-{number}-{run["id"]}-{phase}'
    artifacts = pages(f'{PREFIX}/actions/runs/{run["id"]}/artifacts', 'artifacts')
    matches = [a for a in artifacts if a['name'] == name]
    need(len(matches) == 1 and matches[0].get('expired') is False, 'Missing/expired ledger artifact')
    entry = matches[0]
    need(entry.get('workflow_run', {}).get('id') == run['id'], 'Artifact/run mismatch')
    result = subprocess.run(['gh', 'api', f'{PREFIX}/actions/artifacts/{entry["id"]}/zip'],
                            capture_output=True)
    need(result.returncode == 0, 'Ledger download failed')
    need(entry.get('digest') == 'sha256:' + hashlib.sha256(result.stdout).hexdigest(),
         'Missing/mismatched artifact digest')
    with zipfile.ZipFile(io.BytesIO(result.stdout)) as archive:
        need(archive.namelist() == ['ledger.json'], 'Unexpected ledger archive members')
        info = archive.getinfo('ledger.json')
        need(info.file_size < 5_000_000, 'Ledger exceeds size limit')
        value = json.loads(archive.read('ledger.json'))
    need(value['repo'] == REPO and value['pr'] == number and value['run_id'] == run['id']
         and value['phase'] == phase, 'Ledger scope mismatch')
    return value


def load_ledger(number, branch, current_run=None):
    title = f'MXDR budget / PR #{number}'
    runs = gate.complete_run_history(gate.gh_api(
        f'{PREFIX}/actions/workflows/{WORKFLOW}/runs?event=workflow_dispatch&branch={branch}&per_page=100',
        paginate=True))
    matching = sorted((r for r in runs if r['display_title'] == title), key=lambda r: r['id'])
    previous, chain = None, []
    for short in matching:
        if short['id'] == current_run:
            continue
        run = api(f'{PREFIX}/actions/runs/{short["id"]}')
        verify_run(run, branch)
        if ((run.get('status') in ('queued','pending','requested') and run.get('conclusion') is None)
                or (run.get('status')=='completed' and run.get('conclusion')=='cancelled')):
            if gate.has_no_jobs(REPO,run):
                continue
        # A final checkpoint is committed before the dispatch-only tail. It remains
        # valid if that tail fails or is still finishing. Prepared-only runs block.
        entries = pages(f'{PREFIX}/actions/runs/{run["id"]}/artifacts', 'artifacts')
        final_name = f'mxdr-budget-{number}-{run["id"]}-final'
        if not any(a['name'] == final_name for a in entries):
            jobs = pages(f'{PREFIX}/actions/runs/{run["id"]}/attempts/1/jobs', 'jobs')
            steps = [step for job in jobs for step in job.get('steps', [])
                     if step['name'] == 'Execute prepared action']
            need(run.get('status') == 'completed' and len(steps) == 1
                 and steps[0]['conclusion'] == 'skipped',
                 'Uncertain controller write requires audited recovery')
            continue
        value = artifact(run, 'final', number)
        need(run.get('status') != 'completed' or run.get('conclusion') == 'success', 'Previous controller tail failed; audited recovery required')
        need(value['history'] == chain, 'Ledger gap, deletion, reorder or fork')
        if previous:
            need(value['previous_digest'] == policy.digest(previous), 'Broken ledger chain')
        else:
            need(value['previous_digest'] is None, 'Missing ledger genesis')
        chain.append(run['id']); previous = value
    if previous:
        previous = dict(previous, history=chain, previous_digest=policy.digest(previous))
    return previous


def thread_evidence(number, head, base):
    query = '''query($number:Int!, $after:String) {
      repository(owner:"nexus-kernel", name:"CyberSOC_Creation") {
        pullRequest(number:$number) {
          headRefOid baseRefOid reviewDecision mergeStateStatus
          reviewThreads(first:100,after:$after) {
            nodes { id isResolved isOutdated comments(first:100) {
              totalCount nodes { databaseId } pageInfo { hasNextPage } } }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }'''
    result, seen, after, decision = [], set(), None, None
    for _ in range(1000):
        data = api('graphql', 'POST', {'query': query, 'variables': {'number': number, 'after': after}})
        need(not data.get('errors'), 'GraphQL evidence failed')
        pr = data['data']['repository']['pullRequest']
        need(pr['headRefOid'] == head and pr['baseRefOid'] == base, 'PR moved during thread collection')
        current = (pr['reviewDecision'], pr['mergeStateStatus'])
        need(decision in (None, current), 'Native review state changed')
        decision = current
        page = pr['reviewThreads']
        need(type(page['pageInfo']['hasNextPage']) is bool and isinstance(page['nodes'], list), 'Bad thread page')
        for thread in page['nodes']:
            need(thread['id'] not in seen and type(thread['isResolved']) is bool, 'Duplicate/unknown thread')
            seen.add(thread['id'])
            comments = thread['comments']
            need(comments['pageInfo']['hasNextPage'] is False
                 and comments['totalCount'] == len(comments['nodes']) and comments['nodes'],
                 'Thread exceeds supported complete comment window')
            result.append(thread)
        if page['pageInfo']['hasNextPage'] is False:
            return result, decision
        after = page['pageInfo']['endCursor']
        need(isinstance(after, str) and after and after not in seen, 'Bad thread cursor')
        seen.add(after)
    raise Blocked('Thread pagination cap')


def mergeable_pr(number):
    """Retry only unknown mergeability; never retry writes or a confirmed conflict."""
    identity = None
    for attempt in range(5):
        pr = api(f'{PREFIX}/pulls/{number}')
        need(pr['state'] == 'open' and pr.get('draft') is False,
             'PR must be open and ready')
        need(pr['head'].get('repo', {}).get('full_name') == REPO
             and pr['base']['repo']['full_name'] == REPO, 'Same-repository PR only')
        current = (policy.sha(pr['head']['sha']), policy.sha(pr['base']['sha']))
        need(identity is None or current == identity, 'PR moved while awaiting mergeability')
        identity = current
        if pr.get('mergeable') is True:
            return pr
        need('mergeable' in pr and pr['mergeable'] is None,
             'PR has a confirmed conflict or invalid mergeability')
        if attempt < 4:
            time.sleep(2 ** (attempt + 1))
    raise Blocked('Mergeability still unknown after 5 reads/30s backoff; fresh controller wake required')


def collect(number, cfg, deferred_ids=()):
    pr = mergeable_pr(number)
    head, base = policy.sha(pr['head']['sha']), policy.sha(pr['base']['sha'])
    comments = pages(f'{PREFIX}/issues/{number}/comments')
    reviews = pages(f'{PREFIX}/pulls/{number}/reviews')
    inline = pages(f'{PREFIX}/pulls/{number}/comments')
    reactions = pages(f'{PREFIX}/issues/{number}/reactions')
    threads, decision = thread_evidence(number, head, base)
    summaries = [c for c in comments if gate.is_bot(c['user']) and c['body'].startswith(gate.SUMMARY_MARKER)]
    need(len(summaries) <= 1, 'Ambiguous summaries')
    summary = summaries[0] if summaries else None
    completed = None
    finished = None
    if summary:
        marker = re.search(r'<!-- codex-review-state:v1 (\{.*\}) -->', summary['body'])
        need(marker is not None, 'Missing structured review state')
        state = json.loads(marker[1])
        code = state['code_review']; security = state['security_review']
        if code['status'] == 'completed':
            reviewed_head = policy.sha(code['commit_sha'])
            times = gate.completed_review_times(summary, reviewed_head, REPO)
            finished = times['Code Review']
        if code['status'] == 'completed' and code['commit_sha'] == head:
            completed = {'id': f'{summary["id"]}/{head}/{times["Code Review"].isoformat()}',
                         'at': times['Code Review'].isoformat(), 'head': head,
                         'summary_id': summary['id'], 'digest': policy.digest(state),
                         'has_findings': code['has_any_findings'], 'has_unresolved': code['has_unresolved_findings']}
            need(type(code['has_any_findings']) is bool and type(code['has_unresolved_findings']) is bool,
                 'Unknown Code Review finding state')
        # Security findings are NEVER eligible for budget transfer, even P2.
        security_present = security['status'] is not None or cfg['security_review_required']
        security_clear = (not security_present or (
            security['status'] == 'completed' and security['commit_sha'] == head
            and security['has_any_findings'] is False and security['has_unresolved_findings'] is False))
    else:
        security_clear = not cfg['security_review_required']
    review_map = {r['id']: r for r in reviews}
    inline_map = {c['id']: c for c in inline}
    findings, unresolved = [], []
    linked_ids = set()
    for thread in threads:
        ids = [c['databaseId'] for c in thread['comments']['nodes']]
        need(all(i in inline_map for i in ids), 'Thread comments absent from REST inventory')
        linked_ids.update(ids)
        if thread['isResolved'] and ids[0] not in deferred_ids:
            continue
        root = inline_map[ids[0]]
        if not thread['isResolved']:
            unresolved.append(root['id'])
        # Replies can introduce blockers; classify only root-only automated threads.
        need(thread['isResolved'] or len(ids) == 1, 'Unresolved thread replies require manual resolution/classification')
        review = review_map.get(root['pull_request_review_id'])
        need(review is not None and gate.is_bot(review['user']) and review['state'] == 'COMMENTED'
             and review['body'].startswith('<!-- codex-review-receipt:v1 -->'), 'Unclassified review source')
        need(gate.is_bot(root['user']) and root['original_commit_id'] == review['commit_id'], 'Finding/review provenance mismatch')
        item = dict(id=root['id'], review_id=review['id'], head=review['commit_id'], actor=root['user'],
                    stream='code', review_link_verified=True, body=root['body'])
        policy.severity(item)
        findings.append(item)
    need(set(inline_map) == linked_ids, 'Unmapped inline comments')
    # Native decisions and all nonstandard review bodies stay blocking, not silently discarded.
    decisions = {}
    for review in reviews:
        if review['state'] in ('APPROVED', 'CHANGES_REQUESTED'):
            decisions[review['user']['id']] = review['state']
        need(review['state'] != 'PENDING', 'Pending review')
        if gate.is_bot(review['user']):
            need(review['state'] == 'COMMENTED' and review['body'].startswith('<!-- codex-review-receipt:v1 -->'),
                 'Unknown Codex review receipt')
    for comment in comments:
        if summary and comment['id'] == summary['id']:
            continue
        if gate.is_bot(comment['user']):
            raise Blocked('Unclassified Codex issue comment/security finding')
        if re.search(r'@codex\s+security\s+review\b', comment['body'], re.I):
            need(summary is not None and security['status'] == 'completed'
                 and security['commit_sha'] == head and security['has_any_findings'] is False
                 and security['has_unresolved_findings'] is False, 'Requested Security Review not clean')
            security_times=gate.completed_review_times(summary, head, REPO)
            need('Security Review' in security_times, 'Missing Security Review completion')
            need(gate.timestamp(comment['updated_at']).replace(microsecond=0) < security_times['Security Review'],
                 'Security request postdates completed review')
        if re.search(r'@codex\s+(?:security\s+)?review\b', comment['body'], re.I):
            rs = pages(f'{PREFIX}/issues/comments/{comment["id"]}/reactions')
            for reaction in rs:
                if reaction['content'] == 'eyes':
                    reactions.append(reaction)
                elif (reaction['content'] == '+1' and '@codex security' not in comment['body'].lower()
                      and gate.request_signoff_is_fresh(comment, reaction)):
                    reactions.append(reaction)
    # Running/unknown activity must block even when no live completion exists.
    newer = bool(summary and code['status'] not in (None, 'completed'))
    newer |= any(gate.is_bot_reaction(r['user']) and r['content'] == 'eyes'
                 and (finished is None or gate.timestamp(r['created_at']).replace(microsecond=0) >= finished)
                 for r in reactions)
    if completed:
        newer |= any(gate.is_bot(r['user']) and gate.timestamp(r['submitted_at']).replace(microsecond=0) > finished
                     for r in reviews)
    fresh = mergeable_pr(number)
    need((fresh['head']['sha'], fresh['base']['sha'], fresh['state'], fresh['draft'], fresh['mergeable'])
         == (head, base, 'open', False, True), 'PR changed during collection')
    return dict(pr=pr, comments=comments, reviews=reviews, reactions=reactions, threads=threads,
                summary=summary, completed=completed, findings=findings, unresolved=unresolved,
                security_clear=security_clear, newer=newer,
                native_ok=decision[0] in (None, 'APPROVED') and 'CHANGES_REQUESTED' not in decisions.values(),
                merge_state=decision[1])


def deferred_ids(state):
    return [saved['item']['finding_id'] for saved in state.get('issues',{}).values()] if state else []


def snapshot(number, evidence, state):
    pr = evidence['pr']
    need(evidence['completed'] is not None
         and evidence['completed']['head'] == pr['head']['sha'],
         'Live exact-head Code Review completion required')
    return dict(repo=REPO, pr=number, head=pr['head']['sha'], base=pr['base']['sha'], complete=True,
                ledger_from_start=True, open=True, draft=False, same_repo=True,
                mergeable=pr['mergeable'], native_reviews_satisfied=evidence['native_ok'],
                security_clear=evidence['security_clear'], no_newer_review_activity=not evidence['newer'],
                rounds=state['rounds'], unresolved_thread_root_ids=evidence['unresolved'],
                unresolved_findings=evidence['findings'])


def reconcile(state, evidence):
    """Count each completed request once; do not infer overwritten/missing rounds."""
    known_requests={r.get('comment_id') for r in state['rounds']}
    for comment in evidence['comments']:
        if re.search(r'@codex\s+review\b',comment['body'],re.I) and not gate.is_bot(comment['user']):
            need(comment['id'] in known_requests, 'Independent/unrecorded review request')
    pending = [r for r in state['rounds'] if r['state'] == 'reserved']
    need(len(pending) <= 1, 'Concurrent reservation')
    completion = evidence['completed']
    if not pending:
        if completion:
            matches=[r for r in state['rounds'] if r.get('completion_id') == completion['id']]
            need(len(matches)==1, 'Unrequested or lost review completion')
            saved=matches[0].get('completion')
            if saved:
                need(all(saved.get(k)==completion.get(k) for k in ('id','at','head','summary_id','has_findings')),
                     'Completion identity changed')
        return
    row = pending[0]
    if completion and completion['id'] != row.get('previous_completion'):
        need(completion['head'] == row['head'], 'Reserved head changed or completion lost')
        need(gate.timestamp(completion['at']) > gate.timestamp(row['requested_at']),
             'Completion does not follow request')
        request = [c for c in evidence['comments'] if c['id'] == row['comment_id']]
        need(len(request) == 1 and all(request[0]['user'].get(k) == v for k,v in ACTIONS_BOT.items())
             and request[0]['body'] == row['request_body']
             and request[0]['created_at'] == request[0]['updated_at'], 'Request changed or lost')
        row.update(state='completed', completion_id=completion['id'], actor=policy.BOT,
                   completion=completion)


def budget_receipts(number, evidence, state):
    s = snapshot(number, evidence, state)
    plan = policy.handoff_plan(s)
    result = []
    for item in plan:
        saved = state['issues'].get(item['key'])
        need(saved is not None, 'Finding has no persisted handoff')
        issue = api(f'{PREFIX}/issues/{saved["number"]}')
        need('pull_request' not in issue and issue['state'] == 'open'
             and all(issue['user'].get(k) == v for k,v in ACTIONS_BOT.items())
             and issue['body'] == saved['body'] and issue['title'] == saved['title'], 'Issue handoff altered')
        need(saved['item'] == item, 'Finding/head changed after handoff')
        result.append(dict(item, repo=REPO, number=issue['number'], open=True,
                           is_issue=True, publisher_verified=True))
    return policy.clearance(s, result)


def clean(evidence):
    need(evidence['completed'] is not None and evidence['completed']['has_unresolved'] is False, 'Code Review still reports unresolved findings')
    need(evidence['security_clear'] and evidence['native_ok'] and not evidence['newer'], 'Security/native blocker')
    return gate.evaluate(evidence['pr'], evidence['summary'], evidence['reactions'], evidence['reviews'],
                         evidence['threads'], evidence['pr']['head']['sha'])


def fingerprint(evidence):
    return policy.digest({'head': evidence['pr']['head']['sha'], 'base': evidence['pr']['base']['sha'],
                          'completion': evidence['completed'], 'findings': evidence['findings'],
                          'security_clear': evidence['security_clear']})


def check(number, expected_sha=None):
    cfg = config(); branch = trusted_context()
    state = load_ledger(number, branch)
    need(state is not None, 'No auditable review ledger')
    evidence = collect(number, cfg, deferred_ids(state))
    need(expected_sha is None or evidence['pr']['head']['sha'] == expected_sha, 'Current head mismatch')
    reconcile(state, evidence)
    need(not any(r['state'] == 'reserved' for r in state['rounds']), 'Review still outstanding')
    if evidence['findings']:
        budget_receipts(number, evidence, state)
        basis = 'p2-budget'
    else:
        clean(evidence); basis = 'clean-review'
    return dict(evidence['pr'], clearance_basis=basis, clearance_base=evidence['pr']['base']['sha'],
                clearance_evidence=fingerprint(evidence))


def output(key, value):
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as handle:
            handle.write(f'{key}={value}\n')


def prepare(number, directory):
    cfg = config(); branch = trusted_context()
    run_id = int(os.environ['GITHUB_RUN_ID'])
    current = api(f'{PREFIX}/actions/runs/{run_id}')
    verify_run(current, branch)
    need(current['display_title'] == f'MXDR budget / PR #{number}', 'Current run scope mismatch')
    state = load_ledger(number, branch, current_run=run_id)
    evidence = collect(number, cfg, deferred_ids(state))
    if state is None:
        need(gate.timestamp(evidence['pr']['created_at']) > gate.timestamp(cfg['activation_after']),
             'Historical PR requires independently verified migration; no zero reset')
        need(evidence['summary'] is None and not any(gate.is_bot(r['user']) for r in evidence['reviews'])
             and not any(gate.is_bot_reaction(r['user']) for r in evidence['reactions']),
             'Pre-ledger review evidence exists')
        state = dict(repo=REPO, pr=number, history=[], previous_digest=None, rounds=[], issues={},
                     created_at=evidence['pr']['created_at'])
    reconcile(state, evidence)
    pending = any(r['state'] == 'reserved' for r in state['rounds'])
    state.update(run_id=run_id, phase='prepared', action='none', head=evidence['pr']['head']['sha'],
                 base=evidence['pr']['base']['sha'])
    if not pending:
        completion = evidence['completed']
        if completion:
            # A completed review is durable history even when it cannot clear CI.
            # Save P1 completion before the author pushes a fix requiring an exception.
            try:
                if not evidence['findings']:
                    clean(evidence); state['action'] = 'ci-or-merge'
                elif len(state['rounds']) >= 3:
                    need(all(policy.severity(f) == 'P2' for f in evidence['findings']),
                         'Only P2 findings may be deferred')
                    plan = policy.handoff_plan(snapshot(number, evidence, state))
                    state.update(action='handoff', plan=plan)
            except (Blocked, gate.Blocked, policy.Blocked) as exc:
                state['clearance_blocked'] = str(exc)
        else:
            need(not evidence['newer'], 'Review activity still outstanding')
            completed_count = sum(r['state'] == 'completed' for r in state['rounds'])
            levels = [policy.severity(f) for f in evidence['findings']]
            need('P0' not in levels, 'P0 blocks automatic requests')
            need(completed_count < 3 or 'P1' in levels, 'Budget exhausted on a new head; owner decision required')
            # Never retry a completed same head solely because it still has findings.
            previous = state['rounds'][-1].get('completion_id') if state['rounds'] else None
            ordinal = len(state['rounds']) + 1
            body = f'@codex review\n\n<!-- mxdr-budget-request:v1 pr={number} round={ordinal} head={state["head"]} run={run_id} -->'
            row = dict(ordinal=ordinal, request_id=run_id, state='reserved', head=state['head'],
                       previous_completion=previous, request_body=body)
            if completed_count >= 3:
                row.update(p1_exception=True, p1_finding_id=next(f['id'] for f in evidence['findings'] if policy.severity(f)=='P1'))
            state['rounds'].append(row); state['action']='request'
    directory.mkdir(parents=True, exist_ok=True)
    (directory/'ledger.json').write_text(json.dumps(state, sort_keys=True))
    output('pr', number); output('action', state['action'])


def trusted_ci(number, head, base, branch, evidence_digest):
    runs = gate.matching_runs(REPO, branch, number, head)
    success = [r for r in runs if r['status']=='completed' and r['conclusion']=='success']
    if not success:
        return False
    run = api(f'{PREFIX}/actions/runs/{success[-1]["id"]}')
    need(run['path'] == '.github/workflows/review-clearance.yml' and run['head_branch'] == branch
         and run['event'] == 'workflow_dispatch' and run['run_attempt'] == 1, 'Unexpected CI origin')
    ancestry=api(f'{PREFIX}/compare/{run["head_sha"]}...{branch}')
    need(ancestry.get('status') in ('ahead','identical'),'CI control lacks trusted ancestry')
    # The gate/workflow revision must equal the installed trusted one for merging.
    for name in ('.github/workflows/review-clearance.yml', '.github/scripts/review_gate.py',
                 '.github/scripts/review_budget.py', '.github/scripts/budget_policy.py'):
        blob=api(f'{PREFIX}/contents/{name}?ref={run["head_sha"]}')
        need(base64.b64decode(blob['content'])==(ROOT/name).read_bytes(), 'CI used obsolete control code')
    jobs=pages(f'{PREFIX}/actions/runs/{run["id"]}/attempts/1/jobs','jobs')
    expected={'Check Codex sign-off and unresolved items','Verify reviewed commit',
              'CyberSOC offline tests (Node and PowerShell)','Report CI on the reviewed commit'}
    need({j['name'] for j in jobs}==expected and all(j['conclusion']=='success' for j in jobs),
         'Incomplete trusted CI jobs')
    statuses=pages(f'{PREFIX}/commits/{head}/statuses')
    status=next((s for s in statuses if s['context']=='Reviewed CI'), None)
    need(status is not None and status['state']=='success'
         and status['target_url']==f'https://github.com/{REPO}/actions/runs/{run["id"]}'
         and status['description']==f'base:{base} evidence:{evidence_digest}'
         and all(status['creator'].get(k)==v for k,v in ACTIONS_BOT.items()), 'Status/run/evidence mismatch')
    return True


def act(number, directory):
    cfg=config(); branch=trusted_context(); run_id=int(os.environ['GITHUB_RUN_ID'])
    current=api(f'{PREFIX}/actions/runs/{run_id}'); verify_run(current,branch)
    # Download the uploaded checkpoint. Local mutation cannot skip durable prepare.
    state=artifact(current,'prepared',number)
    evidence=collect(number,cfg,deferred_ids(state))
    need((evidence['pr']['head']['sha'],evidence['pr']['base']['sha'])==(state['head'],state['base']),
         'PR changed after prepare')
    action=state['action']
    if action=='request':
        row=state['rounds'][-1]
        need(evidence['completed'] is None, 'Review completed independently before request')
        levels=[policy.severity(f) for f in evidence['findings']]
        need('P0' not in levels,'P0 appeared before request')
        if sum(r['state']=='completed' for r in state['rounds'])>=3:
            need(row.get('p1_exception') is True and any(f['id']==row.get('p1_finding_id')
                 and policy.severity(f)=='P1' for f in evidence['findings']), 'P1 exception no longer valid')
        need(not any(c['body']==row['request_body'] for c in evidence['comments']), 'Request already exists')
        comment=api(f'{PREFIX}/issues/{number}/comments','POST',{'body':row['request_body']})
        need(all(comment['user'].get(k)==v for k,v in ACTIONS_BOT.items()), 'Unexpected request publisher')
        row.update(comment_id=comment['id'],requested_at=comment['created_at'])
    elif action=='handoff':
        plan=policy.handoff_plan(snapshot(number,evidence,state))
        need(plan==state['plan'], 'Finding evidence changed after prepare')
        existing=pages(f'{PREFIX}/issues?state=all')
        for item in plan:
            if item['key'] in state['issues']:
                continue
            marker=f'<!-- mxdr-budget-finding:v1 {item["key"]} -->'
            need(not any(marker in (i.get('body') or '') for i in existing), 'Unmapped/duplicate issue requires recovery')
            finding=next(f for f in evidence['findings'] if f['id']==item['finding_id'])
            title=f'[P2] Deferred CyberSOC PR #{number} finding {item["finding_id"]}'
            body=(f'{marker}\nDeferred, not fixed.\n\nPR: https://github.com/{REPO}/pull/{number}\n'
                  f'Source: {item["source_url"]}\nReviewed head: `{item["head"]}`\n'
                  f'Original review: {finding["review_id"]}; commit: `{finding["head"]}`\n'
                  f'Evidence digest: `{item["source_digest"]}`\n\n{finding["body"]}')
            issue=api(f'{PREFIX}/issues','POST',{'title':title,'body':body})
            read=api(f'{PREFIX}/issues/{issue["number"]}')
            need(read['body']==body and read['title']==title and 'pull_request' not in read
                 and all(read['user'].get(k)==v for k,v in ACTIONS_BOT.items()), 'Issue read-back failed')
            state['issues'][item['key']]=dict(number=issue['number'],title=title,body=body,item=item)
        # Do not dispatch until final checkpoint is uploaded and another invocation revalidates.
    elif action=='ci-or-merge':
        clean(evidence)
        state['ready_for_ci']=True
    elif action!='none':
        raise Blocked('Unknown prepared action')
    state['phase']='final'
    (directory/'ledger.json').write_text(json.dumps(state,sort_keys=True))
    output('continue', 'true' if action in ('handoff','ci-or-merge') else 'false')


def advance(number):
    cfg=config(); branch=trusted_context()
    # Current final snapshot exists, but its run is still in_progress: read it
    # directly, then use the same validated prior chain for a read-only clearance.
    run_id=int(os.environ['GITHUB_RUN_ID']); current=api(f'{PREFIX}/actions/runs/{run_id}')
    verify_run(current,branch); state=artifact(current,'final',number)
    evidence=collect(number,cfg,deferred_ids(state)); reconcile(state,evidence)
    need((evidence['pr']['head']['sha'],evidence['pr']['base']['sha'])==(state['head'],state['base']), 'PR moved')
    if evidence['findings']:
        budget_receipts(number,evidence,state)
    else:
        clean(evidence)
    if trusted_ci(number, state['head'], state['base'], branch, fingerprint(evidence)):
        output('merge', 'true')
        return
    # Independent CI admission authenticates the committed final checkpoint and
    # rechecks all live evidence; it never reads the mutable local ledger file.
    api(f'{PREFIX}/actions/workflows/review-clearance.yml/dispatches','POST',
        {'ref':branch,'inputs':{'pr_number':str(number)}})


def merge(number):
    cfg=config(); branch=trusted_context()
    need(cfg.get('native_merge_policy_verified') is True and cfg.get('merge_queue_required') is False,
         'Native merge policy/queue setup not verified')
    need(os.environ.get('GITHUB_JOB') == 'merge', 'Merge must use isolated trusted job')
    current=api(f'{PREFIX}/actions/runs/{int(os.environ["GITHUB_RUN_ID"])}')
    verify_run(current,branch)
    state=artifact(current,'final',number)
    evidence=collect(number,cfg,deferred_ids(state)); reconcile(state,evidence)
    need((state['head'],state['base'])==(evidence['pr']['head']['sha'],evidence['pr']['base']['sha']), 'Merge head/base changed')
    if evidence['findings']:
        budget_receipts(number,evidence,state)
    else:
        clean(evidence)
    files=pages(f'{PREFIX}/pulls/{number}/files',identity='filename')
    need(len(files)==evidence['pr']['changed_files'], 'Incomplete changed-file inventory')
    sensitive=lambda path: path=='AGENTS.md' or path.startswith(('.github/','.agents/','.codex/','tests/ci/'))
    need(not any(sensitive(f['filename']) or sensitive(f.get('previous_filename','')) for f in files),
         'Controller/security changes require parent review and manual merge')
    need(trusted_ci(number,state['head'],state['base'],branch,fingerprint(evidence)), 'CI not passed')
    need(evidence['merge_state']=='CLEAN' and evidence['pr'].get('mergeable_state')=='clean',
         'Native merge requirements not satisfied')
    # Re-collect immediately before the expected-SHA merge. No force/admin bypass.
    fresh=collect(number,cfg,deferred_ids(state))
    need(fingerprint(fresh)==fingerprint(evidence) and fresh['native_ok'] and fresh['security_clear']
         and not fresh['newer'] and fresh['merge_state']=='CLEAN'
         and fresh['pr'].get('mergeable_state')=='clean', 'Merge eligibility changed')
    result=api(f'{PREFIX}/pulls/{number}/merge','PUT',{'sha':state['head'],'merge_method':'squash'})
    need(result.get('merged') is True, 'Merge was not confirmed; do not retry blindly')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=['prepare','act','advance','merge'])
    parser.add_argument('--pr',type=int,required=True)
    parser.add_argument('--directory',type=Path,default=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'budget-ledger')
    args=parser.parse_args()
    try:
        need(args.pr>0,'Invalid PR')
        if args.phase=='prepare': prepare(args.pr,args.directory)
        elif args.phase=='act': act(args.pr,args.directory)
        elif args.phase=='advance': advance(args.pr)
        else: merge(args.pr)
        return 0
    except (Blocked,gate.Blocked,policy.Blocked,KeyError,TypeError,ValueError,OSError) as exc:
        print(f'Review budget blocked: {exc}',file=sys.stderr)
        return 1


if __name__=='__main__':
    sys.exit(main())
