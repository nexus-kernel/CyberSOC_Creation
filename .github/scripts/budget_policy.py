"""Inactive CyberSOC budget-policy prototype. No IO, workflow hook, or JSON CLI.

Inputs MUST come from the trusted collector/ledger described in README.md.
This evaluator cannot authenticate caller-supplied dictionaries or prove API
pagination completeness. Never wire it to PR files, comments, or dispatch inputs.
"""
import hashlib
import json
import re

REPO = 'nexus-kernel/CyberSOC_Creation'
BOT = {'id': 199175422, 'login': 'chatgpt-codex-connector[bot]', 'type': 'Bot'}
MARKER = '<!-- codex-code-review-finding:v1 -->'


class Blocked(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def sha(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value), 'Invalid SHA')
    return value


def identifier(value):
    require(type(value) is int and value > 0, 'Invalid numeric identity')
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def actor(value):
    require(isinstance(value, dict) and all(value.get(k) == v for k, v in BOT.items()),
            'Unauthenticated Codex finding/completion')


def ledger(snapshot):
    require(snapshot['repo'] == REPO, 'CyberSOC only')
    identifier(snapshot['pr'])
    sha(snapshot['head']); sha(snapshot['base'])
    require(snapshot['complete'] is True, 'Incomplete trusted evidence')
    require(snapshot['ledger_from_start'] is True, 'Cannot reconstruct missing rounds')
    require(snapshot['open'] is True and snapshot['draft'] is False
            and snapshot['same_repo'] is True, 'PR is not eligible')
    rows = snapshot['rounds']
    require(isinstance(rows, list), 'Missing ledger')
    requests, completions = set(), set()
    for ordinal, row in enumerate(rows, 1):
        require(row['ordinal'] == ordinal and type(row['ordinal']) is int, 'Ledger gap/reorder')
        identifier(row['request_id']); sha(row['head'])
        require(row['request_id'] not in requests, 'Duplicate reservation')
        requests.add(row['request_id'])
        require(row['state'] in ('completed', 'failed', 'reserved', 'running'), 'Unknown round state')
        if ordinal > 3:
            # A collector-verified P1 exception recorded BEFORE reservation.
            require(row['p1_exception'] is True, 'Unapproved fourth review')
            identifier(row['p1_finding_id'])
        if row['state'] == 'completed':
            actor(row['actor'])
            require(isinstance(row['completion_id'], str) and row['completion_id'], 'Missing completion')
            require(row['completion_id'] not in completions, 'Duplicate completion')
            completions.add(row['completion_id'])
    return rows


def severity(finding):
    """Accept only observed anchored Codex badge + exact code-finding marker."""
    actor(finding['actor'])
    identifier(finding['id']); identifier(finding['review_id'])
    sha(finding['head'])
    require(finding['stream'] == 'code', 'Security/unknown finding is never deferred')
    require(finding['review_link_verified'] is True, 'Finding/review association missing')
    body = finding['body']
    require(isinstance(body, str) and body.rstrip().endswith(MARKER), 'Unknown finding format')
    match = re.match(r'^\*\*<sub><sub>!\[P([012]) Badge\]\(https://img\.shields\.io/badge/P\1-[a-z]+\?style=flat\)</sub></sub>  \S', body)
    require(match is not None, 'Unknown severity')
    return 'P' + match[1]


def findings(snapshot):
    records = snapshot['unresolved_findings']
    require(isinstance(records, list), 'Missing finding inventory')
    ids = set()
    for item in records:
        severity(item)
        require(item['id'] not in ids, 'Duplicate finding')
        ids.add(item['id'])
    # Collector enumerates every unresolved thread, even outdated, plus findings
    # outside threads. No trusting a PR author's claimed unresolved count.
    require(set(snapshot['unresolved_thread_root_ids']) <= ids, 'Unclassified unresolved thread')
    return records


def request_decision(snapshot):
    """Three completed rounds; uncertain/failed requests block for reconciliation."""
    rows = ledger(snapshot)
    require(not any(r['state'] in ('reserved', 'running') for r in rows), 'Review already active')
    require(all(r['state'] == 'completed' for r in rows), 'Uncertain/failed request requires recovery')
    levels = [severity(f) for f in findings(snapshot)]
    require('P0' not in levels, 'P0 requires owner intervention')
    if len(rows) < 3:
        return 'reserve-normal-round'
    require('P1' in levels, 'Budget exhausted; no further review request')
    return 'reserve-p1-exception'


def handoff_plan(snapshot):
    """Return deterministic issue requests; does not create issues or clear CI."""
    rows = ledger(snapshot)
    require(len([r for r in rows if r['state'] == 'completed']) >= 3, 'Three completed rounds required')
    require(rows and rows[-1]['state'] == 'completed' and rows[-1]['head'] == snapshot['head'],
            'Latest round must complete on current head')
    require(not any(r['state'] in ('reserved', 'running') for r in rows), 'Review active')
    require(snapshot['mergeable'] is True and snapshot['native_reviews_satisfied'] is True,
            'Native review/mergeability blocker')
    require(snapshot['security_clear'] is True and snapshot['no_newer_review_activity'] is True,
            'Security/new review blocker')
    records = findings(snapshot)
    require(records, 'Use existing clean-signoff path for zero findings')
    require(all(severity(f) == 'P2' for f in records), 'Only P2 findings may be deferred')
    result = []
    for item in sorted(records, key=lambda f: f['id']):
        # Key survives head changes; digest detects edits and changed evidence.
        key = f'{REPO}/pull/{snapshot["pr"]}/finding/{item["id"]}'
        result.append({'key': key, 'finding_id': item['id'], 'source_digest': digest(item),
                       'source_url': f'https://github.com/{REPO}/pull/{snapshot["pr"]}#discussion_r{item["id"]}',
                       'head': snapshot['head']})
    return result


def clearance(snapshot, receipts):
    """Receipts are read-back verified records from a trusted issue publisher."""
    plan = handoff_plan(snapshot)
    require(isinstance(receipts, list) and len(receipts) == len(plan), 'Incomplete/duplicate issue handoff')
    mapped, numbers = {}, set()
    for receipt in receipts:
        identifier(receipt['number'])
        require(receipt['repo'] == REPO and receipt['is_issue'] is True
                and receipt['open'] is True and receipt['publisher_verified'] is True,
                'Issue provenance/state invalid')
        require(receipt['key'] not in mapped and receipt['number'] not in numbers, 'Duplicate issue mapping')
        mapped[receipt['key']] = receipt
        numbers.add(receipt['number'])
    for item in plan:
        receipt = mapped.get(item['key'])
        require(receipt is not None and all(receipt.get(k) == v for k, v in item.items()),
                'Missing, stale or edited issue handoff')
    return {'basis': 'p2-budget', 'head': snapshot['head'], 'base': snapshot['base'],
            'evidence_digest': digest(snapshot), 'handoff_digest': digest(receipts)}


def merge_preflight(snapshot, receipts, ticket, ci):
    """No merge IO. Collector must verify check origin and ALL native requirements."""
    require(clearance(snapshot, receipts) == ticket, 'Review/handoff changed since admission')
    require(ci['head'] == ticket['head'] and ci['base'] == ticket['base'], 'CI tested stale revision')
    require(ci['trusted_workflow'] is True and ci['attempt'] == 1 and type(ci['attempt']) is int
            and ci['conclusion'] == 'success', 'No trusted successful current-head CI')
    require(ci['required_checks_satisfied'] is True and ci['protections_satisfied'] is True,
            'Native checks/protections not satisfied')
    return {'expected_head_sha': ticket['head'], 'basis': 'p2-budget'}
