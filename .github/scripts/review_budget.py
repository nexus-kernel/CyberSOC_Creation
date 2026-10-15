"""Inactive, transport-independent review-budget policy.

Only a trusted adapter with complete lifetime evidence may construct Snapshot.
This module has no CLI, GitHub client, permissions, or CI admission authority.
See REVIEW_BUDGET.md before wiring it into a controller.
"""
from dataclasses import dataclass
import hashlib
import re
from typing import Callable


MAX_ROUNDS = 3


class Blocked(RuntimeError):
    """Evidence cannot authorize the proposed operation."""


@dataclass(frozen=True)
class Round:
    identity: str  # Provider invocation ID, not head SHA or review-comment ID.
    kind: str
    head: str
    state: str


@dataclass(frozen=True)
class Finding:
    identity: str  # Stable provider finding ID; never derived from mutable text.
    source: str
    priority: str
    resolved: bool
    kind: str
    title: str


@dataclass(frozen=True)
class Snapshot:
    repo: str
    pr: int
    head: str
    base: str
    revision: str  # Trusted adapter's digest of ALL evidence, not just head/base.
    complete: bool
    open_ready: bool
    mergeable: bool
    human_requirements_met: bool
    security_required: bool
    security_cleared: bool
    rounds: tuple[Round, ...]
    findings: tuple[Finding, ...]


def validate(snapshot):
    if (not re.fullmatch(r'[\w.-]+/[\w.-]+', snapshot.repo)
            or type(snapshot.pr) is not int or snapshot.pr < 1
            or any(not re.fullmatch(r'[0-9a-f]{40}', value)
                   for value in (snapshot.head, snapshot.base))
            or not re.fullmatch(r'[0-9a-f]{64}', snapshot.revision)):
        raise Blocked('Invalid snapshot identity.')
    if snapshot.complete is not True:
        raise Blocked('Complete lifetime history is required, including initial review.')
    if snapshot.open_ready is not True or snapshot.mergeable is not True:
        raise Blocked('PR must be open, ready and mergeable.')
    seen = set()
    for run in snapshot.rounds:
        if (not run.identity or run.identity in seen
                or run.kind not in ('Code Review', 'Security Review')
                or not re.fullmatch(r'[0-9a-f]{40}', run.head)
                or run.state != 'completed'):
            raise Blocked('Duplicate, unknown, running or incomplete review invocation.')
        seen.add(run.identity)
    seen = set()
    for finding in snapshot.findings:
        if (not finding.identity or finding.identity in seen
                or not re.fullmatch(
                    rf'https://github\.com/{re.escape(snapshot.repo)}/pull/{snapshot.pr}'
                    r'#(?:discussion_r|issuecomment-|pullrequestreview-)[1-9][0-9]*', finding.source)
                or finding.kind not in ('Code Review', 'Security Review')
                or finding.priority not in ('P0', 'P1', 'P2', 'P3')
                or type(finding.resolved) is not bool
                or not finding.title.strip()):
            raise Blocked('Unknown priority or incomplete finding identity/history.')
        seen.add(finding.identity)


def completed_rounds(snapshot):
    validate(snapshot)
    return sum(run.kind == 'Code Review' for run in snapshot.rounds)


def request_allowed(snapshot):
    """For a controlled requester only. New commits never reset the count."""
    return completed_rounds(snapshot) < MAX_ROUNDS


def deferral_candidates(snapshot):
    if completed_rounds(snapshot) < MAX_ROUNDS:
        raise Blocked('Code Review budget has not been exhausted.')
    if not any(run.kind == 'Code Review' and run.head == snapshot.head
               for run in snapshot.rounds):
        raise Blocked('Current head has not completed Code Review; cap is not a waiver.')
    if snapshot.human_requirements_met is not True:
        raise Blocked('Human approval and changes-request requirements remain in force.')
    if (type(snapshot.security_required) is not bool
            or snapshot.security_required or any(run.kind == 'Security Review' for run in snapshot.rounds)
            or any(f.kind == 'Security Review' for f in snapshot.findings)):
        if (snapshot.security_cleared is not True
                or not any(run.kind == 'Security Review' and run.head == snapshot.head
                           for run in snapshot.rounds)):
            raise Blocked('Separate current-head Security Review clearance required.')
    # All history, including outdated threads, dismissed reviews and old heads.
    if any(not f.resolved and f.priority in ('P0', 'P1') for f in snapshot.findings):
        raise Blocked('An unresolved P0/P1 prevents every lower-priority deferral.')
    if any(not f.resolved and f.kind == 'Security Review' for f in snapshot.findings):
        raise Blocked('Security Review findings cannot be deferred by the Code Review budget.')
    return tuple(f for f in snapshot.findings if not f.resolved)


def marker(snapshot, finding):
    identity = '\0'.join((snapshot.repo, str(snapshot.pr), finding.identity))
    return '<!-- codex-deferred:' + hashlib.sha256(identity.encode()).hexdigest() + ' -->'


def tracking_title(finding):
    return f'[{finding.priority}] {finding.title}'


def tracking_body(snapshot, finding):
    return (f'{marker(snapshot, finding)}\n\n'
            f'Deferred {finding.priority} Code Review finding after the PR lifetime '
            f'budget of {MAX_ROUNDS} rounds. This is not Codex approval.\n\n'
            f'Source: {finding.source}\nReviewed head: `{snapshot.head}`\n')


@dataclass(frozen=True)
class Issue:
    number: int
    state: str
    body: str
    is_pull_request: bool = False
    title: str = ''
    author: tuple[int, str] | None = None


@dataclass(frozen=True)
class IssueInventory:
    complete: bool
    issues: tuple[Issue, ...]
    # Trusted controller configuration, never inferred from issue content.
    trusted_authors: tuple[tuple[int, str], ...] = ()


def existing_issue(snapshot, finding, inventory, *, require_marked=False):
    if inventory.complete is not True:
        raise Blocked('Complete all-state issue inventory required; search is insufficient.')
    seen, matches = set(), []
    for issue in inventory.issues:
        if (type(issue.number) is not int or issue.number < 1 or issue.number in seen
                or issue.state not in ('open', 'closed') or not isinstance(issue.body, str)
                or type(issue.is_pull_request) is not bool):
            raise Blocked('Invalid issue inventory.')
        seen.add(issue.number)
        # Exact URL boundary avoids #discussion_r12 matching #discussion_r123.
        source = re.search(re.escape(finding.source) + r'(?:(?![A-Za-z0-9_/#?=&%.-])|\.(?=\s|$))', issue.body)
        # One review-body permalink can contain several distinct findings. A
        # legacy URL-only issue is safe only when that source names one finding
        # in the complete history. An issue marked for another identity is not
        # a legacy issue and must never satisfy this one by URL alone.
        legacy = source and '<!-- codex-deferred:' not in issue.body
        if (not issue.is_pull_request and legacy
                and sum(f.source == finding.source for f in snapshot.findings) != 1):
            raise Blocked('Ambiguous legacy source-only issue; reconcile finding identities before writing.')
        marked = marker(snapshot, finding) in issue.body
        if not issue.is_pull_request and (marked or legacy):
            if require_marked and not marked:
                raise Blocked('Recorded controller issue lost its tracking marker.')
            if issue.author is None or issue.author not in inventory.trusted_authors:
                raise Blocked('Tracking association has no trusted issue-author provenance.')
            if marked and (issue.title != tracking_title(finding)
                           or issue.body != tracking_body(snapshot, finding)):
                raise Blocked('Marked issue does not contain the complete expected tracking association.')
            matches.append(issue.number)
    if len(matches) > 1:
        raise Blocked('Multiple existing issues match; reconcile without another write.')
    return matches[0] if matches else None


@dataclass(frozen=True)
class Deferral:
    outcome: str
    head: str
    issues: tuple[int, ...]


def defer(read: Callable, inventory: Callable, create: Callable):
    """Staged writer algorithm, NOT installed in any workflow.

    Caller must hold an exclusive repository/PR lock across this call and read
    live authenticated evidence, with no PR-controlled code/data supplying trust
    flags. create is single-attempt: disable automatic POST retries. Inventory
    must include every open/closed issue; after uncertain writes only read back.
    A returned Deferral is policy evidence, never a Codex approval or CI token.
    """
    original = read()
    findings = deferral_candidates(original)

    def unchanged():
        fresh = read()
        deferral_candidates(fresh)
        if fresh != original:
            raise Blocked('Review evidence changed during deferral.')

    linked = []
    for finding in findings:
        unchanged()
        number = existing_issue(original, finding, inventory())
        if number is None:
            unchanged()
            body = tracking_body(original, finding)
            try:
                create(tracking_title(finding), body)
            except Exception:
                # A lost response can conceal a successful write. Never retry it.
                pass
            number = existing_issue(original, finding, inventory(), require_marked=True)
            if number is None:
                raise Blocked('Issue write is unconfirmed; do not retry without reconciliation.')
        linked.append(number)
    unchanged()
    return Deferral('capped-deferral', original.head, tuple(linked))
