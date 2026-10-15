"""Durable GitHub Git-data journal; no local disk is treated as authority.

A pre-provisioned dedicated branch is required. Non-fast-forward ref updates are
our compare-and-swap. Locks never expire: process death requires reconciliation,
not timed lock stealing. This module is inert until the disabled runtime is enabled.
"""
from contextlib import contextmanager
from copy import deepcopy
import base64
import json
import subprocess
import uuid

from review_budget import Blocked


def api(endpoint, method='GET', payload=None, paginate=False):
    command = ['gh', 'api', endpoint, '--method', method]
    if paginate:
        command += ['--paginate']
    if payload is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                            capture_output=True, text=True, check=False)
    if result.returncode:
        raise Blocked('GitHub API failed; operation may be uncertain: ' + endpoint)
    if paginate:
        decoder, pages, remaining = json.JSONDecoder(), [], result.stdout.strip()
        while remaining:
            page, end = decoder.raw_decode(remaining)
            pages.append(page)
            remaining = remaining[end:].lstrip()
        return pages
    return json.loads(result.stdout) if result.stdout.strip() else None


def all_items(endpoint, call=api):
    pages = call(endpoint, paginate=True)
    if not isinstance(pages, list) or not pages:
        raise Blocked('Missing API pagination.')
    result, seen = [], set()
    for index, page in enumerate(pages):
        if not isinstance(page, list) or len(page) > 100 or (index < len(pages)-1 and len(page) != 100):
            raise Blocked('Incomplete pagination.')
        for item in page:
            identity = item.get('id')
            if type(identity) is not int or identity < 1 or identity in seen:
                raise Blocked('Invalid or duplicated API identity.')
            seen.add(identity)
            result.append(item)
    return result


class GitJournal:
    def __init__(self, repo, branch='codex-review-ledger', call=api, source_repo=None):
        self.prefix = f'repos/{repo}/git'
        self.branch = branch
        self.call = call
        self.source_repo = source_repo

    def read(self):
        ref = self.call(f'{self.prefix}/ref/heads/{self.branch}')
        sha = ref['object']['sha']
        commit = self.call(f'{self.prefix}/commits/{sha}')
        tree = self.call(f"{self.prefix}/trees/{commit['tree']['sha']}")
        if tree.get('truncated') is not False or len(tree['tree']) != 1:
            raise Blocked('Journal tree is incomplete or contains unexpected files.')
        entry = tree['tree'][0]
        if entry['path'] != 'ledger.json' or entry['type'] != 'blob':
            raise Blocked('Unexpected journal tree.')
        blob = self.call(f"{self.prefix}/blobs/{entry['sha']}")
        if blob.get('encoding') != 'base64':
            raise Blocked('Unexpected journal encoding.')
        state = json.loads(base64.b64decode(blob['content']).decode())
        if state.get('version') != 1 or not isinstance(state.get('prs'), dict):
            raise Blocked('Journal is absent, corrupt or unsupported.')
        if self.source_repo is not None and state.get('source_repo') != self.source_repo:
            raise Blocked('Journal is not bound to the source repository.')
        return sha, state

    def compare_swap(self, expected, state):
        blob = self.call(f'{self.prefix}/blobs', 'POST',
                         {'content': json.dumps(state, sort_keys=True), 'encoding': 'utf-8'})
        tree = self.call(f'{self.prefix}/trees', 'POST', {'tree': [
            {'path': 'ledger.json', 'mode': '100644', 'type': 'blob', 'sha': blob['sha']}]})
        commit = self.call(f'{self.prefix}/commits', 'POST', {
            'message': 'Review budget journal transaction', 'tree': tree['sha'], 'parents': [expected]})
        try:
            self.call(f'{self.prefix}/refs/heads/{self.branch}', 'PATCH',
                      {'sha': commit['sha'], 'force': False})
        except Blocked:
            pass  # A lost response is not proof of failure. Read back exactly once.
        actual, readback = self.read()
        if actual != commit['sha'] or readback != state:
            raise Blocked('Journal CAS lost or uncertain; no external operation authorized.')
        return actual

    @contextmanager
    def transaction(self, number):
        """Durable per-PR lock; CAS also serializes simultaneous branch updates."""
        sha, state = self.read()
        key, owner = str(number), str(uuid.uuid4())
        if state.get('locks', {}).get(key):
            raise Blocked('PR journal is locked; reconcile the existing owner before recovery.')
        state.setdefault('locks', {})[key] = owner
        sha = self.compare_swap(sha, state)
        transaction = Transaction(self, key, owner)
        try:
            yield transaction
        finally:
            # If ownership/readback is uncertain this raises and leaves a lock,
            # never silently authorizing another writer.
            transaction.release()


class Transaction:
    def __init__(self, journal, key, owner):
        self.journal, self.key, self.owner = journal, key, owner

    def read(self):
        sha, state = self.journal.read()
        if state.get('locks', {}).get(self.key) != self.owner:
            raise Blocked('Journal lock ownership lost.')
        return sha, state

    def update(self, change):
        sha, state = self.read()
        updated = deepcopy(state)
        change(updated)
        self.journal.compare_swap(sha, updated)

    def release(self):
        self.update(lambda state: state['locks'].pop(self.key))
