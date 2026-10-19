#!/usr/bin/env python3
"""Verify latest-commit Codex clearance, then optionally dispatch CI."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import quote


BOT = "chatgpt-codex-connector[bot]"
BOT_ID = 199175422


def is_bot(user):
    return user.get("id") == BOT_ID and user.get("login") == BOT and user.get("type") == "Bot"


def is_bot_reaction(user):
    # Reaction API records can label the pinned Codex account as User.
    # Keep comments, summaries and reviews on the strict Bot predicate.
    return (user.get("id") == BOT_ID and user.get("login") == BOT
            and user.get("type") in ("Bot", "User"))


SUMMARY_MARKER = "<!-- codex-pull-request-review-summary -->"

class Blocked(RuntimeError):
    """The PR is not cleared for CI."""


class AwaitingSignoff(Blocked):
    """Codex may post its clean reaction just after updating the review summary."""


def gh_api(endpoint, *, fields=None, method="GET", paginate=False):
    command = ["gh", "api", endpoint, "--method", method]
    if paginate:
        command += ["--paginate"]
    for key, value in (fields or {}).items():
        command += ["-f", f"{key}={value}"]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        raise Blocked(f"GitHub API request failed ({endpoint}); clearance cannot be verified.")
    if paginate:
        # --paginate emits consecutive JSON values. Avoid --slurp, which requires
        # a newer gh than some development environments provide.
        decoder, pages, remaining = json.JSONDecoder(), [], result.stdout.strip()
        while remaining:
            page, end = decoder.raw_decode(remaining)
            pages.append(page)
            remaining = remaining[end:].lstrip()
        return pages
    return json.loads(result.stdout) if result.stdout.strip() else None


def list_api(endpoint):
    pages = gh_api(endpoint, paginate=True)
    if not isinstance(pages, list) or not pages or any(not isinstance(page, list) for page in pages):
        raise Blocked("Missing or malformed paginated review evidence.")
    return [item for page in pages for item in page]


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)", value):
        raise Blocked("Missing or invalid timezone-aware review timestamp.")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def request_signoff_is_fresh(comment, reaction):
    """A request's current text must provably predate its sign-off reaction."""
    def request_time(value):
        # Reject missing, malformed and timezone-less API evidence. Do not infer
        # updated_at from created_at: that would conceal an unknown edit.
        if not isinstance(value, str) or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)", value):
            raise ValueError("Invalid request/reaction timestamp")
        return timestamp(value)

    try:
        created = request_time(comment.get("created_at"))
        revised = request_time(comment.get("updated_at"))
        reacted = request_time(reaction.get("created_at"))
    except (ValueError, TypeError, OverflowError):
        return False
    # GitHub comment/reaction timestamps have second-level precision. Even if
    # fractional values appear, same-second ordering is not proof of freshness.
    return (revised >= created and
            reacted.replace(microsecond=0) > revised.replace(microsecond=0))


def completed_review_times(comment, sha, repo):
    """Resolve reviewed commits and retain completion times by review type."""
    if not is_bot(comment.get("user", {})) or not comment.get("body", "").startswith(SUMMARY_MARKER):
        raise Blocked("No authenticated Codex review summary.")
    rows, resolved = {}, {}
    for line in comment["body"].splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 4:
            raise Blocked("Unrecognized Codex summary row; review it manually.")
        if cells[0] == "Review" or set(cells[0]) <= {"-", ":", " "}:
            continue
        labels = [label for label in ("Code Review", "Security Review") if label in cells[0]]
        if len(labels) != 1 or labels[0] in rows:
            raise Blocked("Unrecognized Codex summary row; review it manually.")
        commit = re.fullmatch(r"`([0-9a-f]{7,40})`", cells[2])
        date = re.search(r'datetime="([^"]+)"', cells[1])
        if not re.match(r"^✅ \*\*Completed\*\*(?:\s|$)", cells[1]) or not date:
            raise Blocked("A Codex review is pending, running, or incomplete.")
        if not commit or not sha.startswith(commit[1]):
            raise Blocked("Codex has not reviewed the latest PR commit.")
        ref = commit[1]
        if ref not in resolved:
            # GitHub rejects ambiguous abbreviations. Never use a shared prefix
            # as proof that a replacement commit was reviewed.
            resolved[ref] = gh_api(f"repos/{repo}/commits/{ref}")["sha"] if len(ref) < 40 else ref
        if resolved[ref] != sha:
            raise Blocked("Codex has not reviewed the latest PR commit.")
        rows[labels[0]] = timestamp(date[1]).replace(microsecond=0)
    if "Code Review" not in rows:
        raise Blocked("No completed Code Review row in the Codex summary.")
    return rows


def evaluate(pr, summary, reactions, reviews, threads, expected_sha=None):
    if pr["state"] != "open" or pr.get("draft") is not False:
        raise Blocked("PR must be open and ready for review.")
    if pr.get("mergeable") is not True:
        raise Blocked("PR mergeability is unknown or conflicting.")
    sha = pr["head"]["sha"]
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise Blocked("Missing immutable PR head.")
    if expected_sha and sha != expected_sha:
        raise Blocked("The PR changed after clearance; review the new commit before running CI.")
    if not pr["head"].get("repo") or pr["head"]["repo"]["full_name"] != pr["base"]["repo"]["full_name"]:
        raise Blocked("This dispatcher supports branches in the same repository only.")
    if any(thread.get("isResolved") is not True for thread in threads):
        raise Blocked("Unresolved review threads remain (including outdated threads).")
    decisions = {}
    for review in sorted(reviews, key=lambda item: item["id"]):
        # Dismissal changes that review record's state; it is not a new decision
        # clearing every earlier decision by the same reviewer.
        if review["state"] in ("APPROVED", "CHANGES_REQUESTED"):
            decisions[review["user"]["id"]] = review["state"]
    if "CHANGES_REQUESTED" in decisions.values():
        raise Blocked("An outstanding changes-requested review remains.")
    if not summary:
        raise Blocked("No Codex review summary is available for this PR.")
    completed = completed_review_times(summary, sha, pr["base"]["repo"]["full_name"])
    bot_reactions = [r for r in reactions if is_bot_reaction(r.get("user", {}))]
    if any(r["content"] == "eyes" and any(
            kind not in completed or timestamp(r["created_at"]).replace(microsecond=0) >= completed[kind]
            for kind in r.get("review_types", ["Code Review"])) for r in bot_reactions):
        raise AwaitingSignoff("Codex still indicates a review is running.")
    clean = [r for r in bot_reactions if r["content"] == "+1"
             # Completion and reaction APIs only prove ordering across seconds.
             and timestamp(r["created_at"]).replace(microsecond=0) > completed["Code Review"]]
    if not clean:
        raise AwaitingSignoff("No fresh Codex thumbs-up sign-off after the latest completed Code Review.")
    signed_off = max(timestamp(r["created_at"]) for r in clean)
    if any(is_bot(r["user"]) and r["state"] != "DISMISSED"
           and timestamp(r.get("submitted_at")).replace(microsecond=0) >= signed_off.replace(microsecond=0)
           for r in reviews):
        raise Blocked("A newer Codex review supersedes the clean sign-off.")
    return sha


def review_threads(repo, number, head, base):
    owner, name = repo.split("/")
    query = """query($owner:String!, $name:String!, $number:Int!, $after:String) {
      repository(owner:$owner, name:$name) {
        pullRequest(number:$number) {
          headRefOid baseRefOid reviewDecision
          reviewThreads(first:100, after:$after) {
            nodes { isResolved }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }"""
    threads, cursor, seen = [], None, set()
    for _ in range(1000):
        # gh -f passes strings, so provide GraphQL variables as JSON through stdin.
        payload = {"query": query, "variables": {"owner": owner, "name": name, "number": number, "after": cursor}}
        result = subprocess.run(["gh", "api", "graphql", "--input", "-"], input=json.dumps(payload),
                                text=True, capture_output=True, check=False)
        if result.returncode:
            raise Blocked("Cannot read review threads; clearance cannot be verified.")
        data = json.loads(result.stdout)
        if data.get("errors"):
            raise Blocked("GitHub returned incomplete review-thread data.")
        pr = data["data"]["repository"]["pullRequest"]
        if pr["headRefOid"] != head or pr["baseRefOid"] != base:
            raise Blocked("PR changed while reading review threads.")
        if pr["reviewDecision"] not in (None, "APPROVED"):
            raise Blocked("Repository review requirements are not satisfied.")
        page = pr["reviewThreads"]
        if (not isinstance(page["nodes"], list)
                or type(page["pageInfo"]["hasNextPage"]) is not bool):
            raise Blocked("Incomplete review-thread pagination evidence.")
        threads.extend(page["nodes"])
        if not page["pageInfo"]["hasNextPage"]:
            return threads
        cursor = page["pageInfo"]["endCursor"]
        if not cursor or cursor in seen:
            raise Blocked("Invalid review-thread pagination cursor.")
        seen.add(cursor)
    raise Blocked("Review-thread pagination limit reached.")


def check_clean(repo, number, expected_sha=None):
    prefix = f"repos/{repo}"
    pr = gh_api(f"{prefix}/pulls/{number}")
    comments = list_api(f"{prefix}/issues/{number}/comments?per_page=100")
    summaries = [c for c in comments if is_bot(c["user"]) and c["body"].startswith(SUMMARY_MARKER)]
    if len(summaries) != 1:
        raise Blocked("Expected one authenticated Codex review summary.")
    summary = summaries[0]
    reactions = list_api(f"{prefix}/issues/{number}/reactions?per_page=100")
    # Explicit requests receive reactions on the request comment. Only a
    # Code Review request can provide its sign-off; security/mixed requests
    # contribute running-review blockers but never Code Review clearance.
    for comment in comments:
        body = comment.get("body", "")
        code_request = re.search(r"@codex\s+review\b", body, re.I)
        security_request = re.search(r"@codex\s+security\s+review\b", body, re.I)
        if (code_request or security_request) and comment["user"]["login"] != BOT:
            request_reactions = list_api(f"{prefix}/issues/comments/{comment['id']}/reactions?per_page=100")
            kinds = [kind for kind, requested in (("Code Review", code_request), ("Security Review", security_request))
                     if requested]
            reactions += [dict(r, review_types=kinds) for r in request_reactions
                          if r["content"] == "eyes" or (
                              r["content"] == "+1" and code_request and not security_request
                              and request_signoff_is_fresh(comment, r))]
    reviews = list_api(f"{prefix}/pulls/{number}/reviews?per_page=100")
    threads = review_threads(repo, number, pr["head"]["sha"], pr["base"]["sha"])
    sha = evaluate(pr, summary, reactions, reviews, threads, expected_sha)
    # Detect a push/draft/close while the paginated review data was being read.
    fresh = gh_api(f"{prefix}/pulls/{number}")
    if (fresh["head"]["sha"] != sha or fresh["base"]["sha"] != pr["base"]["sha"]
            or fresh["state"] != "open" or fresh.get("draft") is not False
            or fresh.get("mergeable") is not True):
        raise Blocked("PR changed while checking clearance; run the check again.")
    return fresh


def check(repo, number, expected_sha=None):
    config_path = Path(__file__).resolve().parents[1] / 'review-budget.json'
    if repo == 'nexus-kernel/CyberSOC_Creation' and config_path.exists():
        settings = json.loads(config_path.read_text())
        if settings.get('enabled') is True:
            # Pre-activation PRs retain strict clean review; never invent a budget
            # history or silently enroll an existing assessment PR.
            current = gh_api(f'repos/{repo}/pulls/{number}')
            if timestamp(current['created_at']) <= timestamp(settings['activation_after']):
                return check_clean(repo, number, expected_sha)
            import review_budget
            return review_budget.check(number, expected_sha)
    return check_clean(repo, number, expected_sha)


def get_default_branch(repo):
    branch = gh_api(f"repos/{repo}")["default_branch"]
    if not isinstance(branch, str) or not branch:
        raise Blocked("Cannot determine the trusted default branch.")
    return branch


def complete_run_history(pages):
    """Validate completeness before using filtered history to authorize a run."""
    if not isinstance(pages, list) or not pages:
        raise Blocked("Cannot verify existing CI dispatches.")
    runs, seen, total = [], set(), None
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get("workflow_runs"), list):
            raise Blocked("Cannot verify existing CI dispatches.")
        count = page.get("total_count")
        if type(count) is not int or count < 0:
            raise Blocked("Missing or invalid CI history total_count.")
        # GitHub caps this event/branch-filtered endpoint at 1,000 results.
        # At the boundary, even a capped total_count is not completeness proof.
        if count >= 1000:
            raise Blocked("CI history reaches the 1,000-result cap; completeness is uncertain.")
        if total is not None and count != total:
            raise Blocked("CI history total_count changed across pages.")
        total = count
        if len(page["workflow_runs"]) > 100 or (not page["workflow_runs"] and
                                              (count != 0 or len(pages) != 1)):
            raise Blocked("Unexpected CI history page size.")
        for run in page["workflow_runs"]:
            if not isinstance(run, dict) or type(run.get("id")) is not int or run["id"] < 1:
                raise Blocked("Missing or invalid CI history run identity.")
            if run["id"] in seen:
                raise Blocked("Duplicate CI history run identity; pagination is uncertain.")
            if any(not isinstance(run.get(key), str) or not run[key]
                   for key in ("display_title", "head_branch", "event")):
                raise Blocked("Cannot classify a CI history run.")
            seen.add(run["id"])
            runs.append(run)
    if len(runs) != total:
        raise Blocked("CI history is incomplete or inconsistent with total_count.")
    return runs


def retry_is_allowed(runs):
    """Manual retries need a finished unsuccessful latest run and no active copy."""
    for run in runs:
        if not isinstance(run.get("status"), str) or not run["status"]:
            raise Blocked("Cannot verify the status of an existing CI run.")
        if run["status"] != "completed":
            # Includes queued/waiting runs and unknown nonterminal states.
            return False
        if type(run.get("id")) is not int or run["id"] < 1:
            raise Blocked("Cannot determine the latest CI run.")
    latest = max(runs, key=lambda run: run["id"])
    if latest.get("conclusion") in {"failure", "cancelled", "timed_out"}:
        return True
    if latest.get("conclusion") == "success":
        return False
    raise Blocked("Latest CI conclusion is not a verified retryable failure.")


def matching_runs(repo, branch, number, sha):
    title = f"Reviewed CI / PR #{number} / {sha}"
    runs, seen = [], set()
    # Preserve the inherited retired identity as well as controller execution history.
    for workflow in ("reviewed-ci.yml", "review-clearance.yml"):
        pages = gh_api(f"repos/{repo}/actions/workflows/{workflow}/runs?event=workflow_dispatch&branch={quote(branch, safe='')}&per_page=100", paginate=True)
        for run in complete_run_history(pages):
            if run["id"] in seen:
                raise Blocked("Run identity appears under multiple workflow identities.")
            seen.add(run["id"])
            if (run["display_title"] == title and run["head_branch"] == branch
                    and run["event"] == "workflow_dispatch"):
                # The run endpoint exposes only the latest attempt's conclusion.
                # A rejected native rerun can overwrite an earlier success.
                # Without verified prior-attempt history, never authorize another
                # execution, even when the latest conclusion looks retryable.
                if type(run.get("run_attempt")) is not int or run["run_attempt"] != 1:
                    raise Blocked("CI attempt history is uncertain; native reruns cannot authorize retries.")
                runs.append(dict(run, history_workflow=workflow))
    return runs


def has_no_jobs(repo, run):
    """Require explicit, stable first-attempt evidence before ignoring a run."""
    endpoint = f"repos/{repo}/actions/runs/{run['id']}"
    keys = ('id', 'run_attempt', 'status', 'conclusion', 'head_branch', 'event', 'display_title')
    def verify_snapshot():
        fresh = gh_api(endpoint)
        if (not isinstance(fresh, dict) or type(fresh.get('id')) is not int
                or type(fresh.get('run_attempt')) is not int
                or any(key not in fresh or key not in run or fresh[key] != run[key] for key in keys)):
            raise Blocked("Duplicate run changed while checking job provenance.")
    verify_snapshot()
    pages = gh_api(f"{endpoint}/attempts/1/jobs?per_page=100", paginate=True)
    # Accept only an explicit, complete empty collection. Any job, even a skipped
    # or apparently unstarted job, may conceal earlier activity; retain that run.
    # Missing pages, errors, nonzero totals and inconsistent pagination never
    # establish non-execution. This endpoint needs only existing Actions read.
    if not isinstance(pages, list) or not pages:
        raise Blocked("Missing duplicate-run job provenance.")
    total, seen = None, set()
    for page in pages:
        if (not isinstance(page, dict) or type(page.get('total_count')) is not int
                or page['total_count'] < 0 or not isinstance(page.get('jobs'), list)):
            raise Blocked("Malformed duplicate-run job provenance.")
        if total is not None and page['total_count'] != total:
            raise Blocked("Duplicate-run job totals changed across pages.")
        total = page['total_count']
        if not page['jobs'] and (total != 0 or len(pages) != 1):
            raise Blocked("Incomplete duplicate-run job pages.")
        for job in page['jobs']:
            if (not isinstance(job, dict) or type(job.get('id')) is not int or job['id'] < 1
                    or job['id'] in seen or job.get('run_id') != run['id']
                    or type(job.get('run_attempt')) is not int or job['run_attempt'] != 1):
                raise Blocked("Uncertain duplicate-run job identity.")
            seen.add(job['id'])
    if len(seen) != total:
        raise Blocked("Incomplete duplicate-run job provenance.")
    verify_snapshot()
    return total == 0


def exclude_admission_run(runs, repo, branch):
    """Elect the running invocation over duplicates proven never to have jobs."""
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or os.environ.get("GITHUB_WORKFLOW_REF") !=
            f"{repo}/.github/workflows/review-clearance.yml@refs/heads/{branch}"):
        raise Blocked("Admission must execute in the trusted default-branch controller.")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise Blocked("Cannot identify the current admission run.")
    current = [run for run in runs if run["id"] == int(run_id)]
    if (len(current) != 1 or current[0]["history_workflow"] != "review-clearance.yml"
            or current[0].get("status") != "in_progress"):
        raise Blocked("Current admission run is absent or inconsistent in complete history.")
    # Workflow concurrency serializes execution with cancel-in-progress false;
    # the running slot wins independently of ID/scheduling order. A third event
    # can replace a pending duplicate, leaving a cancelled run with zero jobs.
    # Retain success, in-progress, waiting and unknown states unconditionally.
    # Complete history and attempt == 1 were checked before this function.
    retained = []
    for run in runs:
        if run['id'] == int(run_id):
            continue
        candidate = ('conclusion' in run and (
            (run.get('status') in ('queued', 'pending', 'requested') and run['conclusion'] is None)
            or (run.get('status') == 'completed' and run['conclusion'] == 'cancelled')))
        if candidate and has_no_jobs(repo, run):
            continue
        retained.append(run)
    return retained


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="OWNER/REPOSITORY")
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--expected-sha", help="Require this exact reviewed commit (used by CI).")
    parser.add_argument("--admit-run", action="store_true", help="Authorize tests within the trusted controller run.")
    parser.add_argument("--dispatch", action="store_true", help="Start CI only after successful clearance.")
    parser.add_argument("--wait-for-signoff", action="store_true", help="Briefly allow the bot's reaction to follow its completed summary.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Automatic mode: suppress any prior dispatch for this PR/SHA.")
    mode.add_argument("--retry-failed", action="store_true", help="Manual mode: retry failed/cancelled/timed-out runs, never an active or successful copy.")
    args = parser.parse_args(argv)
    if args.dispatch and args.admit_run:
        parser.error("--dispatch and --admit-run are mutually exclusive.")
    if args.admit_run and (not args.expected_sha or not (args.once or args.retry_failed)):
        parser.error("--admit-run requires --expected-sha and a guarded mode.")
    if args.retry_failed and not (args.dispatch or args.admit_run):
        parser.error("--retry-failed requires --dispatch or --admit-run.")
    if args.dispatch and not (args.once or args.retry_failed):
        parser.error("--dispatch requires --once or --retry-failed.")
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", args.repo) or args.pr < 1:
        parser.error("Expected OWNER/REPOSITORY and a positive PR number.")
    if args.expected_sha and not re.fullmatch(r"[0-9a-f]{40}", args.expected_sha):
        parser.error("Expected a full 40-character commit SHA.")
    try:
        default_branch = None
        if os.environ.get("GITHUB_ACTIONS") == "true":
            default_branch = get_default_branch(args.repo)
            if os.environ.get("GITHUB_RUN_ATTEMPT", "1") != "1":
                raise Blocked("Native reruns are blocked; request fresh clearance.")
            if os.environ.get("GITHUB_REF") != f"refs/heads/{default_branch}":
                raise Blocked("CI control must run from the trusted default branch.")
        attempts = 3 if args.wait_for_signoff else 1
        for attempt in range(attempts):
            try:
                pr = check(args.repo, args.pr, args.expected_sha)
                break
            except AwaitingSignoff:
                if attempt == attempts - 1:
                    raise
                time.sleep(5)
        sha = pr["head"]["sha"]
        basis = pr.get('clearance_basis', 'clean-review')
        print(f"Cleared ({basis}): {args.repo}#{args.pr} at {sha}")
        if args.dispatch or args.admit_run:
            default_branch = default_branch or get_default_branch(args.repo)
            trusted_ref = f"refs/heads/{default_branch}"
            existing = matching_runs(args.repo, default_branch, args.pr, sha)
            if args.admit_run:
                existing = exclude_admission_run(existing, args.repo, default_branch)
            # A denied direct request must not turn an older success into an
            # apparently retryable latest failure. Any prior success is final.
            suppressed = existing and (args.once or any(run.get("conclusion") == "success"
                                                        for run in existing)
                                       or not retry_is_allowed(existing))
            if suppressed:
                if args.admit_run:
                    raise Blocked("History does not authorize another test run for this commit.")
                print("CI already exists for this commit; duplicate, active, or successful history was not repeated.")
                return 0
            check(args.repo, args.pr, sha)
            # The PR SHA is checkout data, never the workflow definition to execute.
            if args.dispatch:
                payload = {"ref": trusted_ref, "inputs": {"pr_number": str(args.pr), "reviewed_sha": sha,
                           "dispatch_mode": "once" if args.once else "retry-failed"}}
                result = subprocess.run(["gh", "api", f"repos/{args.repo}/actions/workflows/review-clearance.yml/dispatches",
                                         "--method", "POST", "--input", "-"], input=json.dumps(payload),
                                        text=True, capture_output=True, check=False)
                if result.returncode:
                    raise Blocked("CI dispatch failed; no successful dispatch is confirmed.")
                print("CI requested through the controller; execution still requires admission.")
        if os.environ.get("GITHUB_OUTPUT"):
            with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
                output.write(f"sha={sha}\n")
                if pr.get('clearance_base') and pr.get('clearance_evidence'):
                    output.write(f"base={pr['clearance_base']}\nevidence={pr['clearance_evidence']}\n")
        return 0
    except (Blocked, KeyError, TypeError, ValueError, OSError) as exc:
        print(f"CI blocked: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
