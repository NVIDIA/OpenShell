"""Dispatch boundary around the shared labeling runner (issue #5411).

This module owns no classification, eligibility or checkpoint implementation.
The runner always prepares fresh evidence and uses the shared helper, including
for duplicate deliveries. Fixed import and production wiring await #5411.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from urllib.parse import quote

from check_review_readiness import _api, check_review_readiness, parse_reviewers
from labeling_agent_events import REPOSITORY, item_number, select_invocation
from labeling_item_lock import item_lock

SUCCESS = frozenset({"preview", "applied", "unchanged", "no-op", "skipped"})


class DispatchFailure(RuntimeError):
    """Preserve the runner's recovery references and uncertain-write details."""

    def __init__(self, report):
        super().__init__("Labeling did not finish; inspect runner recovery report")
        self.report = report


def acceptance_written(repository: str, number: int, default_branch: str, *, api):
    """Call immediately after a successful acceptance write, before PR routing.

    GITHUB_TOKEN label events do not launch another workflow. Explicit workflow
    dispatch does. No actor/body fields confer authority; the target runner
    rechecks current acceptance. Dispatch failure propagates and must be surfaced.
    """
    number = item_number(str(number), repository)
    if not default_branch:
        raise ValueError("trusted default branch required")
    api(f"repos/{repository}/actions/workflows/labeling-dispatch.yml/dispatches",
        method="POST", data={"ref": default_branch,
                             "inputs": {"item": str(number), "force": "false"}})


def dispatch(invocation, *, runner, lock, reviewers, apply=False,
             application_enabled=False, reporter=None):
    """Run one selected item, serialized with every other mutation caller.

    The injected runner contract is run(invocation, apply=bool) -> shared report.
    Eligibility, excluded/unchanged skips and force semantics remain in #5411.
    Preview never routes reviewers. Reviewer handoff repeats after an unchanged
    checkpoint so a prior handoff failure does not require reclassification.
    """
    if apply and not application_enabled:
        raise ValueError("Explicit application gate is disabled")
    with lock():
        report = runner(invocation, apply=apply)
        if reporter is not None:
            reporter(report)
        if not isinstance(report, dict) or report.get("status") not in SUCCESS:
            raise DispatchFailure(report)
        if (apply and report.get("kind") == "pull_request"
                and report["status"] in {"applied", "unchanged", "no-op"}):
            reviewers(invocation.repository, invocation.number)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--select", action="store_true")
    args = parser.parse_args()
    repository = os.environ["GITHUB_REPOSITORY"]
    if not REPOSITORY.fullmatch(repository):
        parser.error("invalid configured repository")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    invocation = select_invocation(
        os.environ["GITHUB_EVENT_NAME"], event, repository,
        permission=lambda login: _api(
            f"repos/{repository}/collaborators/{quote(login, safe='')}/permission")["permission"],
        acceptance_actor="github-actions[bot]",
    )
    if args.select:
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            output.write(f"item={invocation.number if invocation else ''}\n")
        return
    if invocation is None:
        return
    # Provisional integration contract; reconcile the actual interface on #5411
    # rebase. There is deliberately no fallback classifier/helper implementation.
    try:
        from labeling_runner import run
    except ImportError as exc:
        raise RuntimeError("Pending #5411 runner integration; keep activation disabled") from exc
    apply = os.environ.get("LABELING_APPLY") == "true"
    enabled = os.environ.get("LABELING_APPLICATION_ENABLED") == "true"
    parent = _api(f"repos/{repository}/commits/{quote(event['repository']['default_branch'], safe='')}")
    categories = parse_reviewers(Path("REVIEWERS.md").read_text())
    dispatch(
        invocation,
        runner=lambda invocation, apply: run(
            invocation.repository, invocation.number, force=invocation.force, apply=apply),
        lock=lambda: item_lock(repository, invocation.number, parent["sha"],
                               parent["commit"]["tree"]["sha"], api=_api),
        reviewers=lambda repository, number: check_review_readiness(
            categories, repository, number, apply=True),
        apply=apply, application_enabled=enabled,
        reporter=lambda report: print(json.dumps(report), flush=True),
    )


if __name__ == "__main__":
    main()
