#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Record the ARC baseline for OS-49 Phase 1.

Pulls workflow-run history from the GitHub Actions API for each of the ten
workflows currently pinned to the `build-amd64` / `build-arm64` ARC scale sets
and reports wall time, queue time, and success rate over a rolling window.
Output is both machine-readable JSON and a Markdown table so Phase 6/7 cut-over
PRs can compare like-for-like.

Usage:
    uv run python scripts/baseline_workflow_metrics.py
    uv run python scripts/baseline_workflow_metrics.py --days 30 --out architecture/plans/OS-49-baseline.json

Auth:
    Relies on `gh auth login` — the script shells out to `gh api` so no token
    needs to live in this process.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import math
import pathlib
import statistics
import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

REPO = "NVIDIA/OpenShell"

WORKFLOWS: list[str] = [
    "branch-checks.yml",
    "branch-e2e.yml",
    "ci-image.yml",
    "docker-build.yml",
    "e2e-test.yml",
    "release-canary.yml",
    "release-dev.yml",
    "release-tag.yml",
    "release-vm-dev.yml",
    "release-vm-kernel.yml",
]

# Reusable workflows (workflow_call targets). The Actions API returns no runs
# when querying these by workflow id — their runs are rolled into the caller's
# workflow_run. For these, we scan all repo runs in the window and attribute
# via `referenced_workflows`.
REUSABLE_WORKFLOWS: set[str] = {
    "docker-build.yml",
    "e2e-test.yml",
}

# Conclusions that represent a real execution on a runner. Percentile math
# excludes the rest (skipped runs in particular produce near-zero wall times
# that poison p50/p95).
RUN_TIME_CONCLUSIONS: set[str] = {"success", "failure"}


@dataclasses.dataclass
class RunSummary:
    id: int
    created_at: dt.datetime
    run_started_at: dt.datetime | None
    updated_at: dt.datetime
    conclusion: str | None
    event: str

    @property
    def queue_seconds(self) -> float | None:
        if self.run_started_at is None:
            return None
        return max(0.0, (self.run_started_at - self.created_at).total_seconds())

    @property
    def wall_seconds(self) -> float | None:
        start = self.run_started_at or self.created_at
        return max(0.0, (self.updated_at - start).total_seconds())


@dataclasses.dataclass
class WorkflowStats:
    workflow: str
    window_days: int
    run_count: int
    success_count: int
    failure_count: int
    cancelled_count: int
    other_count: int
    wall_p50: float | None
    wall_p95: float | None
    wall_mean: float | None
    queue_p50: float | None
    queue_p95: float | None
    queue_mean: float | None
    reusable: bool = False

    @property
    def completed(self) -> int:
        return self.success_count + self.failure_count + self.cancelled_count

    @property
    def success_rate(self) -> float | None:
        denom = self.success_count + self.failure_count
        if denom == 0:
            return None
        return self.success_count / denom


def gh_api(path: str) -> dict | list:
    """Call the GitHub REST API via the gh CLI and return parsed JSON."""
    cmd = ["gh", "api", "-H", "Accept: application/vnd.github+json", path]
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("gh CLI not found on PATH. Install: https://cli.github.com/")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"gh api failed for {path}: {exc.stderr.strip()}")
    return json.loads(result.stdout)


def parse_iso(value: str | None) -> dt.datetime | None:
    if value is None:
        return None
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _run_from_raw(raw: dict) -> RunSummary | None:
    created = parse_iso(raw.get("created_at"))
    if created is None:
        return None
    return RunSummary(
        id=raw["id"],
        created_at=created,
        run_started_at=parse_iso(raw.get("run_started_at")),
        updated_at=parse_iso(raw.get("updated_at")) or created,
        conclusion=raw.get("conclusion"),
        event=raw.get("event", ""),
    )


def fetch_runs(workflow: str, since: dt.datetime) -> list[RunSummary]:
    """Fetch runs for a workflow in the window via `/actions/workflows/{id}/runs`.

    Returns [] for reusable (workflow_call) workflows — the API only surfaces
    them under the caller. Use `fetch_reusable_runs` for those.
    """
    runs: list[RunSummary] = []
    page = 1
    cutoff = since.date().isoformat()
    while True:
        path = (
            f"/repos/{REPO}/actions/workflows/{workflow}/runs"
            f"?created=%3E%3D{cutoff}&per_page=100&page={page}"
        )
        payload = gh_api(path)
        assert isinstance(payload, dict), f"unexpected payload: {type(payload)}"
        batch = payload.get("workflow_runs") or []
        if not batch:
            break
        for raw in batch:
            run = _run_from_raw(raw)
            if run is None or run.created_at < since:
                continue
            runs.append(run)
        if len(batch) < 100:
            break
        page += 1
        if page > 50:  # safety valve: 5000 runs is plenty for 30 days
            break
    return runs


def fetch_all_repo_runs(since: dt.datetime) -> list[dict]:
    """Single pass over `/actions/runs` for the window, returning raw payloads.

    Raw so callers can inspect `referenced_workflows` to attribute reusable
    workflows. This is called once and shared across all reusable workflows.
    """
    raws: list[dict] = []
    page = 1
    cutoff = since.date().isoformat()
    while True:
        path = (
            f"/repos/{REPO}/actions/runs"
            f"?created=%3E%3D{cutoff}&per_page=100&page={page}"
        )
        payload = gh_api(path)
        assert isinstance(payload, dict), f"unexpected payload: {type(payload)}"
        batch = payload.get("workflow_runs") or []
        if not batch:
            break
        for raw in batch:
            created = parse_iso(raw.get("created_at"))
            if created is None or created < since:
                continue
            raws.append(raw)
        if len(batch) < 100:
            break
        page += 1
        if page > 200:  # safety valve: 20k runs — generous for 30 days
            break
    return raws


def fetch_reusable_runs(workflow: str, all_repo_runs: list[dict]) -> list[RunSummary]:
    """Attribute a reusable workflow via `referenced_workflows` on caller runs.

    Wall/queue times come from the caller run, so they are caller-inclusive —
    a caller that inlines other jobs alongside the reusable workflow will
    overstate the reusable piece. Annotated in the rendered output.
    """
    suffix = f".github/workflows/{workflow}"
    runs: list[RunSummary] = []
    for raw in all_repo_runs:
        refs = raw.get("referenced_workflows") or []
        # GitHub returns paths like "org/repo/.github/workflows/foo.yml@<sha>"
        # — strip the `@ref` suffix before matching.
        if not any(r.get("path", "").split("@", 1)[0].endswith(suffix) for r in refs):
            continue
        run = _run_from_raw(raw)
        if run is None:
            continue
        runs.append(run)
    return runs


def _percentile(values: Iterable[float], p: float) -> float | None:
    sample = sorted(v for v in values if v is not None)
    if not sample:
        return None
    if len(sample) == 1:
        return sample[0]
    k = (len(sample) - 1) * p
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return sample[int(k)]
    return sample[lo] + (sample[hi] - sample[lo]) * (k - lo)


def summarize(
    workflow: str,
    window_days: int,
    runs: list[RunSummary],
    reusable: bool = False,
) -> WorkflowStats:
    completed = [r for r in runs if r.conclusion is not None]
    success_count = sum(1 for r in completed if r.conclusion == "success")
    failure_count = sum(1 for r in completed if r.conclusion == "failure")
    cancelled_count = sum(1 for r in completed if r.conclusion == "cancelled")
    other_count = len(completed) - success_count - failure_count - cancelled_count
    # p50/p95 over real executions only — skipped/cancelled/startup_failure
    # produce near-zero wall times and would poison percentiles.
    executed = [r for r in completed if r.conclusion in RUN_TIME_CONCLUSIONS]
    wall = [r.wall_seconds for r in executed if r.wall_seconds is not None]
    queue = [r.queue_seconds for r in executed if r.queue_seconds is not None]
    return WorkflowStats(
        workflow=workflow,
        window_days=window_days,
        run_count=len(runs),
        success_count=success_count,
        failure_count=failure_count,
        cancelled_count=cancelled_count,
        other_count=other_count,
        wall_p50=_percentile(wall, 0.50),
        wall_p95=_percentile(wall, 0.95),
        wall_mean=statistics.fmean(wall) if wall else None,
        queue_p50=_percentile(queue, 0.50),
        queue_p95=_percentile(queue, 0.95),
        queue_mean=statistics.fmean(queue) if queue else None,
        reusable=reusable,
    )


def fmt_seconds(value: float | None) -> str:
    if value is None:
        return "—"
    if value < 60:
        return f"{value:.0f}s"
    if value < 3600:
        return f"{value / 60:.1f}m"
    return f"{value / 3600:.2f}h"


def fmt_rate(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value * 100:.0f}%"


def render_markdown(stats: list[WorkflowStats], since: dt.datetime) -> str:
    lines: list[str] = []
    lines.append(
        f"# OS-49 Phase 1 — ARC baseline ({REPO}, last {stats[0].window_days} days)"
    )
    lines.append("")
    lines.append(f"Window: `{since.date().isoformat()}` → today (UTC).")
    lines.append("")
    lines.append(
        "| Workflow | Runs | Success | Wall p50 | Wall p95 | Queue p50 | Queue p95 |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    has_reusable = False
    for s in stats:
        name = f"`{s.workflow}`"
        if s.reusable:
            name += " †"
            has_reusable = True
        lines.append(
            f"| {name} | {s.run_count} | {fmt_rate(s.success_rate)} "
            f"| {fmt_seconds(s.wall_p50)} | {fmt_seconds(s.wall_p95)} "
            f"| {fmt_seconds(s.queue_p50)} | {fmt_seconds(s.queue_p95)} |"
        )
    lines.append("")
    lines.append(
        "Percentiles cover runs with conclusion `success` or `failure` only — "
        "`skipped`/`cancelled`/`startup_failure` are excluded so `if:` guards and early aborts "
        "don't poison wall-time p50. Success rate = `success / (success + failure)`. "
        "Queue time = `run_started_at − created_at`. Wall time = `updated_at − run_started_at`."  # noqa: RUF001 — U+2212 minus rendered in output markdown
    )
    if has_reusable:
        lines.append("")
        lines.append(
            "† Reusable workflow (`workflow_call`). Runs attributed via "
            "`referenced_workflows` on caller runs; wall/queue times are the "
            "caller's totals, so they overstate the reusable piece."
        )
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Look-back window in days (default: 30)",
    )
    parser.add_argument(
        "--out",
        type=pathlib.Path,
        default=pathlib.Path("architecture/plans/OS-49-baseline.json"),
        help="Where to write the JSON report (default: architecture/plans/OS-49-baseline.json)",
    )
    parser.add_argument(
        "--md",
        type=pathlib.Path,
        default=pathlib.Path("architecture/plans/OS-49-baseline.md"),
        help="Where to write the Markdown report (default: architecture/plans/OS-49-baseline.md)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    since = dt.datetime.now(dt.UTC) - dt.timedelta(days=args.days)
    all_stats: list[WorkflowStats] = []
    # Only do the expensive all-repo scan if at least one reusable workflow
    # appears in the target list.
    need_repo_scan = any(w in REUSABLE_WORKFLOWS for w in WORKFLOWS)
    all_repo_runs: list[dict] = []
    if need_repo_scan:
        print("• (scanning all repo runs for reusable attribution)", file=sys.stderr)
        all_repo_runs = fetch_all_repo_runs(since)
    for workflow in WORKFLOWS:
        print(f"• {workflow}", file=sys.stderr)
        if workflow in REUSABLE_WORKFLOWS:
            runs = fetch_reusable_runs(workflow, all_repo_runs)
            all_stats.append(summarize(workflow, args.days, runs, reusable=True))
        else:
            runs = fetch_runs(workflow, since)
            all_stats.append(summarize(workflow, args.days, runs))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(
            {
                "repo": REPO,
                "window_days": args.days,
                "generated_at": dt.datetime.now(dt.UTC).isoformat(),
                "workflows": [dataclasses.asdict(s) for s in all_stats],
            },
            indent=2,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )
    args.md.write_text(render_markdown(all_stats, since), encoding="utf-8")
    print(f"wrote {args.out}", file=sys.stderr)
    print(f"wrote {args.md}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
