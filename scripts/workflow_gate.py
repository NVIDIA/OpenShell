#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check issue labels before queued planning or implementation."""

import argparse
import json
import subprocess
from dataclasses import dataclass

AXES = ("type:", "state:", "needs:")
ACCEPTED_STATES = {"state:accepted", "state:in-progress", "state:in-review"}
PICKUP_STATES = {"state:accepted", "state:in-progress"}


@dataclass(frozen=True)
class GateResult:
    allowed: bool
    problems: tuple[str, ...]


def assess(
    labels: set[str],
    phase: str,
    *,
    has_plan: bool = False,
    direct: bool = False,
    specialized: bool = False,
) -> GateResult:
    if phase not in {"plan", "implement"}:
        raise ValueError("phase must be plan or implement")
    if "topic:security" in labels and not specialized:
        return GateResult(
            False, ("topic:security requires a specialized security skill",)
        )
    if specialized and "topic:security" not in labels:
        return GateResult(False, ("specialized security work requires topic:security",))

    problems = []
    for axis in AXES:
        found = sorted(label for label in labels if label.startswith(axis))
        if len(found) > 1:
            problems.append(f"conflicting {axis} labels: {', '.join(found)}")
        if axis == "state:" and not found:
            problems.append("missing state:* label")

    accepted = bool(labels & ACCEPTED_STATES or "roadmap" in labels)
    if not accepted and (not specialized or phase == "implement"):
        problems.append("missing state:accepted or roadmap placement")
    expected_need = "needs:plan" if phase == "plan" else "needs:pr"
    if expected_need not in labels:
        problems.append(f"missing {expected_need}")
    can_pick_up = bool(labels & PICKUP_STATES)
    if specialized and phase == "plan" and "state:validated" in labels:
        can_pick_up = True
    if not can_pick_up:
        problems.append("issue state does not permit unattended phase pickup")
    if phase == "implement" and not has_plan:
        problems.append("approved implementation plan is not present")
    if "state:new" in labels:
        problems.append("state:new permits screening only")

    if specialized and phase == "implement" and not has_plan:
        return GateResult(False, tuple(problems))
    return GateResult(direct or not problems, tuple(problems))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issue", type=int, required=True)
    parser.add_argument("--phase", choices=("plan", "implement"), required=True)
    parser.add_argument(
        "--direct",
        action="store_true",
        help="Report queue discrepancies for a direct request",
    )
    parser.add_argument(
        "--security", action="store_true", help="Apply the specialized security gate"
    )
    args = parser.parse_args()

    result = subprocess.run(
        ["gh", "issue", "view", str(args.issue), "--json", "state,labels,comments"],
        check=True,
        capture_output=True,
        text=True,
    )
    issue = json.loads(result.stdout)
    labels = {label["name"] for label in issue["labels"]}
    marker = "> **🔒 security-review-agent**" if args.security else "> **🏗️ build-plan**"
    has_plan = any(
        comment["body"].startswith(marker)
        and (
            not args.security
            or (
                "**Determination:** Legitimate concern" in comment["body"]
                and "### Remediation Plan" in comment["body"]
            )
        )
        for comment in issue["comments"]
    )
    gate = assess(
        labels,
        args.phase,
        has_plan=has_plan,
        direct=args.direct,
        specialized=args.security,
    )
    if issue["state"] != "OPEN":
        gate = GateResult(False, ("issue is closed",))
    print(json.dumps({"allowed": gate.allowed, "problems": gate.problems}))
    if not gate.allowed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
