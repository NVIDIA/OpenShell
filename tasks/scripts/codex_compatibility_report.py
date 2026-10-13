# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate agent output and render the advisory compatibility report."""

import json
from html import escape
from pathlib import Path

SURFACES = (
    "rust-sdk",
    "python-sdk",
    "go-sdk",
    "typescript-sdk",
    "api-behavior",
    "cli",
    "configuration",
    "policy",
    "helm",
    "state",
)


def validate_review(review: dict) -> None:
    fields = {
        "verdict",
        "summary",
        "reviewed_surfaces",
        "unreviewed_surfaces",
        "findings",
    }
    if not isinstance(review, dict) or set(review) != fields:
        raise ValueError("Review is missing required fields or has unexpected fields.")
    if review["verdict"] not in (
        "no_unaddressed_breaks",
        "unaddressed_breaks",
        "needs_review",
    ):
        raise ValueError("Review has an invalid verdict.")
    if not isinstance(review["summary"], str) or not review["summary"].strip():
        raise ValueError("Review has no summary.")
    for key in ("reviewed_surfaces", "unreviewed_surfaces"):
        if not isinstance(review[key], list) or any(
            not isinstance(s, str) for s in review[key]
        ):
            raise ValueError("Review has invalid coverage.")
    coverage = review["reviewed_surfaces"] + review["unreviewed_surfaces"]
    if len(coverage) != len(SURFACES) or set(coverage) != set(SURFACES):
        raise ValueError("Review must account for every surface exactly once.")
    if review["unreviewed_surfaces"] and review["verdict"] != "needs_review":
        raise ValueError("Incomplete coverage cannot claim a conclusive verdict.")
    if not isinstance(review["findings"], list):
        raise ValueError("Review has invalid findings.")
    for finding in review["findings"]:
        if (
            not isinstance(finding, dict)
            or set(finding)
            != {
                "surface",
                "change",
                "impact",
                "evidence",
                "recommendation",
                "pull_request",
                "acknowledgement",
            }
            or any(not isinstance(v, str) or not v.strip() for v in finding.values())
            or finding["surface"] not in SURFACES
            or finding["acknowledgement"] not in ("ACKED", "NOT ACKED", "UNKNOWN")
        ):
            raise ValueError(
                "Finding has invalid or missing compatibility or acknowledgement fields."
            )
    if review["verdict"] == "unaddressed_breaks" and not review["findings"]:
        raise ValueError("A breaking verdict needs supporting findings.")


def write_report(output: Path, result: dict) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    context = result["context"]
    lines = ["## Compatibility review (advisory)", ""]
    if result["error"]:
        lines += [escape(result["error"]), ""]
    review = result["review"]
    if review:
        assessment = {
            "no_unaddressed_breaks": "No unaddressed breaking changes",
            "unaddressed_breaks": "Unaddressed breaking changes",
            "needs_review": "Needs review",
        }[review["verdict"]]
        lines += [
            f"**{assessment}**",
            "",
            escape(review["summary"]),
            "",
        ]
        if review["unreviewed_surfaces"]:
            lines += [
                "**Not inspected:** " + ", ".join(review["unreviewed_surfaces"]),
                "",
            ]
        for number, finding in enumerate(review["findings"], 1):
            lines += [
                f"### {number}. {finding['surface']} — {finding['acknowledgement']}",
                "",
                escape(finding["change"]),
                "",
                f"- **Impact:** {escape(finding['impact'])}",
                f"- **Action:** {escape(finding['recommendation'])}",
                f"- **PR:** {escape(finding['pull_request'])}",
                "",
            ]
    else:
        lines += ["**No assessment available.**", ""]
    lines += [
        "<details>",
        "<summary>Review details</summary>",
        "",
        f"- Execution: **{result['status']}**",
        f"- Candidate: `{context.get('candidate_tag', 'unresolved')}` "
        f"(`{context.get('candidate_sha', 'unresolved')}`)",
        f"- Baseline: `{context.get('baseline_tag', 'unresolved')}` "
        f"(`{context.get('baseline_sha', 'unresolved')}`)",
    ]
    if review:
        lines.append(f"- Reviewed: {', '.join(review['reviewed_surfaces']) or 'none'}")
    lines += [
        "",
        "</details>",
        "",
        "Advisory review; publication gates are unchanged.",
        "",
    ]
    (output / "report.md").write_text("\n".join(lines))
