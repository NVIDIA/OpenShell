# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate agent output and render the advisory compatibility report."""

import json
import re
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
                "acknowledgement_url",
                "previous_report_url",
            }
            or any(not isinstance(v, str) for v in finding.values())
            or any(
                not finding[key].strip()
                for key in (
                    "change",
                    "impact",
                    "evidence",
                    "recommendation",
                    "pull_request",
                )
            )
            or finding["surface"] not in SURFACES
            or finding["acknowledgement"] not in ("ACKED", "NOT ACKED", "UNKNOWN")
        ):
            raise ValueError(
                "Finding has invalid or missing compatibility or acknowledgement fields."
            )
        pr_url = finding["pull_request"]
        for key in ("acknowledgement_url", "previous_report_url"):
            url = finding[key]
            if url and (
                not re.fullmatch(r"https://github\.com/[^/]+/[^/]+/pull/\d+", pr_url)
                or not re.fullmatch(
                    re.escape(pr_url)
                    + r"#(?:issuecomment-\d+|discussion_r\d+|pullrequestreview-\d+)",
                    url,
                )
            ):
                raise ValueError("Discussion evidence must link to the associated PR.")
        if finding["acknowledgement"] == "ACKED":
            if not finding["acknowledgement_url"]:
                raise ValueError("ACKED requires a direct discussion URL.")
        elif finding["acknowledgement_url"]:
            raise ValueError(
                "Only an explicit acknowledgment may carry acceptance evidence."
            )
    if review["verdict"] == "unaddressed_breaks" and not review["findings"]:
        raise ValueError("A breaking verdict needs supporting findings.")


def write_report(output: Path, result: dict) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    context = result["context"]
    lines = ["## Compatibility review (advisory)", ""]
    comment_lines = [
        "## Compatibility review (advisory)",
        "",
        "New or updated breaking changes; see the full report for all findings.",
        "",
    ]
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
            acknowledgement = {
                "ACKED": "Risk explicitly accepted",
                "NOT ACKED": "No explicit risk acceptance found",
                "UNKNOWN": "Risk acceptance could not be verified",
            }[finding["acknowledgement"]]
            section = [
                f"### {number}. {finding['surface']} — {acknowledgement}",
                "",
                escape(finding["change"]),
                "",
                f"- **Impact:** {escape(finding['impact'])}",
                f"- **Action:** {escape(finding['recommendation'])}",
                f"- **PR:** {escape(finding['pull_request'])}",
                "",
            ]
            if finding["acknowledgement"] == "ACKED":
                section += [
                    f"- **Acceptance:** [comment]({finding['acknowledgement_url']})",
                    "",
                ]
            if finding["previous_report_url"]:
                section += [
                    f"[Previously reported]({finding['previous_report_url']})",
                    "",
                ]
            else:
                comment_lines += section
            lines += section
    else:
        lines += ["**No assessment available.**", ""]
    details = [
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
        details.append(
            f"- Reviewed: {', '.join(review['reviewed_surfaces']) or 'none'}"
        )
    details += [
        "",
        "</details>",
        "",
        "Advisory review; publication gates are unchanged.",
        "",
    ]
    (output / "report.md").write_text("\n".join(lines + details))
    (output / "comment.md").write_text("\n".join(comment_lines + details))
