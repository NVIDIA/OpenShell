# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Acknowledgment evidence and repeat-comment regression tests."""

import tempfile
import unittest
from pathlib import Path

from codex_compatibility_report import SURFACES, validate_review, write_report


class CompatibilityReportTest(unittest.TestCase):
    def setUp(self):
        self.finding = {
            "surface": "api-behavior",
            "change": "Signed requests reject placeholders.",
            "impact": "Existing requests fail with 403.",
            "evidence": "baseline:proxy.rs:10; candidate:proxy.rs:10",
            "recommendation": "Use a separate endpoint.",
            "pull_request": "https://github.com/NVIDIA/OpenShell/pull/4558",
            "acknowledgement": "NOT ACKED",
            "acknowledgement_url": "",
            "previous_report_url": "",
        }
        self.review = {
            "verdict": "unaddressed_breaks",
            "summary": "Signed request behavior changed.",
            "reviewed_surfaces": list(SURFACES),
            "unreviewed_surfaces": [],
            "findings": [self.finding],
        }

    def test_ack_requires_comment_link(self):
        self.finding["acknowledgement"] = "ACKED"
        with self.assertRaises(ValueError):
            validate_review(self.review)
        self.finding["acknowledgement_url"] = (
            self.finding["pull_request"] + "#issuecomment-123"
        )
        validate_review(self.review)

    def test_ack_requires_link_to_associated_pr(self):
        self.finding.update(
            acknowledgement="ACKED",
            acknowledgement_url="https://github.com/other/project/pull/1",
        )
        with self.assertRaises(ValueError):
            validate_review(self.review)

    def test_unacknowledged_finding_has_no_acceptance_link(self):
        validate_review(self.review)
        self.finding["acknowledgement_url"] = (
            self.finding["pull_request"] + "#issuecomment-123"
        )
        for status in ("NOT ACKED", "UNKNOWN"):
            with self.subTest(status=status):
                self.finding["acknowledgement"] = status
                with self.assertRaises(ValueError):
                    validate_review(self.review)

    def test_previous_report_requires_comment_link(self):
        for url in (
            self.finding["pull_request"],
            "https://example.com/#issuecomment-1",
        ):
            with self.subTest(url=url):
                self.finding["previous_report_url"] = url
                with self.assertRaises(ValueError):
                    validate_review(self.review)

    def test_report_shows_proof_and_omits_repeats_from_comment(self):
        self.finding.update(
            acknowledgement="ACKED",
            acknowledgement_url=self.finding["pull_request"] + "#issuecomment-123",
        )
        repeated = dict(
            self.finding,
            change="Upstream error details are suppressed.",
            previous_report_url=self.finding["pull_request"] + "#issuecomment-456",
        )
        self.review["findings"].append(repeated)
        validate_review(self.review)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            write_report(
                output,
                {
                    "context": {},
                    "error": "",
                    "status": "complete",
                    "review": self.review,
                },
            )
            report = (output / "report.md").read_text()
            comment = (output / "comment.md").read_text()
        self.assertIn(self.finding["acknowledgement_url"], comment)
        self.assertIn(repeated["change"], report)
        self.assertNotIn(repeated["change"], comment)
        self.assertIn(repeated["previous_report_url"], report)


if __name__ == "__main__":
    unittest.main()
