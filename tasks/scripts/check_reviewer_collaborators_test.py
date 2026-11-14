# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for reviewer roster eligibility."""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check_reviewer_collaborators as check

ROSTER = """### area:build

| Name | GitHub ID | Company/Organization |
| --- | --- | --- |
| Alice | [@Alice](https://github.com/Alice) | Example |
| Bob | [@bob](https://github.com/bob) | Example |
"""


class CollaboratorTests(unittest.TestCase):
    def run_check(self, response):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text(ROSTER)
            with (
                mock.patch.object(check.subprocess, "run", side_effect=response) as api,
                contextlib.redirect_stdout(io.StringIO()) as output,
                contextlib.redirect_stderr(io.StringIO()) as errors,
            ):
                result = check.main(["--repo", "owner/repo", "--reviewers", str(path)])
        return result, api, output.getvalue(), errors.getvalue()

    def test_accepts_collaborators_on_all_pages_without_write_access(self):
        pages = [
            [{"login": "ALICE", "role_name": "read"}],
            [{"login": "bob", "role_name": "triage"}],
        ]
        result, api, _, _ = self.run_check(
            [subprocess.CompletedProcess([], 0, stdout=json.dumps(pages))]
        )
        self.assertEqual(result, 0)
        command = api.call_args.args[0]
        self.assertIn(
            "repos/owner/repo/collaborators?per_page=100&affiliation=all", command
        )
        self.assertIn("--paginate", command)
        self.assertIn("--slurp", command)

    def test_reports_all_non_collaborators_in_sorted_order(self):
        result, _, _, errors = self.run_check(
            [subprocess.CompletedProcess([], 0, stdout="[[]]")]
        )
        self.assertEqual(result, 1)
        self.assertIn("alice, bob", errors)
        self.assertIn("REVIEWERS.md", errors)

    def test_lookup_failure_fails_closed(self):
        result, _, output, errors = self.run_check(
            subprocess.CalledProcessError(1, "gh", stderr="Forbidden (HTTP 403)")
        )
        self.assertEqual(result, 1)
        self.assertEqual(output, "")
        self.assertIn("403", errors)

    def test_invalid_roster_fails_before_lookup(self):
        with mock.patch.object(
            check, "parse_reviewers", side_effect=ValueError("bad roster")
        ):
            result, api, _, errors = self.run_check([])
        self.assertEqual(result, 1)
        api.assert_not_called()
        self.assertIn("bad roster", errors)


if __name__ == "__main__":
    unittest.main()
