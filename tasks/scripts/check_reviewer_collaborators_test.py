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
    def run_check(self, response, roster=ROSTER):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text(roster)
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
            [{"login": "outside", "role_name": "read"}],
        ]
        result, api, _, _ = self.run_check(
            [subprocess.CompletedProcess([], 0, stdout=json.dumps(pages))],
            ROSTER + "| Outside | [@outside](https://github.com/outside) | Other |\n",
        )
        self.assertEqual(result, 0)
        self.assertEqual(api.call_count, 1)
        command = api.call_args.args[0]
        self.assertIn(
            "repos/owner/repo/collaborators?per_page=100&affiliation=all", command
        )
        self.assertIn("--paginate", command)
        self.assertIn("--slurp", command)

    def test_reports_unlisted_read_and_none_in_sorted_order(self):
        result, api, output, errors = self.run_check(
            [
                subprocess.CompletedProcess([], 0, stdout="[[]]"),
                subprocess.CompletedProcess(
                    [], 0, stdout='{"permission": "read", "role_name": "admin"}'
                ),
                subprocess.CompletedProcess(
                    [], 0, stdout='{"permission": "none", "role_name": "custom-role"}'
                ),
            ]
        )
        self.assertEqual(result, 1)
        self.assertEqual(output, "")
        self.assertIn("alice, bob", errors)
        self.assertIn("REVIEWERS.md", errors)
        self.assertEqual(api.call_count, 3)
        self.assertIn(
            "repos/owner/repo/collaborators/alice/permission",
            api.call_args_list[1].args[0],
        )
        self.assertIn(
            "repos/owner/repo/collaborators/bob/permission",
            api.call_args_list[2].args[0],
        )

    def test_accepts_unlisted_writer_with_custom_role(self):
        result, api, output, errors = self.run_check(
            [
                subprocess.CompletedProcess([], 0, stdout='[[{"login": "bob"}]]'),
                subprocess.CompletedProcess(
                    [], 0, stdout='{"permission": "write", "role_name": "custom-role"}'
                ),
            ]
        )
        self.assertEqual(result, 0, errors)
        self.assertIn("All 2 reviewer roster accounts", output)
        self.assertEqual(api.call_count, 2)
        command = api.call_args.args[0]
        self.assertEqual(
            command,
            [
                "gh",
                "api",
                "repos/owner/repo/collaborators/alice/permission",
                "--method",
                "GET",
            ],
        )

    def test_accepts_unlisted_administrator(self):
        result, _, output, errors = self.run_check(
            [
                subprocess.CompletedProcess([], 0, stdout='[[{"login": "bob"}]]'),
                subprocess.CompletedProcess(
                    [], 0, stdout='{"permission": "admin", "role_name": "admin"}'
                ),
            ]
        )
        self.assertEqual(result, 0, errors)
        self.assertIn("All 2 reviewer roster accounts", output)

    def test_permission_lookup_errors_fail_closed(self):
        for status in (403, 404, 500):
            with self.subTest(status=status):
                result, _, output, errors = self.run_check(
                    [
                        subprocess.CompletedProcess([], 0, stdout="[[]]"),
                        subprocess.CalledProcessError(
                            1, "gh", stderr=f"lookup failed (HTTP {status})"
                        ),
                    ]
                )
                self.assertEqual(result, 1)
                self.assertEqual(output, "")
                self.assertIn(f"HTTP {status}", errors)
                self.assertNotIn("ineligible accounts", errors)

    def test_malformed_permission_responses_fail_closed(self):
        responses = ["invalid JSON", "", "null", "[]", "{}", '{"role_name": "admin"}']
        responses.extend(
            json.dumps({"permission": permission, "role_name": "admin"})
            for permission in (
                None,
                [],
                {},
                True,
                1,
                "maintain",
                "triage",
                "custom-role",
            )
        )
        for response in responses:
            with self.subTest(response=response):
                result, _, output, errors = self.run_check(
                    [
                        subprocess.CompletedProcess([], 0, stdout="[[]]"),
                        subprocess.CompletedProcess([], 0, stdout=response),
                    ]
                )
                self.assertEqual(result, 1)
                self.assertEqual(output, "")
                self.assertIn("Reviewer roster:", errors)
                self.assertNotIn("ineligible accounts", errors)

    def test_permission_process_error_fails_closed(self):
        result, _, output, errors = self.run_check(
            [
                subprocess.CompletedProcess([], 0, stdout="[[]]"),
                OSError("connection failed"),
            ]
        )
        self.assertEqual(result, 1)
        self.assertEqual(output, "")
        self.assertIn("connection failed", errors)

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
