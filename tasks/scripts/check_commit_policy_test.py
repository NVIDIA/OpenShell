# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import io
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import check_commit_policy as policy


def commit(sha="a" * 40, login="alice", verified=True, message="fix: thing", **author):
    return {
        "sha": sha,
        "author": {"login": login, **author} if login else None,
        "commit": {
            "message": message,
            "verification": {
                "verified": verified,
                "reason": "valid" if verified else "unsigned",
            },
        },
    }


def permissions(table):
    return lambda login: table.get(login, "none")


class SigningTests(unittest.TestCase):
    def test_unsigned_collaborator_fails(self):
        found = policy.find_problems(
            {}, [commit(verified=False)], permissions({"alice": "write"})
        )
        self.assertEqual(len(found), 1)
        self.assertIn("not cryptographically signed", found[0])
        self.assertIn("unsigned", found[0])

    def test_admin_is_covered(self):
        found = policy.find_problems(
            {}, [commit(verified=False)], permissions({"alice": "admin"})
        )
        self.assertEqual(len(found), 1)

    def test_unsigned_external_contributor_passes(self):
        self.assertEqual(
            policy.find_problems({}, [commit(verified=False)], permissions({})), []
        )

    def test_read_permission_passes(self):
        found = policy.find_problems(
            {}, [commit(verified=False)], permissions({"alice": "read"})
        )
        self.assertEqual(found, [])

    def test_unsigned_bot_passes(self):
        bot = commit(login="dependabot[bot]", verified=False, type="Bot")
        self.assertEqual(
            policy.find_problems({}, [bot], permissions({"dependabot[bot]": "write"})),
            [],
        )

    def test_unlinked_author_passes(self):
        self.assertEqual(
            policy.find_problems(
                {}, [commit(login=None, verified=False)], permissions({})
            ),
            [],
        )

    def test_signed_commit_does_not_query_permission(self):
        def fail(_login):
            raise AssertionError("permission must not be looked up")

        self.assertEqual(policy.find_problems({}, [commit()], fail), [])


class AttributionTests(unittest.TestCase):
    def test_agent_coauthor_in_commit_fails(self):
        message = "feat: x\n\nCo-Authored-By: Claude Sonnet <noreply@anthropic.com>"
        found = policy.find_problems({}, [commit(message=message)], permissions({}))
        self.assertEqual(len(found), 1)
        self.assertIn("Co-authored-by", found[0])

    def test_human_coauthor_passes(self):
        message = "feat: x\n\nCo-authored-by: Octo Cat <octo@example.com>"
        self.assertEqual(
            policy.find_problems({}, [commit(message=message)], permissions({})), []
        )

    def test_generated_with_footer_in_pr_body_fails(self):
        pull = {
            "title": "fix: x",
            "body": "Done.\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)",
        }
        found = policy.find_problems(pull, [], permissions({}))
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].startswith("PR body:"))

    def test_generated_with_unrelated_tool_passes(self):
        pull = {"title": "chore: x", "body": "Types generated with protobuf."}
        self.assertEqual(policy.find_problems(pull, [], permissions({})), [])

    def test_agent_name_in_pr_title_trailer_fails(self):
        pull = {"title": "fix: x\nCo-authored-by: Copilot", "body": None}
        self.assertEqual(len(policy.find_problems(pull, [], permissions({}))), 1)

    def test_agent_word_outside_trailer_passes(self):
        message = "docs: explain how Claude Code reads AGENTS.md"
        self.assertEqual(
            policy.find_problems({}, [commit(message=message)], permissions({})), []
        )


class MainTests(unittest.TestCase):
    def run_main(self, responses):
        def fake_api(path, **_kwargs):
            value = responses[path.split("?")[0]]
            if isinstance(value, Exception):
                raise value
            return value

        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(policy, "_api", fake_api),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            code = policy.main(["--repo", "o/r", "--pr", "7"])
        return code, out.getvalue(), err.getvalue()

    def test_passes_for_clean_pr(self):
        code, out, _ = self.run_main(
            {
                "repos/o/r/pulls/7": {"title": "fix: x", "body": ""},
                "repos/o/r/pulls/7/commits": [commit()],
            }
        )
        self.assertEqual(code, 0)
        self.assertIn("meet the commit policy", out)

    def test_reports_each_problem(self):
        code, _, err = self.run_main(
            {
                "repos/o/r/pulls/7": {"title": "fix: x", "body": ""},
                "repos/o/r/pulls/7/commits": [commit(verified=False)],
                "repos/o/r/collaborators/alice/permission": {"permission": "write"},
            }
        )
        self.assertEqual(code, 1)
        self.assertIn("1 problem(s)", err)

    def test_missing_collaborator_is_external(self):
        not_found = subprocess.CalledProcessError(
            1, "gh", stderr="gh: Not Found (HTTP 404)"
        )
        code, _, _ = self.run_main(
            {
                "repos/o/r/pulls/7": {"title": "fix: x", "body": ""},
                "repos/o/r/pulls/7/commits": [commit(verified=False)],
                "repos/o/r/collaborators/alice/permission": not_found,
            }
        )
        self.assertEqual(code, 0)

    def test_api_failure_fails_closed(self):
        boom = subprocess.CalledProcessError(1, "gh", stderr="HTTP 502")
        code, _, err = self.run_main({"repos/o/r/pulls/7": boom})
        self.assertEqual(code, 1)
        self.assertIn("Cannot verify commit policy", err)


if __name__ == "__main__":
    unittest.main()
