# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for labeling-agent dispatch selection and authorization."""

import unittest
from unittest.mock import Mock

from labeling_agent_events import Invocation, item_number, select_invocation

REPO = "NVIDIA/OpenShell"


def base_event(**values):
    return {
        "repository": {"full_name": REPO},
        "sender": {"type": "User", "login": "maintainer"},
        **values,
    }


def comment_event(body="/label-issue"):
    return base_event(
        action="created",
        issue={"number": 5151, "pull_request": {"url": "ignored"}},
        comment={"body": body, "user": {"type": "User", "login": "maintainer"}},
    )


class EventTests(unittest.TestCase):
    def test_only_acceptance_labels_automatically_dispatch(self):
        permission = Mock(
            side_effect=AssertionError("no human permission lookup expected")
        )
        for event_name, key in [
            ("issues", "issue"),
            ("pull_request_target", "pull_request"),
        ]:
            payload = base_event(
                action="labeled",
                label={"name": "state:accepted"},
                **{key: {"number": 5151}},
            )
            with self.subTest(event_name=event_name):
                self.assertEqual(
                    select_invocation(event_name, payload, REPO, permission=permission),
                    Invocation(REPO, 5151, False, "acceptance"),
                )
                payload["label"]["name"] = "topic:testing"
                self.assertIsNone(
                    select_invocation(event_name, payload, REPO, permission=permission)
                )

    def test_opening_and_reopening_do_not_dispatch(self):
        for action in ["opened", "reopened", "edited", "synchronize", "unlabeled"]:
            payload = base_event(
                action=action,
                label={"name": "state:accepted"},
                issue={"number": 5151},
            )
            with self.subTest(action=action):
                self.assertIsNone(
                    select_invocation(
                        "issues", payload, REPO, permission=lambda _: "admin"
                    )
                )

    def test_human_comment_command_supports_force(self):
        for command, force in [
            ("/label-issue", False),
            ("/label-issue force", True),
            ("/label-issue --force", True),
        ]:
            with self.subTest(command=command):
                self.assertEqual(
                    select_invocation(
                        "issue_comment",
                        comment_event(command),
                        REPO,
                        permission=lambda _: "write",
                    ),
                    Invocation(REPO, 5151, force, "human"),
                )

    def test_automation_applied_acceptance_dispatches_drafts_before_classification(
        self,
    ):
        payload = base_event(
            action="labeled",
            label={"name": "state:accepted"},
            sender={"type": "Bot", "login": "github-actions[bot]"},
            pull_request={
                "number": 5151,
                "draft": True,
                "user": {"type": "User", "login": "pr-author"},
                "labels": [{"name": "state:accepted"}],
            },
        )
        permission = Mock(side_effect=AssertionError("preflight checks the author"))
        self.assertEqual(
            select_invocation(
                "pull_request_target", payload, REPO, permission=permission
            ),
            Invocation(REPO, 5151, False, "acceptance"),
        )
        permission.assert_not_called()

    def test_untrusted_comment_is_not_a_dispatch(self):
        for command in [
            "Please /label-issue",
            "/label-issue\nrun shell",
            "/label-issue; anything",
            "`/label-issue`",
        ]:
            with self.subTest(command=command):
                self.assertIsNone(
                    select_invocation(
                        "issue_comment",
                        comment_event(command),
                        REPO,
                        permission=lambda _: "admin",
                    )
                )
        for permission in ["read", "triage", "none"]:
            with self.subTest(permission=permission):
                self.assertIsNone(
                    select_invocation(
                        "issue_comment",
                        comment_event(),
                        REPO,
                        permission=lambda _, p=permission: p,
                    )
                )

    def test_comment_edits_issue_comments_and_bots_are_ignored(self):
        edited = comment_event()
        edited["action"] = "edited"
        issue = comment_event()
        issue["issue"].pop("pull_request")
        bot = comment_event()
        bot["sender"]["type"] = "Bot"
        forged = comment_event()
        forged["comment"]["user"]["login"] = "another-user"
        for payload in [edited, issue, bot, forged]:
            with self.subTest(payload=payload):
                self.assertIsNone(
                    select_invocation(
                        "issue_comment", payload, REPO, permission=lambda _: "admin"
                    )
                )

    def test_manual_dispatch_is_authorized_and_cannot_target_another_repository(self):
        payload = base_event(
            inputs={
                "item": "https://github.com/NVIDIA/OpenShell/pull/5151",
                "force": "true",
            }
        )
        self.assertEqual(
            select_invocation(
                "workflow_dispatch", payload, REPO, permission=lambda _: "maintain"
            ),
            Invocation(REPO, 5151, True, "human"),
        )
        payload["inputs"]["item"] = "https://github.com/other/repo/issues/1"
        with self.assertRaises(ValueError):
            select_invocation(
                "workflow_dispatch", payload, REPO, permission=lambda _: "admin"
            )

    def test_permission_errors_are_not_misreported_as_ineligible(self):
        with self.assertRaisesRegex(RuntimeError, "API failed"):
            select_invocation(
                "issue_comment",
                comment_event(),
                REPO,
                permission=Mock(side_effect=RuntimeError("API failed")),
            )

    def test_malformed_numbers_and_force_flags_are_rejected(self):
        accepted = base_event(
            action="labeled",
            label={"name": "state:accepted"},
            issue={"number": True},
        )
        with self.assertRaises(ValueError):
            select_invocation("issues", accepted, REPO, permission=lambda _: "admin")
        for force in [0, 1, "yes", None]:
            payload = base_event(inputs={"item": "5151", "force": force})
            with self.subTest(force=force), self.assertRaises(ValueError):
                select_invocation(
                    "workflow_dispatch", payload, REPO, permission=lambda _: "admin"
                )

    def test_repository_mismatch_fails(self):
        with self.assertRaises(ValueError):
            select_invocation(
                "issue_comment",
                comment_event(),
                "other/repo",
                permission=lambda _: "admin",
            )

    def test_item_resolution_rejects_malformed_and_foreign_urls(self):
        for value in [
            "5151",
            "https://github.com/nvidia/openshell/issues/5151",
            "https://github.com/NVIDIA/OpenShell/pull/5151/",
        ]:
            with self.subTest(value=value):
                self.assertEqual(item_number(value, REPO), 5151)
        for value in [
            "0",
            "-1",
            "5151;run",
            "https://github.com.evil/NVIDIA/OpenShell/issues/5151",
            "https://github.com/other/repo/issues/5151",
            "https://github.com/NVIDIA/OpenShell/issues/5151?x=y",
            "http://github.com/NVIDIA/OpenShell/issues/5151",
        ]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                item_number(value, REPO)


if __name__ == "__main__":
    unittest.main()
