# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Private Slack triage handoff behavior."""

import unittest

import triage_handoff


class FakeSlack:
    def __init__(self, roots=(), replies=(), error=None):
        self.roots = list(roots)
        self.replies = list(replies)
        self.error = error
        self.posts = []

    def messages(self, _channel, thread_ts=None):
        if self.error:
            raise RuntimeError(self.error)
        return self.replies if thread_ts else self.roots

    def post(self, channel, text, thread_ts=None):
        self.posts.append((channel, text, thread_ts))
        return "123.456"


class TriageHandoffTest(unittest.TestCase):
    def setUp(self):
        self.url = "https://github.com/NVIDIA/OpenShell/issues/42"

    def test_new_summary_mentions_duty_group_and_issue(self):
        slack = FakeSlack()
        triage_handoff.deliver(
            slack,
            "C0C20SDLDNW",
            "S0C099KM56F",
            self.url,
            "Evidence and decision needed",
        )
        self.assertEqual(len(slack.posts), 1)
        channel, text, thread = slack.posts[0]
        self.assertEqual(channel, "C0C20SDLDNW")
        self.assertIsNone(thread)
        self.assertIn("<!subteam^S0C099KM56F>", text)
        self.assertIn(self.url, text)
        self.assertIn("Evidence and decision needed", text)

    def test_same_summary_is_not_posted_twice(self):
        slack = FakeSlack()
        triage_handoff.deliver(
            slack, "C0C20SDLDNW", "S0C099KM56F", self.url, "Assessment"
        )
        slack.roots = [{"text": slack.posts[0][1], "ts": "123.456"}]
        self.assertFalse(
            triage_handoff.deliver(
                slack, "C0C20SDLDNW", "S0C099KM56F", self.url, "Assessment"
            )
        )
        self.assertEqual(len(slack.posts), 1)

    def test_new_assessment_replies_in_existing_thread(self):
        slack = FakeSlack(
            roots=[{"text": "OpenShell triage issue #42", "ts": "123.456"}]
        )
        triage_handoff.deliver(
            slack, "C0C20SDLDNW", "S0C099KM56F", self.url, "New evidence"
        )
        self.assertEqual(slack.posts[0][2], "123.456")

    def test_security_notice_does_not_include_assessment(self):
        slack = FakeSlack()
        triage_handoff.deliver(
            slack,
            "C0C20SDLDNW",
            "S0C099KM56F",
            self.url,
            "secret exploit",
            security=True,
        )
        text = slack.posts[0][1]
        self.assertNotIn("secret exploit", text)
        self.assertIn("SECURITY.md", text)

    def test_history_failure_prevents_post(self):
        slack = FakeSlack(error="history unavailable")
        with self.assertRaisesRegex(RuntimeError, "history unavailable"):
            triage_handoff.deliver(
                slack, "C0C20SDLDNW", "S0C099KM56F", self.url, "Assessment"
            )
        self.assertEqual(slack.posts, [])


if __name__ == "__main__":
    unittest.main()
