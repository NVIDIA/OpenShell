# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline behavioral tests for bounded GitHub transport."""
import json
import subprocess
import sys
import unittest

from label_issue_github import GitHubClient, GitHubError, _run_bounded


class Clock:
    def __init__(self):
        self.now = 0
        self.sleeps = []

    def sleep(self, delay):
        self.sleeps.append(delay)
        self.now += delay


class Runner:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return subprocess.CompletedProcess(command, result[0], result[1], result[2])


def response(body, status=200, headers=None):
    lines = [f"HTTP/2.0 {status} Status"]
    lines.extend(f"{key}: {value}" for key, value in (headers or {}).items())
    return (0 if status < 400 else 1, "\r\n".join(lines) + "\r\n\r\n" + json.dumps(body), "failure")


class TransportTests(unittest.TestCase):
    def client(self, *responses, **options):
        self.clock = Clock()
        self.runner = Runner(*responses)
        return GitHubClient(runner=self.runner, monotonic=lambda: self.clock.now,
                            wall_clock=lambda: 1000 + self.clock.now,
                            sleeper=self.clock.sleep, jitter=lambda: 0, **options)

    def test_pages_follow_links_and_flatten_acceptance_adapter(self):
        client = self.client(response([{"name": "a"}], headers={"Link": '<https://api.github.com/repos/o/r/labels?page=2>; rel="next"'}), response([{"name": "b"}]))
        self.assertEqual(client("repos/o/r/labels", pages=True), [{"name": "a"}, {"name": "b"}])
        self.assertIn("repos/o/r/labels?page=2", self.runner.calls[1][0])
        self.assertEqual(client.diagnostics["requests"], 2)

    def test_invalid_repeated_or_foreign_links_do_not_fetch(self):
        for link in ('<https://api.github.com/x>; rel="next"', '<https://evil.example/x>; rel="next"', '<>; rel="next"'):
            with self.subTest(link=link):
                client = self.client(response([], headers={"Link": link}))
                with self.assertRaises(GitHubError):
                    client.pages("x")
                self.assertEqual(len(self.runner.calls), 1)

    def test_page_budget_does_not_silently_return_partial_data(self):
        client = self.client(response([], headers={"Link": '<https://api.github.com/y>; rel="next"'}), max_pages=1)
        with self.assertRaises(GitHubError):
            client.pages("x")

    def test_non_list_page_and_invalid_json_are_errors(self):
        for fixture in (response({"nodes": []}), (0, 'HTTP/2.0 200 OK\n\n{bad', '')):
            client = self.client(fixture)
            with self.assertRaises(GitHubError):
                client.pages("x")

    def test_permission_failure_is_not_retried(self):
        client = self.client(response({"message": "Resource not accessible"}, 403))
        with self.assertRaises(GitHubError) as caught:
            client.request("x")
        self.assertFalse(caught.exception.retryable)
        self.assertEqual(len(self.runner.calls), 1)

    def test_404_retains_acceptance_called_process_error_semantics(self):
        client = self.client(response({"message": "Not Found"}, 404))
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            client("x")
        self.assertIn("(HTTP 404)", caught.exception.stderr)

    def test_rate_limit_delay_precedence(self):
        for status, headers, message, delay in (
            (429, {"Retry-After": "7"}, "limited", 7),
            (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1010"}, "limit", 10),
            (403, {}, "You have exceeded a secondary rate limit", 60),
            (429, {"Retry-After": "Thu, 01 Jan 1970 00:16:47 GMT"}, "limit", 7),
        ):
            with self.subTest(headers=headers, message=message):
                client = self.client(response({"message": message}, status, headers), response({"ok": True}))
                self.assertEqual(client.request("x"), {"ok": True})
                self.assertEqual(self.clock.sleeps, [delay])

    def test_exhaustion_stops_after_three_read_attempts(self):
        client = self.client(*(response({}, 503) for _ in range(3)))
        with self.assertRaises(GitHubError) as caught:
            client.request("x")
        self.assertTrue(caught.exception.retryable)
        self.assertEqual(len(self.runner.calls), 3)
        self.assertEqual(self.clock.sleeps, [1, 2])

    def test_deadline_reports_earliest_retry_without_sleep(self):
        client = self.client(response({}, 429, {"Retry-After": "60"}), invocation_timeout=20)
        with self.assertRaises(GitHubError) as caught:
            client.request("x")
        self.assertEqual(caught.exception.retry_at, 1060)
        self.assertEqual(self.clock.sleeps, [])

    def test_timeout_retries_read_but_never_uncertain_write(self):
        for data, method, read in ((None, "GET", True), ({"query": "query { viewer { login } }"}, "POST", True), ({"query": "mutation { change }"}, "POST", False)):
            with self.subTest(method=method, read=read):
                client = self.client(subprocess.TimeoutExpired("gh", 30), response({"ok": 1}))
                if read:
                    self.assertEqual(client.request("graphql" if data else "x", method=method, data=data), {"ok": 1})
                else:
                    with self.assertRaises(GitHubError) as caught:
                        client.request("graphql", method=method, data=data)
                    self.assertTrue(caught.exception.uncertain_write)
                    self.assertEqual(len(self.runner.calls), 1)

    def test_graphql_multioperation_document_cannot_hide_a_mutation_retry(self):
        client = self.client(subprocess.TimeoutExpired("gh", 30), response({}))
        with self.assertRaises(GitHubError) as caught:
            client.request("graphql", method="POST", data={
                "query": "query Read { viewer { login } } mutation Write { change }",
                "operationName": "Write",
            })
        self.assertTrue(caught.exception.uncertain_write)
        self.assertEqual(len(self.runner.calls), 1)

    def test_graphql_partial_errors_preserve_payload_without_retrying_mutation(self):
        body = {"data": {"first": {"id": "ok"}, "second": None}, "errors": [{"message": "failed", "path": ["second"]}]}
        client = self.client(response(body))
        with self.assertRaises(GitHubError) as caught:
            client.request("graphql", method="POST", data={"query": "mutation { first second }"})
        self.assertEqual(caught.exception.payload, body)
        self.assertTrue(caught.exception.uncertain_write)

    def test_graphql_rate_limited_reads_retry_using_headers(self):
        client = self.client(response({"errors": [{"type": "RATE_LIMITED", "message": "API rate limit exceeded"}]}, headers={"Retry-After": "4"}), response({"data": {"viewer": {"login": "a"}}}))
        self.assertEqual(client.request("graphql", method="POST", data={"query": "query { viewer { login } }"}), {"data": {"viewer": {"login": "a"}}})
        self.assertEqual(self.clock.sleeps, [4])

    def test_writes_are_paced_and_body_uses_stdin(self):
        client = self.client(response({}), response({}))
        client.request("x", method="POST", data={"labels": ["a"]})
        client.request("x", method="DELETE")
        self.assertEqual(self.clock.sleeps, [1])
        self.assertEqual(json.loads(self.runner.calls[0][1]["input"]), {"labels": ["a"]})
        self.assertIn("--include", self.runner.calls[0][0])
        self.assertEqual(self.runner.calls[0][1]["timeout"], 30)

    def test_oversized_payload_is_not_accepted_as_complete(self):
        client = self.client(response({"long": "x" * 100}), max_response_bytes=50)
        with self.assertRaises(GitHubError):
            client.request("x")

    def test_default_runner_stops_output_before_collecting_unbounded_data(self):
        with self.assertRaises(GitHubError):
            _run_bounded([sys.executable, "-c", "import sys; sys.stdout.write('x' * 1000000)"],
                         input=None, capture_output=True, text=True, timeout=5,
                         check=False, output_limit=100)

    def test_graphql_nonobject_response_is_not_success(self):
        client = self.client(response([]))
        with self.assertRaises(GitHubError):
            client.request("graphql", method="POST", data={"query": "query { viewer { login } }"})

    def test_deadline_caps_subprocess_timeout(self):
        client = self.client(response({}), invocation_timeout=3)
        client.request("x")
        self.assertEqual(self.runner.calls[0][1]["timeout"], 3)
        self.clock.now = 3
        with self.assertRaises(GitHubError):
            client.request("x")
        self.assertEqual(len(self.runner.calls), 1)


if __name__ == "__main__":
    unittest.main()
