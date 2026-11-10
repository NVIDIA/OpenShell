"""Offline dispatch and cross-host coordination regression tests."""

import subprocess
import unittest
from contextlib import contextmanager
from unittest.mock import Mock

from labeling_agent_events import Invocation
from labeling_dispatch import DispatchFailure, acceptance_written, dispatch
from labeling_item_lock import ItemBusy, item_lock

REPO = "NVIDIA/OpenShell"


class ReferenceStore:
    """A shared GitHub service; clients have no shared process lock."""

    def __init__(self):
        self.refs = {}
        self.commits = 0

    def __call__(self, path, *, method="GET", data=None):
        root = f"repos/{REPO}/git/"
        if path == root + "commits":
            self.commits += 1
            return {"sha": f"{self.commits:040x}"}
        if path == root + "refs" and method == "POST":
            ref = data["ref"]
            if ref in self.refs:
                raise subprocess.CalledProcessError(1, "gh", stderr="HTTP 422")
            self.refs[ref] = data["sha"]
            return {"object": {"sha": data["sha"]}}
        ref = "refs/" + path.removeprefix(root + ("ref/" if method == "GET" else "refs/"))
        if ref not in self.refs:
            raise subprocess.CalledProcessError(1, "gh", stderr="HTTP 404")
        if method == "DELETE":
            del self.refs[ref]
            return None
        return {"object": {"sha": self.refs[ref]}}


class LockTests(unittest.TestCase):
    def test_separate_clients_cannot_enter_same_item(self):
        service = ReferenceStore()
        with item_lock(REPO, 5412, "a" * 40, "tree", api=service):
            with self.assertRaises(ItemBusy):
                with item_lock(REPO, 5412, "a" * 40, "tree", api=service):
                    self.fail("second host entered")
            with item_lock(REPO, 5411, "a" * 40, "tree", api=service):
                pass
        self.assertEqual(service.refs, {})

    def test_failed_operation_retains_lock_for_reconciliation(self):
        service = ReferenceStore()
        with self.assertRaisesRegex(RuntimeError, "uncertain"):
            with item_lock(REPO, 5412, "a" * 40, "tree", api=service):
                raise RuntimeError("uncertain write")
        self.assertEqual(len(service.refs), 1)
        with self.assertRaises(ItemBusy):
            with item_lock(REPO, 5412, "a" * 40, "tree", api=service):
                self.fail("retained lock bypassed")

    def test_changed_ownership_is_never_deleted(self):
        service = ReferenceStore()
        with self.assertRaisesRegex(RuntimeError, "ownership"):
            with item_lock(REPO, 5412, "a" * 40, "tree", api=service):
                service.refs["refs/labeler-locks/5412"] = "other"
        self.assertEqual(service.refs["refs/labeler-locks/5412"], "other")

    def test_lookup_and_create_failures_propagate_without_retry(self):
        api = Mock(side_effect=RuntimeError("unavailable"))
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            with item_lock(REPO, 5412, "a" * 40, "tree", api=api):
                self.fail("failed acquisition entered")
        self.assertEqual(api.call_count, 1)


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.invocation = Invocation(REPO, 5412, False, "acceptance")
        self.order = []

        @contextmanager
        def lock():
            self.order.append("lock")
            yield
            self.order.append("unlock")

        self.lock = lock

    def run_dispatch(self, report, **options):
        def runner(invocation, *, apply):
            self.order.append(("runner", apply))
            return report

        def reviewers(repository, number):
            self.order.append("reviewers")

        return dispatch(self.invocation, runner=runner, lock=self.lock,
                        reviewers=reviewers, **options)

    def test_preview_default_never_changes_reviewers(self):
        self.run_dispatch({"status": "preview", "kind": "pull_request"})
        self.assertEqual(self.order, ["lock", ("runner", False), "unlock"])

    def test_apply_requires_request_and_deployment_gate(self):
        with self.assertRaisesRegex(ValueError, "application gate"):
            self.run_dispatch({"status": "applied"}, apply=True)
        self.assertEqual(self.order, [])

    def test_unchanged_checkpoint_retries_reviewer_handoff_under_lock(self):
        self.run_dispatch({"status": "unchanged", "kind": "pull_request"},
                          apply=True, application_enabled=True)
        self.assertEqual(self.order, ["lock", ("runner", True), "reviewers", "unlock"])

    def test_partial_or_unknown_results_fail_without_reviewer_mutation(self):
        for status in ["partial", "error", "stale", "held", "ready", "invented"]:
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                self.run_dispatch({"status": status, "kind": "pull_request"},
                                  apply=True, application_enabled=True)
        self.assertNotIn("reviewers", self.order)

    def test_failure_keeps_actionable_runner_report(self):
        report = {"status": "partial", "session_id": "recover-session",
                  "error": {"uncertain_write": True, "retry_at": "later"}}
        with self.assertRaises(DispatchFailure) as caught:
            self.run_dispatch(report)
        self.assertEqual(caught.exception.report, report)

    def test_completed_report_is_emitted_before_failed_reviewer_handoff(self):
        report = {"status": "applied", "kind": "pull_request", "session_id": "audit"}
        emitted = []
        with self.assertRaisesRegex(RuntimeError, "review failure"):
            dispatch(self.invocation, runner=lambda *a, **kw: report, lock=self.lock,
                     reviewers=Mock(side_effect=RuntimeError("review failure")),
                     apply=True, application_enabled=True, reporter=emitted.append)
        self.assertEqual(emitted, [report])

    def test_issue_and_ineligible_results_do_not_route_reviewers(self):
        for report in [{"status": "applied", "kind": "issue"},
                       {"status": "skipped", "kind": "pull_request"}]:
            self.run_dispatch(report, apply=True, application_enabled=True)
        self.assertNotIn("reviewers", self.order)

    def test_acceptance_hook_dispatches_default_branch_without_draft_filter(self):
        calls = []
        def api(path, *, method, data):
            calls.append((path, data))
        acceptance_written(REPO, 5412, "main", api=api)
        self.assertEqual(calls, [(f"repos/{REPO}/actions/workflows/labeling-dispatch.yml/dispatches",
                                 {"ref": "main", "inputs": {"item": "5412", "force": "false"}})])


if __name__ == "__main__":
    unittest.main()
