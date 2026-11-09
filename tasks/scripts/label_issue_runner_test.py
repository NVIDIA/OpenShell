# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline orchestration tests using the actual shared helper and fake services."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import label_issue_runner as runner
from label_issue_evidence_test import REPO
from label_issue_github import GitHubError
from label_issue_test import LiveAPI
from managed_label_classifier import AgentConfig

CONFIG = AgentConfig("agent_test", 1, "env_test")


class CMA:
    """Complete managed sessions whose results bind the actual prepared envelope."""

    def __init__(self, proposals=None):
        self.proposals = iter(proposals) if proposals is not None else None
        self.calls = []
        self.requests = []

    def request(self, method, path, payload, timeout):
        self.calls.append((method, path, payload, timeout))
        if path == "/sessions":
            self.requests.append(payload)
            evidence = json.loads(payload["initial_events"][0]["content"][0]["text"])
            manifest = evidence["manifest"]
            self.result = {
                key: manifest[key] for key in (
                    "schema_version", "repository", "number", "kind", "snapshot_id"
                )
            } | {
                "area": "area:platform", "topics": [], "ambiguity": None,
                "reasons": [{
                    "labels": ["area:platform"] + (
                        ["area:old"] if "area:old" in evidence["packets"][0].get("existing_labels", []) else []
                    ),
                    "evidence": ["body", "labels"],
                    "reason": "CLI behavior changes the platform component.",
                }],
            }
            if self.proposals is not None:
                value = next(self.proposals)
                if callable(value):
                    value = value(self.result)
                self.result = value
            return {"id": f"sesn_test{len(self.requests)}"}
        if path.endswith("/archive"):
            return {}
        return {"data": [
            {"id": "message", "type": "agent.message", "content": [
                {"type": "text", "text": json.dumps(self.result)}
            ]},
            {"id": "idle", "type": "session.status_idle",
             "stop_reason": {"type": "end_turn"}},
        ]}


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "run"
        self.api = LiveAPI()
        self.cma = CMA()

    def run_item(self, **options):
        defaults = {
            "api": self.api, "trusted_actors": {"maintainer"},
            "executor": "maintainer", "config": CONFIG, "transport": self.cma,
        }
        return runner.run(REPO, 3, self.directory, **(defaults | options))

    def test_preview_then_explicit_application_reuses_proposal_and_verifies_checkpoint(self):
        report = self.run_item()
        self.assertEqual(report["status"], "preview", report)
        self.assertEqual(self.api.writes, [])
        self.assertEqual(report["executions"][0]["session_id"], "sesn_test1")
        applied = self.run_item(apply_saved=True, config=None)
        self.assertEqual(applied["status"], "applied", applied)
        self.assertTrue(applied["checkpoint_verified"])
        self.assertEqual(len(self.cma.requests), 1)
        self.assertTrue((self.directory / "applied.json").exists())

    def test_unchanged_is_model_free_and_force_only_bypasses_unchanged(self):
        self.run_item()
        self.run_item(apply_saved=True)
        self.directory = Path(self.temp.name) / "unchanged"
        report = self.run_item(config=None, transport=None)
        self.assertEqual(report["status"], "unchanged", report)
        self.directory = Path(self.temp.name) / "forced"
        report = self.run_item(force=True)
        self.assertEqual(report["status"], "preview", report)
        self.assertEqual(len(self.cma.requests), 2)
        self.assertEqual(len(self.api.writes), 2)

    def test_deterministic_terminal_preparations_never_create_a_model_session(self):
        for status in ("unchanged", "skipped", "held", "error"):
            self.directory = Path(self.temp.name) / status
            with patch.object(runner.helper, "prepare", return_value={
                "status": status, "classifier_required": False,
            }), patch.object(runner, "ManagedAgents") as transport:
                report = self.run_item(config=None, transport=None, force=True)
            self.assertEqual(report["status"], status)
            transport.assert_not_called()
        self.assertEqual(self.api.writes, [])

    def test_real_ineligible_preparation_is_model_free(self):
        self.api.item.update(state="closed", state_reason="completed")
        report = self.run_item(force=True, config=None)
        self.assertIn(report["status"], {"skipped", "held"})
        self.assertEqual(self.cma.requests, [])

    def test_lookup_failure_remains_error(self):
        def failing_api(*args, **kwargs):
            raise GitHubError("permission unavailable", status=503, retryable=True)
        report = self.run_item(api=failing_api)
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["error"]["status"], 503)
        self.assertEqual(self.cma.requests, [])

    def test_request_preview_uses_trusted_files_without_transport_or_key(self):
        with patch.object(runner, "ManagedAgents") as transport:
            report = self.run_item(request_preview=True, transport=None)
        transport.assert_not_called()
        self.assertEqual(report["status"], "ready", report)
        request = runner.read(self.directory / "request.json")
        self.assertIn("Choose the desired set", request["agent"]["system"])
        self.assertIn("schema_version", request["agent"]["system"])
        self.assertEqual(request["agent"]["tools"], [])
        self.assertEqual(request["budget"]["max_list_cost"]["amount"], "6")
        self.assertEqual(self.api.writes, [])

    def test_evidence_expansion_preserves_packets_and_uses_helper(self):
        self.cma = CMA([{"expand_evidence": ["comments"]}, lambda result: result])
        with patch.object(runner, "expand_evidence", wraps=runner.expand_evidence) as expand:
            report = self.run_item()
        self.assertEqual(report["status"], "preview", report)
        expand.assert_called_once()
        second = json.loads(self.cma.requests[1]["initial_events"][0]["content"][0]["text"])
        self.assertEqual(len(second["packets"]), 2)
        self.assertIn("content", second["packets"][1]["evidence_index"]["comments"])
        self.assertEqual(len(report["executions"]), 2)

    def test_unknown_evidence_is_error_and_never_applies(self):
        self.cma = CMA([{"expand_evidence": ["invented"]}])
        report = self.run_item()
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["stage"], "expand")
        self.assertEqual(len(report["executions"]), 1)
        self.assertEqual(self.api.writes, [])

    def test_expansion_failure_does_not_claim_complete_evidence(self):
        self.cma = CMA([{"expand_evidence": ["comments"]}])
        with patch.object(runner, "expand_evidence", side_effect=GitHubError(
            "evidence fetch timed out", status=503, retry_at="later", retryable=True
        )):
            report = self.run_item()
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["error"]["retry_at"], "later")
        self.assertEqual(len(self.cma.requests), 1)

    def test_deferred_requested_content_stops_with_prerequisite(self):
        self.cma = CMA([{"expand_evidence": ["comments"]}])
        def deferred(snapshot, ids, *, api):
            packet = runner.read(snapshot["packet_path"])
            packet["evidence_index"]["comments"].pop("content", None)
            runner.write(snapshot["packet_path"], packet)
        with patch.object(runner, "expand_evidence", side_effect=deferred):
            report = self.run_item()
        self.assertEqual(report["status"], "prerequisite", report)
        self.assertEqual(len(self.cma.requests), 1)
        self.assertEqual(self.api.writes, [])

    def test_expansion_round_limit_does_not_validate_or_write(self):
        self.cma = CMA([{"expand_evidence": ["comments"]}])
        report = self.run_item(max_rounds=1)
        self.assertEqual(report["status"], "held")
        self.assertEqual(self.api.writes, [])

    def test_repeated_expansion_stops_without_looping(self):
        self.cma = CMA([{"expand_evidence": ["comments"]}] * 3)
        report = self.run_item()
        self.assertEqual(report["status"], "error")
        self.assertIn("Repeated", report["error"]["message"])
        self.assertEqual(len(self.cma.requests), 2)

    def test_invalid_proposal_uses_shared_validator(self):
        self.cma = CMA([lambda result: result | {"area": "invented"}])
        report = self.run_item()
        self.assertEqual(report["status"], "held", report)
        self.assertEqual(self.api.writes, [])

    def test_missing_canonical_prerequisite_is_preserved(self):
        self.api.definitions = [
            value for value in self.api.definitions if value["name"] != "area:platform"
        ]
        report = self.run_item()
        self.assertEqual(report["status"], "prerequisite", report)
        self.assertTrue(report["missing_prerequisites"])
        self.assertEqual(self.api.writes, [])

    def test_stale_content_after_preview_blocks_apply_without_model_replay(self):
        self.run_item()
        self.api.item["body"] = "Changed requested outcome"
        report = self.run_item(apply_saved=True)
        self.assertEqual(report["status"], "stale", report)
        self.assertEqual(self.api.writes, [])
        self.assertEqual(len(self.cma.requests), 1)

    def test_changed_exact_preview_blocks_apply(self):
        self.run_item()
        expected = runner.read(self.directory / "preview.json")
        expected["ordered_writes"] = []
        runner.write(self.directory / "preview.json", expected)
        report = self.run_item(apply_saved=True)
        self.assertEqual(report["status"], "stale", report)
        self.assertEqual(self.api.writes, [])

    def test_partial_uncertain_write_is_preserved_and_not_replayed(self):
        self.run_item()
        self.api.fail_write = True
        report = self.run_item(apply_saved=True)
        self.assertEqual(report["status"], "partial", report)
        self.assertTrue(report["error"]["uncertain_write"])
        self.assertFalse(report["checkpoint_verified"])
        writes = len(self.api.writes)
        retried = self.run_item(apply_saved=True)
        self.assertEqual(retried["status"], "stale", retried)
        self.assertEqual(len(self.api.writes), writes)
        self.assertEqual(len(self.cma.requests), 1)

    def test_session_reference_persisted_before_poll_failure(self):
        original = self.cma.request
        def request(method, path, payload, timeout):
            if method == "GET":
                raise RuntimeError("poll unavailable")
            return original(method, path, payload, timeout)
        self.cma.request = request
        report = self.run_item()
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["executions"][0]["session_id"], "sesn_test1")
        self.assertIn("session archived", report["error"]["message"])
        self.assertEqual(runner.read(self.directory / "executions.json")[0]["session_id"], "sesn_test1")
        self.assertEqual(self.api.writes, [])

    def test_report_save_failure_preserves_post_write_outcome(self):
        self.run_item()
        original = runner.write
        def fail_applied(path, value):
            if Path(path).name == "applied.json":
                raise OSError("report storage unavailable")
            return original(path, value)
        with patch.object(runner, "write", side_effect=fail_applied):
            report = self.run_item(apply_saved=True)
        self.assertEqual(report["status"], "partial", report)
        self.assertEqual(report["stage"], "apply")
        self.assertIn("storage unavailable", report["error"]["message"])
        self.assertEqual(len(self.api.writes), 2)
        self.assertEqual(len(self.cma.requests), 1)

    def test_cannot_overwrite_artifacts_or_apply_another_item(self):
        self.run_item()
        report = self.run_item()
        self.assertEqual(report["status"], "error")
        report = runner.run(REPO, 4, self.directory, api=self.api,
                            trusted_actors={"maintainer"}, apply_saved=True)
        self.assertEqual(report["status"], "error")
        self.assertEqual(self.api.writes, [])

    def test_input_budget_stops_before_model_call(self):
        with patch.object(runner, "MAX_INPUT_BYTES", 1):
            report = self.run_item()
        self.assertEqual(report["status"], "error")
        self.assertEqual(self.cma.requests, [])

    def test_cli_resolves_url_and_reports_shared_summary(self):
        args = [
            f"https://github.com/{REPO}/issues/3", "--repo", REPO,
            "--output", str(self.directory), "--trusted-actor", "maintainer",
            "--human",
        ]
        with (
            patch.object(runner, "run", return_value={
                "status": "unchanged", "add": [], "remove": [], "preserve": [],
                "diagnostics": [], "ambiguity": None,
            }) as run,
            patch("sys.stdout", new_callable=io.StringIO) as output,
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            self.assertEqual(runner.main(args, api=self.api), 0)
        self.assertEqual(run.call_args.args[:2], (REPO, 3))
        self.assertEqual(json.loads(output.getvalue())["status"], "unchanged")


    def test_substantive_child_expansion_delivers_content_and_retains_coverage(self):
        self.api.collections["comments"] = [{
            "id": 7, "body": "The failure affects the installed CLI.",
            "user": {"login": "maintainer", "type": "User"},
            "created_at": "2026-11-07T00:00:00Z",
        }]
        self.cma = CMA([{"expand_evidence": ["comment:7"]}, lambda result: result])
        report = self.run_item()
        self.assertEqual(report["status"], "preview", report)
        payload = json.loads(self.cma.requests[1]["initial_events"][0]["content"][0]["text"])
        entry = payload["packets"][-1]["evidence_index"]["comment:7"]
        self.assertEqual(entry["content"]["body"], self.api.collections["comments"][0]["body"])
        self.assertEqual(entry["coverage"], "complete")
        self.assertTrue(entry["inspected"])

    def test_current_author_permission_is_rechecked_before_application(self):
        self.api.labels.remove("state:accepted")
        self.api.item["user"] = {"login": "writer"}
        report = self.run_item()
        self.assertEqual(report["status"], "preview", report)
        self.api.permissions["writer"] = "read"
        report = self.run_item(apply_saved=True)
        self.assertIn(report["status"], {"held", "stale", "skipped"}, report)
        self.assertEqual(self.api.writes, [])

    def test_uncertain_session_creation_is_not_retried_or_classified_as_label_success(self):
        from managed_label_classifier import ClassifierError
        with patch.object(self.cma, "request", side_effect=ClassifierError(
            "Session creation response unavailable", uncertain_write=True
        )) as request:
            report = self.run_item()
        request.assert_called_once()
        self.assertEqual(report["status"], "error")
        self.assertTrue(report["error"]["uncertain_write"])
        self.assertEqual(report["executions"], [])
        self.assertEqual(self.api.writes, [])

    def test_classification_deadline_spans_expansion_rounds(self):
        self.cma = CMA([{"expand_evidence": ["comments"]}])
        ticks = iter([0, 1, 181])
        report = self.run_item(clock=lambda: next(ticks))
        self.assertEqual(report["status"], "error")
        self.assertIn("deadline", report["error"]["message"])
        self.assertEqual(len(self.cma.requests), 1)

    def test_timeout_and_budget_validation(self):
        for options in (
            {"timeout": float("nan")}, {"max_rounds": 0},
            {"config": AgentConfig("agent_test", 1, "env_test", 1)},
            {"apply_saved": True, "force": True},
        ):
            with self.subTest(options=options):
                report = self.run_item(**options)
                self.assertEqual(report["status"], "error")
        self.assertEqual(self.cma.requests, [])


if __name__ == "__main__":
    unittest.main()
