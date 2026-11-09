# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""False-positive controls for the collector-backed trace receipt check."""

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import run


def batch(service, operation, trace="1" * 32, **overrides):
    resource = {
        "service.name": service,
        "service.version": "test-version",
        "openshell.gateway.name": "test-gateway",
        "openshell.gateway.compute_driver": "kubernetes",
    }
    resource.update(overrides)
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": key, "value": {"stringValue": value}}
                        for key, value in resource.items()
                    ]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {"name": operation, "traceId": trace, "spanId": "2" * 16}
                        ]
                    }
                ],
            }
        ]
    }


def successful_batches():
    return [
        batch(run.GATEWAY_SERVICE, run.GATEWAY_CREATE),
        batch("openshell-driver-kubernetes", run.DRIVER_VALIDATE),
        batch("openshell-driver-kubernetes", run.DRIVER_CREATE, trace="3" * 32),
    ]


def logs(batches):
    return "\n".join(json.dumps(item) for item in batches)


class ReceiptTest(unittest.TestCase):
    @unittest.skipUnless(
        shutil.which("kubectl"),
        "kubectl is required for the local config-merge control",
    )
    def test_kubeconfig_single_file_and_file_list_select_the_same_context(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            cluster = {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [
                    {
                        "name": "review-cluster",
                        "cluster": {"server": "http://127.0.0.1:9"},
                    }
                ],
            }
            context = {
                "apiVersion": "v1",
                "kind": "Config",
                "contexts": [
                    {"name": "review-context", "context": {"cluster": "review-cluster"}}
                ],
                "current-context": "review-context",
            }
            single, first, second = (
                root / "single.json",
                root / "cluster.json",
                root / "context.json",
            )
            single.write_text(json.dumps(cluster | context))
            first.write_text(json.dumps(cluster))
            second.write_text(json.dumps(context))
            explicit = subprocess.run(
                [
                    "kubectl",
                    "--kubeconfig",
                    str(single),
                    "--context",
                    "review-context",
                    "config",
                    "view",
                    "--minify",
                    "-o",
                    "json",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            expected = json.loads(explicit.stdout)
            for config in [str(single), os.pathsep.join([str(first), str(second)])]:
                with (
                    self.subTest(kubeconfig=config),
                    mock.patch.dict(
                        os.environ,
                        {
                            "KUBECONFIG": config,
                            "OPENSHELL_E2E_KUBE_CONTEXT": "review-context",
                        },
                    ),
                ):
                    # config view is client-only; the fake API endpoint is never contacted.
                    result = subprocess.run(
                        [
                            *run.kubectl("fixture-only"),
                            "config",
                            "view",
                            "--minify",
                            "-o",
                            "json",
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(json.loads(result.stdout), expected)

    def test_gateway_and_driver_receipt_with_shared_validation_context(self):
        receipt = run.witnesses(logs(successful_batches()), "test-gateway")
        self.assertEqual(receipt["gateway"]["trace_id"], "1" * 32)
        self.assertEqual(receipt["driver_create"]["trace_id"], "3" * 32)

    def test_unrelated_collector_diagnostics_cannot_supply_spans(self):
        for value in ("", "collector ready", '{"level":"info","msg":"ready"}'):
            with self.subTest(log=value), self.assertRaisesRegex(ValueError, "missing"):
                run.witnesses(value, "test-gateway")

    def test_each_required_operation_must_arrive(self):
        batches = successful_batches()
        for index in range(3):
            with (
                self.subTest(missing=index),
                self.assertRaisesRegex(ValueError, "missing"),
            ):
                run.witnesses(
                    logs(batches[:index] + batches[index + 1 :]), "test-gateway"
                )

    def test_wrong_service_cannot_supply_driver_operation(self):
        batches = successful_batches()
        batches[1] = batch(run.GATEWAY_SERVICE, run.DRIVER_VALIDATE)
        with self.assertRaisesRegex(ValueError, "driver_validation"):
            run.witnesses(logs(batches), "test-gateway")

    def test_unrelated_or_misattributed_gateway_cannot_satisfy_probe(self):
        for key, value in [
            ("openshell.gateway.name", "previous-run"),
            ("openshell.gateway.compute_driver", "docker"),
            ("service.version", ""),
        ]:
            batches = successful_batches()
            batches[2] = batch(
                "openshell-driver-kubernetes", run.DRIVER_CREATE, **{key: value}
            )
            with (
                self.subTest(attribute=key),
                self.assertRaisesRegex(ValueError, "driver_create"),
            ):
                run.witnesses(logs(batches), "test-gateway")

    def test_ids_must_be_valid_and_nonzero(self):
        for key, value in [
            ("traceId", "0" * 32),
            ("traceId", "x" * 32),
            ("spanId", "0" * 16),
        ]:
            batches = successful_batches()
            batches[1]["resourceSpans"][0]["scopeSpans"][0]["spans"][0][key] = value
            with (
                self.subTest(field=key),
                self.assertRaisesRegex(ValueError, "driver_validation"),
            ):
                run.witnesses(logs(batches), "test-gateway")

    def test_failed_operations_cannot_satisfy_successful_probe(self):
        batches = successful_batches()
        batches[2]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["status"] = {
            "code": 2
        }
        with self.assertRaisesRegex(ValueError, "driver_create"):
            run.witnesses(logs(batches), "test-gateway")

    def test_broken_gateway_to_driver_propagation_is_rejected(self):
        batches = successful_batches()
        batches[1] = batch(
            "openshell-driver-kubernetes", run.DRIVER_VALIDATE, trace="4" * 32
        )
        with self.assertRaisesRegex(ValueError, "shared trace"):
            run.witnesses(logs(batches), "test-gateway")

    def test_duplicate_resource_key_is_rejected(self):
        batches = successful_batches()
        attrs = batches[1]["resourceSpans"][0]["resource"]["attributes"]
        attrs.append(copy.deepcopy(attrs[0]))
        with self.assertRaisesRegex(ValueError, "duplicate resource"):
            run.witnesses(logs(batches), "test-gateway")

    def test_missing_receipts_fail_at_deadline(self):
        with self.assertRaisesRegex(RuntimeError, "deadline exceeded.*missing"):
            run.wait_for_witnesses(lambda: "", "test-gateway", timeout=0)

    def test_persisted_receipt_is_rechecked_against_collector_data(self):
        with tempfile.TemporaryDirectory() as work:
            evidence = Path(work)
            collected = logs(successful_batches())
            (evidence / "collector.log").write_text(collected)
            receipt = run.witnesses(collected, "test-gateway")
            (evidence / "receipt.json").write_text(json.dumps(receipt))
            run.confirm_receipt(evidence, "test-gateway")

    def test_receipt_with_different_trace_is_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            evidence = Path(work)
            collected = logs(successful_batches())
            (evidence / "collector.log").write_text(collected)
            receipt = run.witnesses(collected, "test-gateway")
            receipt["gateway"]["trace_id"] = "f" * 32
            (evidence / "receipt.json").write_text(json.dumps(receipt))
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                run.confirm_receipt(evidence, "test-gateway")

    def test_harness_exit_zero_without_running_probe_cannot_pass(self):
        # Reproduces the macOS Bash failure: an EXIT trap can leave a zero
        # status although the gateway harness never reached the probe.
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            cli = root / "openshell"
            cli.write_text("unused test CLI")
            environment = {
                "OPENSHELL_BIN": str(cli),
                "OPENSHELL_E2E_KUBE_CONTEXT": "kind-disposable-test",
            }
            owned_namespace = {}

            def fake_run(command, **kwargs):
                if "create" in command and "-f" in command:
                    owned_namespace.update(json.loads(kwargs["input"]))
                text = (
                    json.dumps(owned_namespace)
                    if "get" in command and "namespace" in command
                    else ""
                )
                return subprocess.CompletedProcess(command, 0, text, "")

            with (
                mock.patch.object(run, "ROOT", root),
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(sys, "argv", ["run.py"]),
                mock.patch.object(
                    run,
                    "run",
                    side_effect=fake_run,
                ) as invoked,
                self.assertRaisesRegex(RuntimeError, "receipt"),
            ):
                run.main()
            self.assertTrue(
                any("delete" in call.args[0] for call in invoked.call_args_list),
                "collector cleanup must run when the receipt is absent",
            )


if __name__ == "__main__":
    unittest.main()
