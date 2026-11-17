#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Exercise the chart's public migration contract across complete rendered resources."""

import copy
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import yaml

CHART = Path(__file__).parent / "openshell"


def render(values, chart=CHART, *, notes=False, succeeds=True):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "values.yaml"
        path.write_text(yaml.safe_dump(values))
        command = [
            "helm",
            "template",
            "migration",
            str(chart),
            "-n",
            "migration",
            "--set",
            "agentSandbox.preflight.enabled=false",
            "-f",
            str(path),
        ]
        if notes:
            command += ["--render-subchart-notes"]
        result = subprocess.run(command, capture_output=True, text=True)
        if succeeds and result.returncode:
            raise AssertionError(result.stderr)
        if not succeeds:
            if not result.returncode:
                raise AssertionError("expected rendering to fail")
            return result.stderr
        return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def resource(docs, kind, suffix=""):
    return next(
        d for d in docs if d["kind"] == kind and d["metadata"]["name"].endswith(suffix)
    )


def config(docs):
    return tomllib.loads(resource(docs, "ConfigMap", "-config")["data"]["gateway.toml"])


def comparable(docs):
    docs = copy.deepcopy(docs)
    for doc in docs:
        # Helm intentionally generates bootstrap keys when lookup has no live cluster.
        if doc["kind"] == "Secret":
            doc.pop("data", None)
            doc.pop("stringData", None)
    return sorted(docs, key=lambda d: (d["kind"], d["metadata"]["name"]))


class ComponentValues(unittest.TestCase):
    def test_explicit_false_zero_and_empty_string_override_legacy_values(self):
        docs = render(
            {
                "priorityClassName": "legacy-priority",
                "podLifecycle": {"terminationGracePeriodSeconds": 45},
                "server": {"tls": {"enableMtls": True}},
                "gateway": {
                    "priorityClassName": "",
                    "podLifecycle": {"terminationGracePeriodSeconds": 0},
                    "tls": {"enableMtls": False},
                },
            }
        )
        pod = resource(docs, "StatefulSet")["spec"]["template"]["spec"]
        self.assertNotIn("priorityClassName", pod)
        self.assertEqual(pod["terminationGracePeriodSeconds"], 0)
        self.assertNotIn("client_ca_path", config(docs)["openshell"]["gateway"]["tls"])

    def test_install_notes_explain_legacy_paths_without_exposing_values(self):
        result = subprocess.run(
            [
                "helm",
                "install",
                "migration",
                str(CHART),
                "--dry-run=client",
                "--set",
                "agentSandbox.preflight.enabled=false",
                "--set",
                "nodeSelector.pool=legacy-pool",
                "--set",
                "gateway.nodeSelector.pool=canonical-pool",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        notes = result.stdout.split("NOTES:", 1)[1]
        self.assertIn("nodeSelector -> gateway.nodeSelector", notes)
        self.assertIn("0.2.0", notes)
        self.assertIn("canonical values take precedence", notes)
        self.assertNotIn("legacy-pool", notes)

    def test_equivalent_legacy_and_component_overrides(self):
        for kind in ["statefulset", "deployment"]:
            with self.subTest(kind=kind):
                legacy = {
                    "workload": {"kind": kind},
                    "nodeSelector": {"pool": "gateway"},
                    "resources": {"requests": {"cpu": "300m", "memory": "256Mi"}},
                    "serviceAccount": {"create": False, "name": "gateway-existing"},
                    "sandboxServiceAccount": {
                        "create": False,
                        "name": "sandbox-existing",
                    },
                    "sandboxRuntime": {
                        "image": {"repository": "custom/runtime", "tag": "v1"}
                    },
                    "networkPolicy": {"enabled": False},
                    "server": {
                        "externalDbSecret": "database",
                        "dataStorageClass": "fast",
                        "sandboxNamespace": "workspaces",
                        "extraEnv": [{"name": "CUSTOM", "value": "true"}],
                    },
                }
                canonical = {
                    "gateway": {
                        k: legacy[k]
                        for k in [
                            "workload",
                            "nodeSelector",
                            "resources",
                            "serviceAccount",
                        ]
                    },
                    "sandbox": {
                        "serviceAccount": legacy["sandboxServiceAccount"],
                        "runtime": legacy["sandboxRuntime"],
                        "networkPolicy": legacy["networkPolicy"],
                        "namespace": "workspaces",
                    },
                }
                canonical["gateway"].update(
                    {
                        k: v
                        for k, v in legacy["server"].items()
                        if k != "sandboxNamespace"
                    }
                )
                self.assertEqual(
                    comparable(render(legacy)), comparable(render(canonical))
                )

    def test_incremental_migration_and_explicit_empty_values(self):
        docs = render(
            {
                "nodeSelector": {"old": "pool"},
                "tolerations": [{"operator": "Exists"}],
                "resources": {"requests": {"cpu": "200m", "memory": "256Mi"}},
                "server": {"telemetryEnabled": True},
                "gateway": {
                    "nodeSelector": {},
                    "tolerations": [],
                    "telemetryEnabled": False,
                    "resources": {"requests": {"cpu": "400m"}},
                },
            }
        )
        pod = resource(docs, "StatefulSet")["spec"]["template"]["spec"]
        self.assertNotIn("nodeSelector", pod)
        self.assertNotIn("tolerations", pod)
        container = pod["containers"][0]
        self.assertEqual(
            container["resources"]["requests"], {"cpu": "400m", "memory": "256Mi"}
        )
        self.assertEqual(
            next(
                e["value"]
                for e in container["env"]
                if e["name"] == "OPENSHELL_TELEMETRY_ENABLED"
            ),
            "false",
        )

    def test_components_schedule_and_identify_independently(self):
        values = {
            "gatewayConfig": {
                "openshell.drivers.kubernetes": {"supervisor_topology": "gateway"}
            }
        }
        for component in ["gateway", "supervisor"]:
            values[component] = {
                "nodeSelector": {"pool": component},
                "tolerations": [
                    {
                        "key": "pool",
                        "operator": "Equal",
                        "value": component,
                        "effect": "NoSchedule",
                    }
                ],
                "schedulerName": component + "-scheduler",
                "priorityClassName": component + "-priority",
                "topologySpreadConstraints": [
                    {
                        "maxSkew": 1,
                        "topologyKey": "zone",
                        "whenUnsatisfiable": "ScheduleAnyway",
                    }
                ],
                "resources": {
                    "requests": {"cpu": "200m", "memory": "256Mi"},
                    "limits": {"memory": "1Gi"},
                },
                "podLabels": {"custom": component},
                "podAnnotations": {"custom": component},
                "podLifecycle": {"terminationGracePeriodSeconds": 75},
                "serviceAccount": {
                    "create": True,
                    "name": component + "-account",
                    "labels": {"custom": component},
                    "annotations": {"identity": component},
                    "automountServiceAccountToken": False,
                },
            }
        values["sandbox"] = {
            "serviceAccount": {"create": False, "name": "workload-account"}
        }
        docs = render(values)
        for component, kind in [
            ("gateway", "StatefulSet"),
            ("supervisor", "Deployment"),
        ]:
            pod_template = resource(docs, kind)["spec"]["template"]
            pod = pod_template["spec"]
            self.assertEqual(pod["nodeSelector"], {"pool": component})
            self.assertEqual(pod["tolerations"], values[component]["tolerations"])
            self.assertEqual(pod["schedulerName"], component + "-scheduler")
            self.assertEqual(pod["priorityClassName"], component + "-priority")
            self.assertEqual(
                pod["topologySpreadConstraints"],
                values[component]["topologySpreadConstraints"],
            )
            self.assertEqual(pod["terminationGracePeriodSeconds"], 75)
            self.assertEqual(
                pod["containers"][0]["resources"], values[component]["resources"]
            )
            self.assertEqual(pod["serviceAccountName"], component + "-account")
            self.assertFalse(pod["automountServiceAccountToken"])
            self.assertEqual(pod_template["metadata"]["labels"]["custom"], component)
            account = resource(docs, "ServiceAccount", component + "-account")
            self.assertEqual(account["metadata"]["annotations"]["identity"], component)
            self.assertEqual(account["metadata"]["labels"]["custom"], component)
        subjects = [
            s["name"]
            for d in docs
            if d["kind"] in ["RoleBinding", "ClusterRoleBinding"]
            for s in d["subjects"]
        ]
        self.assertIn("gateway-account", subjects)
        self.assertNotIn("supervisor-account", subjects)
        self.assertEqual(
            config(docs)["openshell"]["drivers"]["kubernetes"]["service_account_name"],
            "workload-account",
        )

    def test_component_image_pull_secrets_override_global(self):
        docs = render(
            {
                "imagePullSecrets": [{"name": "global"}],
                "gateway": {"imagePullSecrets": []},
                "supervisor": {"imagePullSecrets": [{"name": "supervisor-only"}]},
                "gatewayConfig": {
                    "openshell.drivers.kubernetes": {"supervisor_topology": "gateway"}
                },
            }
        )
        self.assertNotIn(
            "imagePullSecrets",
            resource(docs, "StatefulSet")["spec"]["template"]["spec"],
        )
        self.assertEqual(
            resource(docs, "Deployment")["spec"]["template"]["spec"][
                "imagePullSecrets"
            ],
            [{"name": "supervisor-only"}],
        )

    def test_runtime_configuration_controls_chart_dependencies(self):
        docs = render(
            {
                "server": {
                    "hostGatewayIP": "192.0.2.1",
                    "grpcEndpoint": "https://old.invalid:8080",
                },
                "gatewayConfig": {
                    "openshell.drivers.kubernetes": {
                        "host_gateway_ip": "192.0.2.2",
                        "grpc_endpoint": "https://new.invalid:8080",
                    }
                },
            }
        )
        self.assertEqual(
            resource(docs, "StatefulSet")["spec"]["template"]["spec"]["hostAliases"][0][
                "ip"
            ],
            "192.0.2.2",
        )
        self.assertEqual(
            config(docs)["openshell"]["drivers"]["kubernetes"]["grpc_endpoint"],
            "https://new.invalid:8080",
        )

    def test_existing_supervisor_identity_and_sandbox_boundary_preserved(self):
        docs = render(
            {
                "supervisor": {"serviceAccount": {"name": "existing-supervisor"}},
                "gatewayConfig": {
                    "openshell.drivers.kubernetes": {"supervisor_topology": "gateway"}
                },
            }
        )
        pod = resource(docs, "Deployment")["spec"]["template"]["spec"]
        self.assertEqual(pod["serviceAccountName"], "existing-supervisor")
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertNotIn(
            "existing-supervisor",
            [d["metadata"]["name"] for d in docs if d["kind"] == "ServiceAccount"],
        )
        self.assertIn(
            "must remain false",
            render(
                {"sandbox": {"serviceAccount": {"automountServiceAccountToken": True}}},
                succeeds=False,
            ),
        )

    def test_removal_boundary_and_retained_top_level_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            chart = Path(directory) / "chart"
            shutil.copytree(CHART, chart)
            metadata = yaml.safe_load((chart / "Chart.yaml").read_text())
            metadata["version"] = "0.2.0"
            (chart / "Chart.yaml").write_text(yaml.safe_dump(metadata))
            for values, replacement in [
                ({"nodeSelector": {}}, "gateway.nodeSelector"),
                ({"server": {"logLevel": "debug"}}, "gatewayConfig"),
                ({"sandboxRuntime": {}}, "sandbox.runtime"),
            ]:
                with self.subTest(values=values):
                    error = render(values, chart, succeeds=False)
                    self.assertIn("removed in chart 0.2.0", error)
                    self.assertIn(replacement, error)
            render(
                {
                    "gateway": {"nodeSelector": {"pool": "gateway"}},
                    "pkiInitJob": {"enabled": False},
                    "certManager": {"enabled": False},
                    "grpcRoute": {"enabled": False},
                    "openshiftRoute": {"enabled": False},
                    "gatewayConfig": {"openshell.gateway": {"log_level": "debug"}},
                },
                chart,
            )


if __name__ == "__main__":
    unittest.main()
