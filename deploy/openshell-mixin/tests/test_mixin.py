# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exercise the public Jsonnet API, including late-bound consumer overrides."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import promql_parser

ROOT = Path(__file__).resolve().parents[1]


def evaluate(expression):
    return json.loads(
        subprocess.check_output(
            [os.environ.get("JSONNET", "jsonnet"), "-J", "vendor", "-e", expression],
            cwd=ROOT,
        )
    )


def objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


class MixinTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.default = evaluate('import "mixin.libsonnet"')
        cls.custom = evaluate('import "examples/custom.jsonnet"')
        cls.composed = evaluate('import "examples/composed.jsonnet"')

    def test_dashboard_defaults_and_composition(self):
        dashboards = self.composed["grafanaDashboards"]
        for name, dashboard in dashboards.items():
            expected_uid = (
                "operations"
                if "operational-logs" in name
                else name.removesuffix(".json")
            )
            self.assertEqual(dashboard["uid"], "team-" + expected_uid)
            self.assertEqual(dashboard["refresh"], "1m")
            self.assertEqual(dashboard["timezone"], "utc")
            self.assertIn("production", dashboard["tags"])
            self.assertEqual(dashboard["links"][0]["tags"], ["openshell", "production"])
        self.assertEqual(
            dashboards["openshell-ocsf-logs.json"]["tags"],
            ["openshell", "production", "ocsf"],
        )
        health = dashboards["openshell-operational-health.json"]
        self.assertEqual(health["title"], "Production OpenShell health")
        self.assertNotIn("traces", {v["name"] for v in health["templating"]["list"]})
        latency = next(p for p in health["panels"] if p["id"] == 2)
        self.assertEqual(
            latency["fieldConfig"]["defaults"]["thresholds"]["steps"][-1]["value"], 0.5
        )
        self.assertEqual(health["panels"][-1]["id"], 100)
        self.assertEqual(health["panels"][-1]["title"], "Runbook")

    def test_metric_matcher_validation(self):
        invalid = [
            {"metricsMatchers": []},
            {"metricsMatchers": 'job="gateway"'},
            {
                "metricsMatchers": [
                    {"name": "job", "operator": "==", "value": "gateway"}
                ]
            },
            {
                "metricsMatchers": [
                    {"name": "bad-label", "operator": "=", "value": "gateway"}
                ]
            },
            {"metricsMatchers": [{"name": "job", "operator": "=", "value": 42}]},
            {
                "metricsMatchers": [
                    {"name": "job", "operator": "=", "value": "gateway", "typo": True}
                ]
            },
        ]
        for override in invalid:
            with self.subTest(override=override):
                expression = (
                    '(import "queries.libsonnet").new((import "config.libsonnet")._config.openshell + '
                    + json.dumps(override)
                    + ").metricsSelector"
                )
                result = subprocess.run(
                    [os.environ.get("JSONNET", "jsonnet"), "-e", expression],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("RUNTIME ERROR", result.stderr)
        for field in (
            "metricsClusterLabel",
            "metricsInstanceLabel",
            "logsClusterLabel",
            "logsNamespaceLabel",
            "tracesClusterAttribute",
        ):
            expression = (
                '(import "queries.libsonnet").new((import "config.libsonnet")._config.openshell + '
                + json.dumps({field: "bad-name"})
                + ")."
                + field
            )
            result = subprocess.run(
                [os.environ.get("JSONNET", "jsonnet"), "-e", expression],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0, field)

    def test_promql_and_matcher_escaping(self):
        for mixin in (self.default, self.custom, self.composed):
            for dashboard in mixin["grafanaDashboards"].values():
                for obj in objects(dashboard):
                    if (
                        "expr" in obj
                        and obj.get("datasource", {}).get("type") == "prometheus"
                    ):
                        expression = obj["expr"].replace("$__rate_interval", "5m")
                        with self.subTest(expression=expression):
                            promql_parser.parse(expression)
        value = 'gateway"\\name\nnext'
        matchers = [{"name": "job", "operator": "=", "value": value}]
        selector = evaluate(
            '(import "queries.libsonnet").new((import "config.libsonnet")._config.openshell + { metricsMatchers: '
            + json.dumps(matchers)
            + " }).metricsSelector"
        )
        self.assertEqual(selector, "job=" + json.dumps(value))
        promql_parser.parse("up{" + selector + "}")

    def test_jb_vendor_consumer(self):
        # Install this exact working tree as a versioned Git subtree. Redirect
        # only the package's SSH remote to a local fixture; transitive packages
        # are resolved by jb from the committed dependency manifests/lockfile.
        with tempfile.TemporaryDirectory(prefix="openshell-mixin-consumer-") as tmp:
            tmp = Path(tmp)
            repository, consumer = tmp / "repository", tmp / "consumer"
            package = repository / "deploy" / "openshell-mixin"
            shutil.copytree(
                ROOT,
                package,
                ignore=shutil.ignore_patterns(
                    "vendor", "build", "__pycache__", ".tools"
                ),
            )
            consumer.mkdir()

            def git(*args):
                return subprocess.check_output(
                    ["git", *args], cwd=repository, text=True
                ).strip()

            git("init", "-q")
            git("config", "user.name", "OpenShell Mixin Tests")
            git("config", "user.email", "mixin-tests@example.invalid")
            git("add", ".")
            git(
                "commit",
                "-q",
                "--signoff",
                "-m",
                "test(monitoring): snapshot consumer fixture",
            )
            revision = git("rev-parse", "HEAD")
            env = os.environ.copy()
            env.pop("JSONNET_PATH", None)
            # Isolate this fixture from user/CI Git config and credentials.
            env.update(
                {
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": f"url.{repository.as_uri()}.insteadOf",
                    "GIT_CONFIG_VALUE_0": "ssh://git@github.com/NVIDIA/OpenShell.git",
                }
            )
            subprocess.run(
                ["jb", "init"], cwd=consumer, env=env, check=True, capture_output=True
            )
            subprocess.run(
                [
                    "jb",
                    "install",
                    "ssh://git@github.com/NVIDIA/OpenShell.git/deploy/openshell-mixin@"
                    + revision,
                ],
                cwd=consumer,
                env=env,
                check=True,
                capture_output=True,
            )
            vendor_import = (
                "github.com/NVIDIA/OpenShell/deploy/openshell-mixin/mixin.libsonnet"
            )
            expression = (
                '(import "'
                + vendor_import
                + '") + { _config+:: { openshell+: { uidPrefix: "vendor-", refresh: "2m" } } }'
            )
            result = subprocess.check_output(
                [
                    os.environ.get("JSONNET", "jsonnet"),
                    "-J",
                    "vendor",
                    "-e",
                    expression,
                ],
                cwd=consumer,
                env=env,
                text=True,
            )
            installed = json.loads(result)
            self.assertEqual(len(installed["grafanaDashboards"]), 3)
            for name, dashboard in installed["grafanaDashboards"].items():
                self.assertEqual(
                    dashboard["uid"], "vendor-" + name.removesuffix(".json")
                )
                self.assertEqual(dashboard["refresh"], "2m")
                self.assertEqual(
                    dashboard["panels"],
                    self.default["grafanaDashboards"][name]["panels"],
                )

    def test_standard_exports(self):
        self.assertEqual(
            set(self.default),
            {"grafanaDashboards", "prometheusAlerts", "prometheusRules"},
        )
        self.assertEqual(self.default["prometheusAlerts"], {"groups": []})
        self.assertEqual(self.default["prometheusRules"], {"groups": []})
        self.assertEqual(len(self.default["grafanaDashboards"]), 3)
        self.assertEqual(len(self.custom["grafanaDashboards"]), 3)

    def test_portability_and_identity(self):
        for result in (self.default, self.custom):
            encoded = json.dumps(result)
            for forbidden in (
                "__OS_",
                "${tenant",
                "openshell-tools",
                "openshell-density",
                "ag34rbum5xgqoe",
                "firecracker",
            ):
                self.assertNotIn(forbidden, encoded)
            for name, dashboard in result["grafanaDashboards"].items():
                self.assertEqual(dashboard["uid"], name.removesuffix(".json"))
                self.assertIsNone(dashboard["id"])
                variables = {v["name"] for v in dashboard["templating"]["list"]}
                for obj in objects(dashboard):
                    if obj.get("type") == "datasource" and "name" in obj:
                        self.assertNotIn("current", obj)
                        self.assertEqual(obj["hide"], 0)
                    if "datasource" in obj and isinstance(obj["datasource"], dict):
                        uid = obj["datasource"].get("uid", "")
                        if uid.startswith("${"):
                            self.assertIn(uid[2:-1], variables)

    def test_consumer_overrides(self):
        default = self.default["grafanaDashboards"]["openshell-operational-health.json"]
        custom = self.custom["grafanaDashboards"]["openshell-operational-health.json"]
        self.assertTrue(
            any(
                'job="openshell-gateway"' in obj.get("expr", "")
                for obj in objects(default["panels"])
            )
        )
        queries = [
            obj[k]
            for obj in objects(custom)
            for k in ("expr", "definition")
            if k in obj
        ]
        self.assertTrue(queries)
        for query in queries:
            self.assertIn('job=~"gateway|openshell-gateway"', query)
            self.assertNotIn('job="openshell-gateway"', query)
            self.assertNotIn("cluster=~", query.replace("kubernetes_cluster=~", ""))
        self.assertNotIn('"type": "tempo"', json.dumps(custom))
        self.assertNotIn("traces", {v["name"] for v in custom["templating"]["list"]})
        metrics = next(
            v for v in custom["templating"]["list"] if v["name"] == "metrics"
        )
        self.assertEqual(metrics["regex"], "^production-metrics$")

    def test_log_label_overrides_and_escaping(self):
        namespace = 'team"\\namespace.*'
        overrides = json.dumps(
            {
                "logsClusterLabel": "cluster_name",
                "logsNamespaceLabel": "namespace",
                "namespaceRegex": namespace,
            }
        )
        result = evaluate(
            '(import "mixin.libsonnet") + { _config+:: { openshell+: '
            + overrides
            + " } }"
        )
        dashboard = result["grafanaDashboards"]["openshell-ocsf-logs.json"]
        cluster = next(
            v for v in dashboard["templating"]["list"] if v["name"] == "cluster"
        )
        self.assertEqual(cluster["query"]["label"], "cluster_name")
        self.assertEqual(
            cluster["query"]["stream"],
            "{namespace=~" + json.dumps(namespace, separators=(",", ":")) + "}",
        )
        for obj in objects(dashboard["panels"]):
            if "expr" in obj:
                self.assertIn('cluster_name=~"${cluster:regex}"', obj["expr"])
                self.assertNotIn("k8s_namespace_name", obj["expr"])

    def test_shared_panel_references(self):
        for dashboard in (
            dashboard
            for mixin in (self.default, self.custom, self.composed)
            for dashboard in mixin["grafanaDashboards"].values()
        ):
            panels = [
                p for p in objects(dashboard["panels"]) if "id" in p and "type" in p
            ]
            ids = [p["id"] for p in panels]
            self.assertEqual(len(ids), len(set(ids)))
            for obj in objects(dashboard["panels"]):
                if "panelId" in obj:
                    self.assertIn(obj["panelId"], ids)


if __name__ == "__main__":
    unittest.main()
