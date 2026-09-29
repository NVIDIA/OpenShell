# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Focused checks for repeatable workflow label provisioning."""

import json
import tempfile
import unittest
from pathlib import Path

try:
    import workflow_labels
except ModuleNotFoundError:
    workflow_labels = None


class WorkflowLabelsTest(unittest.TestCase):
    def test_committed_manifest_is_valid(self):
        self.assertIsNotNone(workflow_labels, "workflow_labels.py is missing")
        manifest = (
            Path(__file__).resolve().parents[1] / ".agents" / "workflow-labels.json"
        )
        labels = workflow_labels.load_manifest(manifest)
        self.assertIn("state:new", {label["name"] for label in labels})
        self.assertFalse(any(label["name"].startswith("ready-for:") for label in labels))
        self.assertIn("status:stale", {label["name"] for label in labels})

    def test_manifest_rejects_duplicate_names(self):
        self.assertIsNotNone(workflow_labels, "workflow_labels.py is missing")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.json"
            path.write_text(
                json.dumps(
                    {
                        "labels": [
                            {
                                "name": "state:new",
                                "color": "ffffff",
                                "description": "New",
                            },
                            {
                                "name": "state:new",
                                "color": "ffffff",
                                "description": "Duplicate",
                            },
                        ]
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "duplicate.*state:new"):
                workflow_labels.load_manifest(path)

    def test_plan_only_changes_managed_definitions(self):
        self.assertIsNotNone(workflow_labels, "workflow_labels.py is missing")
        desired = [
            {"name": "state:new", "color": "d4f4dd", "description": "New submission"},
            {"name": "needs:plan", "color": "f2c97d", "description": "Needs a plan"},
        ]
        existing = [
            {"name": "state:new", "color": "ffffff", "description": "Old description"},
            {"name": "roadmap", "color": "123456", "description": "Unrelated"},
        ]

        changes = workflow_labels.plan_changes(desired, existing)

        self.assertEqual(
            changes,
            [
                {
                    "action": "update",
                    "name": "state:new",
                    "color": "d4f4dd",
                    "description": "New submission",
                },
                {
                    "action": "create",
                    "name": "needs:plan",
                    "color": "f2c97d",
                    "description": "Needs a plan",
                },
            ],
        )
        provisioned = [*existing[1:], *desired]
        self.assertEqual(workflow_labels.plan_changes(desired, provisioned), [])

    def test_apply_changes_only_edits_label_definitions(self):
        self.assertIsNotNone(workflow_labels, "workflow_labels.py is missing")
        calls = []

        def run(args):
            calls.append(args)

        workflow_labels.apply_changes(
            [
                {
                    "action": "create",
                    "name": "state:new",
                    "color": "d4f4dd",
                    "description": "New submission",
                },
                {
                    "action": "update",
                    "name": "needs:plan",
                    "color": "f2c97d",
                    "description": "Needs a plan",
                },
            ],
            "NVIDIA/OpenShell",
            run,
        )

        self.assertEqual(
            calls,
            [
                [
                    "gh",
                    "label",
                    "create",
                    "state:new",
                    "--repo",
                    "NVIDIA/OpenShell",
                    "--color",
                    "d4f4dd",
                    "--description",
                    "New submission",
                ],
                [
                    "gh",
                    "label",
                    "edit",
                    "needs:plan",
                    "--repo",
                    "NVIDIA/OpenShell",
                    "--color",
                    "f2c97d",
                    "--description",
                    "Needs a plan",
                ],
            ],
        )


if __name__ == "__main__":
    unittest.main()
