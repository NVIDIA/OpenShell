# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Definition preparation never changes issue/PR associations."""

import copy
import json
import subprocess
import unittest
from unittest import mock

import prepare_label_taxonomy as prep

TABLE = "| Name | GitHub ID | Company/Organization |\n| --- | --- | --- |\n"
ROSTER = "### area:runtime\n\n" + TABLE
ACTIVE = {
    "name": "area:runtime",
    "description": "Runtime execution.",
    "color": "6699cc",
}
RETIRE = {
    "name": "area:sandbox",
    "new_name": "retired:area:sandbox",
    "description": "Retired; do not apply.",
    "color": "ededed",
}
CATALOG = {"schema_version": 1, "active": [ACTIVE], "retire": [RETIRE]}


class PreparationTests(unittest.TestCase):
    def test_preserves_original_definitions_ids_and_unrelated_labels(self):
        original = [
            {
                "id": 1,
                "name": "area:sandbox",
                "description": "Old scope",
                "color": "000000",
            },
            {"id": 2, "name": "state:accepted", "description": None, "color": "009966"},
        ]
        backup = copy.deepcopy(original)
        plan = prep.plan_definitions(CATALOG, ROSTER, original)
        self.assertEqual(original, backup)
        self.assertEqual(plan["original_labels"], backup)
        self.assertEqual(
            [o["action"] for o in plan["operations"]], ["create", "retire"]
        )
        self.assertEqual(plan["operations"][1]["before"]["id"], 1)
        self.assertFalse(plan["applied"])
        self.assertFalse(plan["item_assignments_changed"])
        self.assertEqual(plan["missing_descriptions"], ["state:accepted"])

    def test_idempotent_after_creation_and_identity_preserving_rename(self):
        retired = {
            "name": RETIRE["new_name"],
            "description": RETIRE["description"],
            "color": RETIRE["color"],
            "id": 1,
        }
        self.assertEqual(
            prep.plan_definitions(CATALOG, ROSTER, [ACTIVE, retired])["operations"], []
        )

    def test_rejects_target_collision_unreviewed_labels_and_roster_drift(self):
        for current, roster in (
            ([{"name": "area:sandbox"}, {"name": "retired:area:sandbox"}], ROSTER),
            ([{"name": "area:surprise"}], ROSTER),
            ([], ROSTER + "\n### topic:unreviewed\n\n" + TABLE),
            ([{**ACTIVE, "archived_at": "2026-11-01"}], ROSTER),
        ):
            with self.subTest(current=current), self.assertRaises(ValueError):
                prep.plan_definitions(CATALOG, roster, current)

    def test_fetches_every_page_using_only_get(self):
        response = subprocess.CompletedProcess(
            [], 0, json.dumps([[ACTIVE], [{"name": "other"}]])
        )
        with mock.patch.object(prep.subprocess, "run", return_value=response) as run:
            self.assertEqual(len(prep.fetch_labels("owner/repo")), 2)
        command = run.call_args.args[0]
        self.assertIn("--paginate", command)
        self.assertIn("--slurp", command)
        self.assertEqual(command[command.index("--method") + 1], "GET")
        self.assertEqual(command[-1], "repos/owner/repo/labels?per_page=100")

    def test_repository_catalog_matches_real_roster_and_routes_all_languages(self):
        catalog = json.loads((prep.ROOT / "tasks/labels/taxonomy.json").read_text())
        roster = (prep.ROOT / "REVIEWERS.md").read_text()
        plan = prep.plan_definitions(catalog, roster, [])
        self.assertEqual(len(plan["operations"]), 29)
        self.assertEqual(len(catalog["retire"]), 18)
        categories = prep.parse_reviewers(roster)
        from check_review_readiness import select_reviewers

        broad = select_reviewers(categories, {"area:platform", "topic:sdk"})
        for language in ("go", "python", "rust", "typescript"):
            self.assertEqual(
                select_reviewers(
                    categories, {"area:platform", "topic:sdk", f"topic:sdk:{language}"}
                ),
                broad,
            )


if __name__ == "__main__":
    unittest.main()
