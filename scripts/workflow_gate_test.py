# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Queued work must have the human-authorized workflow tuple."""

import unittest

import workflow_gate


class WorkflowGateTest(unittest.TestCase):
    def test_intake_eligibility_does_not_authorize_build_work(self):
        labels = {"state:new"}
        self.assertFalse(workflow_gate.assess(labels, "plan").allowed)
        self.assertFalse(
            workflow_gate.assess(labels, "implement", has_plan=True).allowed
        )

    def test_plan_queue_requires_acceptance_and_need(self):
        labels = {"state:accepted", "needs:plan"}
        self.assertTrue(workflow_gate.assess(labels, "plan").allowed)
        self.assertFalse(
            workflow_gate.assess(labels, "implement", has_plan=True).allowed
        )
        self.assertFalse(
            workflow_gate.assess(labels - {"needs:plan"}, "plan").allowed
        )
        self.assertFalse(
            workflow_gate.assess(
                {"roadmap", "needs:plan"}, "plan"
            ).allowed
        )

    def test_roadmap_label_can_record_acceptance(self):
        labels = {"roadmap", "state:accepted", "needs:plan"}
        self.assertTrue(workflow_gate.assess(labels, "plan").allowed)

    def test_review_state_does_not_queue_an_agent(self):
        for phase, need in (("plan", "needs:plan"), ("implement", "needs:pr")):
            with self.subTest(phase=phase):
                labels = {"state:in-review", need}
                self.assertFalse(workflow_gate.assess(labels, phase, has_plan=True).allowed)

    def test_implementation_requires_approved_plan_and_tuple(self):
        labels = {"state:in-progress", "needs:pr"}
        self.assertFalse(workflow_gate.assess(labels, "implement").allowed)
        self.assertTrue(
            workflow_gate.assess(labels, "implement", has_plan=True).allowed
        )
        self.assertFalse(
            workflow_gate.assess(
                labels | {"needs:plan"}, "implement", has_plan=True
            ).allowed
        )

    def test_direct_request_reports_discrepancies_but_proceeds(self):
        result = workflow_gate.assess({"state:validated"}, "implement", direct=True)
        self.assertTrue(result.allowed)
        self.assertIn("needs:pr", " ".join(result.problems))

    def test_security_never_enters_general_build_skill(self):
        labels = {"topic:security", "state:accepted", "needs:pr"}
        self.assertFalse(
            workflow_gate.assess(
                labels, "implement", has_plan=True, direct=True
            ).allowed
        )

    def test_specialized_review_does_not_authorize_remediation(self):
        labels = {"topic:security", "state:validated", "needs:plan"}
        self.assertTrue(workflow_gate.assess(labels, "plan", specialized=True).allowed)
        self.assertFalse(
            workflow_gate.assess(
                labels, "implement", has_plan=True, specialized=True
            ).allowed
        )

    def test_specialized_remediation_needs_human_approval_and_review(self):
        labels = {"topic:security", "state:accepted", "needs:pr"}
        self.assertFalse(
            workflow_gate.assess(labels, "implement", specialized=True).allowed
        )
        self.assertTrue(
            workflow_gate.assess(
                labels, "implement", has_plan=True, specialized=True
            ).allowed
        )
        self.assertFalse(
            workflow_gate.assess(
                {"topic:security"}, "implement", specialized=True, direct=True
            ).allowed
        )


if __name__ == "__main__":
    unittest.main()
