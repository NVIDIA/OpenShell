# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Issue-opened workflow behavior, including retry and maintainer routing."""

import unittest

import issue_intake


class FakeGitHub:
    def __init__(self, permission, labels=()):
        self.permission = permission
        self.labels = list(labels)
        self.added = []

    def get_permission(self, _login):
        return self.permission

    def get_labels(self, _number):
        return self.labels

    def add_labels(self, _number, labels):
        self.added.append(labels)
        self.labels.extend(labels)


class IssueIntakeTest(unittest.TestCase):
    def test_external_author_gets_screening_labels(self):
        api = FakeGitHub("read")
        issue_intake.apply_intake(api, 42, "contributor")
        self.assertEqual(api.added, [["state:new"]])

    def test_maintainer_enters_accepted_path(self):
        for permission in ("write", "maintain", "admin"):
            with self.subTest(permission=permission):
                api = FakeGitHub(permission)
                issue_intake.apply_intake(api, 42, "maintainer")
                self.assertEqual(api.added, [["state:accepted"]])

    def test_unknown_collaborator_is_external(self):
        api = FakeGitHub(None)
        issue_intake.apply_intake(api, 42, "newcomer")
        self.assertEqual(api.added, [["state:new"]])

    def test_retry_does_not_add_duplicate_labels(self):
        api = FakeGitHub("read")
        issue_intake.apply_intake(api, 42, "contributor")
        issue_intake.apply_intake(api, 42, "contributor")
        self.assertEqual(len(api.added), 1)

    def test_existing_state_and_type_are_preserved(self):
        api = FakeGitHub("read", ["state:validated", "type:bug"])
        issue_intake.apply_intake(api, 42, "contributor")
        self.assertEqual(api.added, [])

    def test_existing_state_needs_no_additional_label(self):
        api = FakeGitHub("read", ["state:new"])
        issue_intake.apply_intake(api, 42, "contributor")
        self.assertEqual(api.added, [])


if __name__ == "__main__":
    unittest.main()
