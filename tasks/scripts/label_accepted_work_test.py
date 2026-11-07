# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for the shared accepted-work predicate and GitHub adapter."""

from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from label_accepted_work import (
    ACCEPTED_LABEL,
    ClosingIssue,
    check_pr_accepted_work,
    is_accepted_work,
)

REPO = "NVIDIA/OpenShell"
PR = {"number": 7, "user": {"login": "contributor"}}


def facts(*, repository=REPO, accepted=True, author="submitter", assignees=()):
    return ClosingIssue(repository, accepted, author, frozenset(assignees))


def connection(*numbers, more=False, cursor=None, repository=REPO):
    linked = {
        "nodes": [
            {"number": number, "repository": {"nameWithOwner": repository}}
            for number in numbers
        ],
        "pageInfo": {"hasNextPage": more, "endCursor": cursor},
    }
    pull = {"closingIssuesReferences": linked}
    return {"data": {"repository": {"pullRequest": pull}}}


def issue(*, author="contributor", assignees=()):
    return {
        "user": {"login": author} if author else None,
        "assignees": [{"login": login} for login in assignees],
    }


class PredicateTests(unittest.TestCase):
    def decide(
        self, *, author="contributor", maintainers=None, permission="read", issues=()
    ):
        return is_accepted_work(
            author,
            repository=REPO,
            maintainers=maintainers or {"maintainer"},
            permission=permission,
            closing_issues=issues,
        )

    def test_maintainers_and_write_roles_qualify_without_issues(self):
        self.assertTrue(self.decide(author="MAINTAINER"))
        for permission in ("write", "maintain", "admin"):
            with self.subTest(permission=permission):
                self.assertTrue(self.decide(permission=permission))

    def test_read_triage_none_and_unknown_roles_do_not_qualify(self):
        for permission in ("read", "triage", "none", "unknown"):
            with self.subTest(permission=permission):
                self.assertFalse(self.decide(permission=permission))

    def test_issue_submitter_and_assignee_qualify_case_insensitively(self):
        for value in (
            facts(author="CONTRIBUTOR"),
            facts(assignees=("other", "CONTRIBUTOR")),
            facts(author=None, assignees=("contributor",)),
        ):
            with self.subTest(issue=value):
                self.assertTrue(self.decide(issues=[value]))

    def test_accepted_issue_without_author_relationship_does_not_qualify(self):
        self.assertFalse(self.decide(issues=[facts()]))

    def test_author_relationship_without_acceptance_does_not_qualify(self):
        for value in (
            facts(author="contributor", accepted=False),
            facts(assignees=("contributor",), accepted=False),
        ):
            with self.subTest(issue=value):
                self.assertFalse(self.decide(issues=[value]))

    def test_acceptance_and_relationship_must_be_on_the_same_issue(self):
        self.assertFalse(
            self.decide(issues=[facts(), facts(author="contributor", accepted=False)])
        )
        self.assertTrue(
            self.decide(
                issues=[facts(accepted=False), facts(assignees=("contributor",))]
            )
        )

    def test_only_target_repository_issues_qualify(self):
        self.assertFalse(
            self.decide(
                issues=[facts(repository="purp/OpenShell", author="contributor")]
            )
        )
        self.assertTrue(
            self.decide(
                issues=[facts(repository="nvidia/openshell", author="contributor")]
            )
        )

    def test_bots_do_not_receive_an_implicit_exemption(self):
        self.assertFalse(self.decide(author="dependabot[bot]"))

    def test_privileged_decision_does_not_consume_issue_metadata(self):
        def unavailable():
            yield from ()
            raise AssertionError("must not load issues")

        self.assertTrue(self.decide(permission="write", issues=unavailable()))
        self.assertTrue(self.decide(author="maintainer", issues=unavailable()))


class GitHubAdapterTests(unittest.TestCase):
    def check(self, responses, *, pull=None, maintainers=None):
        api = mock.Mock(side_effect=responses)
        result = check_pr_accepted_work(
            REPO, pull or PR, maintainers or {"maintainer"}, api=api
        )
        return result, api

    def test_maintainer_skips_all_api_reads(self):
        result, api = self.check(
            [], pull={"number": 7, "user": {"login": "MAINTAINER"}}
        )
        self.assertTrue(result)
        api.assert_not_called()

    def test_write_author_only_reads_their_permissions(self):
        result, api = self.check([{"permission": "write"}])
        self.assertTrue(result)
        api.assert_called_once_with(
            f"repos/{REPO}/collaborators/contributor/permission"
        )

    def test_empty_roster_is_an_error_before_any_api_reads(self):
        api = mock.Mock()
        with self.assertRaisesRegex(ValueError, "Could not parse"):
            check_pr_accepted_work(REPO, PR, set(), api=api)
        api.assert_not_called()

    def test_checks_current_issue_author_assignees_and_paginated_labels(self):
        result, api = self.check(
            [
                {"permission": "read"},
                connection(42),
                issue(author="other", assignees=("contributor",)),
                [{"name": "area:build"}, {"name": ACCEPTED_LABEL}],
            ]
        )
        self.assertTrue(result)
        self.assertEqual(
            api.call_args_list[-2:],
            [
                mock.call(f"repos/{REPO}/issues/42"),
                mock.call(f"repos/{REPO}/issues/42/labels?per_page=100", pages=True),
            ],
        )

    def test_no_native_closing_reference_does_not_qualify(self):
        pull = {**PR, "body": "Accepted work: #42. Maintainer requested."}
        result, _ = self.check([{"permission": "read"}, connection()], pull=pull)
        self.assertFalse(result)

    def test_cross_repository_references_are_not_fetched(self):
        result, api = self.check(
            [{"permission": "read"}, connection(42, repository="purp/OpenShell")]
        )
        self.assertFalse(result)
        self.assertEqual(api.call_count, 2)

    def test_prs_are_not_issues_for_acceptance(self):
        result, api = self.check(
            [
                {"permission": "read"},
                connection(42),
                {**issue(), "pull_request": {"url": "pull"}},
            ]
        )
        self.assertFalse(result)
        self.assertEqual(api.call_count, 3)

    def test_reaches_a_qualifying_issue_on_a_later_page(self):
        result, api = self.check(
            [
                {"permission": "read"},
                connection(more=True, cursor="next"),
                connection(42),
                issue(),
                [{"name": ACCEPTED_LABEL}],
            ]
        )
        self.assertTrue(result)
        graphql_calls = [
            call for call in api.call_args_list if call.args[0] == "graphql"
        ]
        self.assertEqual(graphql_calls[0].kwargs["data"]["variables"]["cursor"], None)
        self.assertEqual(graphql_calls[1].kwargs["data"]["variables"]["cursor"], "next")
        self.assertEqual(graphql_calls[0].kwargs["data"]["variables"]["number"], 7)

    def test_invalid_cursor_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "cursor"):
            self.check([{"permission": "read"}, connection(more=True)])

    def test_noncollaborator_404_still_qualifies_through_an_issue(self):
        error = subprocess.CalledProcessError(
            1, "gh", stderr="gh: Not Found (HTTP 404)"
        )
        result, _ = self.check(
            [error, connection(42), issue(), [{"name": ACCEPTED_LABEL}]]
        )
        self.assertTrue(result)

    def test_permission_errors_propagate(self):
        for status in (401, 403, 429, 500):
            error = subprocess.CalledProcessError(1, "gh", stderr=f"(HTTP {status})")
            with (
                self.subTest(status=status),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                self.check([error])

    def test_graphql_errors_are_errors_not_a_negative_decision(self):
        for response in (
            {"errors": [{"message": "denied"}]},
            {"data": {"repository": None}},
        ):
            with (
                self.subTest(response=response),
                self.assertRaises((ValueError, TypeError)),
            ):
                self.check([{"permission": "read"}, response])

    def test_issue_and_label_errors_propagate(self):
        error = subprocess.CalledProcessError(1, "gh", stderr="(HTTP 403)")
        for responses in (
            [{"permission": "read"}, connection(42), error],
            [{"permission": "read"}, connection(42), issue(), error],
        ):
            with (
                self.subTest(responses=responses),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                self.check(responses)

    def test_metadata_reads_never_call_label_mutation_endpoints(self):
        _, api = self.check(
            [
                {"permission": "read"},
                connection(42),
                issue(),
                [{"name": ACCEPTED_LABEL}],
            ]
        )
        for call in api.call_args_list:
            if call.args[0] == "graphql":
                self.assertIn("query(", call.kwargs["data"]["query"])
            else:
                self.assertEqual(call.kwargs.get("method", "GET"), "GET")

class IssueAdapterTests(unittest.TestCase):
    def test_recorded_acceptance_uses_paginated_labels(self):
        from accepted_work import check_issue_accepted_work
        api = mock.Mock(return_value=[{'name': ACCEPTED_LABEL}])
        self.assertTrue(check_issue_accepted_work(REPO, {'number': 9, 'user': {'login': 'x'}}, {'m'}, api=api))
        api.assert_called_once_with(f'repos/{REPO}/issues/9/labels?per_page=100', pages=True)

    def test_authority_and_errors(self):
        from accepted_work import check_issue_accepted_work
        item = {'number': 9, 'user': {'login': 'x'}}
        api = mock.Mock(side_effect=[[], {'permission': 'write'}])
        self.assertTrue(check_issue_accepted_work(REPO, item, {'m'}, api=api))
        api = mock.Mock(side_effect=[[], {'permission': 'read'}])
        self.assertFalse(check_issue_accepted_work(REPO, item, {'m'}, api=api))
        api = mock.Mock(side_effect=RuntimeError('unavailable'))
        with self.assertRaises(RuntimeError):
            check_issue_accepted_work(REPO, item, {'m'}, api=api)

    def test_issue_adapter_rejects_prs_instead_of_using_recorded_pr_label(self):
        from accepted_work import check_issue_accepted_work
        api = mock.Mock(return_value=[{'name': ACCEPTED_LABEL}])
        with self.assertRaises(ValueError):
            check_issue_accepted_work(REPO, {'number': 9, 'pull_request': {}, 'user': {'login': 'x'}}, {'m'}, api=api)

    def test_maintainer_issue_needs_no_permission_lookup(self):
        from accepted_work import check_issue_accepted_work
        api = mock.Mock(return_value=[])
        self.assertTrue(check_issue_accepted_work(REPO, {'number': 9, 'user': {'login': 'M'}}, {'m'}, api=api))
        self.assertEqual(api.call_count, 1)

    def test_noncollaborator_issue_404_is_unaccepted_other_errors_propagate(self):
        from accepted_work import check_issue_accepted_work
        item = {'number': 9, 'user': {'login': 'x'}}
        for status in (404, 403, 429, 500):
            with self.subTest(status=status):
                api = mock.Mock(side_effect=[[], subprocess.CalledProcessError(1, 'gh', stderr=f'(HTTP {status})')])
                if status == 404:
                    self.assertFalse(check_issue_accepted_work(REPO, item, {'m'}, api=api))
                else:
                    with self.assertRaises(subprocess.CalledProcessError):
                        check_issue_accepted_work(REPO, item, {'m'}, api=api)


if __name__ == "__main__":
    unittest.main()
