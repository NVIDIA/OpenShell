# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for deterministic accepted-work labeling."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import label_accepted_work as labeling

REPO = "NVIDIA/OpenShell"
ROOT = f"repos/{REPO}"


def pr(*, author="contributor", number=7, labels=(), state="open", draft=False):
    return {
        "number": number,
        "user": {"login": author},
        "labels": [{"name": name} for name in labels],
        "state": state,
        "draft": draft,
    }


def issue(*, author="submitter", assignees=(), labels=(labeling.ACCEPTED,)):
    return {
        "user": {"login": author} if author else None,
        "assignees": [{"login": login} for login in assignees],
        "labels": [{"name": name} for name in labels],
    }


def reference(number=1, repository=REPO):
    return {"number": number, "repository": {"nameWithOwner": repository}}


def connection(nodes, *, more=False, cursor=None):
    linked = {
        "nodes": nodes,
        "pageInfo": {"hasNextPage": more, "endCursor": cursor},
    }
    pull = {"closingIssuesReferences": linked}
    return {"data": {"repository": {"pullRequest": pull}}}


class AcceptanceTests(unittest.TestCase):
    def evaluate(self, *, pull=None, permission="read", references=None, issues=None):
        issues = issues or {1: issue()}
        references = references if references is not None else [reference()]

        def api(path, **kwargs):
            if "/collaborators/" in path:
                if isinstance(permission, Exception):
                    raise permission
                return {"permission": permission}
            if path == "graphql":
                self.assertEqual(kwargs["data"]["variables"]["number"], 7)
                return connection(references)
            for number, value in issues.items():
                if path == f"{ROOT}/issues/{number}":
                    return value.copy()
                if path == f"{ROOT}/issues/{number}/labels?per_page=100":
                    self.assertTrue(kwargs["pages"])
                    return value["labels"]
            self.fail(f"Unexpected API call: {path}")

        with mock.patch.object(labeling, "_api", side_effect=api) as calls:
            result = labeling.AcceptedWork(REPO, {"maintainer"}).accepted(pull or pr())
        return result, calls

    def test_maintainer_needs_no_permission_or_issue_lookup(self):
        result, calls = self.evaluate(pull=pr(author="MAINTAINER"))
        self.assertTrue(result)
        calls.assert_not_called()

    def test_empty_maintainer_roster_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "Could not parse"):
            labeling.AcceptedWork(REPO, set())

    def test_write_maintain_and_admin_qualify_without_an_issue(self):
        for permission in ("write", "maintain", "admin"):
            with self.subTest(permission=permission):
                result, calls = self.evaluate(permission=permission, references=[])
                self.assertTrue(result)
                self.assertEqual(calls.call_count, 1)

    def test_read_triage_and_no_access_need_an_issue_relationship(self):
        for permission in ("read", "triage", "none"):
            with self.subTest(permission=permission):
                result, _ = self.evaluate(permission=permission)
                self.assertFalse(result)

    def test_accepted_issue_submitter_qualifies_case_insensitively(self):
        result, _ = self.evaluate(issues={1: issue(author="CONTRIBUTOR")})
        self.assertTrue(result)

    def test_current_assignee_qualifies_case_insensitively(self):
        result, _ = self.evaluate(issues={1: issue(assignees=("other", "CONTRIBUTOR"))})
        self.assertTrue(result)

    def test_unrelated_accepted_issue_does_not_qualify(self):
        result, _ = self.evaluate()
        self.assertFalse(result)

    def test_submitter_and_assignee_of_unaccepted_issue_do_not_qualify(self):
        for value in (
            issue(author="contributor", labels=()),
            issue(assignees=("contributor",), labels=("state:validated",)),
        ):
            with self.subTest(issue=value):
                result, _ = self.evaluate(issues={1: value})
                self.assertFalse(result)

    def test_deleted_submitter_does_not_block_current_assignee(self):
        result, _ = self.evaluate(
            issues={1: issue(author=None, assignees=("contributor",))}
        )
        self.assertTrue(result)

    def test_cross_repository_accepted_issue_does_not_qualify(self):
        result, calls = self.evaluate(
            references=[reference(repository="purp/OpenShell")]
        )
        self.assertFalse(result)
        self.assertEqual(calls.call_count, 2)

    def test_target_repository_identity_is_case_insensitive(self):
        result, _ = self.evaluate(
            references=[reference(repository="nvidia/openshell")],
            issues={1: issue(author="contributor")},
        )
        self.assertTrue(result)

    def test_at_least_one_issue_must_have_both_acceptance_and_relationship(self):
        result, _ = self.evaluate(
            references=[reference(1), reference(2)],
            issues={1: issue(), 2: issue(author="contributor", labels=())},
        )
        self.assertFalse(result)
        result, _ = self.evaluate(
            references=[reference(1), reference(2)],
            issues={1: issue(labels=()), 2: issue(assignees=("contributor",))},
        )
        self.assertTrue(result)

    def test_arbitrary_mentions_and_body_claims_do_not_qualify(self):
        pull = pr()
        pull["body"] = "Accepted work: #1. No issue required: maintainer requested."
        result, _ = self.evaluate(pull=pull, references=[])
        self.assertFalse(result)

    def test_another_pr_is_not_a_qualifying_issue(self):
        value = issue(author="contributor")
        value["pull_request"] = {"url": "pull"}
        result, _ = self.evaluate(issues={1: value})
        self.assertFalse(result)

    def test_bots_have_no_automatic_exemption(self):
        result, _ = self.evaluate(pull=pr(author="dependabot[bot]"), references=[])
        self.assertFalse(result)

    def test_noncollaborator_404_still_qualifies_as_submitter(self):
        error = subprocess.CalledProcessError(
            1, "gh", stderr="gh: Not Found (HTTP 404)"
        )
        result, _ = self.evaluate(
            permission=error, issues={1: issue(author="contributor")}
        )
        self.assertTrue(result)

    def test_other_permission_errors_propagate(self):
        for status in (401, 403, 429, 500):
            error = subprocess.CalledProcessError(1, "gh", stderr=f"(HTTP {status})")
            with (
                self.subTest(status=status),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                self.evaluate(permission=error)

    def test_closing_issue_pagination_reaches_later_pages(self):
        responses = [
            connection([reference(1)], more=True, cursor="next"),
            connection([reference(2)]),
        ]
        with mock.patch.object(labeling, "_api", side_effect=responses) as api:
            refs = list(labeling.AcceptedWork(REPO, {"maintainer"}).closing_issues(7))
        self.assertEqual(refs, [reference(1), reference(2)])
        self.assertEqual(api.call_args.kwargs["data"]["variables"]["cursor"], "next")

    def test_graphql_errors_do_not_become_nonacceptance(self):
        values = [{"errors": [{"message": "denied"}]}, {"data": {"repository": None}}]
        for value in values:
            with (
                self.subTest(value=value),
                mock.patch.object(labeling, "_api", return_value=value),
                self.assertRaises((ValueError, TypeError)),
            ):
                list(labeling.AcceptedWork(REPO, {"maintainer"}).closing_issues(7))

    def test_missing_pagination_cursor_fails(self):
        with (
            mock.patch.object(labeling, "_api", return_value=connection([], more=True)),
            self.assertRaisesRegex(ValueError, "cursor"),
        ):
            list(labeling.AcceptedWork(REPO, {"maintainer"}).closing_issues(7))

    def test_permissions_and_shared_issues_are_cached_within_one_sweep(self):
        evaluator = labeling.AcceptedWork(REPO, {"maintainer"})
        responses = [
            {"permission": "read"},
            connection([reference()]),
            issue(author="contributor"),
            [{"name": labeling.ACCEPTED}],
            connection([reference()]),
        ]
        with mock.patch.object(labeling, "_api", side_effect=responses) as api:
            self.assertTrue(evaluator.accepted(pr()))
            self.assertTrue(evaluator.accepted(pr(number=8)))
        self.assertEqual(api.call_count, 5)


class ReconciliationTests(unittest.TestCase):
    def test_adds_only_accepted_label_and_preserves_other_labels(self):
        evaluator = labeling.AcceptedWork(REPO, {"maintainer"})
        with mock.patch.object(labeling, "_api") as api:
            plan = evaluator.reconcile(
                [pr(author="maintainer", labels=("area:build",))], apply=True
            )
        self.assertEqual(plan, [{"number": 7, "accepted": True, "action": "add"}])
        api.assert_called_once_with(
            f"{ROOT}/issues/7/labels",
            method="POST",
            data={"labels": [labeling.ACCEPTED]},
        )

    def test_removes_stale_or_manually_applied_acceptance_only(self):
        evaluator = labeling.AcceptedWork(REPO, {"maintainer"})
        with (
            mock.patch.object(evaluator, "accepted", return_value=False),
            mock.patch.object(labeling, "_api") as api,
        ):
            evaluator.reconcile(
                [pr(labels=(labeling.ACCEPTED, "area:build"))], apply=True
            )
        api.assert_called_once_with(
            f"{ROOT}/issues/7/labels/state%3Aaccepted", method="DELETE"
        )

    def test_idempotent_for_labeled_accepted_and_unlabeled_unaccepted(self):
        evaluator = labeling.AcceptedWork(REPO, {"maintainer"})
        with (
            mock.patch.object(evaluator, "accepted", side_effect=[True, False]),
            mock.patch.object(labeling, "_api") as api,
        ):
            plans = evaluator.reconcile(
                [pr(labels=(labeling.ACCEPTED,)), pr(number=8)], apply=True
            )
        self.assertEqual([plan["action"] for plan in plans], ["none", "none"])
        api.assert_not_called()

    def test_preview_never_mutates(self):
        with mock.patch.object(labeling, "_api") as api:
            plan = labeling.AcceptedWork(REPO, {"maintainer"}).reconcile(
                [pr(author="maintainer")]
            )
        self.assertEqual(plan[0]["action"], "add")
        api.assert_not_called()

    def test_drafts_qualify_and_closed_prs_are_skipped(self):
        with mock.patch.object(labeling, "_api") as api:
            plan = labeling.AcceptedWork(REPO, {"maintainer"}).reconcile(
                [pr(author="maintainer", draft=True), pr(number=8, state="closed")]
            )
        self.assertEqual(len(plan), 1)
        self.assertTrue(plan[0]["accepted"])
        api.assert_not_called()

    def test_lookup_failure_does_not_apply_any_pending_changes(self):
        evaluator = labeling.AcceptedWork(REPO, {"maintainer"})
        with (
            mock.patch.object(
                evaluator, "accepted", side_effect=[True, ValueError("lookup failed")]
            ),
            mock.patch.object(labeling, "_api") as api,
            self.assertRaisesRegex(ValueError, "lookup failed"),
        ):
            evaluator.reconcile([pr(), pr(number=8)], apply=True)
        api.assert_not_called()

    def test_mutation_failure_propagates(self):
        with (
            mock.patch.object(labeling, "_api", side_effect=OSError("denied")),
            self.assertRaisesRegex(OSError, "denied"),
        ):
            labeling.AcceptedWork(REPO, {"maintainer"}).reconcile(
                [pr(author="maintainer")], apply=True
            )

    def test_fresh_run_reflects_acceptance_assignment_and_permission_changes(self):
        for first, second in (
            (issue(assignees=("contributor",)), issue()),
            (issue(author="contributor"), issue(author="contributor", labels=())),
        ):
            with self.subTest(first=first):
                accepted, _ = AcceptanceTests().evaluate(issues={1: first})
                removed, _ = AcceptanceTests().evaluate(issues={1: second})
                self.assertTrue(accepted)
                self.assertFalse(removed)
        self.assertTrue(AcceptanceTests().evaluate(permission="write")[0])
        self.assertFalse(AcceptanceTests().evaluate(permission="read")[0])


class ApiAndCliTests(unittest.TestCase):
    def test_api_flattens_all_pages_and_posts_json(self):
        with mock.patch.object(labeling.subprocess, "run") as run:
            run.return_value.stdout = '[[{"number": 1}], [{"number": 2}]]'
            self.assertEqual(
                labeling._api("endpoint", pages=True), [{"number": 1}, {"number": 2}]
            )
            self.assertIn("--paginate", run.call_args.args[0])
            self.assertIn("--slurp", run.call_args.args[0])
            labeling._api("graphql", method="POST", data={"query": "query"})
            self.assertEqual(
                json.loads(run.call_args.kwargs["input"]), {"query": "query"}
            )
            self.assertTrue(run.call_args.kwargs["check"])

    def test_cli_single_pr_or_paginated_sweep_defaults_to_preview(self):
        for target in (["--pr", "7"], ["--all-open"]):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "MAINTAINERS.md"
                path.write_text("[@maintainer](https://github.com/maintainer)")
                with (
                    mock.patch.object(
                        labeling, "_api", return_value=pr() if "--pr" in target else [pr()]
                    ) as api,
                    mock.patch.object(
                        labeling.AcceptedWork, "reconcile", return_value=[]
                    ) as reconcile,
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(
                        labeling.main(
                            ["--repo", REPO, "--maintainers", str(path), *target]
                        ),
                        0,
                    )
                reconcile.assert_called_once_with([pr()], apply=False)
                if "--all-open" in target:
                    api.assert_called_once_with(
                        f"{ROOT}/pulls?state=open&per_page=100", pages=True
                    )
                else:
                    api.assert_called_once_with(f"{ROOT}/pulls/7")

    def test_invalid_roster_fails_before_github_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "MAINTAINERS.md"
            path.write_text("# No maintainers")
            with (
                mock.patch.object(labeling, "_api") as api,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    labeling.main(
                        [
                            "--repo",
                            REPO,
                            "--maintainers",
                            str(path),
                            "--pr",
                            "7",
                            "--apply",
                        ]
                    ),
                    1,
                )
            api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
