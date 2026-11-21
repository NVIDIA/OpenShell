# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for roster parsing and PR reviewer reconciliation."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check_review_readiness as routing

TABLE = "| Name | GitHub ID | Company/Organization |\n| --- | --- | --- |\n"
ALICE = "| Alice | [@Alice](https://github.com/alice) | Example |\n"
DOCUMENT = "# Reviewers\n\n## Areas\n\n### area:runtime\n\nScope.\n\n" + TABLE + ALICE
CATEGORIES = {
    "area:runtime": {"alice", "bob"},
    "area:build": {"dave"},
    "topic:policy": {"bob", "carol"},
}
REPO = "owner/repo"
PULL = "repos/owner/repo/pulls/42"


def pr(*labels, requested=(), author="author", draft=False, state="open"):
    return {
        "number": 42,
        "state": state,
        "draft": draft,
        "user": {"login": author},
        "labels": [{"name": label} for label in labels],
        "requested_reviewers": [{"login": login} for login in requested],
    }


def fork(owner, *, full_name=None, owner_type="User"):
    return {
        "repo": {
            "full_name": full_name or f"{owner}/repo",
            "owner": {"login": owner, "type": owner_type},
        }
    }


def reviewers(*, requested=(), engaged=(), manual=()):
    return {"requested": set(requested), "engaged": set(engaged), "manual": set(manual)}


def event(number, login, *, human=False, removed=False):
    return {
        "id": number,
        "event": "review_request_removed" if removed else "review_requested",
        "actor": {"type": "User" if human else "Bot"},
        "requested_reviewer": {"login": login},
    }


class RegistryTests(unittest.TestCase):
    def test_nested_sdk_subscription_topics_route_without_the_parent_topic(self):
        text = DOCUMENT + "\n### topic:sdk\n\n" + TABLE + ALICE
        language_member = "| Bob | [@bob](https://github.com/bob) | Example |\n"
        for language in ("go", "python", "rust", "typescript"):
            text += f"\n### topic:sdk:{language}\n\n" + TABLE + language_member
        categories = routing.parse_reviewers(text)
        for language in ("go", "python", "rust", "typescript"):
            with self.subTest(language=language):
                self.assertEqual(categories[f"topic:sdk:{language}"], {"bob"})
                self.assertEqual(
                    routing.select_reviewers(
                        categories,
                        {"area:runtime", f"topic:sdk:{language}"},
                    ),
                    {"alice", "bob"},
                )

    def test_malformed_nested_headings_are_not_active_categories(self):
        for label in (
            "topic:sdk:",
            "topic:sdk::go",
            "topic:sdk:-go",
            "retired:topic:sdk:go",
        ):
            with self.subTest(label=label):
                text = DOCUMENT + f"\n### {label}\n\n" + TABLE
                self.assertEqual(
                    routing.parse_reviewers(text), {"area:runtime": {"alice"}}
                )

    def test_reads_only_membership_rows_and_allows_empty_categories(self):
        text = DOCUMENT.replace(
            "Scope.", "Thanks [@outside](https://github.com/outside)."
        )
        text += "\n## Topics\n\n### topic:policy\n\n" + TABLE
        self.assertEqual(
            routing.parse_reviewers(text),
            {"area:runtime": {"alice"}, "topic:policy": set()},
        )

    def test_same_person_can_belong_to_multiple_categories(self):
        text = DOCUMENT + "\n### area:build\n\n" + TABLE + ALICE
        self.assertEqual(routing.parse_reviewers(text)["area:build"], {"alice"})

    def test_rejects_duplicate_category_or_member(self):
        for text in (DOCUMENT + ALICE, DOCUMENT + "\n### area:runtime\n" + TABLE):
            with (
                self.subTest(text=text),
                self.assertRaisesRegex(ValueError, "duplicate"),
            ):
                routing.parse_reviewers(text)

    def test_rejects_missing_or_malformed_membership_table(self):
        cases = [
            "# Reviewers",
            DOCUMENT.replace(TABLE, ""),
            DOCUMENT.replace("| GitHub ID |", "| Role |"),
            DOCUMENT.replace("| --- | --- | --- |", "| --- | --- |"),
            DOCUMENT.replace(ALICE, ALICE.rstrip().removesuffix("|")),
        ]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                routing.parse_reviewers(text)

    def test_rejects_mismatched_or_ambiguous_profile_links(self):
        for profile in (
            "[@alice](https://github.com/other)",
            "@alice",
            "[@alice](https://github.com.evil/alice)",
            "[@alice](https://github.com/alice/repo)",
        ):
            text = DOCUMENT.replace("[@Alice](https://github.com/alice)", profile)
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                routing.parse_reviewers(text)


class PlanningTests(unittest.TestCase):
    def test_selects_all_matching_members_deduplicated(self):
        self.assertEqual(
            routing.select_reviewers(
                CATEGORIES, {"area:runtime", "topic:policy", "kind:bug"}
            ),
            {"alice", "bob", "carol"},
        )

    def test_multiple_area_labels_message(self):
        with self.assertRaises(routing.LabelRoutingError) as caught:
            routing.select_reviewers(CATEGORIES, {"area:runtime", "area:build"})
        self.assertEqual(
            str(caught.exception),
            "This PR has more than one area label: area:build, area:runtime. "
            "A ready PR needs exactly one; remove the others.",
        )

    def test_missing_area_label_message(self):
        with self.assertRaises(routing.LabelRoutingError) as caught:
            routing.select_reviewers(CATEGORIES, {"topic:policy"})
        self.assertEqual(
            str(caught.exception),
            "This PR has no area label. A ready PR needs exactly one; add one.",
        )

    def test_unknown_label_message(self):
        with self.assertRaises(routing.LabelRoutingError) as caught:
            routing.select_reviewers(
                CATEGORIES, {"area:runtime", "topic:nope", "topic:zzz"}
            )
        self.assertEqual(
            str(caught.exception),
            "There are invalid area and topic labels on this PR: topic:nope, "
            "topic:zzz. Remove them.",
        )

    def test_single_unknown_label_message(self):
        with self.assertRaises(routing.LabelRoutingError) as caught:
            routing.select_reviewers(CATEGORIES, {"area:runtime", "topic:nope"})
        self.assertEqual(
            str(caught.exception),
            "There is an invalid area or topic label on this PR: topic:nope. "
            "Remove it.",
        )

    def test_area_count_is_checked_before_unknown_labels(self):
        with self.assertRaises(routing.LabelRoutingError) as caught:
            routing.select_reviewers(CATEGORIES, {"area:nope", "area:other"})
        self.assertIn("more than one area label", str(caught.exception))

    def test_requires_one_known_area_and_known_topics(self):
        for labels in (
            set(),
            {"topic:policy"},
            {"area:build", "area:runtime"},
            {"area:unknown"},
            {"area:runtime", "topic:unknown"},
        ):
            with self.subTest(labels=labels), self.assertRaises(ValueError):
                routing.select_reviewers(CATEGORIES, labels)

    def test_preserves_manual_and_engaged_reviewers_during_label_changes(self):
        plan = routing.plan_review_requests(
            {"dave"},
            **reviewers(
                requested=("alice", "bob", "manual"),
                engaged=("BOB",),
                manual=("MANUAL",),
            ),
        )
        self.assertEqual(plan, routing.ReviewPlan(("dave",), ("alice",)))

    def test_does_not_re_request_engaged_or_manually_removed_reviewers(self):
        plan = routing.plan_review_requests(
            {"alice", "bob", "carol"},
            **reviewers(requested=("carol",), engaged=("ALICE",), manual=("bob",)),
        )
        self.assertEqual(plan, routing.ReviewPlan((), ()))

    def test_repeated_routing_is_idempotent(self):
        self.assertEqual(
            routing.plan_review_requests({"alice"}, **reviewers(requested=("alice",))),
            routing.ReviewPlan((), ()),
        )

    def test_all_review_states_and_comment_types_count_as_engaged(self):
        states = ("APPROVED", "CHANGES_REQUESTED", "DISMISSED", "COMMENTED", "PENDING")
        reviews = [{"user": {"login": state}, "state": state} for state in states]
        result = routing.engaged_reviewers(
            reviews,
            [{"user": {"login": "General"}}, {"user": None}],
            [{"user": {"login": "Inline"}}],
        )
        self.assertEqual(
            result, {state.lower() for state in states} | {"general", "inline"}
        )


class TimelineTests(unittest.TestCase):
    def test_distinguishes_human_and_bot_requests(self):
        events = [event(1, "Alice", human=True), event(2, "Bob")]
        self.assertEqual(routing.manual_reviewers(events, {"alice", "bob"}), {"alice"})

    def test_unknown_actor_and_missing_history_are_preserved(self):
        unknown = event(1, "alice")
        unknown["actor"] = None
        self.assertEqual(
            routing.manual_reviewers([unknown], {"alice", "bob"}), {"alice", "bob"}
        )

    def test_bot_re_request_does_not_erase_existing_human_request(self):
        events = [event(1, "alice", human=True), event(2, "alice")]
        self.assertEqual(routing.manual_reviewers(events, {"alice"}), {"alice"})

    def test_orders_events_and_preserves_manual_additions_and_removals(self):
        events = [
            event(4, "bob", human=True, removed=True),
            event(3, "alice", human=True),
            event(2, "alice", removed=True),
            event(1, "alice"),
            {"id": 5, "event": "review_requested", "requested_team": {"slug": "team"}},
        ]
        self.assertEqual(routing.manual_reviewers(events, {"alice"}), {"alice", "bob"})

    def test_new_automatic_request_after_removal_is_not_protected(self):
        events = [
            event(1, "alice", human=True),
            event(2, "alice", removed=True),
            event(3, "alice"),
        ]
        self.assertEqual(routing.manual_reviewers(events, {"alice"}), set())


class GitHubTests(unittest.TestCase):
    def test_api_rejects_empty_paginated_response(self):
        with mock.patch.object(routing.subprocess, "run") as run:
            run.return_value.stdout = ""
            with self.assertRaisesRegex(ValueError, "paginated"):
                routing._api("endpoint", pages=True)

    def test_api_reads_all_pages(self):
        with mock.patch.object(routing.subprocess, "run") as run:
            run.return_value.stdout = json.dumps(
                [[{"user": {"login": "first"}}], [{"user": {"login": "last"}}]]
            )
            result = routing._api("endpoint", pages=True)
            self.assertEqual(routing.engaged_reviewers(result), {"first", "last"})
            self.assertIn("--paginate", run.call_args.args[0])
            self.assertIn("--slurp", run.call_args.args[0])

    def test_loads_all_engagement_and_timeline_feeds(self):
        responses = [
            [{"user": {"login": "Reviewer"}}],
            [{"user": {"login": "Commenter"}}],
            [{"user": {"login": "Inline"}}],
            [event(1, "Manual", human=True)],
        ]
        with mock.patch.object(routing, "_api", side_effect=responses) as api:
            result = routing._load_reviewers(REPO, 42, pr(requested=("Manual",)))
        self.assertEqual(
            result,
            reviewers(
                requested=("manual",),
                engaged=("reviewer", "commenter", "inline"),
                manual=("manual",),
            ),
        )
        self.assertTrue(all(call.kwargs["pages"] for call in api.call_args_list))
        self.assertIn("/timeline?per_page=100", api.call_args.args[0])


class ReconciliationTests(unittest.TestCase):
    def run_routing(self, categories, *, snapshots, responses, apply=True):
        with (
            mock.patch.object(routing, "_api", side_effect=responses) as api,
            mock.patch.object(
                routing, "_load_reviewers", side_effect=snapshots
            ) as load,
        ):
            plan = routing.check_review_readiness(categories, REPO, 42, apply=apply)
        return plan, api, load

    def test_initial_assignment_excludes_author_without_extra_refresh(self):
        plan, api, load = self.run_routing(
            CATEGORIES,
            snapshots=[reviewers()],
            responses=[pr("area:runtime", "topic:policy", author="ALICE"), None],
        )
        self.assertEqual(plan, routing.ReviewPlan(("bob", "carol"), ()))
        load.assert_called_once()
        self.assertEqual(api.call_count, 2)
        self.assertEqual(
            api.call_args.kwargs,
            {"method": "POST", "data": {"reviewers": ["bob", "carol"]}},
        )

    def test_requests_roster_members_without_permission_lookups(self):
        members = {"read-member", "triage-member", "outside-collaborator"}
        categories = {"area:runtime": members}
        plan, api, _ = self.run_routing(
            categories,
            snapshots=[reviewers()],
            responses=[pr("area:runtime"), None],
        )
        self.assertEqual(plan, routing.ReviewPlan(tuple(sorted(members)), ()))
        self.assertEqual(
            api.call_args_list,
            [
                mock.call(PULL),
                mock.call(
                    f"{PULL}/requested_reviewers",
                    method="POST",
                    data={"reviewers": sorted(members)},
                ),
            ],
        )

    def test_empty_area_does_not_block_topic_reviewers(self):
        categories = {"area:runtime": set(), "topic:policy": {"carol"}}
        plan, _, _ = self.run_routing(
            categories,
            snapshots=[reviewers()],
            responses=[pr("area:runtime", "topic:policy")],
            apply=False,
        )
        self.assertEqual(plan.add, ("carol",))

    def test_draft_and_closed_prs_skip_all_routing(self):
        for value in (pr(draft=True), pr(state="closed")):
            with self.subTest(value=value):
                plan, api, load = self.run_routing(
                    CATEGORIES, snapshots=[], responses=[value]
                )
                self.assertIsNone(plan)
                api.assert_called_once_with(PULL)
                load.assert_not_called()

    def test_ready_fork_pr_without_maintainer_edits_is_not_ready(self):
        value = pr("area:build", draft=False)
        value["head"] = fork("user")
        value["maintainer_can_modify"] = False
        with self.assertRaises(routing.MaintainerEditsError) as caught:
            self.run_routing(CATEGORIES, snapshots=[], responses=[value])
        self.assertIn("gh pr create", str(caught.exception))
        self.assertEqual(
            routing.describe_failure(caught.exception)[0], "Maintainer edits"
        )

    def test_maintainer_edits_check_applies_only_where_github_offers_it(self):
        cases = {
            "enabled": (fork("user"), True, False),
            "draft": (fork("user"), False, True),
            "same repository": (fork("owner", full_name=REPO), False, False),
            "organization fork": (fork("org", owner_type="Organization"), False, False),
            "deleted fork": ({"repo": None}, False, False),
            "unknown head": (None, False, False),
        }
        for name, (head, allowed, draft) in cases.items():
            with self.subTest(name):
                value = pr(draft=draft)
                value["maintainer_can_modify"] = allowed
                if head is not None:
                    value["head"] = head
                self.assertFalse(routing.needs_maintainer_edits(value, REPO))

    def test_fork_pr_without_maintainer_edits_needs_them(self):
        value = pr()
        value["head"] = fork("user")
        self.assertTrue(routing.needs_maintainer_edits(value, REPO))

    def test_preview_makes_no_changes(self):
        plan, api, _ = self.run_routing(
            CATEGORIES,
            snapshots=[reviewers()],
            responses=[pr("area:build")],
            apply=False,
        )
        self.assertEqual(plan.add, ("dave",))
        api.assert_called_once_with(PULL)

    def test_refresh_before_removal_protects_new_manual_choices_and_engagement(self):
        before = pr("area:build", requested=("alice", "bob", "carol"))
        after = pr("area:build", requested=("alice", "bob", "carol", "dave"))
        snapshots = [
            reviewers(requested=("alice", "bob", "carol")),
            reviewers(
                requested=("alice", "bob", "carol", "dave"),
                engaged=("bob",),
                manual=("carol",),
            ),
        ]
        plan, api, _ = self.run_routing(
            CATEGORIES, snapshots=snapshots, responses=[before, None, after, None]
        )
        self.assertEqual(plan, routing.ReviewPlan(("dave",), ("alice",)))
        self.assertEqual(
            api.call_args,
            mock.call(
                f"{PULL}/requested_reviewers",
                method="DELETE",
                data={"reviewers": ["alice"]},
            ),
        )

    def test_changed_routing_or_draft_status_stops_removals(self):
        before = pr("area:build", requested=("alice", "dave"))
        for after in (
            pr("area:runtime"),
            pr("area:build", draft=True),
            pr("area:build", state="closed"),
        ):
            with (
                self.subTest(after=after),
                mock.patch.object(routing, "_api", side_effect=[before, after]) as api,
                mock.patch.object(
                    routing,
                    "_load_reviewers",
                    return_value=reviewers(requested=("alice", "dave")),
                ),
            ):
                with self.assertRaisesRegex(ValueError, "routing changed"):
                    routing.check_review_readiness(CATEGORIES, REPO, 42, apply=True)
                self.assertTrue(
                    all(
                        call.kwargs.get("method", "GET") == "GET"
                        for call in api.call_args_list
                    )
                )

    def test_new_commit_and_unrelated_label_do_not_interrupt_routing(self):
        before = pr("area:build", requested=("alice", "dave"))
        after = pr("area:build", "kind:bug", requested=("alice", "dave"))
        before["head"], after["head"] = {"sha": "old"}, {"sha": "new"}
        snapshots = [reviewers(requested=("alice", "dave"))] * 2
        plan, _, _ = self.run_routing(
            CATEGORIES, snapshots=snapshots, responses=[before, after, None]
        )
        self.assertEqual(plan.remove, ("alice",))

    def test_retry_after_partial_failure_uses_updated_github_metadata(self):
        before = pr("area:build", requested=("alice",))
        after = pr("area:build", requested=("alice", "dave"))
        snapshots = [
            reviewers(requested=("alice",)),
            reviewers(requested=("alice", "dave")),
        ]
        failed, _, _ = self.run_routing(
            CATEGORIES,
            snapshots=snapshots,
            responses=[
                before,
                None,
                after,
                subprocess.CalledProcessError(1, "gh"),
                [],
                None,
            ],
        )
        self.assertTrue(failed.assignment_error)
        plan, api, _ = self.run_routing(
            CATEGORIES, snapshots=[snapshots[1]] * 2, responses=[after, after, None]
        )
        self.assertEqual(plan, routing.ReviewPlan((), ("alice",)))
        self.assertFalse(
            any(call.kwargs.get("method") == "POST" for call in api.call_args_list)
        )


class AssignmentFailureTests(unittest.TestCase):
    COMMENTS = "repos/owner/repo/issues/42/comments"
    REJECTED = subprocess.CalledProcessError(
        1,
        ["gh", "api", f"{PULL}/requested_reviewers", "--method", "POST"],
        stderr="gh: Reviews may only be requested from collaborators. (HTTP 422)\n",
    )

    def run_routing(self, responses):
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(routing, "_api", side_effect=responses) as api,
            mock.patch.object(routing, "_load_reviewers", return_value=reviewers()),
        ):
            plan = routing.check_review_readiness(CATEGORIES, REPO, 42, apply=True)
        return plan, api

    def test_rejected_request_is_noted_on_the_pr_without_failing(self):
        plan, api = self.run_routing([pr("area:build"), self.REJECTED, [], None])
        self.assertEqual(plan.add, ("dave",))
        self.assertIn("Requesting reviewers failed", plan.assignment_error)
        self.assertIn("HTTP 422", plan.assignment_error)
        comment = api.call_args
        self.assertEqual(comment.args, (self.COMMENTS,))
        self.assertEqual(comment.kwargs["method"], "POST")
        body = comment.kwargs["data"]["body"]
        self.assertTrue(body.startswith(routing.ASSIGNMENT_MARKER))
        self.assertIn("HTTP 422", body)
        self.assertNotIn(
            "DELETE", [call.kwargs.get("method") for call in api.call_args_list]
        )

    def test_repeated_failure_updates_the_existing_bot_comment(self):
        marked = routing.ASSIGNMENT_MARKER + "\nold"
        comments = [
            {"id": 7, "user": {"type": "User"}, "body": marked},
            {"id": 9, "user": {"type": "Bot"}, "body": marked},
        ]
        _, api = self.run_routing([pr("area:build"), self.REJECTED, comments, None])
        self.assertEqual(api.call_args.args, ("repos/owner/repo/issues/comments/9",))
        self.assertEqual(api.call_args.kwargs["method"], "PATCH")

    def test_comment_failure_is_reported_without_failing(self):
        denied = subprocess.CalledProcessError(
            1,
            ["gh", "api", self.COMMENTS, "--method", "POST"],
            stderr="gh: Resource not accessible by integration (HTTP 403)",
        )
        plan, _ = self.run_routing([pr("area:build"), self.REJECTED, [], denied])
        self.assertIn("HTTP 422", plan.assignment_error)
        self.assertIn("Commenting on the PR failed", plan.assignment_error)

    def test_comment_links_the_workflow_run(self):
        body = routing.assignment_failure_comment("x", "https://github.test/run/1")
        self.assertIn("[workflow](https://github.test/run/1)", body)
        self.assertIn("re-run the check", routing.assignment_failure_comment("x"))

    def test_label_errors_still_fail(self):
        with self.assertRaises(routing.LabelRoutingError):
            self.run_routing([pr("area:build", "area:runtime")])

    def test_cli_passes_with_a_warning_annotation(self):
        plan = routing.ReviewPlan(("dave",), (), assignment_error="boom")
        errors, output = io.StringIO(), io.StringIO()
        with (
            mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}),
            mock.patch.object(routing, "check_review_readiness", return_value=plan),
            tempfile.TemporaryDirectory() as directory,
            contextlib.redirect_stderr(errors),
            contextlib.redirect_stdout(output),
        ):
            path = Path(directory) / "REVIEWERS.md"
            path.write_text(DOCUMENT, encoding="utf-8")
            result = routing.main(
                ["--reviewers", str(path), "--repo", REPO, "--pr", "42", "--apply"]
            )
        self.assertEqual(result, 0)
        self.assertIn(
            "::warning title=Review Readiness%3A reviewer assignment::boom",
            errors.getvalue(),
        )
        self.assertEqual(json.loads(output.getvalue())["assignment_error"], "boom")


class AcceptedWorkIntegrationTests(unittest.TestCase):
    def test_accepted_label_event_carries_structured_rationale(self):
        with (
            mock.patch.object(
                routing,
                "_api",
                side_effect=[
                    {**pr(draft=True), "node_id": "PR_node"},
                    {"node_id": "label_node"},
                    {
                        "data": {
                            "addLabelsToLabelable": {
                                "labelable": {"__typename": "PullRequest"}
                            }
                        }
                    },
                ],
            ) as api,
            mock.patch.object(
                routing,
                "evaluate_pr_accepted_work",
                return_value={"basis": "repository_permission", "permission": "admin"},
            ),
        ):
            routing.check_review_readiness(
                CATEGORIES,
                REPO,
                42,
                apply=True,
                label_accepted_work=True,
                maintainers={"maintainer"},
            )
        request = api.call_args.kwargs["data"]
        label = request["variables"]["input"]["labels"][0]
        self.assertEqual(request["variables"]["input"]["labelableId"], "PR_node")
        self.assertEqual(label["labelId"], "label_node")
        self.assertEqual(
            json.loads(label["rationale"]),
            {
                "schema": "openshell-acceptance-v1",
                "basis": "repository_permission",
                "permission": "admin",
            },
        )

    def test_label_mutation_graphql_error_is_not_silent(self):
        with (
            mock.patch.object(
                routing,
                "_api",
                side_effect=[
                    {"node_id": "label_node"},
                    {"errors": [{"message": "denied"}]},
                ],
            ),
            self.assertRaisesRegex(ValueError, "Could not apply"),
        ):
            routing._add_accepted_label(
                REPO, {"node_id": "PR_node"}, {"basis": "maintainer"}
            )

    def run_check(self, value, *, accepted=True, apply=True, opened=True):
        with (
            mock.patch.object(routing, "_api", side_effect=[value]) as api,
            mock.patch.object(routing, "_add_accepted_label") as add_label,
            mock.patch.object(
                routing,
                "evaluate_pr_accepted_work",
                return_value={"basis": "maintainer"} if accepted else None,
            ) as check,
            mock.patch.object(
                routing, "_load_reviewers", return_value=reviewers()
            ) as load,
        ):
            plan = routing.check_review_readiness(
                CATEGORIES,
                REPO,
                42,
                apply=apply,
                label_accepted_work=opened,
                maintainers={"maintainer"},
            )
        if (
            value["state"] == "open"
            and opened
            and accepted
            and apply
            and not any(label["name"] == "state:accepted" for label in value["labels"])
        ):
            add_label.assert_called_once_with(REPO, value, {"basis": "maintainer"})
        else:
            add_label.assert_not_called()
        return plan, api, check, load

    def test_new_draft_is_labeled_without_requesting_reviewers(self):
        plan, api, check, load = self.run_check(pr(draft=True))
        self.assertEqual(plan, routing.ReviewPlan((), (), True, ("state:accepted",)))
        check.assert_called_once_with(REPO, pr(draft=True), {"maintainer"}, api=api)
        api.assert_called_once_with(PULL)
        load.assert_not_called()

    def test_new_ready_pr_can_be_labeled_before_area_classification(self):
        plan, api, _, load = self.run_check(pr())
        self.assertEqual(plan.add_labels, ("state:accepted",))
        self.assertEqual(api.call_count, 1)
        load.assert_not_called()

    def test_nonqualifying_pr_is_not_labeled(self):
        plan, api, _, _ = self.run_check(pr(), accepted=False)
        self.assertFalse(plan.accepted_work)
        self.assertEqual(plan.add_labels, ())
        api.assert_called_once_with(PULL)

    def test_existing_labels_are_preserved_and_acceptance_is_not_readded(self):
        plan, api, _, _ = self.run_check(pr("state:accepted", "unrelated"))
        self.assertTrue(plan.accepted_work)
        self.assertEqual(plan.add_labels, ())
        api.assert_called_once_with(PULL)
        plan, api, _, _ = self.run_check(pr("state:accepted"), accepted=False)
        self.assertEqual(plan.add_labels, ())
        api.assert_called_once_with(PULL)

    def test_preview_reports_label_addition_without_writing(self):
        plan, api, _, _ = self.run_check(pr(draft=True), apply=False)
        self.assertEqual(plan.add_labels, ("state:accepted",))
        api.assert_called_once_with(PULL)

    def test_later_events_do_not_recheck_or_change_acceptance(self):
        plan, api, check, _ = self.run_check(pr(), opened=False)
        self.assertIsNone(plan.accepted_work)
        check.assert_not_called()
        api.assert_called_once_with(PULL)

    def test_closed_pr_is_never_classified_or_labeled(self):
        plan, api, check, load = self.run_check(pr(state="closed"))
        self.assertIsNone(plan)
        check.assert_not_called()
        load.assert_not_called()
        api.assert_called_once_with(PULL)

    def test_labels_and_requests_reviewers_for_a_classified_ready_pr(self):
        with (
            mock.patch.object(
                routing, "_api", side_effect=[pr("area:build"), None]
            ) as api,
            mock.patch.object(routing, "_add_accepted_label"),
            mock.patch.object(
                routing,
                "evaluate_pr_accepted_work",
                return_value={"basis": "maintainer"},
            ),
            mock.patch.object(routing, "_load_reviewers", return_value=reviewers()),
        ):
            plan = routing.check_review_readiness(
                CATEGORIES,
                REPO,
                42,
                apply=True,
                label_accepted_work=True,
                maintainers={"maintainer"},
            )
        self.assertEqual(
            plan, routing.ReviewPlan(("dave",), (), True, ("state:accepted",))
        )
        self.assertEqual(
            api.call_args.kwargs,
            {"method": "POST", "data": {"reviewers": ["dave"]}},
        )

    def test_lookup_failure_does_not_label_or_request_reviewers(self):
        with (
            mock.patch.object(routing, "_api", return_value=pr("area:build")) as api,
            mock.patch.object(
                routing,
                "evaluate_pr_accepted_work",
                side_effect=ValueError("lookup failed"),
            ),
            self.assertRaisesRegex(ValueError, "lookup failed"),
        ):
            routing.check_review_readiness(
                CATEGORIES,
                REPO,
                42,
                apply=True,
                label_accepted_work=True,
                maintainers={"maintainer"},
            )
        api.assert_called_once_with(PULL)

    def test_real_library_qualifies_a_maintainer_without_permission_reads(self):
        with (
            mock.patch.object(
                routing, "_api", side_effect=[pr(author="MAINTAINER", draft=True)]
            ) as api,
            mock.patch.object(routing, "_add_accepted_label"),
        ):
            plan = routing.check_review_readiness(
                CATEGORIES,
                REPO,
                42,
                apply=True,
                label_accepted_work=True,
                maintainers={"maintainer"},
            )
        assert plan is not None
        self.assertTrue(plan.accepted_work)
        self.assertEqual(api.call_count, 1)

    def test_label_result_survives_the_refresh_before_reviewer_removal(self):
        before = pr("area:build", requested=("alice", "dave"))
        after = pr("area:build", "state:accepted", requested=("alice", "dave"))
        with (
            mock.patch.object(
                routing, "_api", side_effect=[before, after, None]
            ) as api,
            mock.patch.object(routing, "_add_accepted_label"),
            mock.patch.object(
                routing,
                "evaluate_pr_accepted_work",
                return_value={"basis": "maintainer"},
            ),
            mock.patch.object(
                routing,
                "_load_reviewers",
                return_value=reviewers(requested=("alice", "dave")),
            ),
        ):
            plan = routing.check_review_readiness(
                CATEGORIES,
                REPO,
                42,
                apply=True,
                label_accepted_work=True,
                maintainers={"maintainer"},
            )
        self.assertEqual(
            plan, routing.ReviewPlan((), ("alice",), True, ("state:accepted",))
        )
        self.assertEqual(
            api.call_args.kwargs,
            {"method": "DELETE", "data": {"reviewers": ["alice"]}},
        )

    def test_label_write_failure_does_not_request_reviewers(self):
        error = subprocess.CalledProcessError(1, "gh", stderr="(HTTP 403)")
        with (
            mock.patch.object(routing, "_api", side_effect=[pr("area:build")]),
            mock.patch.object(routing, "_add_accepted_label", side_effect=error),
            mock.patch.object(
                routing,
                "evaluate_pr_accepted_work",
                return_value={"basis": "maintainer"},
            ),
            mock.patch.object(routing, "_load_reviewers") as load,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            routing.check_review_readiness(
                CATEGORIES,
                REPO,
                42,
                apply=True,
                label_accepted_work=True,
                maintainers={"maintainer"},
            )
        load.assert_not_called()


class FailureReportTests(unittest.TestCase):
    GH_COMMAND = (
        "gh",
        "api",
        "repos/o/r/pulls/42/requested_reviewers",
        "--method",
        "POST",
        "--input",
        "-",
    )

    def test_escape_data_and_property(self):
        self.assertEqual(routing._escape_annotation("a%b\r\nc"), "a%25b%0D%0Ac")
        self.assertEqual(routing._escape_annotation("x:y,z", prop=True), "x%3Ay%2Cz")

    def test_api_failure_includes_method_path_status_and_stderr(self):
        error = subprocess.CalledProcessError(
            1,
            self.GH_COMMAND,
            stderr="gh: Reviews may only be requested from collaborators. (HTTP 422)\n",
        )
        category, message = routing.describe_failure(error)
        self.assertEqual(category, "GitHub API error")
        self.assertTrue(
            message.startswith("Requesting reviewers failed with a GitHub API error"),
            message,
        )
        self.assertIn("POST repos/o/r/pulls/42/requested_reviewers", message)
        self.assertIn("exit status 1", message)
        self.assertIn("HTTP 422", message)
        self.assertNotIn("--input", message)

    def test_api_failure_with_empty_stderr(self):
        for stderr in (None, "", "  \n"):
            error = subprocess.CalledProcessError(1, self.GH_COMMAND, stderr=stderr)
            _, message = routing.describe_failure(error)
            self.assertNotIn("None", message)
            self.assertTrue(message.endswith("(exit status 1)"), message)

    def test_get_is_the_default_method(self):
        error = subprocess.CalledProcessError(
            1, ["gh", "api", "repos/o/r/pulls/42", "--method", "GET"], stderr="x"
        )
        _, message = routing.describe_failure(error)
        self.assertIn("GET repos/o/r/pulls/42", message)

    def test_api_failure_names_the_action(self):
        pull = "repos/o/r/pulls/42"
        cases = (
            ("POST", f"{pull}/requested_reviewers", "Requesting reviewers"),
            ("DELETE", f"{pull}/requested_reviewers", "Removing reviewer requests"),
            ("POST", "repos/o/r/issues/42/labels", "Adding labels"),
            ("GET", pull, "Reading the PR from GitHub"),
        )
        for method, path, action in cases:
            error = subprocess.CalledProcessError(
                1, ["gh", "api", path, "--method", method], stderr="x"
            )
            with self.subTest(method=method, path=path):
                _, message = routing.describe_failure(error)
                self.assertTrue(
                    message.startswith(f"{action} failed with a GitHub API error"),
                    message,
                )

    def test_label_error_category(self):
        self.assertEqual(
            routing.describe_failure(routing.LabelRoutingError("x")),
            ("PR labels", "x"),
        )

    def test_other_value_error_is_generic(self):
        text = "PR routing changed; rerun reconciliation"
        self.assertEqual(routing.describe_failure(ValueError(text)), ("error", text))

    def test_annotation_only_in_actions(self):
        error = routing.LabelRoutingError("bad 100%\nlabel")
        actions, local = io.StringIO(), io.StringIO()
        routing.report_failure(error, stream=actions, env={"GITHUB_ACTIONS": "true"})
        routing.report_failure(error, stream=local, env={})
        self.assertEqual(
            actions.getvalue(),
            "Review readiness: bad 100%\nlabel\n"
            "::error title=Review Readiness%3A PR labels::bad 100%25%0Alabel\n",
        )
        self.assertEqual(local.getvalue(), "Review readiness: bad 100%\nlabel\n")

    def test_cli_failure_in_actions_prints_annotation(self):
        errors = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}),
            mock.patch.object(
                routing,
                "check_review_readiness",
                side_effect=routing.LabelRoutingError("boom"),
            ),
            tempfile.TemporaryDirectory() as directory,
            contextlib.redirect_stderr(errors),
        ):
            path = Path(directory) / "REVIEWERS.md"
            path.write_text(DOCUMENT, encoding="utf-8")
            result = routing.main(
                ["--reviewers", str(path), "--repo", REPO, "--pr", "42"]
            )
        self.assertEqual(result, 1)
        self.assertIn(
            "::error title=Review Readiness%3A PR labels::boom", errors.getvalue()
        )


class CliTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("GITHUB_ACTIONS", None)

    def test_emits_plan_and_passes_apply_option(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text(DOCUMENT, encoding="utf-8")
            output = io.StringIO()
            with (
                mock.patch.object(
                    routing,
                    "check_review_readiness",
                    return_value=routing.ReviewPlan(("alice",), ()),
                ) as check,
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(
                    routing.main(
                        [
                            "--reviewers",
                            str(path),
                            "--repo",
                            REPO,
                            "--pr",
                            "42",
                            "--apply",
                        ]
                    ),
                    0,
                )
            self.assertEqual(
                json.loads(output.getvalue()),
                {
                    "add": ["alice"],
                    "remove": [],
                    "accepted_work": None,
                    "add_labels": [],
                    "assignment_error": "",
                },
            )
            check.assert_called_once_with(
                {"area:runtime": {"alice"}},
                REPO,
                42,
                apply=True,
                label_accepted_work=False,
                maintainers=None,
            )

    def test_opened_pr_option_loads_trusted_maintainer_roster(self):
        with tempfile.TemporaryDirectory() as directory:
            roster = Path(directory) / "REVIEWERS.md"
            roster.write_text(DOCUMENT, encoding="utf-8")
            maintainers = Path(directory) / "MAINTAINERS.md"
            maintainers.write_text("[@maintainer](https://github.com/maintainer)")
            with (
                mock.patch.object(
                    routing,
                    "check_review_readiness",
                    return_value=routing.ReviewPlan((), (), True, ("state:accepted",)),
                ) as check,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                result = routing.main(
                    [
                        "--repo",
                        REPO,
                        "--pr",
                        "42",
                        "--reviewers",
                        str(roster),
                        "--maintainers",
                        str(maintainers),
                        "--label-accepted-work",
                    ]
                )
            self.assertEqual(result, 0)
            self.assertEqual(
                json.loads(output.getvalue())["add_labels"], ["state:accepted"]
            )
            check.assert_called_once_with(
                {"area:runtime": {"alice"}},
                REPO,
                42,
                apply=False,
                label_accepted_work=True,
                maintainers={"maintainer"},
            )

    def test_invalid_registry_fails_before_contacting_github(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text("not a registry", encoding="utf-8")
            output, errors = io.StringIO(), io.StringIO()
            with (
                mock.patch.object(routing, "_api") as api,
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(errors),
            ):
                self.assertEqual(
                    routing.main(
                        [
                            "--reviewers",
                            str(path),
                            "--repo",
                            REPO,
                            "--pr",
                            "42",
                        ]
                    ),
                    1,
                )
            api.assert_not_called()
            self.assertEqual(output.getvalue(), "")
            self.assertIn("no area/topic", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
