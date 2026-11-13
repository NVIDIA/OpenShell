# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for roster parsing and PR reviewer reconciliation."""

from __future__ import annotations

import contextlib
import io
import json
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
    def test_api_failure_reports_operation_status_and_reviewers_without_raw_output(
        self,
    ):
        error = subprocess.CalledProcessError(
            1,
            ["gh", "api"],
            output='{"message":"sensitive-response-body"}',
            stderr="gh: sensitive-response-body (HTTP 422)",
        )
        with (
            mock.patch.object(routing.subprocess, "run", side_effect=error),
            self.assertRaises(subprocess.CalledProcessError) as raised,
        ):
            routing._api(
                f"{PULL}/requested_reviewers",
                method="POST",
                data={"reviewers": ["alice", "bob"]},
            )
        message = str(raised.exception)
        for expected in (
            "POST",
            f"{PULL}/requested_reviewers",
            "HTTP 422",
            "alice",
            "bob",
        ):
            self.assertIn(expected, message)
        self.assertNotIn("sensitive-response-body", message)

    def test_mixed_roster_requests_collaborators_from_every_page_in_preview_and_apply(
        self,
    ):
        for apply in (False, True):
            with self.subTest(apply=apply):
                writes = []

                def github(command, *, writes=writes, **kwargs):
                    endpoint = command[2]
                    method = command[command.index("--method") + 1]
                    if endpoint == PULL:
                        result = pr("area:runtime", author="author")
                    elif "/collaborators?" in endpoint:
                        self.assertIn("--paginate", command)
                        self.assertIn("--slurp", command)
                        result = [
                            [
                                {
                                    "login": "READ-MEMBER",
                                    "permissions": {"pull": True, "push": False},
                                }
                            ],
                            [
                                {
                                    "login": "triage-member",
                                    "permissions": {
                                        "pull": True,
                                        "push": False,
                                        "triage": True,
                                    },
                                }
                            ],
                        ]
                    elif endpoint.endswith("/requested_reviewers") and method == "POST":
                        writes.append(json.loads(kwargs["input"]))
                        result = {}
                    else:
                        result = [[]]
                    return subprocess.CompletedProcess(
                        command, 0, stdout=json.dumps(result), stderr=""
                    )

                with mock.patch.object(routing.subprocess, "run", side_effect=github):
                    plan = routing.check_review_readiness(
                        {
                            "area:runtime": {
                                "read-member",
                                "triage-member",
                                "non-collaborator",
                            }
                        },
                        REPO,
                        42,
                        apply=apply,
                    )
                assert plan is not None
                self.assertEqual(plan.add, ("read-member", "triage-member"))
                self.assertEqual(plan.skipped_non_collaborators, ("non-collaborator",))
                self.assertEqual(
                    writes,
                    [{"reviewers": ["read-member", "triage-member"]}] if apply else [],
                )

    def test_all_non_collaborators_are_reported_without_request_or_removal(self):
        with (
            mock.patch.object(
                routing, "_api", side_effect=[pr("area:runtime"), []]
            ) as api,
            mock.patch.object(routing, "_load_reviewers", return_value=reviewers()),
        ):
            plan = routing.check_review_readiness(CATEGORIES, REPO, 42, apply=True)
        assert plan is not None
        self.assertEqual(plan.add, ())
        self.assertEqual(plan.skipped_non_collaborators, ("alice", "bob"))
        self.assertTrue(
            all(
                call.kwargs.get("method", "GET") == "GET" for call in api.call_args_list
            )
        )

    def test_collaborator_filter_does_not_remove_selected_existing_reviewers(self):
        value = pr("area:runtime", requested=("alice",))
        with (
            mock.patch.object(routing, "_api", side_effect=[value, []]) as api,
            mock.patch.object(
                routing, "_load_reviewers", return_value=reviewers(requested=("alice",))
            ),
        ):
            plan = routing.check_review_readiness(CATEGORIES, REPO, 42, apply=True)
        assert plan is not None
        self.assertEqual(plan.remove, ())
        self.assertEqual(plan.skipped_non_collaborators, ("bob",))
        self.assertTrue(
            all(
                call.kwargs.get("method", "GET") == "GET" for call in api.call_args_list
            )
        )

    def test_api_preserves_404_for_the_shared_accepted_work_checker(self):
        error = subprocess.CalledProcessError(
            1, "gh", stderr="gh: Not Found (HTTP 404)"
        )
        closing_issues = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "closingIssuesReferences": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            }
        }
        with mock.patch.object(
            routing.subprocess,
            "run",
            side_effect=[
                error,
                subprocess.CompletedProcess([], 0, stdout=json.dumps(closing_issues)),
            ],
        ):
            self.assertFalse(
                routing.check_pr_accepted_work(
                    REPO, pr(), {"maintainer"}, api=routing._api
                )
            )

    def test_collaborator_lookup_failure_stops_reviewer_writes(self):
        error = subprocess.CalledProcessError(
            1, "gh", stderr="gh: forbidden (HTTP 403)"
        )
        with (
            mock.patch.object(
                routing, "_api", side_effect=[pr("area:runtime"), error]
            ) as api,
            mock.patch.object(routing, "_load_reviewers", return_value=reviewers()),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            routing.check_review_readiness(CATEGORIES, REPO, 42, apply=True)
        self.assertTrue(
            all(
                call.kwargs.get("method", "GET") == "GET" for call in api.call_args_list
            )
        )

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
        responses = iter(responses)

        def github(path, **_kwargs):
            if "/collaborators?" in path:
                return [
                    {"login": login}
                    for login in (
                        "alice",
                        "bob",
                        "carol",
                        "dave",
                        "read-member",
                        "triage-member",
                        "outside-collaborator",
                    )
                ]
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return response

        with (
            mock.patch.object(routing, "_api", side_effect=github) as api,
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
        self.assertEqual(api.call_count, 3)
        self.assertEqual(
            api.call_args.kwargs,
            {"method": "POST", "data": {"reviewers": ["bob", "carol"]}},
        )

    def test_requests_read_triage_and_outside_collaborators_without_write_checks(self):
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
                    "repos/owner/repo/collaborators?per_page=100&affiliation=all",
                    pages=True,
                ),
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

    def test_preview_makes_no_changes(self):
        plan, api, _ = self.run_routing(
            CATEGORIES,
            snapshots=[reviewers()],
            responses=[pr("area:build")],
            apply=False,
        )
        self.assertEqual(plan.add, ("dave",))
        self.assertTrue(
            all(
                call.kwargs.get("method", "GET") == "GET" for call in api.call_args_list
            )
        )

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
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_routing(
                CATEGORIES,
                snapshots=snapshots,
                responses=[before, None, after, subprocess.CalledProcessError(1, "gh")],
            )
        plan, api, _ = self.run_routing(
            CATEGORIES, snapshots=[snapshots[1]] * 2, responses=[after, after, None]
        )
        self.assertEqual(plan, routing.ReviewPlan((), ("alice",)))
        self.assertFalse(
            any(call.kwargs.get("method") == "POST" for call in api.call_args_list)
        )


class AcceptedWorkIntegrationTests(unittest.TestCase):
    def run_check(self, value, *, accepted=True, apply=True, opened=True):
        with (
            mock.patch.object(routing, "_api", side_effect=[value, None]) as api,
            mock.patch.object(
                routing, "check_pr_accepted_work", return_value=accepted
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
        return plan, api, check, load

    def test_new_draft_is_labeled_without_requesting_reviewers(self):
        plan, api, check, load = self.run_check(pr(draft=True))
        self.assertEqual(plan, routing.ReviewPlan((), (), True, ("state:accepted",)))
        check.assert_called_once_with(REPO, pr(draft=True), {"maintainer"}, api=api)
        api.assert_has_calls(
            [
                mock.call(PULL),
                mock.call(
                    "repos/owner/repo/issues/42/labels",
                    method="POST",
                    data={"labels": ["state:accepted"]},
                ),
            ]
        )
        self.assertEqual(api.call_count, 2)
        load.assert_not_called()

    def test_new_ready_pr_can_be_labeled_before_area_classification(self):
        plan, api, _, load = self.run_check(pr())
        self.assertEqual(plan.add_labels, ("state:accepted",))
        self.assertEqual(api.call_count, 2)
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
                routing,
                "_api",
                side_effect=[pr("area:build"), None, [{"login": "dave"}], None],
            ) as api,
            mock.patch.object(routing, "check_pr_accepted_work", return_value=True),
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
                "check_pr_accepted_work",
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
        with mock.patch.object(
            routing, "_api", side_effect=[pr(author="MAINTAINER", draft=True), None]
        ) as api:
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
        self.assertEqual(api.call_count, 2)

    def test_label_result_survives_the_refresh_before_reviewer_removal(self):
        before = pr("area:build", requested=("alice", "dave"))
        after = pr("area:build", "state:accepted", requested=("alice", "dave"))
        with (
            mock.patch.object(
                routing, "_api", side_effect=[before, None, after, None]
            ) as api,
            mock.patch.object(routing, "check_pr_accepted_work", return_value=True),
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
            mock.patch.object(routing, "_api", side_effect=[pr("area:build"), error]),
            mock.patch.object(routing, "check_pr_accepted_work", return_value=True),
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


class CliTests(unittest.TestCase):
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
                    "skipped_non_collaborators": [],
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
