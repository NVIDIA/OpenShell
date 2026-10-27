# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for PR acceptance, roster parsing, and reviewer reconciliation."""

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
ROSTER = Path("REVIEWERS.md")
DRAFTED = {"data": {"convertPullRequestToDraft": {"pullRequest": {"isDraft": True}}}}


def pr(*labels, requested=(), author="author", draft=False, state="open", body=""):
    return {
        "number": 42,
        "state": state,
        "draft": draft,
        "user": {"login": author},
        "node_id": "PR_node_42",
        "body": body,
        "labels": [{"name": label} for label in labels],
        "requested_reviewers": [{"login": login} for login in requested],
    }


def graphql_pr(value, *, cursor=None):
    return {
        "repository": {
            "pullRequest": {
                **value,
                "labels": {
                    "nodes": value["labels"],
                    "pageInfo": {
                        "hasNextPage": cursor is not None,
                        "endCursor": cursor,
                    },
                },
            }
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


class AcceptanceTests(unittest.TestCase):
    @staticmethod
    def member(permission="READ", login="author", cursor=None):
        return {
            "data": {
                "repository": {
                    "collaborators": {
                        "edges": [{"permission": permission, "node": {"login": login}}],
                        "pageInfo": {
                            "hasNextPage": cursor is not None,
                            "endCursor": cursor,
                        },
                    }
                }
            }
        }

    @staticmethod
    def linked(*numbers, repository=REPO, cursor=None):
        return {
            "data": {
                "repository": {
                    "pullRequest": {
                        "closingIssuesReferences": {
                            "nodes": [
                                {
                                    "number": n,
                                    "repository": {"nameWithOwner": repository},
                                }
                                for n in numbers
                            ],
                            "pageInfo": {
                                "hasNextPage": cursor is not None,
                                "endCursor": cursor,
                            },
                        }
                    }
                }
            }
        }

    @staticmethod
    def issue(author="author", accepted=True, cursor=None):
        return {
            "data": {
                "repository": {
                    "issueOrPullRequest": {
                        "author": {"login": author},
                        "labels": {
                            "nodes": [{"name": "state:accepted"}] if accepted else [],
                            "pageInfo": {
                                "hasNextPage": cursor is not None,
                                "endCursor": cursor,
                            },
                        },
                    }
                }
            }
        }

    def test_dependabot_remains_exempt_without_lookups(self):
        with mock.patch.object(
            routing, "_api", side_effect=AssertionError("No lookups")
        ):
            self.assertTrue(
                routing._accepted_work(REPO, 42, pr(author="dependabot[bot]"))
            )

    def test_write_maintain_and_admin_return_without_looking_up_issues(self):
        for permission in ("WRITE", "MAINTAIN", "ADMIN"):
            with (
                self.subTest(permission=permission),
                mock.patch.object(
                    routing, "_api", return_value=self.member(permission)
                ) as api,
            ):
                self.assertTrue(
                    routing._accepted_work(REPO, 42, pr(body="See #9999999"))
                )
                api.assert_called_once()
                self.assertNotIn("pullRequest", api.call_args.kwargs["data"]["query"])

    def test_acceptance_recorded_on_pr_needs_no_further_lookups(self):
        with mock.patch.object(routing, "_api") as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr("state:accepted")))
        api.assert_not_called()

    def test_collaborator_search_result_must_match_the_pr_author(self):
        with mock.patch.object(
            routing,
            "_api",
            side_effect=[
                self.member("ADMIN", login="someone-else"),
                self.linked(),
            ],
        ):
            self.assertFalse(routing._accepted_work(REPO, 42, pr()))

    def test_qualifying_description_reference_skips_all_closing_link_queries(self):
        with mock.patch.object(
            routing,
            "_api",
            side_effect=[
                self.member(),
                self.issue(),
            ],
        ) as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr(body="Related to #1")))
        self.assertEqual(api.call_count, 2)

    def test_qualifying_closing_reference_skips_later_pages(self):
        with mock.patch.object(
            routing,
            "_api",
            side_effect=[
                self.member(),
                self.linked(1, cursor="unneeded-page"),
                self.issue(),
            ],
        ) as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr()))
        self.assertEqual(api.call_count, 3)

    def test_description_and_closing_references_require_acceptance_not_same_submitter(
        self,
    ):
        for body in (
            "",
            "Related to #1",
            "Related to owner/repo#1",
            "Related to OWNER/REPO#1",
            "Related to https://github.com/owner/repo/issues/1",
        ):
            for author, accepted, expected in (
                ("AUTHOR", True, True),
                ("someone-else", True, True),
                ("author", False, False),
                ("someone-else", False, False),
            ):
                with (
                    self.subTest(body=body, author=author, accepted=accepted),
                    mock.patch.object(
                        routing,
                        "_api",
                        side_effect=(
                            [
                                self.member(),
                                self.linked(1),
                                self.issue(author, accepted),
                            ]
                            if not body
                            else [self.member(), self.issue(author, accepted)]
                            + ([] if expected else [self.linked()])
                        ),
                    ) as api,
                ):
                    self.assertEqual(
                        routing._accepted_work(REPO, 42, pr(body=body)), expected
                    )
                    lookups = [
                        call.kwargs["data"]["variables"]["number"]
                        for call in api.call_args_list
                        if "issueOrPullRequest" in call.kwargs["data"]["query"]
                    ]
                    self.assertEqual(lookups, [1])

    def test_one_qualifying_issue_is_enough_and_duplicate_references_are_read_once(
        self,
    ):
        with mock.patch.object(
            routing,
            "_api",
            side_effect=[
                self.member(),
                self.issue(accepted=False),
                self.linked(1, 2),
                self.issue(),
            ],
        ) as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr(body="Related to #1")))
        self.assertEqual(api.call_count, 4)

    def test_paginates_permission_lookup_before_querying_issues(self):
        with mock.patch.object(
            routing,
            "_api",
            side_effect=[
                self.member(login="someone-else", cursor="next-page"),
                self.member("WRITE"),
            ],
        ) as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr()))
        self.assertEqual(api.call_count, 2)
        self.assertEqual(
            api.call_args.kwargs["data"]["variables"]["cursor"], "next-page"
        )

    def test_reads_later_closing_reference_pages(self):
        with mock.patch.object(
            routing,
            "_api",
            side_effect=[
                self.member(),
                self.linked(cursor="next-page"),
                self.linked(1),
                self.issue(),
            ],
        ) as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr()))
        self.assertEqual(
            api.call_args_list[2].kwargs["data"]["variables"]["cursor"], "next-page"
        )

    def test_reads_later_label_pages_on_the_referenced_issue(self):
        with mock.patch.object(
            routing,
            "_api",
            side_effect=[
                self.member(),
                self.linked(1),
                self.issue(accepted=False, cursor="next-page"),
                self.issue(),
            ],
        ) as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr()))
        self.assertEqual(
            api.call_args.kwargs["data"]["variables"]["cursor"], "next-page"
        )

    def test_cross_repository_references_do_not_qualify(self):
        with mock.patch.object(
            routing,
            "_api",
            side_effect=[
                self.member(),
                self.linked(1, repository="other/repo"),
            ],
        ) as api:
            self.assertFalse(
                routing._accepted_work(
                    REPO,
                    42,
                    pr(
                        body=(
                            "Related to other/repo#1 and https://github.com/other/repo/issues/1"
                        )
                    ),
                )
            )
        self.assertEqual(api.call_count, 2)

    def test_missing_issues_do_not_qualify_and_other_graphql_errors_propagate(self):
        for error_type in ("NOT_FOUND", "FORBIDDEN"):
            error = subprocess.CalledProcessError(
                1,
                "gh",
                output=json.dumps({"errors": [{"type": error_type}]}),
            )
            with (
                self.subTest(error_type=error_type),
                mock.patch.object(
                    routing,
                    "_api",
                    side_effect=[
                        self.member(),
                        error,
                        self.linked(),
                    ],
                ),
            ):
                if error_type == "NOT_FOUND":
                    self.assertFalse(
                        routing._accepted_work(REPO, 42, pr(body="See #1"))
                    )
                else:
                    with self.assertRaises(subprocess.CalledProcessError):
                        routing._accepted_work(REPO, 42, pr(body="See #1"))

    def test_pull_request_references_do_not_qualify(self):
        with mock.patch.object(
            routing,
            "_api",
            side_effect=[
                self.member(),
                {"data": {"repository": {"issueOrPullRequest": {}}}},
                self.linked(),
            ],
        ):
            self.assertFalse(routing._accepted_work(REPO, 42, pr(body="See #1")))

    def test_missing_description_reference_falls_back_to_qualifying_closing_link(self):
        missing = subprocess.CalledProcessError(
            1,
            "gh",
            output=json.dumps({"errors": [{"type": "NOT_FOUND"}]}),
        )
        with mock.patch.object(
            routing,
            "_api",
            side_effect=[
                self.member(),
                missing,
                self.linked(2),
                self.issue(),
            ],
        ):
            self.assertTrue(routing._accepted_work(REPO, 42, pr(body="Related to #1")))

    def test_first_draft_conversion_comments_once_and_subsequent_attempts_are_silent(
        self,
    ):
        comments = f"repos/{REPO}/issues/42/comments"
        posted = {"user": {"type": "Bot"}, "body": ""}
        with (
            mock.patch.object(
                routing,
                "_api",
                side_effect=[
                    pr(),
                    DRAFTED,
                    [],
                    posted,
                    pr(),
                    DRAFTED,
                    [posted],
                    pr(),
                    DRAFTED,
                    [posted],
                ],
            ) as api,
            mock.patch.object(routing, "_accepted_work", return_value=False),
            mock.patch.object(routing, "_load_reviewers") as load,
        ):
            for attempt in range(3):
                with self.assertRaisesRegex(ValueError, "not accepted work"):
                    routing.check_review_readiness(
                        ROSTER, REPO, 42, apply=True, event="ready_for_review"
                    )
                if attempt == 0:
                    posted["body"] = api.call_args.kwargs["data"]["body"]
            self.assertEqual(
                sum(
                    "convertPullRequestToDraft"
                    in call.kwargs.get("data", {}).get("query", "")
                    for call in api.call_args_list
                ),
                3,
            )
            self.assertEqual(
                sum(
                    call.args[0] == comments and call.kwargs.get("method") == "POST"
                    for call in api.call_args_list
                ),
                1,
            )
            load.assert_not_called()

    def test_existing_notice_suppresses_comment_and_all_pages_are_read(self):
        comments = f"repos/{REPO}/issues/42/comments"
        for previous, should_post in (
            ([{"user": {"type": "User"}, "body": routing.DRAFT_COMMENT}], False),
            ([{"user": {"type": "Bot"}, "body": "unrelated comment"}], True),
            ([{"user": None, "body": None}], True),
            (
                [{"user": {"type": "Bot"}, "body": None}] * 100
                + [{"user": {"type": "Bot"}, "body": routing.DRAFT_COMMENT}],
                False,
            ),
        ):
            with (
                self.subTest(previous=previous, should_post=should_post),
                mock.patch.object(
                    routing,
                    "_api",
                    side_effect=[
                        pr(),
                        DRAFTED,
                        previous,
                        {},
                    ],
                ) as api,
                mock.patch.object(routing, "_accepted_work", return_value=False),
                self.assertRaisesRegex(ValueError, "not accepted work"),
            ):
                routing.check_review_readiness(ROSTER, REPO, 42, apply=True)
            self.assertIn(
                mock.call(f"{comments}?per_page=100", pages=True), api.call_args_list
            )
            self.assertEqual(
                any(
                    call.kwargs.get("method") == "POST" and call.args[0] == comments
                    for call in api.call_args_list
                ),
                should_post,
            )

    def test_comment_lookup_or_post_failure_still_leaves_pr_drafted(self):
        for posting in (False, True):
            error = subprocess.CalledProcessError(1, "gh")
            with (
                self.subTest(posting=posting),
                mock.patch.object(
                    routing,
                    "_api",
                    side_effect=(
                        [pr(), DRAFTED, [], error]
                        if posting
                        else [pr(), DRAFTED, error]
                    ),
                ) as api,
                mock.patch.object(routing, "_accepted_work", return_value=False),
                mock.patch.object(routing, "_load_reviewers") as load,
                self.assertRaises(subprocess.CalledProcessError),
            ):
                routing.check_review_readiness(ROSTER, REPO, 42, apply=True)
            self.assertIn(
                "convertPullRequestToDraft",
                api.call_args_list[1].kwargs["data"]["query"],
            )
            load.assert_not_called()

    def test_lookup_errors_fail_without_drafting_or_requesting_reviewers(self):
        with (
            mock.patch.object(
                routing,
                "_api",
                side_effect=[
                    pr(),
                    subprocess.CalledProcessError(1, "gh"),
                ],
            ) as api,
            mock.patch.object(routing, "_load_reviewers") as load,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            routing.check_review_readiness(ROSTER, REPO, 42, apply=True)
        self.assertEqual(api.call_count, 2)
        load.assert_not_called()

    def test_draft_conversion_errors_propagate(self):
        with (
            mock.patch.object(
                routing,
                "_api",
                side_effect=[pr(), subprocess.CalledProcessError(1, "gh")],
            ),
            mock.patch.object(routing, "_accepted_work", return_value=False),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            routing.check_review_readiness(ROSTER, REPO, 42, apply=True)


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.accepted = mock.patch.object(routing, "_accepted_work", return_value=True)
        self.accepted.start()
        self.addCleanup(self.accepted.stop)
        self.roster = mock.Mock(spec=Path)
        self.roster.read_text.return_value = DOCUMENT
        parser = mock.patch.object(routing, "parse_reviewers", return_value=CATEGORIES)
        self.parser = parser.start()
        self.addCleanup(parser.stop)

    def run_routing(
        self, categories, *, snapshots, responses, apply=True, event="opened"
    ):
        self.parser.return_value = categories
        with (
            mock.patch.object(routing, "_api", side_effect=responses) as api,
            mock.patch.object(
                routing, "_load_reviewers", side_effect=snapshots
            ) as load,
        ):
            plan = routing.check_review_readiness(
                self.roster, REPO, 42, apply=apply, event=event
            )
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

    def test_label_changes_reconcile_without_rechecking_acceptance(self):
        for event in ("labeled", "unlabeled"):
            with (
                self.subTest(event=event),
                mock.patch.object(routing, "_accepted_work") as accepted,
            ):
                plan, _, _ = self.run_routing(
                    CATEGORIES,
                    snapshots=[reviewers()],
                    responses=[pr("area:build"), None],
                    event=event,
                )
                self.assertEqual(plan.add, ("dave",))
                accepted.assert_not_called()

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
                    routing.check_review_readiness(self.roster, REPO, 42, apply=True)
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
    def test_unaccepted_new_ready_pr_is_drafted_before_roster_or_reviewer_reads(self):
        with (
            mock.patch.object(
                routing, "_api", side_effect=[pr(), DRAFTED, [], {}]
            ) as api,
            mock.patch.object(routing, "check_pr_accepted_work", return_value=False),
            mock.patch.object(routing, "_accepted_work", return_value=False),
            mock.patch.object(routing, "_load_reviewers") as load,
            self.assertRaisesRegex(ValueError, "not accepted work"),
        ):
            routing.check_review_readiness(
                Path("missing-roster"),
                REPO,
                42,
                apply=True,
                label_accepted_work=True,
                maintainers={"maintainer"},
            )
        self.assertIn(
            "convertPullRequestToDraft", api.call_args_list[1].kwargs["data"]["query"]
        )
        load.assert_not_called()

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
                event="opened" if opened else "labeled",
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
        plan, api, _, _ = self.run_check(pr(draft=True), accepted=False)
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
                routing, "_api", side_effect=[pr("area:build"), None, None]
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
                roster,
                REPO,
                42,
                apply=False,
                event="opened",
                label_accepted_work=True,
                maintainers={"maintainer"},
            )

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
                },
            )
            check.assert_called_once_with(
                path,
                REPO,
                42,
                apply=True,
                event="opened",
                label_accepted_work=False,
                maintainers=None,
            )

    def test_both_cli_modes_use_the_same_acceptance_policy(self):
        cases = [
            ("WRITE", "", (), {}, (), True),
            ("READ", "", (), {}, ("state:accepted",), True),
            ("READ", "Related to #1", (), {1: ("author", True)}, (), True),
            ("READ", "Closes #1", (1,), {1: ("someone-else", True)}, (), True),
            (
                "READ",
                "Closes #1 and #2",
                (1, 2),
                {1: ("author", True), 2: ("author", False)},
                (),
                True,
            ),
            ("READ", "Related to #1", (), {1: ("author", False)}, (), False),
            ("READ", "", (), {}, (), False),
        ]
        for mode in ("preview", "acceptance-api", "acceptance-event"):
            acceptance_only = mode != "preview"
            for permission, body, linked, issues, labels, expected in cases:
                with (
                    self.subTest(mode=mode, body=body, issues=issues, labels=labels),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    path = Path(directory) / "REVIEWERS.md"
                    path.write_text(DOCUMENT, encoding="utf-8")
                    value = pr("area:runtime", *labels, body=body)

                    def api(
                        endpoint,
                        *,
                        value=value,
                        mode=mode,
                        permission=permission,
                        linked=linked,
                        issues=issues,
                        **kwargs,
                    ):
                        if endpoint == PULL:
                            return value
                        self.assertEqual(endpoint, "graphql")
                        query = kwargs["data"]["query"]
                        self.assertNotIn("mutation", query)
                        if "user: author" in query:
                            self.assertNotEqual(mode, "acceptance-event")
                            self.assertEqual(kwargs["data"]["variables"]["number"], 42)
                            return {"data": graphql_pr(value)}
                        if "collaborators" in query:
                            return AcceptanceTests.member(permission)
                        if "closingIssuesReferences" in query:
                            return AcceptanceTests.linked(*linked)
                        self.assertIn("issueOrPullRequest", query)
                        author, accepted = issues[kwargs["data"]["variables"]["number"]]
                        return AcceptanceTests.issue(author, accepted)

                    output, errors = io.StringIO(), io.StringIO()
                    with (
                        mock.patch.object(routing, "_api", side_effect=api),
                        mock.patch.object(
                            routing, "_load_reviewers", return_value=reviewers()
                        ) as load,
                        contextlib.redirect_stdout(output),
                        contextlib.redirect_stderr(errors),
                    ):
                        argv = ["--repo", REPO, "--pr", "42", "--reviewers", str(path)]
                        if acceptance_only:
                            argv.append("--acceptance-only")
                        if mode == "acceptance-event":
                            event_path = Path(directory) / "event.json"
                            event_path.write_text(json.dumps({"pull_request": value}))
                            argv.extend(["--event-path", str(event_path)])
                        status = routing.main(argv)
                    self.assertEqual(status, 0 if expected else 1)
                    if expected:
                        self.assertEqual(
                            json.loads(output.getvalue()),
                            {"accepted": True}
                            if acceptance_only
                            else {
                                "add": ["alice"],
                                "remove": [],
                                "accepted_work": None,
                                "add_labels": [],
                            },
                        )
                    else:
                        self.assertIn(routing.ACCEPTANCE_ERROR, errors.getvalue())
                    if acceptance_only:
                        load.assert_not_called()

    def test_acceptance_only_reads_later_pr_label_pages(self):
        output = io.StringIO()
        with (
            mock.patch.object(
                routing,
                "_graphql",
                side_effect=[
                    graphql_pr(pr("topic:policy"), cursor="next-page"),
                    graphql_pr(pr("state:accepted")),
                ],
            ) as query,
            mock.patch.object(
                routing, "_api", side_effect=AssertionError("No further lookups")
            ),
            mock.patch.object(routing, "check_review_readiness") as route,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(
                routing.main(
                    [
                        "--repo",
                        REPO,
                        "--pr",
                        "42",
                        "--acceptance-only",
                    ]
                ),
                0,
            )
        self.assertEqual(json.loads(output.getvalue()), {"accepted": True})
        self.assertEqual(query.call_args.kwargs["cursor"], "next-page")
        route.assert_not_called()

    def test_acceptance_only_checks_drafts_and_closed_prs_without_routing(self):
        for value in (pr(), pr(draft=True), pr(state="closed")):
            for accepted in (False, True):
                with self.subTest(value=value, accepted=accepted):
                    output, errors = io.StringIO(), io.StringIO()
                    with (
                        mock.patch.object(
                            routing, "_graphql", return_value=graphql_pr(value)
                        ) as query,
                        mock.patch.object(
                            routing, "_accepted_work", return_value=accepted
                        ) as check,
                        mock.patch.object(routing, "check_review_readiness") as route,
                        mock.patch.object(routing, "parse_reviewers") as parse,
                        mock.patch.object(
                            routing.Path,
                            "read_text",
                            side_effect=AssertionError(
                                "Acceptance-only must not read the roster"
                            ),
                        ),
                        contextlib.redirect_stdout(output),
                        contextlib.redirect_stderr(errors),
                    ):
                        status = routing.main(
                            ["--repo", REPO, "--pr", "42", "--acceptance-only"]
                        )
                    self.assertEqual(status, 0 if accepted else 1)
                    check.assert_called_once_with(REPO, 42, value)
                    query.assert_called_once()
                    self.assertNotIn("mutation", query.call_args.args[0])
                    route.assert_not_called()
                    parse.assert_not_called()

    def test_acceptance_only_lookup_errors_fail_without_routing(self):
        for metadata_error in (False, True):
            error = subprocess.CalledProcessError(1, "gh")
            with (
                self.subTest(metadata_error=metadata_error),
                mock.patch.object(
                    routing,
                    "_graphql",
                    side_effect=error if metadata_error else None,
                    return_value=graphql_pr(pr()),
                ),
                mock.patch.object(
                    routing, "_accepted_work", side_effect=error
                ) as check,
                mock.patch.object(routing, "check_review_readiness") as route,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    routing.main(["--repo", REPO, "--pr", "42", "--acceptance-only"]), 1
                )
                route.assert_not_called()
                if metadata_error:
                    check.assert_not_called()

    def test_invalid_event_payload_fails_without_api_calls_or_routing(self):
        for contents in (None, "not JSON"):
            with (
                self.subTest(contents=contents),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "event.json"
                if contents is not None:
                    path.write_text(contents)
                with (
                    mock.patch.object(routing, "_api") as api,
                    mock.patch.object(routing, "check_review_readiness") as route,
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(
                        routing.main(
                            [
                                "--repo",
                                REPO,
                                "--pr",
                                "42",
                                "--acceptance-only",
                                "--event-path",
                                str(path),
                            ]
                        ),
                        1,
                    )
                api.assert_not_called()
                route.assert_not_called()

    def test_acceptance_only_cannot_be_combined_with_apply(self):
        with (
            mock.patch.object(routing, "_api") as api,
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as error,
        ):
            routing.main(["--repo", REPO, "--pr", "42", "--acceptance-only", "--apply"])
        self.assertEqual(error.exception.code, 2)
        api.assert_not_called()

    def test_rejected_pr_does_not_need_a_readable_valid_roster(self):
        for contents in (None, "not a registry"):
            for apply in (False, True):
                with (
                    self.subTest(contents=contents, apply=apply),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    path = Path(directory) / "REVIEWERS.md"
                    if contents is not None:
                        path.write_text(contents, encoding="utf-8")
                    output, errors = io.StringIO(), io.StringIO()
                    with (
                        mock.patch.object(
                            routing, "_api", side_effect=[pr(), DRAFTED, [], {}]
                        ) as api,
                        mock.patch.object(
                            routing, "_accepted_work", return_value=False
                        ),
                        mock.patch.object(routing, "parse_reviewers") as parse,
                        mock.patch.object(routing, "_load_reviewers") as load,
                        contextlib.redirect_stdout(output),
                        contextlib.redirect_stderr(errors),
                    ):
                        argv = ["--reviewers", str(path), "--repo", REPO, "--pr", "42"]
                        self.assertEqual(
                            routing.main(argv + (["--apply"] if apply else [])), 1
                        )
                    self.assertIn("not accepted work", errors.getvalue())
                    self.assertEqual(output.getvalue(), "")
                    parse.assert_not_called()
                    load.assert_not_called()
                    self.assertEqual(api.call_count, 4 if apply else 1)
                    if apply:
                        self.assertIn(
                            "convertPullRequestToDraft",
                            api.call_args_list[1].kwargs["data"]["query"],
                        )

    def test_accepted_pr_reads_real_roster_and_previews_reviewers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text(DOCUMENT, encoding="utf-8")
            output = io.StringIO()
            with (
                mock.patch.object(
                    routing, "_api", return_value=pr("area:runtime")
                ) as api,
                mock.patch.object(
                    routing, "_accepted_work", return_value=True
                ) as accepted,
                mock.patch.object(routing, "_load_reviewers", return_value=reviewers()),
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
                        ]
                    ),
                    0,
                )
            accepted.assert_called_once()
            api.assert_called_once_with(PULL)
            self.assertEqual(
                json.loads(output.getvalue()),
                {
                    "add": ["alice"],
                    "remove": [],
                    "accepted_work": None,
                    "add_labels": [],
                },
            )

    def test_closed_and_draft_prs_skip_missing_roster_and_acceptance(self):
        for value in (pr(draft=True), pr(state="closed")):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "missing.md"
                output = io.StringIO()
                with (
                    mock.patch.object(routing, "_api", return_value=value) as api,
                    mock.patch.object(routing, "_accepted_work") as accepted,
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
                            ]
                        ),
                        0,
                    )
                api.assert_called_once_with(PULL)
                accepted.assert_not_called()
                self.assertEqual(
                    json.loads(output.getvalue()), {"skipped": "closed or draft PR"}
                )

    def test_accepted_pr_with_invalid_registry_fails_before_reviewer_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text("not a registry", encoding="utf-8")
            output, errors = io.StringIO(), io.StringIO()
            with (
                mock.patch.object(
                    routing, "_api", return_value=pr("area:runtime")
                ) as api,
                mock.patch.object(routing, "_accepted_work", return_value=True),
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
            api.assert_called_once_with(PULL)
            self.assertEqual(output.getvalue(), "")
            self.assertIn("no area/topic", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
