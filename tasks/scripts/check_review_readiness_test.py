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
        "state": state,
        "draft": draft,
        "user": {"login": author},
        "node_id": "PR_node_42",
        "body": body,
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
            routing.plan_review_requests(
                {"alice"}, **reviewers(requested=("alice",))
            ),
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
        self.assertEqual(result, {state.lower() for state in states} | {"general", "inline"})


class TimelineTests(unittest.TestCase):
    def test_distinguishes_human_and_bot_requests(self):
        events = [event(1, "Alice", human=True), event(2, "Bob")]
        self.assertEqual(
            routing.manual_reviewers(events, {"alice", "bob"}), {"alice"}
        )

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
    def test_graphql_passes_variables_and_unwraps_response(self):
        with mock.patch.object(routing, "_api", return_value={"data": {"value": 1}}) as api:
            self.assertEqual(routing._graphql("query", number=42), {"value": 1})
        api.assert_called_once_with(
            "graphql", method="POST",
            data={"query": "query", "variables": {"number": 42}},
        )

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

    def test_only_current_write_maintain_admin_permissions_are_eligible(self):
        responses = [
            {"permission": role}
            for role in ("admin", "maintain", "read", "triage", "write")
        ]
        with mock.patch.object(routing, "_api", side_effect=responses):
            self.assertEqual(
                routing._eligible_reviewers(REPO, {"a", "b", "c", "d", "e"}),
                {"a", "b", "e"},
            )


class AcceptanceTests(unittest.TestCase):
    @staticmethod
    def member(permission="READ", login="author", cursor=None):
        return {"data": {"repository": {"collaborators": {
            "edges": [{"permission": permission, "node": {"login": login}}],
            "pageInfo": {"hasNextPage": cursor is not None, "endCursor": cursor},
        }}}}

    @staticmethod
    def linked(*numbers, repository=REPO, cursor=None):
        return {"data": {"repository": {"pullRequest": {"closingIssuesReferences": {
            "nodes": [{"number": n, "repository": {"nameWithOwner": repository}} for n in numbers],
            "pageInfo": {"hasNextPage": cursor is not None, "endCursor": cursor},
        }}}}}

    @staticmethod
    def issue(author="author", accepted=True, cursor=None):
        return {"data": {"repository": {"issueOrPullRequest": {
            "author": {"login": author},
            "labels": {
                "nodes": [{"name": "state:accepted"}] if accepted else [],
                "pageInfo": {"hasNextPage": cursor is not None, "endCursor": cursor},
            },
        }}}}

    def test_write_maintain_and_admin_return_without_looking_up_issues(self):
        for permission in ("WRITE", "MAINTAIN", "ADMIN"):
            with (
                self.subTest(permission=permission),
                mock.patch.object(routing, "_api", return_value=self.member(permission)) as api,
            ):
                self.assertTrue(routing._accepted_work(REPO, 42, pr(body="See #9999999")))
                api.assert_called_once()
                self.assertNotIn("pullRequest", api.call_args.kwargs["data"]["query"])

    def test_collaborator_search_result_must_match_the_pr_author(self):
        with mock.patch.object(routing, "_api", side_effect=[
            self.member("ADMIN", login="someone-else"), self.linked(),
        ]):
            self.assertFalse(routing._accepted_work(REPO, 42, pr()))

    def test_qualifying_description_reference_skips_all_closing_link_queries(self):
        with mock.patch.object(routing, "_api", side_effect=[
            self.member(), self.issue(),
        ]) as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr(body="Related to #1")))
        self.assertEqual(api.call_count, 2)

    def test_qualifying_closing_reference_skips_later_pages(self):
        with mock.patch.object(routing, "_api", side_effect=[
            self.member(), self.linked(1, cursor="unneeded-page"), self.issue(),
        ]) as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr()))
        self.assertEqual(api.call_count, 3)

    def test_description_and_closing_references_require_same_submitter_and_label(self):
        for body in (
            "", "Related to #1", "Related to owner/repo#1", "Related to OWNER/REPO#1",
            "Related to https://github.com/owner/repo/issues/1",
        ):
            for author, accepted, expected in (
                ("AUTHOR", True, True), ("someone-else", True, False), ("author", False, False),
            ):
                with (
                    self.subTest(body=body, author=author, accepted=accepted),
                    mock.patch.object(routing, "_api", side_effect=(
                        [self.member(), self.linked(1), self.issue(author, accepted)]
                        if not body else
                        [self.member(), self.issue(author, accepted)] + ([] if expected else [self.linked()])
                    )) as api,
                ):
                    self.assertEqual(routing._accepted_work(REPO, 42, pr(body=body)), expected)
                    lookups = [call.kwargs["data"]["variables"]["number"]
                               for call in api.call_args_list
                               if "issueOrPullRequest" in call.kwargs["data"]["query"]]
                    self.assertEqual(lookups, [1])

    def test_one_qualifying_issue_is_enough_and_duplicate_references_are_read_once(self):
        with mock.patch.object(routing, "_api", side_effect=[
            self.member(), self.issue(accepted=False), self.linked(1, 2), self.issue(),
        ]) as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr(body="Related to #1")))
        self.assertEqual(api.call_count, 4)

    def test_paginates_permission_lookup_before_querying_issues(self):
        with mock.patch.object(routing, "_api", side_effect=[
            self.member(login="someone-else", cursor="next-page"), self.member("WRITE"),
        ]) as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr()))
        self.assertEqual(api.call_count, 2)
        self.assertEqual(api.call_args.kwargs["data"]["variables"]["cursor"], "next-page")

    def test_reads_later_closing_reference_pages(self):
        with mock.patch.object(routing, "_api", side_effect=[
            self.member(), self.linked(cursor="next-page"), self.linked(1), self.issue(),
        ]) as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr()))
        self.assertEqual(api.call_args_list[2].kwargs["data"]["variables"]["cursor"], "next-page")

    def test_reads_later_label_pages_on_the_referenced_issue(self):
        with mock.patch.object(routing, "_api", side_effect=[
            self.member(), self.linked(1),
            self.issue(accepted=False, cursor="next-page"), self.issue(),
        ]) as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr()))
        self.assertEqual(api.call_args.kwargs["data"]["variables"]["cursor"], "next-page")

    def test_cross_repository_references_do_not_qualify(self):
        with mock.patch.object(routing, "_api", side_effect=[
            self.member(), self.linked(1, repository="other/repo"),
        ]) as api:
            self.assertFalse(routing._accepted_work(REPO, 42, pr(body=(
                "Related to other/repo#1 and https://github.com/other/repo/issues/1"
            ))))
        self.assertEqual(api.call_count, 2)

    def test_missing_issues_do_not_qualify_and_other_graphql_errors_propagate(self):
        for error_type in ("NOT_FOUND", "FORBIDDEN"):
            error = subprocess.CalledProcessError(
                1, "gh", output=json.dumps({"errors": [{"type": error_type}]}),
            )
            with (
                self.subTest(error_type=error_type),
                mock.patch.object(routing, "_api", side_effect=[
                    self.member(), error, self.linked(),
                ]),
            ):
                if error_type == "NOT_FOUND":
                    self.assertFalse(routing._accepted_work(REPO, 42, pr(body="See #1")))
                else:
                    with self.assertRaises(subprocess.CalledProcessError):
                        routing._accepted_work(REPO, 42, pr(body="See #1"))

    def test_pull_request_references_do_not_qualify(self):
        with mock.patch.object(routing, "_api", side_effect=[
            self.member(), {"data": {"repository": {"issueOrPullRequest": {}}}},
            self.linked(),
        ]):
            self.assertFalse(routing._accepted_work(REPO, 42, pr(body="See #1")))

    def test_missing_description_reference_falls_back_to_qualifying_closing_link(self):
        missing = subprocess.CalledProcessError(
            1, "gh", output=json.dumps({"errors": [{"type": "NOT_FOUND"}]}),
        )
        with mock.patch.object(routing, "_api", side_effect=[
            self.member(), missing, self.linked(2), self.issue(),
        ]):
            self.assertTrue(routing._accepted_work(REPO, 42, pr(body="Related to #1")))

    def test_creation_and_ready_transition_reject_before_reviewer_changes(self):
        for event in ("opened", "ready_for_review"):
            for apply in (False, True):
                with (
                    self.subTest(event=event, apply=apply),
                    mock.patch.object(routing, "_api", side_effect=[pr(), DRAFTED]) as api,
                    mock.patch.object(routing, "_accepted_work", return_value=False),
                    mock.patch.object(routing, "_load_reviewers") as load,
                ):
                    with self.assertRaisesRegex(ValueError, "not accepted work"):
                        routing.check_review_readiness(ROSTER, REPO, 42, apply=apply, event=event)
                    load.assert_not_called()
                    self.assertEqual(api.call_count, 2 if apply else 1)
                    if apply:
                        self.assertIn("convertPullRequestToDraft", api.call_args.kwargs["data"]["query"])
                        self.assertEqual(api.call_args.kwargs["data"]["variables"], {"id": "PR_node_42"})

    def test_lookup_errors_fail_without_drafting_or_requesting_reviewers(self):
        with (
            mock.patch.object(routing, "_api", side_effect=[
                pr(), subprocess.CalledProcessError(1, "gh"),
            ]) as api,
            mock.patch.object(routing, "_load_reviewers") as load,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            routing.check_review_readiness(ROSTER, REPO, 42, apply=True)
        self.assertEqual(api.call_count, 2)
        load.assert_not_called()

    def test_draft_conversion_errors_propagate(self):
        with (
            mock.patch.object(routing, "_api", side_effect=[pr(), subprocess.CalledProcessError(1, "gh")]),
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

    def run_routing(self, categories, *, snapshots, responses, apply=True, event="opened"):
        self.parser.return_value = categories
        with (
            mock.patch.object(routing, "_api", side_effect=responses) as api,
            mock.patch.object(routing, "_load_reviewers", side_effect=snapshots) as load,
            mock.patch.object(
                routing, "_eligible_reviewers", side_effect=lambda _repo, logins: logins
            ) as eligible,
        ):
            plan = routing.check_review_readiness(self.roster, REPO, 42, apply=apply, event=event)
        return plan, api, load, eligible

    def test_initial_assignment_excludes_author_without_extra_refresh(self):
        plan, api, load, eligible = self.run_routing(
            CATEGORIES,
            snapshots=[reviewers()],
            responses=[pr("area:runtime", "topic:policy", author="ALICE"), None],
        )
        self.assertEqual(plan, routing.ReviewPlan(("bob", "carol"), ()))
        eligible.assert_called_once_with(REPO, {"bob", "carol"})
        load.assert_called_once()
        self.assertEqual(api.call_count, 2)
        self.assertEqual(
            api.call_args.kwargs,
            {"method": "POST", "data": {"reviewers": ["bob", "carol"]}},
        )

    def test_empty_area_does_not_block_topic_reviewers(self):
        categories = {"area:runtime": set(), "topic:policy": {"carol"}}
        plan, _, _, _ = self.run_routing(
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
                plan, _, _, _ = self.run_routing(
                    CATEGORIES, snapshots=[reviewers()],
                    responses=[pr("area:build"), None], event=event,
                )
                self.assertEqual(plan.add, ("dave",))
                accepted.assert_not_called()

    def test_draft_and_closed_prs_skip_all_routing(self):
        for value in (pr(draft=True), pr(state="closed")):
            with self.subTest(value=value):
                plan, api, load, eligible = self.run_routing(
                    CATEGORIES, snapshots=[], responses=[value]
                )
                self.assertIsNone(plan)
                api.assert_called_once_with(PULL)
                load.assert_not_called()
                eligible.assert_not_called()

    def test_preview_makes_no_changes(self):
        plan, api, _, _ = self.run_routing(
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
        plan, api, _, _ = self.run_routing(
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
                    routing, "_load_reviewers",
                    return_value=reviewers(requested=("alice", "dave")),
                ),
                mock.patch.object(routing, "_eligible_reviewers", return_value={"dave"}),
            ):
                with self.assertRaisesRegex(ValueError, "routing changed"):
                    routing.check_review_readiness(self.roster, REPO, 42, apply=True)
                self.assertTrue(all(
                    call.kwargs.get("method", "GET") == "GET"
                    for call in api.call_args_list
                ))

    def test_new_commit_and_unrelated_label_do_not_interrupt_routing(self):
        before = pr("area:build", requested=("alice", "dave"))
        after = pr("area:build", "kind:bug", requested=("alice", "dave"))
        before["head"], after["head"] = {"sha": "old"}, {"sha": "new"}
        snapshots = [reviewers(requested=("alice", "dave"))] * 2
        plan, _, _, _ = self.run_routing(
            CATEGORIES, snapshots=snapshots, responses=[before, after, None]
        )
        self.assertEqual(plan.remove, ("alice",))

    def test_retry_after_partial_failure_uses_updated_github_metadata(self):
        before = pr("area:build", requested=("alice",))
        after = pr("area:build", requested=("alice", "dave"))
        snapshots = [
            reviewers(requested=("alice",)), reviewers(requested=("alice", "dave"))
        ]
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_routing(
                CATEGORIES,
                snapshots=snapshots,
                responses=[before, None, after, subprocess.CalledProcessError(1, "gh")],
            )
        plan, api, _, _ = self.run_routing(
            CATEGORIES, snapshots=[snapshots[1]] * 2, responses=[after, after, None]
        )
        self.assertEqual(plan, routing.ReviewPlan((), ("alice",)))
        self.assertFalse(any(
            call.kwargs.get("method") == "POST" for call in api.call_args_list
        ))


class CliTests(unittest.TestCase):
    def test_both_cli_modes_use_the_same_acceptance_policy(self):
        cases = [
            ("WRITE", "", (), {}, True),
            ("READ", "Related to #1", (), {1: ("author", True)}, True),
            ("READ", "Closes #1", (1,), {1: ("someone-else", True)}, False),
            ("READ", "Closes #1 and #2", (1, 2),
             {1: ("author", True), 2: ("author", False)}, True),
            ("READ", "Related to #1", (), {1: ("author", False)}, False),
            ("READ", "", (), {}, False),
        ]
        for acceptance_only in (False, True):
            for permission, body, linked, issues, expected in cases:
                with self.subTest(acceptance_only=acceptance_only, body=body, issues=issues), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "REVIEWERS.md"
                    path.write_text(DOCUMENT, encoding="utf-8")
                    value = pr("area:runtime", body=body)

                    def api(endpoint, **kwargs):
                        if endpoint == PULL:
                            return value
                        self.assertEqual(endpoint, "graphql")
                        query = kwargs["data"]["query"]
                        self.assertNotIn("mutation", query)
                        if "user: author" in query:
                            self.assertEqual(kwargs["data"]["variables"]["number"], 42)
                            return {"data": {"repository": {"pullRequest": value}}}
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
                        mock.patch.object(routing, "_eligible_reviewers", return_value={"alice"}) as eligible,
                        mock.patch.object(routing, "_load_reviewers", return_value=reviewers()) as load,
                        contextlib.redirect_stdout(output),
                        contextlib.redirect_stderr(errors),
                    ):
                        argv = ["--repo", REPO, "--pr", "42", "--reviewers", str(path)]
                        status = routing.main(argv + (["--acceptance-only"] if acceptance_only else []))
                    self.assertEqual(status, 0 if expected else 1)
                    if expected:
                        self.assertEqual(json.loads(output.getvalue()),
                                         {"accepted": True} if acceptance_only else {"add": ["alice"], "remove": []})
                    else:
                        self.assertIn(routing.ACCEPTANCE_ERROR, errors.getvalue())
                    if acceptance_only:
                        eligible.assert_not_called()
                        load.assert_not_called()

    def test_acceptance_only_checks_drafts_and_closed_prs_without_routing(self):
        for value in (pr(), pr(draft=True), pr(state="closed")):
            for accepted in (False, True):
                with self.subTest(value=value, accepted=accepted):
                    output, errors = io.StringIO(), io.StringIO()
                    with (
                        mock.patch.object(routing, "_graphql", return_value={"repository": {"pullRequest": value}}) as query,
                        mock.patch.object(routing, "_accepted_work", return_value=accepted) as check,
                        mock.patch.object(routing, "check_review_readiness") as route,
                        mock.patch.object(routing, "parse_reviewers") as parse,
                        mock.patch.object(routing.Path, "read_text", side_effect=AssertionError("Acceptance-only must not read the roster")),
                        contextlib.redirect_stdout(output),
                        contextlib.redirect_stderr(errors),
                    ):
                        status = routing.main(["--repo", REPO, "--pr", "42", "--acceptance-only"])
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
                mock.patch.object(routing, "_graphql", side_effect=error if metadata_error else None,
                                  return_value={"repository": {"pullRequest": pr()}}),
                mock.patch.object(routing, "_accepted_work", side_effect=error) as check,
                mock.patch.object(routing, "check_review_readiness") as route,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(routing.main(["--repo", REPO, "--pr", "42", "--acceptance-only"]), 1)
                route.assert_not_called()
                if metadata_error:
                    check.assert_not_called()

    def test_acceptance_only_cannot_be_combined_with_apply(self):
        with (
            mock.patch.object(routing, "_api") as api,
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as error,
        ):
            routing.main(["--repo", REPO, "--pr", "42", "--acceptance-only", "--apply"])
        self.assertEqual(error.exception.code, 2)
        api.assert_not_called()

    def test_acceptance_only_refreshes_metadata_for_each_pr_and_run(self):
        for number in (7, 8, 7):
            value = pr(body=f"Related to #{number}")
            with (
                self.subTest(number=number),
                mock.patch.object(routing, "_graphql", return_value={"repository": {"pullRequest": value}}) as query,
                mock.patch.object(routing, "_accepted_work", return_value=True) as check,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(routing.main([
                    "--repo", REPO, "--pr", str(number), "--acceptance-only",
                ]), 0)
            self.assertEqual(query.call_args.kwargs["number"], number)
            check.assert_called_once_with(REPO, number, value)

    def test_rejected_pr_does_not_need_a_readable_valid_roster(self):
        for contents in (None, "not a registry"):
            for apply in (False, True):
                with self.subTest(contents=contents, apply=apply), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "REVIEWERS.md"
                    if contents is not None:
                        path.write_text(contents, encoding="utf-8")
                    output, errors = io.StringIO(), io.StringIO()
                    with (
                        mock.patch.object(routing, "_api", side_effect=[pr(), DRAFTED]) as api,
                        mock.patch.object(routing, "_accepted_work", return_value=False),
                        mock.patch.object(routing, "parse_reviewers") as parse,
                        mock.patch.object(routing, "_load_reviewers") as load,
                        contextlib.redirect_stdout(output),
                        contextlib.redirect_stderr(errors),
                    ):
                        argv = ["--reviewers", str(path), "--repo", REPO, "--pr", "42"]
                        self.assertEqual(routing.main(argv + (["--apply"] if apply else [])), 1)
                    self.assertIn("not accepted work", errors.getvalue())
                    self.assertEqual(output.getvalue(), "")
                    parse.assert_not_called()
                    load.assert_not_called()
                    self.assertEqual(api.call_count, 2 if apply else 1)
                    if apply:
                        self.assertIn("convertPullRequestToDraft", api.call_args.kwargs["data"]["query"])

    def test_accepted_pr_reads_real_roster_and_previews_reviewers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text(DOCUMENT, encoding="utf-8")
            output = io.StringIO()
            with (
                mock.patch.object(routing, "_api", return_value=pr("area:runtime")) as api,
                mock.patch.object(routing, "_accepted_work", return_value=True) as accepted,
                mock.patch.object(routing, "_eligible_reviewers", return_value={"alice"}),
                mock.patch.object(routing, "_load_reviewers", return_value=reviewers()),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(routing.main([
                    "--reviewers", str(path), "--repo", REPO, "--pr", "42",
                ]), 0)
            accepted.assert_called_once()
            api.assert_called_once_with(PULL)
            self.assertEqual(json.loads(output.getvalue()), {"add": ["alice"], "remove": []})

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
                    self.assertEqual(routing.main([
                        "--reviewers", str(path), "--repo", REPO, "--pr", "42",
                    ]), 0)
                api.assert_called_once_with(PULL)
                accepted.assert_not_called()
                self.assertEqual(json.loads(output.getvalue()), {"skipped": "closed or draft PR"})

    def test_passes_label_event_to_reconciliation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text(DOCUMENT, encoding="utf-8")
            with (
                mock.patch.object(
                    routing, "check_review_readiness",
                    return_value=routing.ReviewPlan((), ()),
                ) as check,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(routing.main([
                    "--reviewers", str(path), "--repo", REPO, "--pr", "42",
                    "--event", "labeled", "--apply",
                ]), 0)
            self.assertEqual(check.call_args.kwargs, {"apply": True, "event": "labeled"})

    def test_emits_plan_and_passes_apply_option(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text(DOCUMENT, encoding="utf-8")
            output = io.StringIO()
            with (
                mock.patch.object(
                    routing, "check_review_readiness",
                    return_value=routing.ReviewPlan(("alice",), ()),
                ) as check,
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(
                    routing.main([
                        "--reviewers", str(path), "--repo", REPO,
                        "--pr", "42", "--apply",
                    ]),
                    0,
                )
            self.assertEqual(
                json.loads(output.getvalue()), {"add": ["alice"], "remove": []}
            )
            check.assert_called_once_with(
                path, REPO, 42, apply=True, event="opened"
            )

    def test_accepted_pr_with_invalid_registry_fails_before_reviewer_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text("not a registry", encoding="utf-8")
            output, errors = io.StringIO(), io.StringIO()
            with (
                mock.patch.object(routing, "_api", return_value=pr("area:runtime")) as api,
                mock.patch.object(routing, "_accepted_work", return_value=True),
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(errors),
            ):
                self.assertEqual(
                    routing.main([
                        "--reviewers", str(path), "--repo", REPO, "--pr", "42",
                    ]),
                    1,
                )
            api.assert_called_once_with(PULL)
            self.assertEqual(output.getvalue(), "")
            self.assertIn("no area/topic", errors.getvalue())


class WorkflowTests(unittest.TestCase):
    def test_legacy_workflow_keeps_its_status_events_and_read_only_permissions(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/pr-issue-acceptance.yml").read_text()
        self.assertIn("name: PR Issue Acceptance\n", workflow)
        self.assertIn("    name: OpenShell / PR Issue Acceptance\n", workflow)
        self.assertIn("types: [opened, edited, reopened, synchronize]", workflow)
        permissions = workflow.split("permissions:\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(dict(line.strip().split(": ") for line in permissions.splitlines()),
                         {"contents": "read", "issues": "read", "pull-requests": "read"})
        self.assertIn("ref: ${{ github.sha }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("sparse-checkout: tasks/scripts/check_review_readiness.py", workflow)
        self.assertIn("GH_REPO: ${{ github.repository }}", workflow)
        self.assertIn("PR_NUMBER: ${{ github.event.pull_request.number }}", workflow)
        command = workflow.split("        run: |\n", 1)[1]
        self.assertIn("python3 tasks/scripts/check_review_readiness.py", command)
        self.assertIn('--repo "$GH_REPO" --pr "$PR_NUMBER" --acceptance-only', command)
        self.assertNotIn("--apply", command)


if __name__ == "__main__":
    unittest.main()
