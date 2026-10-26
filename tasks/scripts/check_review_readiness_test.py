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
                    mock.patch.object(routing, "_api", side_effect=[
                        self.member(), self.linked() if body else self.linked(1),
                        self.issue(author=author, accepted=accepted),
                    ]) as api,
                ):
                    self.assertEqual(routing._accepted_work(REPO, 42, pr(body=body)), expected)
                    self.assertEqual(api.call_args.kwargs["data"]["variables"]["number"], 1)

    def test_one_qualifying_issue_is_enough_and_duplicate_references_are_read_once(self):
        with mock.patch.object(routing, "_api", side_effect=[
            self.member(), self.linked(1, 2), self.issue(accepted=False), self.issue(),
        ]) as api:
            self.assertTrue(routing._accepted_work(REPO, 42, pr(body="Related to #1 and #2")))
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
                    self.member(), self.linked(), error,
                ]),
            ):
                if error_type == "NOT_FOUND":
                    self.assertFalse(routing._accepted_work(REPO, 42, pr(body="See #1")))
                else:
                    with self.assertRaises(subprocess.CalledProcessError):
                        routing._accepted_work(REPO, 42, pr(body="See #1"))

    def test_pull_request_references_do_not_qualify(self):
        with mock.patch.object(routing, "_api", side_effect=[
            self.member(), self.linked(),
            {"data": {"repository": {"issueOrPullRequest": {}}}},
        ]):
            self.assertFalse(routing._accepted_work(REPO, 42, pr(body="See #1")))

    def test_creation_and_ready_transition_reject_before_reviewer_changes(self):
        for event in ("opened", "ready_for_review"):
            for apply in (False, True):
                with (
                    self.subTest(event=event, apply=apply),
                    mock.patch.object(routing, "_api", side_effect=[pr(), None]) as api,
                    mock.patch.object(routing, "_accepted_work", return_value=False),
                    mock.patch.object(routing, "_load_reviewers") as load,
                ):
                    with self.assertRaisesRegex(ValueError, "not accepted work"):
                        routing.check_review_readiness(CATEGORIES, REPO, 42, apply=apply, event=event)
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
            routing.check_review_readiness(CATEGORIES, REPO, 42, apply=True)
        self.assertEqual(api.call_count, 2)
        load.assert_not_called()

    def test_draft_conversion_errors_propagate(self):
        with (
            mock.patch.object(routing, "_api", side_effect=[pr(), subprocess.CalledProcessError(1, "gh")]),
            mock.patch.object(routing, "_accepted_work", return_value=False),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            routing.check_review_readiness(CATEGORIES, REPO, 42, apply=True)


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.accepted = mock.patch.object(routing, "_accepted_work", return_value=True)
        self.accepted.start()
        self.addCleanup(self.accepted.stop)

    def run_routing(self, categories, *, snapshots, responses, apply=True, event="opened"):
        with (
            mock.patch.object(routing, "_api", side_effect=responses) as api,
            mock.patch.object(routing, "_load_reviewers", side_effect=snapshots) as load,
            mock.patch.object(
                routing, "_eligible_reviewers", side_effect=lambda _repo, logins: logins
            ) as eligible,
        ):
            plan = routing.check_review_readiness(categories, REPO, 42, apply=apply, event=event)
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
                    routing.check_review_readiness(CATEGORIES, REPO, 42, apply=True)
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
                {"area:runtime": {"alice"}}, REPO, 42, apply=True, event="opened"
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
                    routing.main([
                        "--reviewers", str(path), "--repo", REPO, "--pr", "42",
                    ]),
                    1,
                )
            api.assert_not_called()
            self.assertEqual(output.getvalue(), "")
            self.assertIn("no area/topic", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
