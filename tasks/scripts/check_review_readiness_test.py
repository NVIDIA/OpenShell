# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for registry parsing and PR reviewer reconciliation (stdlib only)."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check_review_readiness as registry

HEADER = "| Name | GitHub ID | Company/Organization |\n| --- | --- | --- |\n"
ALICE = "| Alice | [@Alice](https://github.com/alice) | Example |\n"
DOCUMENT = (
    "# Reviewers\n\n## Areas\n\n### area:runtime\n\nWorkload execution.\n\n"
    + HEADER
    + ALICE
)


class RegistryTests(unittest.TestCase):
    def test_preserves_scope_and_identity_but_normalizes_logins(self):
        category = registry.parse_reviewers(DOCUMENT)[0]
        self.assertEqual(category.label, "area:runtime")
        self.assertEqual(category.description, "Workload execution.")
        self.assertEqual(
            category.members, (registry.Member("Alice", "alice", "Example"),)
        )

    def test_same_member_can_belong_to_several_categories(self):
        markdown = (
            DOCUMENT + "\n## Topics\n\n### topic:policy\n\nPolicy scope.\n\n" + HEADER + ALICE
        )
        categories = registry.parse_reviewers(markdown)
        self.assertEqual(
            [c.label for c in categories], ["area:runtime", "topic:policy"]
        )
        self.assertEqual([c.members[0].login for c in categories], ["alice", "alice"])

    def test_multiline_scope_and_multiple_paragraphs(self):
        scope = "Workload execution\nand isolation.\n\nProvider lifecycle."
        text = DOCUMENT.replace("Workload execution.", scope)
        self.assertEqual(registry.parse_reviewers(text)[0].description, scope)

    def test_explicitly_empty_category_is_valid(self):
        self.assertEqual(
            registry.parse_reviewers(DOCUMENT.replace(ALICE, ""))[0].members, ()
        )

    def test_prose_code_and_comments_cannot_add_members(self):
        examples = (
            "Thanks [@outside](https://github.com/outside).\n\n"
            "<!--\n" + HEADER
            + "| Other | [@other](https://github.com/other) | Example |\n-->\n"
            "```markdown\n### topic:fake\n" + HEADER + ALICE + "```\n"
            "~~~\n" + HEADER + ALICE + "~~~\n"
        )
        text = DOCUMENT.replace("Workload execution.", examples + "Workload execution.")
        result = registry.parse_reviewers(text)
        self.assertEqual(len(result), 1)
        self.assertEqual([m.login for m in result[0].members], ["alice"])

    def test_comments_between_members_do_not_end_the_table(self):
        other = "| Other | [@other](https://github.com/other) | Example |\n"
        text = DOCUMENT + "<!-- nomination note -->\n" + other
        self.assertEqual(
            [m.login for m in registry.parse_reviewers(text)[0].members],
            ["alice", "other"],
        )

    def test_profile_links_outside_category_tables_do_not_count(self):
        text = "[@outside](https://github.com/outside)\n\n" + DOCUMENT
        self.assertEqual(
            [m.login for m in registry.parse_reviewers(text)[0].members], ["alice"]
        )

    def test_escaped_pipes_and_aligned_separator(self):
        text = DOCUMENT.replace("| --- | --- | --- |", "| :--- | :---: | ---: |")
        text = text.replace("| Example |", r"| Example\|Labs |")
        self.assertEqual(
            registry.parse_reviewers(text)[0].members[0].organization, "Example|Labs"
        )

    def test_profile_case_and_trailing_slash_are_accepted(self):
        text = DOCUMENT.replace("https://github.com/alice", "https://github.com/ALICE/")
        self.assertEqual(registry.parse_reviewers(text)[0].members[0].login, "alice")

    def test_rejects_rows_with_ambiguous_or_invalid_identity(self):
        invalid = [
            ALICE.replace("/alice)", "/someone-else)"),
            ALICE.replace("https://github.com/alice", "https://github.com/alice/repo"),
            ALICE.replace("https://github.com/alice", "https://github.com.evil/alice"),
            ALICE.replace("https://github.com/alice", "http://github.com/alice"),
            ALICE.replace("[@Alice](https://github.com/alice)", "@Alice"),
            ALICE.replace(
                "[@Alice](https://github.com/alice)",
                "[@Alice](https://github.com/alice) extra",
            ),
            ALICE.replace("| Alice |", "| |"),
            ALICE.replace("| Example |", "| |"),
        ]
        for row in invalid:
            with self.subTest(row=row), self.assertRaises(registry.RegistryError):
                registry.parse_reviewers(DOCUMENT.replace(ALICE, row))

    def test_rejects_duplicate_members_case_insensitively(self):
        with self.assertRaisesRegex(registry.RegistryError, "duplicate member @alice"):
            registry.parse_reviewers(DOCUMENT + ALICE.replace("@Alice", "@alice"))

    def test_rejects_bad_table_structure(self):
        invalid = [
            DOCUMENT.replace(HEADER, ""),
            DOCUMENT.replace("| --- | --- | --- |\n", ""),
            DOCUMENT.replace("| GitHub ID |", "| Role |"),
            DOCUMENT.replace("| --- | --- | --- |", "| --- | --- |"),
            DOCUMENT.replace(ALICE, ALICE.rstrip().rstrip("|") + "\n"),
            DOCUMENT.replace(ALICE, ALICE.removeprefix("|")),
            DOCUMENT.replace(ALICE, ALICE.rstrip() + " Extra |\n"),
            DOCUMENT + "\n" + HEADER + ALICE,
        ]
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(registry.RegistryError):
                registry.parse_reviewers(text)

    def test_rejects_duplicate_or_misplaced_categories(self):
        invalid = [
            DOCUMENT + "\n### area:runtime\n\nOther scope.\n\n" + HEADER,
            DOCUMENT.replace("area:runtime", "topic:runtime"),
            DOCUMENT.replace("area:runtime", "area:Runtime"),
            DOCUMENT.replace("area:runtime", "area:runtime_"),
            DOCUMENT.replace("## Areas\n", ""),
            DOCUMENT + "\n## Areas\n",
        ]
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(registry.RegistryError):
                registry.parse_reviewers(text)

    def test_rejects_missing_scope_or_no_registry(self):
        for text in [DOCUMENT.replace("Workload execution.", ""), "# Reviewers\n", ""]:
            with self.subTest(text=text), self.assertRaises(registry.RegistryError):
                registry.parse_reviewers(text)

    def test_rejects_unterminated_comments_and_examples(self):
        for suffix in ["\n<!--", "\n```markdown", "\n~~~~"]:
            with self.subTest(suffix=suffix), self.assertRaises(registry.RegistryError):
                registry.parse_reviewers(DOCUMENT + suffix)

    def test_errors_identify_source_line(self):
        with self.assertRaisesRegex(
            registry.RegistryError, r"line 11: .*same GitHub profile"
        ):
            registry.parse_reviewers(DOCUMENT.replace("/alice)", "/other)"))

def category(label, *logins):
    return registry.Category(
        label,
        "Scope.",
        tuple(registry.Member(login, login, "Example") for login in logins),
    )


CATEGORIES = (
    category("area:runtime", "alice", "bob"),
    category("area:build", "dave"),
    category("topic:policy", "bob", "carol"),
)


def context(
    *labels,
    requested=(),
    engaged=(),
    manual=(),
    author="author",
    draft=False,
    state="open",
):
    return {
        "pull_request": {
            "state": state,
            "draft": draft,
            "user": {"login": author},
            "head": {"sha": "commit"},
            "labels": [{"name": label} for label in labels],
        },
        "requested": set(requested),
        "engaged": set(engaged),
        "manual": set(manual),
    }


class RoutingTests(unittest.TestCase):
    def plan(self, snapshot, *, eligible=("alice", "bob", "carol", "dave")):
        return registry.plan_review_requests(
            CATEGORIES, **snapshot, eligible=set(eligible)
        )

    def test_initial_requests_all_matching_members_deduplicated(self):
        plan = self.plan(context("area:runtime", "topic:policy", "kind:bug"))
        self.assertTrue(plan.ready)
        self.assertEqual(plan.add, ("alice", "bob", "carol"))
        self.assertEqual(plan.remove, ())

    def test_author_and_engaged_people_are_not_requested(self):
        plan = self.plan(
            context("area:runtime", "topic:policy", author="ALICE", engaged=("BOB",))
        )
        self.assertEqual(plan.add, ("carol",))

    def test_label_change_preserves_manual_and_engaged_requests(self):
        plan = self.plan(
            context(
                "area:build",
                requested=("alice", "bob", "manual"),
                engaged=("BOB",),
                manual=("MANUAL",),
            ),
        )
        self.assertEqual(plan.add, ("dave",))
        self.assertEqual(plan.remove, ("alice",))
        self.assertEqual(plan.keep, ("bob", "manual"))
        self.assertEqual(plan.manual, ("manual",))

    def test_repeated_run_preserves_manual_requests_and_is_idempotent(self):
        snapshot = context(
            "area:runtime", requested=("alice", "bob", "manual"), manual=("manual",)
        )
        plan = self.plan(snapshot)
        self.assertEqual(plan.add, ())
        self.assertEqual(plan.remove, ())
        self.assertEqual(plan.manual, ("manual",))

    def test_matching_reviewer_manually_removed_is_not_requested_again(self):
        plan = self.plan(context("area:runtime", manual=("alice",)))
        self.assertEqual(plan.add, ("bob",))

    def test_missing_multiple_and_unknown_routing_labels_fail(self):
        cases = [
            (),
            ("topic:policy",),
            ("area:runtime", "area:build"),
            ("area:unknown",),
            ("area:runtime", "topic:unknown"),
        ]
        for labels in cases:
            with (
                self.subTest(labels=labels),
                self.assertRaises(registry.ReadinessError),
            ):
                self.plan(context(*labels))

    def test_draft_and_closed_prs_are_untouched_even_without_labels(self):
        for overrides in ({"draft": True}, {"state": "closed"}):
            with self.subTest(overrides=overrides):
                plan = self.plan(
                    context(requested=("alice",), **overrides)
                )
                self.assertFalse(plan.ready)
                self.assertEqual(
                    (plan.add, plan.remove, plan.keep), ((), (), ("alice",))
                )

    def test_permissions_filter_members_and_area_requires_eligible_non_author(self):
        plan = self.plan(context("area:runtime", "topic:policy"), eligible=("alice",))
        self.assertEqual(plan.add, ("alice",))
        self.assertEqual(plan.ineligible, ("bob", "carol"))
        with self.assertRaisesRegex(registry.ReadinessError, "primary area"):
            self.plan(context("area:runtime", "topic:policy"), eligible=("carol",))
        with self.assertRaisesRegex(registry.ReadinessError, "primary area"):
            self.plan(context("area:runtime", author="alice"), eligible=("alice",))

    def test_any_review_state_general_or_inline_comment_counts_as_engaged(self):
        reviews = [
            {"user": {"login": state}, "state": state}
            for state in
            ("APPROVED", "CHANGES_REQUESTED", "DISMISSED", "COMMENTED", "PENDING")
        ]
        result = registry.engaged_reviewers(
            reviews,
            [{"user": {"login": "General"}}, {"user": None}],
            [{"user": {"login": "Inline"}}],
        )
        self.assertEqual(
            result,
            {"approved", "changes_requested", "dismissed", "commented", "pending",
             "general", "inline"},
        )


def request_event(number, login, *, manual=False, removed=False):
    return {
        "id": number,
        "event": "review_request_removed" if removed else "review_requested",
        "actor": {
            "login": "maintainer" if manual else "workflow[bot]",
            "type": "User" if manual else "Bot",
        },
        "requested_reviewer": {"login": login},
    }


class TimelineTests(unittest.TestCase):
    def test_separates_human_and_bot_requests(self):
        events = [request_event(1, "Alice", manual=True), request_event(2, "Bob")]
        self.assertEqual(
            registry.manual_reviewers(events, {"alice", "bob"}), {"alice"}
        )

    def test_unknown_actor_and_missing_history_preserve_requests(self):
        event = request_event(1, "alice")
        event["actor"] = None
        self.assertEqual(
            registry.manual_reviewers([event], {"alice", "bob"}), {"alice", "bob"}
        )

    def test_human_replaces_automatic_request(self):
        events = [
            request_event(1, "alice"),
            request_event(2, "alice", manual=True, removed=True),
            request_event(3, "alice", manual=True),
        ]
        self.assertEqual(registry.manual_reviewers(events, {"alice"}), {"alice"})

    def test_bot_re_request_does_not_erase_existing_human_request(self):
        events = [request_event(1, "alice", manual=True), request_event(2, "alice")]
        self.assertEqual(registry.manual_reviewers(events, {"alice"}), {"alice"})

    def test_manual_removal_is_preserved_and_automatic_removal_is_not(self):
        events = [
            request_event(1, "alice"),
            request_event(2, "bob"),
            request_event(3, "alice", manual=True, removed=True),
            request_event(4, "bob", removed=True),
        ]
        self.assertEqual(registry.manual_reviewers(events, set()), {"alice"})

    def test_completed_request_cycle_does_not_protect_later_automatic_request(self):
        events = [
            request_event(1, "alice", manual=True),
            request_event(2, "alice", removed=True),
            request_event(3, "alice"),
        ]
        self.assertEqual(registry.manual_reviewers(events, {"alice"}), set())

    def test_orders_changes_by_event_id_and_ignores_team_and_unrelated_events(self):
        events = [
            request_event(3, "alice", manual=True),
            {"event": "review_requested", "id": 4, "requested_team": {"slug": "team"}},
            request_event(2, "alice", removed=True),
            {"event": "commented", "id": 9},
            request_event(1, "alice"),
        ]
        self.assertEqual(registry.manual_reviewers(events, {"alice"}), {"alice"})


class GitHubTests(unittest.TestCase):
    def test_api_paginates_array_and_object_feeds(self):
        feeds = (
            ([[{"login": "a"}], [{"login": "b"}]], None),
            ([{"users": [{"login": "a"}]}, {"users": [{"login": "b"}]}], "users"),
        )
        for pages, collection in feeds:
            with (
                self.subTest(collection=collection),
                mock.patch.object(registry.subprocess, "run") as run,
            ):
                run.return_value.stdout = json.dumps(pages)
                self.assertEqual(
                    registry._api("endpoint", pages=True, collection=collection),
                    [{"login": "a"}, {"login": "b"}],
                )
                self.assertIn("--paginate", run.call_args.args[0])
                self.assertIn("--slurp", run.call_args.args[0])

    def test_load_context_reads_all_engagement_feeds_and_only_user_requests(self):
        pr = context("area:runtime")["pull_request"]
        responses = [
            pr,
            [{"login": "Manual"}],
            [{"user": {"login": "Reviewer"}}],
            [{"user": {"login": "Commenter"}}],
            [{"user": {"login": "Inline"}}],
            [request_event(1, "Manual", manual=True)],
        ]
        with mock.patch.object(registry, "_api", side_effect=responses) as api:
            snapshot = registry._load_context("owner/repo", 42)
        self.assertEqual(snapshot["requested"], {"manual"})
        self.assertEqual(snapshot["engaged"], {"reviewer", "commenter", "inline"})
        self.assertEqual(snapshot["manual"], {"manual"})
        self.assertTrue(all(call.kwargs["pages"] for call in api.call_args_list[1:]))
        self.assertIn("/timeline?per_page=100", api.call_args.args[0])

    def test_only_current_write_maintain_admin_permissions_are_eligible(self):
        responses = [
            {"permission": role}
            for role in ("admin", "maintain", "read", "triage", "write")
        ]
        with mock.patch.object(registry, "_api", side_effect=responses):
            self.assertEqual(
                registry._eligible_reviewers("owner/repo", {"a", "b", "c", "d", "e"}),
                {"a", "b", "e"},
            )


class ReconciliationTests(unittest.TestCase):
    def apply(self, snapshot, *, snapshots, responses=None):
        with (
            mock.patch.object(registry, "_load_context", side_effect=snapshots),
            mock.patch.object(registry, "_api", side_effect=responses) as api,
        ):
            plan = registry._apply_plan(
                repository="owner/repo",
                number=42,
                context=snapshot,
                categories=CATEGORIES,
                eligible={"alice", "bob", "carol", "dave"},
            )
        return plan, api

    def test_engagement_and_manual_request_between_plan_and_delete_protect_reviewers(self):
        snapshot = context("area:build", requested=("alice", "bob", "carol"))
        latest = context(
            "area:build",
            requested=("alice", "bob", "carol", "dave"),
            engaged=("bob",),
            manual=("carol",),
        )
        plan, api = self.apply(snapshot, snapshots=[snapshot, latest])
        self.assertEqual(plan.remove, ("alice",))
        self.assertEqual(plan.keep, ("bob", "carol", "dave"))
        self.assertEqual(plan.manual, ("carol",))
        endpoint = "repos/owner/repo/pulls/42/requested_reviewers"
        self.assertEqual(
            api.call_args_list,
            [
                mock.call(endpoint, method="POST", data={"reviewers": ["dave"]}),
                mock.call(endpoint, method="DELETE", data={"reviewers": ["alice"]}),
            ],
        )

    def test_routing_change_before_apply_prevents_all_writes(self):
        before = context("area:runtime")
        changed = context("area:build")
        with (
            mock.patch.object(registry, "_load_context", return_value=changed),
            mock.patch.object(registry, "_api") as api,
        ):
            with self.assertRaisesRegex(registry.ReadinessError, "PR changed"):
                registry._apply_plan(
                    repository="owner/repo",
                    number=42,
                    context=before,
                    categories=CATEGORIES,
                    eligible={"alice", "bob"},
                )
            api.assert_not_called()

    def test_human_removal_before_first_write_is_preserved(self):
        snapshot = context("area:build")
        latest = context("area:build", manual=("dave",))
        plan, api = self.apply(snapshot, snapshots=[latest, latest])
        self.assertEqual(plan.add, ())
        api.assert_not_called()

    def test_review_completed_after_addition_is_not_requested_again(self):
        snapshot = context("area:build")
        latest = context("area:build", engaged=("dave",))
        plan, api = self.apply(snapshot, snapshots=[snapshot, latest])
        self.assertEqual(plan.keep, ())
        self.assertEqual(plan.engaged, ("dave",))
        self.assertEqual(api.call_count, 1)

    def test_partial_failure_is_reconciled_from_github_on_next_run(self):
        snapshot = context("area:build", requested=("alice",))
        latest = context("area:build", requested=("alice", "dave"))
        with self.assertRaises(subprocess.CalledProcessError):
            self.apply(
                snapshot,
                snapshots=[snapshot, latest],
                responses=[None, subprocess.CalledProcessError(1, "gh")],
            )
        plan, api = self.apply(latest, snapshots=[latest, latest])
        self.assertEqual(plan.add, ())
        self.assertEqual(plan.remove, ("alice",))
        api.assert_called_once_with(
            "repos/owner/repo/pulls/42/requested_reviewers",
            method="DELETE",
            data={"reviewers": ["alice"]},
        )


class CliTests(unittest.TestCase):
    def test_default_mode_previews_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text(DOCUMENT, encoding="utf-8")
            output = io.StringIO()
            with (
                mock.patch.object(
                    registry, "_load_context", return_value=context("area:runtime")
                ),
                mock.patch.object(registry, "_eligible_reviewers", return_value={"alice"}),
                mock.patch.object(registry, "_api") as api,
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(
                    registry.main([
                        "--reviewers", str(path), "--repo", "owner/repo", "--pr", "42",
                    ]),
                    0,
                )
            self.assertEqual(json.loads(output.getvalue())["add"], ["alice"])
            api.assert_not_called()

    def test_apply_uses_github_metadata_without_a_state_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text(DOCUMENT, encoding="utf-8")
            before = context("area:runtime")
            after = context("area:runtime", requested=("alice",))
            output = io.StringIO()
            with (
                mock.patch.object(
                    registry, "_load_context", side_effect=[before, before, after]
                ),
                mock.patch.object(registry, "_eligible_reviewers", return_value={"alice"}),
                mock.patch.object(registry, "_api") as api,
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(
                    registry.main([
                        "--reviewers", str(path), "--repo", "owner/repo", "--pr", "42",
                        "--apply",
                    ]),
                    0,
                )
            api.assert_called_once_with(
                "repos/owner/repo/pulls/42/requested_reviewers",
                method="POST",
                data={"reviewers": ["alice"]},
            )
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_invalid_registry_fails_before_contacting_github_without_partial_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            for content in [None, DOCUMENT.replace("/alice)", "/other)")]:
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                output, errors = io.StringIO(), io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    contextlib.redirect_stderr(errors),
                    mock.patch.object(registry, "_api") as api,
                ):
                    self.assertEqual(
                        registry.main([
                            "--reviewers", str(path), "--repo", "owner/repo", "--pr", "42",
                        ]),
                        1,
                    )
                self.assertEqual(output.getvalue(), "")
                self.assertIn("Review readiness:", errors.getvalue())
                api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
