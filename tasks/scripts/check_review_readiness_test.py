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
    *labels, requested=(), engaged=(), author="author", draft=False, state="open"
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
    }


class RoutingTests(unittest.TestCase):
    def plan(self, snapshot, *, managed=(), eligible=("alice", "bob", "carol", "dave")):
        return registry.plan_review_requests(
            CATEGORIES, **snapshot, eligible=set(eligible), managed=set(managed)
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

    def test_label_change_removes_only_obsolete_owned_unengaged_requests(self):
        plan = self.plan(
            context(
                "area:build", requested=("alice", "bob", "manual"), engaged=("BOB",)
            ),
            managed=("alice", "bob"),
        )
        self.assertEqual(plan.add, ("dave",))
        self.assertEqual(plan.remove, ("alice",))
        self.assertEqual(plan.keep, ("bob", "manual"))
        self.assertEqual(plan.managed_reviewers, ("bob", "dave"))

    def test_repeated_run_preserves_manual_ownership_and_is_idempotent(self):
        snapshot = context("area:runtime", requested=("alice", "bob", "manual"))
        plan = self.plan(snapshot, managed=("bob",))
        self.assertEqual(plan.add, ())
        self.assertEqual(plan.remove, ())
        self.assertEqual(plan.managed_reviewers, ("bob",))

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
                    context(requested=("alice",), **overrides), managed=("alice",)
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
        ]
        with mock.patch.object(registry, "_api", side_effect=responses) as api:
            snapshot = registry._load_context("owner/repo", 42)
        self.assertEqual(snapshot["requested"], {"manual"})
        self.assertEqual(snapshot["engaged"], {"reviewer", "commenter", "inline"})
        self.assertTrue(all(call.kwargs["pages"] for call in api.call_args_list[1:]))

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
    def apply(self, path, snapshot, *, managed, snapshots):
        with (
            mock.patch.object(registry, "_load_context", side_effect=snapshots),
            mock.patch.object(registry, "_api") as api,
        ):
            plan = registry._apply_plan(
                repository="owner/repo",
                number=42,
                state=path,
                context=snapshot,
                managed=set(managed),
                categories=CATEGORIES,
                eligible={"alice", "bob", "carol", "dave"},
            )
        return plan, api

    def test_engagement_between_plan_and_delete_protects_reviewer(self):
        snapshot = context("area:build", requested=("alice", "bob", "manual"))
        latest = context(
            "area:build", requested=("alice", "bob", "manual", "dave"), engaged=("bob",)
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            plan, api = self.apply(
                path, snapshot, managed=("alice", "bob"), snapshots=[snapshot, latest]
            )
            self.assertEqual(plan.remove, ("alice",))
            self.assertEqual(plan.keep, ("bob", "dave", "manual"))
            self.assertEqual(
                registry._read_managed(path, "owner/repo", 42), {"bob", "dave"}
            )
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
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(registry, "_load_context", return_value=changed),
            mock.patch.object(registry, "_api") as api,
        ):
            path = Path(directory) / "state.json"
            with self.assertRaisesRegex(registry.ReadinessError, "PR changed"):
                registry._apply_plan(
                    repository="owner/repo", number=42, state=path, context=before,
                    managed=set(), categories=CATEGORIES, eligible={"alice", "bob"},
                )
            api.assert_not_called()
            self.assertFalse(path.exists())

    def test_review_completed_after_addition_does_not_leave_stale_owned_request(self):
        snapshot = context("area:build")
        latest = context("area:build", engaged=("dave",))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            plan, _ = self.apply(
                path, snapshot, managed=(), snapshots=[snapshot, latest]
            )
            self.assertEqual(plan.managed_reviewers, ())
            self.assertEqual(registry._read_managed(path, "owner/repo", 42), set())

    def test_successful_additions_remain_owned_if_removal_fails(self):
        snapshot = context("area:build", requested=("alice",))
        latest = context("area:build", requested=("alice", "dave"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            with (
                mock.patch.object(
                    registry, "_load_context", side_effect=[snapshot, latest]
                ),
                mock.patch.object(
                    registry, "_api",
                    side_effect=[None, subprocess.CalledProcessError(1, "gh")],
                ),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    registry._apply_plan(
                        repository="owner/repo", number=42, state=path,
                        context=snapshot, managed={"alice"}, categories=CATEGORIES,
                        eligible={"dave"},
                    )
            self.assertEqual(
                registry._read_managed(path, "owner/repo", 42), {"alice", "dave"}
            )

    def test_state_cannot_be_reused_for_another_pr_or_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            registry._write_managed(path, "owner/repo", 42, {"alice"})
            for repository, number in (("owner/other", 42), ("owner/repo", 43)):
                with (
                    self.subTest(repository=repository, number=number),
                    self.assertRaises(registry.ReadinessError),
                ):
                    registry._read_managed(path, repository, number)
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(registry.ReadinessError):
                registry._read_managed(path, "owner/repo", 42)


class CliTests(unittest.TestCase):
    def test_default_mode_previews_without_writes_or_state_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text(DOCUMENT, encoding="utf-8")
            state = Path(directory) / "state.json"
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
                        "--state-file", str(state),
                    ]),
                    0,
                )
            self.assertEqual(json.loads(output.getvalue())["add"], ["alice"])
            self.assertFalse(state.exists())
            api.assert_not_called()

    def test_apply_requires_persisted_ownership_state(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            registry.main(["--repo", "owner/repo", "--pr", "42", "--apply"])

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
