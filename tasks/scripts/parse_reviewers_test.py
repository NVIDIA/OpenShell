# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Behavioral tests for the offline reviewer registry parser (stdlib only)."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import parse_reviewers as registry

HEADER = "| Name | GitHub ID | Company/Organization |\n| --- | --- | --- |\n"
ALICE = "| Alice | [@Alice](https://github.com/alice) | Example |\n"
DOCUMENT = "# Reviewers\n\n## Areas\n\n### area:runtime\n\nWorkload execution.\n\n" + HEADER + ALICE


class RegistryTests(unittest.TestCase):
    def test_preserves_scope_and_identity_but_normalizes_logins(self):
        category = registry.parse_reviewers(DOCUMENT)[0]
        self.assertEqual(category.label, "area:runtime")
        self.assertEqual(category.description, "Workload execution.")
        self.assertEqual(category.members, (registry.Member("Alice", "alice", "Example"),))

    def test_same_member_can_belong_to_several_categories(self):
        markdown = DOCUMENT + "\n## Topics\n\n### topic:policy\n\nPolicy scope.\n\n" + HEADER + ALICE
        categories = registry.parse_reviewers(markdown)
        self.assertEqual([c.label for c in categories], ["area:runtime", "topic:policy"])
        self.assertEqual([c.members[0].login for c in categories], ["alice", "alice"])

    def test_multiline_scope_and_multiple_paragraphs(self):
        text = DOCUMENT.replace("Workload execution.", "Workload execution\nand isolation.\n\nProvider lifecycle.")
        self.assertEqual(registry.parse_reviewers(text)[0].description, "Workload execution\nand isolation.\n\nProvider lifecycle.")

    def test_explicitly_empty_category_is_valid(self):
        self.assertEqual(registry.parse_reviewers(DOCUMENT.replace(ALICE, ""))[0].members, ())

    def test_prose_code_and_comments_cannot_add_members(self):
        examples = (
            "Thanks [@outside](https://github.com/outside).\n\n"
            "<!--\n" + HEADER + "| Other | [@other](https://github.com/other) | Example |\n-->\n"
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
        self.assertEqual([m.login for m in registry.parse_reviewers(text)[0].members], ["alice"])

    def test_escaped_pipes_and_aligned_separator(self):
        text = DOCUMENT.replace("| --- | --- | --- |", "| :--- | :---: | ---: |")
        text = text.replace("| Example |", r"| Example\|Labs |")
        self.assertEqual(registry.parse_reviewers(text)[0].members[0].organization, "Example|Labs")

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
            ALICE.replace("[@Alice](https://github.com/alice)", "[@Alice](https://github.com/alice) extra"),
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
        with self.assertRaisesRegex(registry.RegistryError, r"line 11: .*same GitHub profile"):
            registry.parse_reviewers(DOCUMENT.replace("/alice)", "/other)"))

    def test_cli_emits_json_and_check_mode_validates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            path.write_text(DOCUMENT, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(registry.main(["--reviewers", str(path)]), 0)
            data = json.loads(output.getvalue())
            self.assertEqual(data["schema_version"], 1)
            self.assertEqual(data["categories"][0]["members"][0]["login"], "alice")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(registry.main(["--reviewers", str(path), "--check"]), 0)
            self.assertIn("1 categories and 1 memberships", output.getvalue())

    def test_cli_fails_without_partial_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "REVIEWERS.md"
            for content in [None, DOCUMENT.replace("/alice)", "/other)")]:
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                output, errors = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    self.assertEqual(registry.main(["--reviewers", str(path)]), 1)
                self.assertEqual(output.getvalue(), "")
                self.assertIn(str(path), errors.getvalue())


if __name__ == "__main__":
    unittest.main()
