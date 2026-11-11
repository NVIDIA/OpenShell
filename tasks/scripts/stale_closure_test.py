# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline contract tests for stale closure provenance."""
import copy
import unittest
from pathlib import Path

from stale_closure import STALE_CLOSURE_MARKER, is_stale_closed


class StaleClosureTests(unittest.TestCase):
    def setUp(self):
        self.issue = {'state': 'closed', 'state_reason': 'not_planned',
            'labels': [{'name': 'state:stale'}], 'closed_at': '2026-11-06T08:22:30Z',
            'closed_by': {'login': 'github-actions[bot]', 'type': 'Bot'}}
        self.event = {'__typename': 'ClosedEvent', 'createdAt': self.issue['closed_at'],
            'actor': {'login': 'github-actions[bot]'}, 'closer': None}
        self.comment = {'__typename': 'IssueComment', 'body': STALE_CLOSURE_MARKER,
            'author': {'login': 'github-actions[bot]', '__typename': 'Bot'},
            'createdAt': '2026-11-06T08:22:29Z', 'updatedAt': '2026-11-06T08:22:29Z'}

    def test_prose_and_day_counts_do_not_define_protocol(self):
        for prose in ('Closing after 7 days.', 'Expired after 900 days.', 'Different wording entirely.'):
            self.comment['body'] = prose + '\n' + STALE_CLOSURE_MARKER + '\n'
            self.assertTrue(is_stale_closed(self.issue, self.event, self.comment))

    def test_missing_copied_edited_and_wrong_version_markers_fail_closed(self):
        changes = [{'body': 'Closing after 14 days.'},
            {'body': '<!-- openshell:stale-closure:v2 -->'},
            {'body': '> ' + STALE_CLOSURE_MARKER},
            {'author': {'login': 'reader', '__typename': 'User'}},
            {'author': {'login': 'github-actions[bot]', '__typename': 'User'}},
            {'author': {'login': 'stale[bot]', '__typename': 'Bot'}},
            {'updatedAt': '2026-11-06T08:22:31Z'}]
        for change in changes:
            with self.subTest(change=change):
                self.assertFalse(is_stale_closed(self.issue, self.event, {**self.comment, **change}))
        self.assertFalse(is_stale_closed(self.issue, self.event))
        self.assertFalse(is_stale_closed(self.issue, None, self.comment))

    def test_comment_must_be_near_and_before_current_closure(self):
        for timestamp in ('2026-11-06T08:22:31Z', '2026-11-06T08:17:29Z',
                          '2020-01-01T00:00:00Z', 'invalid', None, '2026-11-06T08:22:29'):
            with self.subTest(timestamp=timestamp):
                comment = {**self.comment, 'createdAt': timestamp, 'updatedAt': timestamp}
                self.assertFalse(is_stale_closed(self.issue, self.event, comment))

    def test_issue_and_event_must_agree(self):
        for target, changes in [('issue', {'state': 'open'}), ('issue', {'state_reason': 'completed'}),
                ('issue', {'labels': []}), ('issue', {'closed_at': None}),
                ('issue', {'closed_by': {'login': 'stale[bot]', 'type': 'Bot'}}),
                ('event', {'__typename': 'ReopenedEvent'}),
                ('event', {'actor': {'login': 'reader'}}),
                ('event', {'createdAt': '2026-11-06T08:22:28Z'}),
                ('event', {'closer': {'__typename': 'PullRequest'}})]:
            with self.subTest(target=target, changes=changes):
                issue, event = copy.deepcopy(self.issue), copy.deepcopy(self.event)
                (issue if target == 'issue' else event).update(changes)
                self.assertFalse(is_stale_closed(issue, event, self.comment))

    def test_workflow_emits_the_protocol_marker(self):
        workflow = Path(__file__).resolve().parents[2] / '.github/workflows/stale.yml'
        # Exercise the literal YAML block without adding a YAML dependency.
        block = workflow.read_text().split('          close-issue-message: |\n', 1)[1]
        lines = []
        for line in block.splitlines():
            if line and not line.startswith('            '): break
            lines.append(line[12:])
        self.comment['body'] = '\n'.join(lines)
        self.assertTrue(is_stale_closed(self.issue, self.event, self.comment))


if __name__ == '__main__':
    unittest.main()
