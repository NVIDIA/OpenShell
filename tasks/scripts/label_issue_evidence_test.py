# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline evidence and lifecycle boundary tests."""
import base64
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from label_issue_evidence import expand_evidence, material_state, preflight, prepare_snapshot

REPO = 'Owner/Repo'
ROOT = f'repos/{REPO}'
MAINTAINERS = '| Maintainer | [@maintainer](https://github.com/maintainer) | Org |'
ROSTER = '### area:platform\n\nCLI and SDK.\n\n### topic:sdk\n\nSDK behavior.\n'


def encoded(text):
    return {'encoding': 'base64', 'content': base64.b64encode(text.encode()).decode()}


class API:
    def __init__(self, *, pull=False):
        self.calls = []
        self.item = {'number': 3, 'node_id': 'node', 'state': 'open', 'title': 'CLI', 'body': 'failure',
                     'user': {'login': 'maintainer'}, 'assignees': [], 'updated_at': 'ignore'}
        if pull:
            self.item['pull_request'] = {'url': 'pull'}
        self.pull = {**self.item, 'head': {'sha': 'head-one'}, 'base': {'sha': 'base-one'},
                     'merged_at': None, 'changed_files': 1}
        self.labels = ['state:accepted', 'area:old']
        self.definitions = [{'name': 'area:platform', 'node_id': 'LA'}, {'name': 'topic:sdk', 'node_id': 'LT'}]
        self.permissions = {'maintainer': 'admin', 'writer': 'write', 'reader': 'read'}
        self.collections = {'comments': [], 'timeline': [], 'files': [], 'reviews': [], 'review_comments': []}
        self.closing = []
        self.lifecycle_events = []
        self.fail = None

    def __call__(self, path, **kwargs):
        self.calls.append((path, kwargs))
        self.assert_read(kwargs)
        if self.fail and self.fail in path:
            raise RuntimeError('provider failed')
        if path == ROOT: return {'default_branch': 'main'}
        if path == f'{ROOT}/commits/main': return {'sha': 'trusted-sha'}
        if path == f'{ROOT}/contents/MAINTAINERS.md?ref=trusted-sha': return encoded(MAINTAINERS)
        if path == f'{ROOT}/contents/REVIEWERS.md?ref=trusted-sha': return encoded(ROSTER)
        if path == f'{ROOT}/contents/CONTRIBUTING.md?ref=trusted-sha': return encoded('Canonical contribution and acceptance policy.')
        if path == f'{ROOT}/issues/3': return copy.deepcopy(self.item)
        if path == f'{ROOT}/pulls/3': return copy.deepcopy(self.pull)
        if path == f'{ROOT}/issues/3/labels?per_page=100': return [{'name': name} for name in self.labels]
        if path == f'{ROOT}/labels?per_page=100': return copy.deepcopy(self.definitions)
        if '/collaborators/' in path:
            return {'permission': self.permissions.get(path.split('/')[-2], 'none')}
        if path == 'graphql':
            if 'closingIssuesReferences' in kwargs['data']['query']:
                return {'data': {'repository': {'pullRequest': {'closingIssuesReferences': {
                    'nodes': self.closing, 'pageInfo': {'hasNextPage': False, 'endCursor': None}}}}}}
            if 'timelineItems' in kwargs['data']['query']:
                return {'data': {'repository': {'issue': {'timelineItems': {
                    'nodes': self.lifecycle_events, 'pageInfo': {'hasPreviousPage': False, 'startCursor': None}}}}}}
            raise AssertionError(kwargs)
        for collection, route in (('comments', f'issues/3/comments'), ('timeline', 'issues/3/timeline'),
                                  ('files', 'pulls/3/files'), ('reviews', 'pulls/3/reviews'),
                                  ('review_comments', 'pulls/3/comments')):
            if path == f'{ROOT}/{route}?per_page=100':
                if kwargs.get('pages') is not True: raise AssertionError('collection not paginated')
                return copy.deepcopy(self.collections[collection])
        if path == f'{ROOT}/issues/8':
            return {'number': 8, 'node_id': 'linked-node', 'title': 'SDK request', 'body': 'Need SDK',
                    'state': 'open', 'user': {'login': 'maintainer'}, 'assignees': []}
        if path == f'{ROOT}/issues/8/labels?per_page=100': return [{'name': 'state:accepted'}]
        if path.startswith(f'{ROOT}/contents/src/example.py?ref=head-one'):
            return encoded('first\nsecond\nthird\nfourth\n')
        raise AssertionError(path)

    @staticmethod
    def assert_read(kwargs):
        if kwargs.get('method', 'GET') != 'GET':
            if not kwargs.get('data', {}).get('query', '').lstrip().startswith('query'):
                raise AssertionError('write attempted')


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.api = API()

    def prepare(self):
        return prepare_snapshot('https://github.com/Owner/Repo/issues/3', '3', Path(self.directory.name), api=self.api)

    def test_snapshot_pins_rosters_and_separates_labels(self):
        snapshot = self.prepare()
        self.assertEqual(snapshot['policy_revision'], 'trusted-sha')
        self.assertEqual(snapshot['evidence_index']['body']['content']['body'], 'failure')
        self.assertNotIn('area:old', str(snapshot['evidence_index']['body']))
        self.assertFalse(snapshot['evidence_index']['comments']['inspected'])
        self.assertEqual(snapshot['taxonomy']['areas']['area:platform'], 'CLI and SDK.')
        self.assertTrue((Path(self.directory.name) / 'manifest.json').exists())

    def test_preflight_open_work_does_not_fetch_optional_evidence(self):
        facts = preflight(REPO, 3, api=self.api, force=True)
        self.assertEqual(facts['eligibility']['lifecycle'], 'eligible')
        self.assertFalse(any('/comments?' in path or '/files?' in path or '/reviews?' in path or 'REVIEWERS' in path for path, _ in self.api.calls))

    def test_invalid_identity_rejected_before_api_access(self):
        for repository, number in [('https://evil.test/Owner/Repo', 3), ('https://github.com/Owner/Repo/pull/4', 3), (REPO, 0), ('bad', 3)]:
            with self.subTest(repository=repository, number=number), self.assertRaises(ValueError):
                preflight(repository, number, api=self.api)
        self.assertEqual(self.api.calls, [])

    def test_merged_pr_even_when_reverted_is_excluded(self):
        self.api = API(pull=True)
        self.api.pull.update(merged_at='date', body='Reverted later')
        self.assertEqual(preflight(REPO, 3, api=self.api, force=True)['eligibility']['lifecycle'], 'excluded')

    def test_completed_issue_is_excluded(self):
        self.api.item.update(state='closed', state_reason='completed')
        self.assertEqual(preflight(REPO, 3, api=self.api)['eligibility']['lifecycle'], 'excluded')

    def test_closed_author_only_holds_with_cited_author_comments(self):
        self.api.item.update(state='closed', state_reason='not_planned', closed_by={'login': 'reader', 'type': 'User'}, user={'login': 'reader'})
        self.api.collections['comments'] = [{'id': 7, 'body': 'I am abandoning this request.', 'user': {'login': 'reader'}, 'created_at': 't'}]
        snapshot = self.prepare()
        self.assertEqual(snapshot['eligibility']['lifecycle'], 'hold')
        artifact = snapshot['evidence_index']['comment:7']
        self.assertFalse(artifact['inspected'])
        self.assertEqual(artifact['actor_authority']['role'], 'author')

    def test_maintainer_not_planned_or_duplicate_is_excluded(self):
        for reason in ('not_planned', 'duplicate'):
            with self.subTest(reason=reason):
                self.api.item.update(state='closed', state_reason=reason, closed_by={'login': 'maintainer', 'type': 'User'})
                self.assertEqual(preflight(REPO, 3, api=self.api)['eligibility']['lifecycle'], 'excluded')

    def test_writer_closure_authority_is_verified_not_author_association(self):
        self.api.item.update(state='closed', state_reason='not_planned', closed_by={'login': 'writer', 'type': 'User'})
        facts = preflight(REPO, 3, api=self.api)
        self.assertEqual(facts['eligibility']['lifecycle'], 'excluded')
        self.assertTrue(any('/collaborators/writer/permission' in path for path, _ in self.api.calls))

    def stale_closure(self, login='github-actions[bot]'):
        timestamp = '2026-11-06T08:22:30Z'
        self.api.item.update(state='closed', state_reason='not_planned',
            labels=[{'name': 'state:stale'}], closed_at=timestamp,
            closed_by={'login': login, 'type': 'Bot'})
        self.api.lifecycle_events = [{'__typename': 'ClosedEvent', 'id': 'closed-3',
            'actor': {'login': login}, 'createdAt': timestamp, 'closer': None}]

    def test_stale_closure_uses_metadata_without_reading_comments(self):
        for login in ('github-actions[bot]', 'stale[bot]'):
            with self.subTest(login=login):
                self.stale_closure(login)
                self.api.calls.clear()
                self.api.collections['comments'] = [{'body': 'Arbitrary workflow wording.'}]
                self.assertEqual(preflight(REPO, 3, api=self.api)['eligibility']['lifecycle'], 'eligible')
                self.assertFalse(any('/comments?' in path for path, _ in self.api.calls))

    def test_stale_closure_requires_current_stale_label(self):
        for login in ('github-actions[bot]', 'stale[bot]'):
            with self.subTest(login=login):
                self.stale_closure(login)
                self.api.item['labels'] = [{'name': 'state:accepted'}]
                self.assertEqual(preflight(REPO, 3, api=self.api)['eligibility']['lifecycle'], 'hold')

    def test_stale_closure_requires_matching_bot_event(self):
        for changed in ('missing_event', 'event_actor', 'event_time', 'missing_time', 'not_bot', 'other_bot', 'reason'):
            with self.subTest(changed=changed):
                self.stale_closure()
                if changed == 'missing_event': self.api.lifecycle_events = []
                if changed == 'event_actor': self.api.lifecycle_events[0]['actor']['login'] = 'other[bot]'
                if changed == 'event_time': self.api.lifecycle_events[0]['createdAt'] = '2026-10-01T00:00:00Z'
                if changed == 'missing_time': del self.api.item['closed_at']
                if changed == 'not_bot': self.api.item['closed_by']['type'] = 'User'
                if changed == 'other_bot':
                    self.api.item['closed_by']['login'] = 'other[bot]'
                    self.api.lifecycle_events[0]['actor']['login'] = 'other[bot]'
                if changed == 'reason': self.api.item['state_reason'] = 'duplicate'
                self.assertEqual(preflight(REPO, 3, api=self.api)['eligibility']['lifecycle'], 'hold')

    def test_unrelated_bot_with_write_permission_is_not_human_rejection(self):
        self.api.item.update(state='closed', state_reason='not_planned', closed_by={'login': 'other-bot', 'type': 'Bot'})
        self.api.permissions['other-bot'] = 'write'
        self.assertEqual(preflight(REPO, 3, api=self.api)['eligibility']['lifecycle'], 'hold')

    def test_merged_closing_pr_is_resolution_even_with_ambiguous_state_reason(self):
        self.api.item.update(state='closed', state_reason='not_planned')
        self.api.lifecycle_events = [{'__typename': 'ClosedEvent', 'id': 'closed-1', 'actor': {'login': 'reader'},
            'closer': {'__typename': 'PullRequest', 'number': 9, 'merged': True, 'mergedAt': 'date', 'repository': {'nameWithOwner': REPO}}}]
        self.assertEqual(preflight(REPO, 3, api=self.api)['eligibility']['lifecycle'], 'excluded')

    def test_linked_issue_content_and_identity_are_snapshot_evidence(self):
        self.api = API(pull=True)
        self.api.closing = [{'number': 8, 'repository': {'nameWithOwner': REPO}}]
        snapshot = self.prepare()
        self.assertEqual(snapshot['head'], 'head-one')
        self.assertEqual(snapshot['linked_closing_issues'][0]['item_id'], 'linked-node')
        self.assertEqual(snapshot['evidence_index']['issue:Owner/Repo#8']['content']['body'], 'Need SDK')
        self.assertFalse(snapshot['evidence_index']['files']['inspected'])

    def test_comments_reviews_and_review_threads_get_stable_artifact_ids(self):
        self.api = API(pull=True)
        self.api.collections['comments'] = [{'id': 7, 'body': 'SDK concern', 'user': {'login': 'reader'}}]
        self.api.collections['reviews'] = [{'id': 9, 'body': 'Review concern', 'state': 'COMMENTED', 'user': {'login': 'maintainer'}}]
        self.api.collections['review_comments'] = [{'id': 10, 'body': 'Thread concern', 'path': 'src/a', 'user': {'login': 'writer'}}]
        snapshot = self.prepare()
        expand_evidence(snapshot, ['comments', 'reviews', 'review_comments'], api=self.api)
        for artifact_id in ('comment:7', 'review:9', 'review-comment:10'):
            self.assertIn(artifact_id, snapshot['evidence_index'])
            self.assertFalse(snapshot['evidence_index'][artifact_id]['inspected'])
        expand_evidence(snapshot, ['comment:7'], api=self.api)
        self.assertEqual(snapshot['evidence_index']['comment:7']['content']['body'], 'SDK concern')
        self.assertTrue(snapshot['evidence_index']['comment:7']['inspected'])

    def test_omitted_or_incomplete_patch_never_claims_complete_diff(self):
        self.api = API(pull=True)
        for patch in (None, '@@ -1,2 +1,2 @@\n-old\n+new'):
            with self.subTest(patch=patch):
                entry = {'filename': 'src/example.py', 'status': 'modified', 'additions': 10, 'deletions': 10, 'changes': 20}
                if patch is not None: entry['patch'] = patch
                self.api.collections['files'] = [entry]
                snapshot = self.prepare()
                expand_evidence(snapshot, ['files'], api=self.api)
                self.assertNotEqual(snapshot['evidence_index']['files']['coverage'], 'complete')
                self.assertNotEqual(snapshot['evidence_index']['patch:src/example.py']['coverage'], 'complete')
                self.assertEqual(snapshot['changed_paths'], ['src/example.py'])

    def test_complete_patch_and_pinned_focused_source_slice(self):
        self.api = API(pull=True)
        self.api.collections['files'] = [{'filename': 'src/example.py', 'status': 'modified', 'additions': 1, 'deletions': 1, 'changes': 2,
            'patch': '@@ -1 +1 @@\n-old\n+new'}]
        snapshot = self.prepare()
        expand_evidence(snapshot, ['files'], api=self.api)
        self.assertEqual(snapshot['evidence_index']['files']['coverage'], 'complete')
        expand_evidence(snapshot, ['source:src/example.py:2:3'], api=self.api)
        self.assertEqual(snapshot['evidence_index']['source:src/example.py:2:3']['content'], 'second\nthird\n')
        self.assertEqual(snapshot['evidence_index']['source:src/example.py:2:3']['coverage'], 'slice')

    def test_pagination_error_is_persisted_incomplete_and_propagated(self):
        snapshot = self.prepare()
        self.api.fail = '/comments?'
        with self.assertRaisesRegex(RuntimeError, 'provider failed'):
            expand_evidence(snapshot, ['comments'], api=self.api)
        self.assertEqual(snapshot['evidence_index']['comments']['coverage'], 'incomplete')
        stored = json.loads((Path(self.directory.name) / 'manifest.json').read_text())
        self.assertFalse(stored['evidence_index']['comments']['inspected'])

    def test_provider_file_cap_is_incomplete_against_changed_file_count(self):
        self.api = API(pull=True)
        self.api.pull['changed_files'] = 3001
        snapshot = self.prepare()
        expand_evidence(snapshot, ['files'], api=self.api)
        self.assertEqual(snapshot['evidence_index']['files']['coverage'], 'incomplete')

    def test_large_unicode_artifact_has_valid_bounded_json_and_honest_coverage(self):
        self.api.collections['comments'] = [{'id': 7, 'body': '\\"é' * 800000, 'user': {'login': 'reader'}}]
        snapshot = self.prepare()
        expand_evidence(snapshot, ['comments', 'comment:7'], api=self.api)
        entry = snapshot['evidence_index']['comment:7']
        self.assertEqual(entry['coverage'], 'truncated')
        self.assertLessEqual(len(json.dumps(entry['content'], ensure_ascii=False).encode()), 2 * 1024 * 1024)
        self.assertTrue(Path(entry['artifact_path']).exists())

    def test_narrow_malformed_candidates_preserve_workflow_labels(self):
        self.api.labels += ['aera:platform', 'topics:sdk', 'bug', 'help wanted', 'priority:high', 'topic:unknown']
        snapshot = self.prepare()
        self.assertEqual(snapshot['malformed_classification_labels'], ['aera:platform', 'topics:sdk'])

    def test_untrusted_api_assessment_marker_is_removed(self):
        self.api.definitions.append({'name': 'state:needs-info', 'assessment': True})
        snapshot = self.prepare()
        self.assertNotIn('assessment', snapshot['taxonomy']['definitions']['state:needs-info'])

    def test_open_author_intent_is_discoverable_without_inventing_disposition(self):
        self.api.collections['comments'] = [{'id': 7, 'body': 'I no longer plan to pursue this request.', 'user': {'login': 'maintainer'}}]
        snapshot = self.prepare()
        self.assertEqual(snapshot['eligibility']['lifecycle'], 'eligible')
        self.assertTrue(snapshot['evidence_index']['comment:7']['actor_authority']['verified'])

    def test_compact_packet_omits_uninspected_comment_content(self):
        self.api.collections['comments'] = [{'id': 7, 'body': 'A long unrelated discussion', 'user': {'login': 'reader'}}]
        snapshot = self.prepare()
        packet = json.loads(Path(snapshot['packet_path']).read_text())
        self.assertNotIn('content', packet['evidence_index']['comment:7'])
        self.assertIn('content', packet['evidence_index']['body'])

    def test_empty_or_headerless_patch_is_not_a_complete_diff(self):
        self.api = API(pull=True)
        for patch, additions in (('', 0), ('+new', 1)):
            self.api.collections['files'] = [{'filename': 'src/example.py', 'additions': additions,
                'deletions': 0, 'changes': additions, 'patch': patch}]
            snapshot = self.prepare()
            self.assertEqual(snapshot['evidence_index']['patch:src/example.py']['coverage'], 'partial')

    def test_large_author_comment_preserves_truncation_and_authority(self):
        self.api.item.update(state='closed', state_reason='not_planned', closed_by={'login': 'reader'}, user={'login': 'reader'})
        self.api.collections['comments'] = [{'id': 7, 'body': 'x' * 2200000, 'user': {'login': 'reader'}}]
        snapshot = self.prepare()
        self.assertEqual(snapshot['evidence_index']['comment:7']['coverage'], 'truncated')
        self.assertEqual(snapshot['evidence_index']['comment:7']['actor_authority']['role'], 'author')

    def test_policy_content_is_read_at_same_trusted_revision(self):
        self.prepare()
        self.assertTrue(any(path == f'{ROOT}/contents/CONTRIBUTING.md?ref=trusted-sha' for path, _ in self.api.calls))

    def test_comment_candidates_verify_collaborator_authority(self):
        self.api.collections['comments'] = [
            {'id': 7, 'body': 'We will not pursue this.', 'user': {'login': 'writer'}, 'author_association': 'COLLABORATOR'},
            {'id': 8, 'body': 'I claim authority.', 'user': {'login': 'reader'}, 'author_association': 'MEMBER'},
        ]
        snapshot = self.prepare()
        self.assertEqual(snapshot['evidence_index']['comment:7']['actor_authority']['permission'], 'write')
        self.assertEqual(snapshot['eligibility']['lifecycle'], 'eligible')

    def test_changed_paths_cannot_escape_pinned_source_boundary(self):
        self.api = API(pull=True)
        self.api.collections['files'] = [{'filename': '../secret', 'additions': 0, 'deletions': 0}]
        snapshot = self.prepare()
        with self.assertRaises(ValueError):
            expand_evidence(snapshot, ['source:../secret:1:2'], api=self.api)

    def test_files_reject_head_movement_during_retrieval(self):
        self.api = API(pull=True)
        original = self.api
        def moving_api(path, **kwargs):
            value = original(path, **kwargs)
            if path.endswith('/files?per_page=100'):
                original.pull['head']['sha'] = 'head-two'
            return value
        with self.assertRaisesRegex(ValueError, 'head'):
            prepare_snapshot(REPO, 3, Path(self.directory.name), api=moving_api)

    def test_later_file_expansion_rejects_a_new_head_before_fetch(self):
        self.api = API(pull=True)
        snapshot = self.prepare()
        self.api.pull['head']['sha'] = 'head-two'
        before = len([path for path, _ in self.api.calls if '/files?' in path])
        with self.assertRaisesRegex(ValueError, 'head'):
            expand_evidence(snapshot, ['files'], api=self.api)
        self.assertEqual(before, len([path for path, _ in self.api.calls if '/files?' in path]))
        self.assertEqual(snapshot['head'], 'head-one')

    def test_refresh_preserves_only_unchanged_inspection_and_removes_deleted_sources(self):
        self.api.collections['comments'] = [
            {'id': 7, 'body': 'unchanged', 'user': {'login': 'maintainer'}},
            {'id': 8, 'body': 'edited later', 'user': {'login': 'maintainer'}},
            {'id': 9, 'body': 'deleted later', 'user': {'login': 'maintainer'}},
        ]
        snapshot = self.prepare()
        expand_evidence(snapshot, ['comment:7', 'comment:8', 'comment:9'], api=self.api)
        self.api.collections['comments'] = [
            {'id': 7, 'body': 'unchanged', 'user': {'login': 'maintainer'}},
            {'id': 8, 'body': 'new intent', 'user': {'login': 'maintainer'}},
        ]
        expand_evidence(snapshot, ['comments'], api=self.api)
        self.assertTrue(snapshot['evidence_index']['comment:7']['inspected'])
        self.assertEqual(snapshot['evidence_index']['comment:7']['actor_authority']['role'], 'maintainer')
        self.assertFalse(snapshot['evidence_index']['comment:8']['inspected'])
        self.assertNotIn('comment:9', snapshot['evidence_index'])

    def test_truncated_body_comment_and_review_support_digest_bound_text_slices(self):
        self.api = API(pull=True)
        text = 'x' * 2200000 + 'THE END'
        self.api.pull['body'] = text
        self.api.collections['comments'] = [{'id': 7, 'body': text, 'user': {'login': 'reader'}}]
        self.api.collections['reviews'] = [{'id': 8, 'body': text, 'user': {'login': 'reader'}}]
        snapshot = self.prepare()
        expand_evidence(snapshot, ['reviews'], api=self.api)
        for source_id in ('body', 'comment:7', 'review:8'):
            entry = snapshot['evidence_index'][source_id]
            digest = entry['source_digest']
            request = f'text:{source_id}:{digest}:2200000:2200007'
            expand_evidence(snapshot, [request], api=self.api)
            self.assertEqual(snapshot['evidence_index'][request]['content'], 'THE END')
            self.assertEqual(snapshot['evidence_index'][request]['coverage'], 'slice')
            self.assertEqual(snapshot['evidence_index'][source_id]['coverage'], 'truncated')
            with self.assertRaises(ValueError):
                expand_evidence(snapshot, [f'text:{source_id}:{"0" * 64}:0:10'], api=self.api)

    def test_packet_aggregate_is_bounded_and_omitted_sources_remain_addressable(self):
        self.api.collections['comments'] = [
            {'id': 7, 'body': 'a' * 1100000, 'user': {'login': 'maintainer'}},
            {'id': 8, 'body': 'b' * 1100000, 'user': {'login': 'maintainer'}},
        ]
        snapshot = self.prepare()
        self.assertLessEqual(Path(snapshot['packet_path']).stat().st_size, 2 * 1024 * 1024)
        packet = json.loads(Path(snapshot['packet_path']).read_text())
        deferred = [entry for entry in packet['evidence_index'].values() if entry.get('content_deferred')]
        self.assertTrue(deferred)
        self.assertTrue(all(Path(entry['artifact_path']).exists() for entry in deferred))

    def test_material_state_is_independent_of_local_chunk_and_packet_paths(self):
        self.api.collections['comments'] = [{'id': 7, 'body': 'original', 'user': {'login': 'maintainer'}}]
        first = self.prepare()
        with tempfile.TemporaryDirectory() as directory:
            second = prepare_snapshot(REPO, 3, Path(directory), api=self.api)
            self.assertEqual(material_state(first), material_state(second))

    def test_text_slices_preserve_crlf_and_refuse_edited_parent_digests(self):
        self.api.collections['comments'] = [{'id': 7, 'body': 'a\r\nb', 'user': {'login': 'reader'}}]
        snapshot = self.prepare()
        digest = snapshot['evidence_index']['comment:7']['source_digest']
        request = f'text:comment:7:{digest}:1:4'
        expand_evidence(snapshot, [request], api=self.api)
        self.assertEqual(snapshot['evidence_index'][request]['content'], '\r\nb')
        self.api.collections['comments'][0]['body'] = 'edited'
        expand_evidence(snapshot, ['comments'], api=self.api)
        self.assertNotIn(request, snapshot['evidence_index'])
        with self.assertRaises(ValueError):
            expand_evidence(snapshot, [request], api=self.api)

    def test_large_index_is_paged_without_losing_addressable_sources(self):
        self.api.collections['comments'] = [{'id': number, 'body': 'short', 'user': {'login': 'reader'}} for number in range(2000)]
        snapshot = self.prepare()
        packet = json.loads(Path(snapshot['packet_path']).read_text())
        self.assertEqual(packet['index_coverage'], 'paged')
        found = {}
        for path in packet['index_pages']:
            self.assertLessEqual(Path(path).stat().st_size, 2 * 1024 * 1024)
            found.update(json.loads(Path(path).read_text()))
        self.assertIn('comment:0', found)
        self.assertIn('comment:1999', found)
        for identity, metadata in found.items():
            self.assertEqual(metadata['inspected'], snapshot['evidence_index'][identity]['inspected'])
        for identity, delivered in packet.get('expanded_evidence', {}).items():
            self.assertEqual(delivered['inspected'], snapshot['evidence_index'][identity]['inspected'])
        self.assertLessEqual(Path(snapshot['packet_path']).stat().st_size, 2 * 1024 * 1024)

    def test_lifecycle_profiles_are_noise_but_actor_identity_is_substantive(self):
        from label_issue_checkpoint import fingerprint
        from label_issue_evidence import _artifact
        self.api.item.update(state='closed', state_reason='not_planned',
            user={'login': 'reader'}, closed_by={'login': 'reader', 'type': 'User'})
        self.api.lifecycle_events = [{'__typename': 'ClosedEvent', 'id': 'C1',
            'createdAt': 't1', 'actor': {'login': 'reader', 'avatar_url': 'first'}, 'closer': None}]
        def current_fingerprint():
            snapshot = self.prepare()
            material = material_state(snapshot)
            material['relevant_timeline'] = _artifact('relevant_timeline', self.api.lifecycle_events)
            return fingerprint(material, {'area:platform'}, snapshot['policy_version'])
        before = current_fingerprint()
        self.api.lifecycle_events[0]['actor']['avatar_url'] = 'second'
        self.assertEqual(before, current_fingerprint())
        self.api.lifecycle_events[0]['actor']['login'] = 'other'
        self.assertNotEqual(before, current_fingerprint())

    def test_material_state_ignores_snapshot_identity_and_blanket_timestamp(self):
        snapshot = self.prepare()
        first = material_state(snapshot)
        snapshot['snapshot_id'] = 'other'
        snapshot['_directory'] = '/tmp/different'
        snapshot['item'] = {'updated_at': 'changed'}
        self.assertEqual(first, material_state(snapshot))
        snapshot['evidence_index']['body']['content']['body'] = 'changed material'
        self.assertNotEqual(first, material_state(snapshot))

    def test_material_state_preserves_real_external_event_ids_and_unseen_coverage(self):
        snapshot = self.prepare()
        self.api.collections['timeline'] = [{'id': 11, 'event': 'labeled', 'actor': {'login': 'maintainer'}, 'label': {'name': 'area:platform'}}]
        before = material_state(snapshot)
        expand_evidence(snapshot, ['timeline'], api=self.api)
        after = material_state(snapshot)
        self.assertNotEqual(before, after)
        self.assertIn('11', json.dumps(after))


    def test_actual_id_only_collections_do_not_substantiate_classification(self):
        from label_issue_policy import validate_result
        self.api = API(pull=True)
        self.api.collections['comments'] = [{'id': 7, 'body': 'SDK context', 'user': {'login': 'reader'}}]
        snapshot = self.prepare()
        expand_evidence(snapshot, ['comments'], api=self.api)
        decision = self.classification(snapshot, ['comments'])
        self.assertFalse(validate_result(snapshot, decision)['valid'])
        expand_evidence(snapshot, ['comment:7'], api=self.api)
        decision['reasons'][0]['evidence'] = ['comments', 'comment:7']
        self.assertTrue(validate_result(snapshot, decision)['valid'])

    @staticmethod
    def classification(snapshot, refs):
        return {**{key: snapshot[key] for key in ('schema_version', 'repository', 'number', 'kind', 'snapshot_id')},
                'area': 'area:platform', 'topics': ['topic:sdk'], 'ambiguity': None,
                'reasons': [{'labels': ['area:platform', 'topic:sdk'], 'evidence': refs, 'reason': 'SDK context.'}]}

    def test_omitted_body_requires_delivered_content_or_focused_slice(self):
        from label_issue_policy import validate_result
        with mock.patch('label_issue_evidence.LIMIT', 65536):
            self.api.item['body'] = 'Large issue content. ' * 2800
            self.api.collections['comments'] = [{'id': n, 'body': 'Other context', 'user': {'login': 'reader'}} for n in range(30)]
            snapshot = self.prepare()
            packet = json.loads(Path(snapshot['packet_path']).read_text())
            self.assertTrue(packet['evidence_index']['body']['content_deferred'])
            self.assertEqual(snapshot['evidence_index']['body']['coverage'], 'complete')
            self.assertFalse(validate_result(snapshot, self.classification(snapshot, ['body']))['valid'])
            expand_evidence(snapshot, ['body'], api=self.api)
            self.assertFalse(snapshot['evidence_index']['body']['inspected'])
            request = f"text:body:{snapshot['evidence_index']['body']['source_digest']}:0:20"
            expand_evidence(snapshot, [request], api=self.api)
            self.assertEqual(snapshot['evidence_index'][request]['content'], 'Large issue content.')
            self.assertTrue(validate_result(snapshot, self.classification(snapshot, [request]))['valid'])
            self.assertLessEqual(Path(snapshot['packet_path']).stat().st_size, 65536)

    def test_same_digest_prior_delivery_survives_later_packet_eviction(self):
        from label_issue_policy import validate_result
        with mock.patch('label_issue_evidence.LIMIT', 65536):
            self.api.item['body'] = 'Large issue content. ' * 2800
            snapshot = self.prepare()
            self.assertTrue(snapshot['evidence_index']['body']['inspected'])
            self.api.collections['comments'] = [{'id': n, 'body': 'Other context', 'user': {'login': 'reader'}} for n in range(30)]
            expand_evidence(snapshot, ['comments'], api=self.api)
            packet = json.loads(Path(snapshot['packet_path']).read_text())
            self.assertTrue(packet['evidence_index']['body']['content_deferred'])
            self.assertTrue(snapshot['evidence_index']['body']['inspected'])
            self.assertTrue(packet['evidence_index']['body']['inspected'])
            self.assertTrue(validate_result(snapshot, self.classification(snapshot, ['body']))['valid'])

    def test_source_change_invalidates_inspection_until_current_content_expanded(self):
        from label_issue_policy import validate_result
        self.api.collections['comments'] = [{'id': 7, 'body': 'Initial', 'user': {'login': 'reader'}}]
        snapshot = self.prepare()
        expand_evidence(snapshot, ['comment:7'], api=self.api)
        prior = snapshot['evidence_index']['comment:7']['source_digest']
        self.api.collections['comments'][0]['body'] = 'Changed source'
        expand_evidence(snapshot, ['comments'], api=self.api)
        self.assertNotEqual(snapshot['evidence_index']['comment:7']['source_digest'], prior)
        self.assertFalse(snapshot['evidence_index']['comment:7']['inspected'])
        self.assertFalse(validate_result(snapshot, self.classification(snapshot, ['comment:7']))['valid'])
        expand_evidence(snapshot, ['comment:7'], api=self.api)
        self.assertTrue(validate_result(snapshot, self.classification(snapshot, ['comment:7']))['valid'])


    def test_read_flags_do_not_change_actual_material_fingerprint(self):
        from label_issue_checkpoint import fingerprint
        snapshot = self.prepare()
        before = material_state(snapshot)
        before['relevant_timeline'] = {'coverage': 'complete', 'source_digest': hashlib.sha256(b'[]').hexdigest(), 'source_bytes': 2}
        without_read_state = copy.deepcopy(before)
        for artifact in without_read_state['evidence_index'].values():
            artifact['inspected'] = False
            artifact.pop('content', None)
        self.assertEqual(fingerprint(before, {'area:platform'}, snapshot['policy_version']),
                         fingerprint(without_read_state, {'area:platform'}, snapshot['policy_version']))

    def test_preparation_does_not_mark_unread_human_comments_inspected(self):
        from label_issue_policy import is_inspected_source
        with mock.patch('label_issue_evidence.LIMIT', 65536):
            self.api.collections['comments'] = [
                {'id': 7, 'body': 'a' * 40000, 'user': {'login': 'maintainer'}},
                {'id': 8, 'body': 'b' * 40000, 'user': {'login': 'maintainer'}},
            ]
            snapshot = self.prepare()
            packet = json.loads(Path(snapshot['packet_path']).read_text())
            deferred = [identity for identity, entry in packet['evidence_index'].items()
                        if entry.get('content_deferred') and entry['kind'] == 'comment']
            self.assertTrue(deferred)
            for identity in deferred:
                self.assertFalse(is_inspected_source(snapshot['evidence_index'][identity]))


    def test_authoritative_comment_preparation_batches_persistence_and_authority(self):
        from unittest import mock
        import label_issue_evidence as module
        self.api.item['user']={'login':'reader'}
        self.api.collections['comments']=[{'id':i,'body':'author detail','user':{'login':'reader','type':'User'}} for i in range(80)]
        with mock.patch.object(module,'_persist',wraps=module._persist) as persist:
            self.prepare()
        self.assertEqual(persist.call_count,1)
        self.assertEqual(len([path for path,_ in self.api.calls if '/collaborators/reader/permission' in path]),1)


    def test_refresh_actor_cache_is_per_refresh_and_observes_permission_revocation(self):
        self.api.collections['comments']=[{'id':i,'body':'reviewed intent','user':{'login':'writer','type':'User'},'author_association':'COLLABORATOR'} for i in range(30)]
        snapshot=self.prepare()
        before=len([path for path,_ in self.api.calls if '/collaborators/writer/permission' in path])
        self.api.permissions['writer']='read'
        expand_evidence(snapshot,['comments'],api=self.api)
        after=len([path for path,_ in self.api.calls if '/collaborators/writer/permission' in path])
        self.assertEqual(after-before,1)
        self.assertTrue(all(snapshot['evidence_index'][f'comment:{i}']['actor_authority']['permission']=='read' for i in range(30)))



if __name__ == '__main__':
    unittest.main()
