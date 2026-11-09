# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Read-only fixtures and observed mutation transcripts for the shared boundary."""
import copy
import fcntl
import io
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from label_issue import apply, main, prepare, preview, _lock_path
from label_issue_evidence_test import API, REPO, ROOT
from label_issue_github import GitHubError
from label_issue_evidence import expand_evidence


class LiveAPI(API):

    def __init__(self):
        super().__init__()
        self.definitions += [{'name': 'area:old', 'node_id': 'OLD', 'id': 111}, {'name': 'state:accepted', 'node_id': 'ACCEPTED', 'id': 222}, {'name': 'meta:labeler-checkpoint', 'node_id': 'BOOK', 'id': 333}, {'name': 'state:needs-info', 'node_id': 'INFO', 'id': 444}]
        self.events = []
        self.writes = []
        self.after_write = None
        self.fail_write = False
        self.partial_alias = False
        self.failed_additions_continue = False
        self.actor = 'maintainer'

    def __call__(self, path, **kwargs):
        if path == 'user':
            return {'login': self.actor}
        if path == 'graphql':
            query = kwargs['data']['query']
            if query.lstrip().startswith('mutation'):
                self.writes.append(copy.deepcopy(kwargs['data']))
                variables = kwargs['data']['variables']
                inputs = [('apply', variables['input'])] if 'input' in variables else list(variables.items())
                returned = {}
                errors = []
                for alias, data in inputs:
                    addition = 'labels' in data
                    entry = data['labels'][0] if addition else {'labelId': data['labelIds'][0]}
                    if addition and self.failed_additions_continue:
                        returned[alias] = None
                        errors.append({'message':'addition rejected','path':[alias]})
                        continue
                    label_id = entry['labelId']
                    label = next((definition for definition in self.definitions if definition['node_id'] == label_id))
                    if addition:
                        if label['name'] in self.labels:
                            raise AssertionError('addition must generate an event')
                        self.labels.append(label['name'])
                    else:
                        if label['name'] not in self.labels:
                            raise AssertionError('removal must generate an event')
                        self.labels.remove(label['name'])
                    event = {'__typename': 'LabeledEvent' if addition else 'UnlabeledEvent', 'id': f'event-{len(self.events) + 1}', 'createdAt': '2026-11-07T00:00:00Z', 'actor': {'login': self.actor}, 'label': {'id': label_id, 'name': label['name']}}
                    if addition:
                        event['intent'] = {'rationale': entry.get('rationale')}
                    self.events.append(event)
                    if self.after_write:
                        self.after_write(self)
                    if self.fail_write:
                        raise GitHubError('write timed out', uncertain_write=True, retryable=True)
                    returned[alias] = {'labelable': {'labels': {'nodes': [{'name': 'WRONG-NESTED-STATE'}]}}}
                    if self.partial_alias:
                        return {'data': returned, 'errors': [{'message': 'later alias failed', 'path': ['op1']}]}
                return {'data': returned, **({'errors':errors} if errors else {})}
            if 'LABELED_EVENT' in query:
                events = self.events
                if 'UNLABELED_EVENT' not in query:
                    events = [event for event in events if event['__typename'] == 'LabeledEvent']
                end = int(kwargs['data']['variables'].get('before') or len(events))
                count = 1 if 'last: 1,' in query else 100
                start = max(0, end - count)
                return {'data': {'node': {'__typename': 'Issue', 'timelineItems': {'nodes': copy.deepcopy(events[start:end]), 'pageInfo': {'hasPreviousPage': start > 0, 'startCursor': str(start) if start else None}}}}}
            if 'node(id:' in query:
                return {'data': {'node': {'__typename': 'Issue', 'timelineItems': {'nodes': [], 'pageInfo': {'hasPreviousPage': False, 'startCursor': None}}}}}
        return super().__call__(path, **kwargs)


class BoundaryTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.api = LiveAPI()
        self.trusted = {'maintainer'}

    def prepared(self, **kwargs):
        report = prepare(REPO, 3, Path(self.temp.name), api=self.api, trusted_actors=self.trusted, force=True, **kwargs)
        self.assertEqual(report['status'], 'ready')
        return report['snapshot']

    def result(self, snapshot):
        return {key: snapshot[key] for key in ('schema_version', 'repository', 'number', 'kind', 'snapshot_id')} | {'area': 'area:platform', 'topics': [], 'reasons': [{'labels': ['area:platform', 'area:old'], 'evidence': ['body', 'labels'], 'reason': 'CLI behavior changes the platform component.'}], 'ambiguity': None}

    def apply(self, snapshot, result=None, **kwargs):
        return apply(snapshot, self.result(snapshot) if result is None else result, api=self.api, trusted_actors=self.trusted, **kwargs)

    def test_embedded_item_labels_remain_reconciliation_state(self):
        self.api.item['labels'] = [{'name': label} for label in self.api.labels]
        snapshot = self.prepared()
        self.api.after_write = lambda api: api.item.update(labels=[{'name': label} for label in api.labels])
        self.assertEqual(self.apply(snapshot)['status'], 'applied')
        self.assertEqual(self.api.labels, ['state:accepted', 'area:platform'])

    def test_provider_metadata_does_not_stale_preview_or_checkpoint(self):
        self.api.item['user'] = {'login': 'writer', 'id': 9, 'type': 'User'}
        self.api.item['assignees'] = [{'login': 'reader', 'id': 10, 'type': 'User'}]
        self.api.collections['comments'] = [{'id': 7, 'body': 'Unrelated context',
            'user': {'login': 'maintainer', 'id': 11, 'type': 'User'},
            'created_at': 't1', 'updated_at': 't1'}]
        snapshot = self.prepared()
        self.api.collections['comments'][0].update(reactions={'total_count': 42}, html_url='new-url')
        self.api.collections['comments'][0]['user'].update(avatar_url='new-avatar', followers_url='profile')
        self.api.item['user']['avatar_url'] = 'author-avatar'
        self.api.item['assignees'][0]['avatar_url'] = 'assignee-avatar'
        self.api.definitions[0].update(color='ffffff', url='label-url')
        self.assertEqual(preview(snapshot, self.result(snapshot), api=self.api)['status'], 'preview')
        self.assertEqual(self.apply(snapshot)['status'], 'applied')
        self.api.collections['comments'][0]['reactions']['total_count'] += 1
        self.api.definitions[0]['color'] = '000000'
        report = prepare(REPO, 3, Path(self.temp.name) / 'again', api=self.api, trusted_actors=self.trusted)
        self.assertEqual(report['status'], 'unchanged')
        self.assertFalse(report['classifier_required'])

    def test_substantive_changes_stale_preview(self):
        changes = [
            lambda api: api.collections['comments'][0].update(body='Edited context'),
            lambda api: api.collections['comments'][0].update(updated_at='t2'),
            lambda api: api.collections['comments'][0]['user'].update(id=12),
            lambda api: api.collections['comments'][0]['user'].update(login='reader'),
            lambda api: api.collections['comments'].clear(),
            lambda api: api.permissions.update(writer='read'),
            lambda api: api.item['assignees'][0].update(login='other'),
            lambda api: api.definitions[0].update(description='Changed scope'),
            lambda api: api.definitions[0].update(node_id='OTHER_LABEL'),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                self.api = LiveAPI()
                self.api.item['assignees'] = [{'login': 'reader', 'type': 'User'}]
                self.api.collections['comments'] = [{'id': 7, 'body': 'Context',
                    'user': {'login': 'writer', 'id': 11, 'type': 'User'},
                    'author_association': 'COLLABORATOR', 'updated_at': 't1'}]
                snapshot = self.prepared()
                change(self.api)
                self.assertEqual(preview(snapshot, self.result(snapshot), api=self.api)['status'], 'stale')
                self.assertEqual(self.api.writes, [])

    def test_unread_irrelevant_human_context_does_not_hold_preview(self):
        self.api.collections['comments'] = [{'id': 7, 'body': 'Thanks for the report.',
            'user': {'login': 'maintainer', 'type': 'User'}}]
        snapshot = self.prepared()
        self.assertFalse(snapshot['evidence_index']['comment:7']['inspected'])
        self.assertEqual(preview(snapshot, self.result(snapshot), api=self.api)['status'], 'preview')
        self.assertEqual(self.api.writes, [])

    def test_real_additions_precede_removals_and_last_addition_has_v2_rationale(self):
        snapshot = self.prepared()
        report = self.apply(snapshot)
        self.assertEqual(report['status'], 'applied')
        self.assertEqual(self.api.labels, ['state:accepted', 'area:platform'])
        self.assertEqual([event['__typename'] for event in self.api.events], ['LabeledEvent', 'UnlabeledEvent'])
        self.assertIn('openshell-labeler:v2:', self.api.events[0]['intent']['rationale'])
        self.assertTrue(report['checkpoint_verified'])

    def test_preview_exact_payload_matches_apply_without_writes_in_preview(self):
        snapshot = self.prepared()
        report = preview(snapshot, self.result(snapshot), api=self.api)
        self.assertEqual(report['status'], 'preview')
        self.assertEqual(self.api.writes, [])
        self.assertEqual(report['ordered_writes'][0]['data']['variables']['input']['labels'][0]['labelId'], 'LA')
        applied = self.apply(snapshot)
        self.assertEqual(applied['status'], 'applied')
        self.assertEqual([request['data'] for request in report['mutation_requests']], self.api.writes)

    def test_nochange_examination_cycles_bookkeeping_then_unchanged_prepare_writes_nothing(self):
        self.api.labels = ['state:accepted', 'area:platform']
        snapshot = self.prepared()
        result = self.result(snapshot)
        result['reasons'][0]['labels'] = ['area:platform']
        report = self.apply(snapshot, result)
        self.assertEqual(report['status'], 'applied')
        self.assertEqual([event['label']['id'] for event in self.api.events], ['BOOK', 'BOOK'])
        before = len(self.api.writes)
        next_report = prepare(REPO, 3, Path(self.temp.name) / 'next', api=self.api, trusted_actors=self.trusted)
        self.assertEqual(next_report['status'], 'unchanged')
        self.assertEqual(len(self.api.writes), before)
        self.assertNotIn('snapshot', next_report)

    def test_removal_only_uses_explicit_bookkeeping_and_missing_label_blocks(self):
        self.api.labels += ['area:platform']
        snapshot = self.prepared()
        report = preview(snapshot, self.result(snapshot), api=self.api)
        self.assertEqual(report['status'], 'preview')
        self.assertEqual([write['action'] for write in report['ordered_writes']], ['add', 'remove', 'remove'])
        self.assertEqual(report['ordered_writes'][0]['label'], 'meta:labeler-checkpoint')
        self.api.definitions = [entry for entry in self.api.definitions if entry['node_id'] != 'BOOK']
        blocked = self.apply(snapshot)
        self.assertIn(blocked['status'], ['stale', 'prerequisite'])
        self.assertEqual(self.api.writes, [])

    def test_missing_bookkeeping_does_not_block_real_addition(self):
        self.api.definitions = [entry for entry in self.api.definitions if entry['node_id'] != 'BOOK']
        snapshot = self.prepared()
        self.assertEqual(self.apply(snapshot)['status'], 'applied')

    def test_leftover_dedicated_label_is_previewed_cleaned_and_recheckpointed(self):
        self.api.labels = ['state:accepted', 'area:platform', 'meta:labeler-checkpoint']
        snapshot = self.prepared()
        result = self.result(snapshot)
        result['reasons'][0]['labels'] = ['area:platform']
        report = preview(snapshot, result, api=self.api)
        self.assertEqual(report['status'], 'preview')
        self.assertEqual([write['action'] for write in report['ordered_writes']], ['remove', 'add', 'remove'])
        self.assertEqual(self.apply(snapshot, result)['status'], 'applied')
        self.assertNotIn('meta:labeler-checkpoint', self.api.labels)

    def test_force_reexamines_but_never_bypasses_lifecycle_or_acceptance(self):
        self.api.item.update(state='closed', state_reason='completed')
        report = prepare(REPO, 3, Path(self.temp.name), api=self.api, trusted_actors=self.trusted, force=True)
        self.assertEqual(report['status'], 'skipped')
        self.assertEqual(self.api.writes, [])

    def test_stale_body_or_external_same_label_cycle_blocks_before_write(self):
        snapshot = self.prepared()
        self.api.item['body'] = 'new unseen material'
        self.assertEqual(self.apply(snapshot)['status'], 'stale')
        self.assertEqual(self.api.writes, [])

    def test_timeout_after_mutation_reads_fresh_state_and_reports_partial_without_replay(self):
        snapshot = self.prepared()
        self.api.fail_write = True
        report = self.apply(snapshot)
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(len(self.api.writes), 1)
        self.assertIn('area:platform', report['observed_labels'])
        self.assertFalse(report['checkpoint_verified'])

    def test_postcheckpoint_unseen_comment_prevents_success(self):
        snapshot = self.prepared()
        self.api.after_write = lambda api: api.collections['comments'].append({'id': len(api.collections['comments']) + 1, 'body': 'unseen evidence', 'user': {'login': 'reader'}})
        report = self.apply(snapshot)
        self.assertEqual(report['status'], 'partial')
        self.assertFalse(report['checkpoint_verified'])

    def test_final_nested_response_is_ignored_and_unrelated_external_label_detected(self):
        snapshot = self.prepared()

        def add_external(api):
            if 'priority:high' not in api.labels:
                api.labels.append('priority:high')
        self.api.after_write = add_external
        report = self.apply(snapshot)
        self.assertEqual(report['status'], 'partial')
        self.assertIn('priority:high', self.api.labels)
        self.assertNotIn('WRONG-NESTED-STATE', report['observed_labels'])

    def test_local_lock_contention_holds_without_mutation(self):
        snapshot = self.prepared()
        path = _lock_path(REPO, 3)
        with path.open('a') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            report = self.apply(snapshot)
        self.assertEqual(report['status'], 'held')
        self.assertEqual(self.api.writes, [])

    def test_unaccepted_assessment_only_is_usable_and_never_checkpoints(self):
        self.api.item['user'] = {'login': 'reader'}
        self.api.labels = ['state:needs-info', 'area:old']
        report = prepare(REPO, 3, Path(self.temp.name), api=self.api, trusted_actors=self.trusted, assessment_only=True, assessment_labels={'state:needs-info'})
        self.assertEqual(report['status'], 'ready')
        snapshot = report['snapshot']
        outcome = {'authorized': True, 'reviewed_labels': ['state:needs-info'], 'desired_labels': []}
        applied = self.apply(snapshot, {}, assessment=outcome)
        self.assertEqual(applied['status'], 'applied')
        self.assertEqual(self.api.labels, ['area:old'])
        self.assertFalse(any(('rationale' in str(write) for write in self.api.writes)))

    def test_semantic_lifecycle_only_restricts_with_read_human_authority(self):
        self.api.collections['comments'] = [{'id': 7, 'body': 'We will not pursue this.', 'user': {'login': 'maintainer', 'type': 'User'}}]
        snapshot = self.prepared()
        result = self.result(snapshot)
        result['lifecycle'] = {'disposition': 'excluded', 'evidence': ['comment:7'], 'reason': 'Recorded maintainer rejection.'}
        self.assertEqual(self.apply(snapshot, result)['status'], 'held')
        expand_evidence(snapshot, ['comment:7'], api=self.api)
        self.assertEqual(self.apply(snapshot, result)['status'], 'skipped')
        snapshot['evidence_index']['comment:7']['actor_authority']['role'] = 'unknown'
        self.assertEqual(self.apply(snapshot, result)['status'], 'stale')
        self.assertEqual(self.api.writes, [])

    def test_final_packet_omission_does_not_credit_intermediate_body_delivery(self):
        from label_issue_evidence import prepare_snapshot
        from label_issue_policy import is_inspected_source, validate_result
        self.api.item['pull_request'] = {'url': 'pull'}
        self.api.pull.update(body='x' * 50000, changed_files=0)
        self.api.collections['reviews'] = [dict(id=i, body='context',
            user={'login': 'reader', 'type': 'User'}) for i in range(30)]
        with mock.patch('label_issue_evidence.LIMIT', 65536):
            standalone = prepare_snapshot(REPO, 3, Path(self.temp.name) / 'standalone', api=self.api)
            self.assertTrue(is_inspected_source(standalone['evidence_index']['body']))
            snapshot = self.prepared()
            packet = json.loads(Path(snapshot['packet_path']).read_text())
            self.assertTrue(packet['evidence_index']['body']['content_deferred'])
            self.assertFalse(is_inspected_source(snapshot['evidence_index']['body']))
            self.assertFalse(validate_result(snapshot, self.result(snapshot))['valid'])
            self.assertLessEqual(Path(snapshot['packet_path']).stat().st_size, 65536)

    def test_untrusted_executor_cannot_write(self):
        snapshot = self.prepared()
        self.api.actor = 'reader'
        self.assertEqual(self.apply(snapshot)['status'], 'held')
        self.assertEqual(self.api.writes, [])

    def test_accepted_assessment_only_preserves_classification_without_result(self):
        self.api.labels += ['state:needs-info']
        snapshot = self.prepared(assessment_only=True, assessment_labels={'state:needs-info'})
        assessment = {'authorized': True, 'reviewed_labels': ['state:needs-info'], 'desired_labels': []}
        report = self.apply(snapshot, {}, assessment=assessment)
        self.assertEqual(report['status'], 'applied')
        self.assertIn('area:old', self.api.labels)
        self.assertFalse(report['checkpoint_verified'])
        self.assertEqual(len(self.api.events), 1)

    def test_arbitrary_bookkeeping_configuration_cannot_authorize_label_cycles(self):
        self.api.labels = ['state:accepted', 'area:platform']
        self.api.definitions.append({'name': 'meta:unapproved', 'node_id': 'UNAPPROVED'})
        snapshot = self.prepared()
        result = self.result(snapshot)
        result['reasons'][0]['labels'] = ['area:platform']
        report = self.apply(snapshot, result, bookkeeping_label='meta:unapproved')
        self.assertEqual(report['status'], 'prerequisite')
        self.assertEqual(self.api.writes, [])

    def test_external_label_drift_is_rejected_even_before_timeline_visibility(self):
        snapshot = self.prepared()
        self.api.labels.append('priority:high')
        self.assertEqual(self.apply(snapshot)['status'], 'stale')
        self.assertEqual(self.api.writes, [])

    def test_bot_write_permission_cannot_supply_human_lifecycle_interpretation(self):
        self.api.collections['comments'] = [{'id': 7, 'body': 'Rejecting.', 'user': {'login': 'bot-writer', 'type': 'Bot'}, 'author_association': 'COLLABORATOR'}]
        self.api.permissions['bot-writer'] = 'write'
        snapshot = self.prepared()
        result = self.result(snapshot)
        expand_evidence(snapshot, ['comment:7'], api=self.api)
        result['lifecycle'] = {'disposition': 'excluded', 'evidence': ['comment:7'], 'reason': 'Bot says reject'}
        self.assertEqual(self.apply(snapshot, result)['status'], 'held')
        self.assertEqual(self.api.writes, [])

    def test_force_after_verified_checkpoint_returns_ready_without_new_writes(self):
        snapshot = self.prepared()
        self.assertEqual(self.apply(snapshot)['status'], 'applied')
        before = len(self.api.writes)
        report = prepare(REPO, 3, Path(self.temp.name) / 'forced', api=self.api, trusted_actors=self.trusted, force=True)
        self.assertEqual(report['status'], 'ready')
        self.assertEqual(len(self.api.writes), before)

    def test_ordered_one_label_aliases_use_verified_add_and_remove_requests(self):
        snapshot = self.prepared()
        report = self.apply(snapshot)
        self.assertEqual(report['status'], 'applied')
        self.assertEqual(len(self.api.writes), 2)
        self.assertIn('op0: addLabelsToLabelable', self.api.writes[0]['query'])
        self.assertIn('op1: removeLabelsFromLabelable', self.api.writes[1]['query'])
        self.assertEqual(list(self.api.writes[0]['variables']), ['op0'])
        self.assertEqual(list(self.api.writes[1]['variables']), ['op1'])

    def test_partial_alias_success_is_read_back_and_never_blindly_replayed(self):
        snapshot = self.prepared()
        self.api.partial_alias = True
        report = self.apply(snapshot)
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(len(self.api.writes), 1)
        self.assertIn('area:platform', report['observed_labels'])
        self.assertIn('area:old', report['observed_labels'])
        self.assertFalse(report['checkpoint_verified'])

    def test_expected_preview_payload_mismatch_blocks_before_any_write(self):
        snapshot = self.prepared()
        confirmed = preview(snapshot, self.result(snapshot), api=self.api)
        confirmed['mutation_requests'][0]['data']['variables']['op0']['labels'][0]['rationale'] = 'different confirmed payload'
        report = self.apply(snapshot, expected_preview=confirmed)
        self.assertEqual(report['status'], 'stale')
        self.assertEqual(self.api.writes, [])

    def test_exact_expected_preview_payload_can_be_applied(self):
        snapshot = self.prepared()
        confirmed = preview(snapshot, self.result(snapshot), api=self.api)
        self.assertEqual(self.apply(snapshot, expected_preview=confirmed)['status'], 'applied')

    def test_partial_bookkeeping_leftover_recovers_with_explicit_cleanup_cycle(self):
        self.api.labels = ['state:accepted', 'area:platform']
        snapshot = self.prepared()
        result = self.result(snapshot)
        result['reasons'][0]['labels'] = ['area:platform']
        self.api.partial_alias = True
        self.assertEqual(self.apply(snapshot, result)['status'], 'partial')
        self.assertIn('meta:labeler-checkpoint', self.api.labels)
        self.api.partial_alias = False
        recovered = prepare(REPO, 3, Path(self.temp.name) / 'recover', api=self.api, trusted_actors=self.trusted)
        self.assertEqual(recovered['status'], 'ready')
        current = recovered['snapshot']
        result = self.result(current)
        result['reasons'][0]['labels'] = ['area:platform']
        report = self.apply(current, result)
        self.assertEqual(report['status'], 'applied')
        self.assertEqual([entry['action'] for entry in report['ordered_writes']], ['remove', 'add', 'remove'])
        self.assertNotIn('meta:labeler-checkpoint', self.api.labels)

    def test_external_same_final_set_event_cycle_invalidates_prepared_boundary(self):
        snapshot = self.prepared()
        for action in ('UnlabeledEvent', 'LabeledEvent'):
            event = {'__typename': action, 'id': f'external-{len(self.api.events)}', 'createdAt': '2026-11-07T00:00:00Z', 'actor': {'login': 'reader'}, 'label': {'id': 'OLD', 'name': 'area:old'}}
            if action == 'LabeledEvent':
                event['intent'] = {'rationale': None}
            self.api.events.append(event)
        self.assertEqual(self.apply(snapshot)['status'], 'stale')
        self.assertEqual(self.api.writes, [])

    def test_last_of_multiple_real_additions_carries_checkpoint(self):
        snapshot = self.prepared()
        result = self.result(snapshot)
        result['topics'] = ['topic:sdk']
        result['reasons'][0]['labels'].append('topic:sdk')
        report = self.apply(snapshot, result)
        self.assertEqual(report['status'], 'applied')
        additions = [event for event in self.api.events if event['__typename'] == 'LabeledEvent']
        self.assertIsNone(additions[0]['intent']['rationale'])
        self.assertTrue(additions[1]['intent']['rationale'].startswith('openshell-labeler:v2:'))

    def test_assessment_policy_cannot_authorize_acceptance(self):
        snapshot = self.prepared(assessment_only=True, assessment_labels={'state:accepted'})
        outcome = {'authorized': True, 'reviewed_labels': ['state:accepted'], 'desired_labels': []}
        self.assertEqual(self.apply(snapshot, {}, assessment=outcome)['status'], 'held')
        self.assertEqual(self.api.writes, [])

    def test_caller_executor_supports_tokens_without_user_endpoint(self):
        snapshot = self.prepared()
        original = self.api

        def app_api(path, **kwargs):
            if path == 'user':
                raise AssertionError('installation tokens do not support user')
            return original(path, **kwargs)
        report = apply(snapshot, self.result(snapshot), api=app_api, trusted_actors=self.trusted, executor='maintainer')
        self.assertEqual(report['status'], 'applied')
        self.assertTrue(report['checkpoint_verified'])

    def test_configured_executor_must_be_trusted_and_match_actual_events(self):
        snapshot = self.prepared()
        self.assertEqual(self.apply(snapshot, executor='reader')['status'], 'held')
        self.assertEqual(self.api.writes, [])
        self.api.actor = 'different-bot'
        report = self.apply(snapshot, executor='maintainer')
        self.assertEqual(report['status'], 'partial')
        self.assertFalse(report['checkpoint_verified'])

    def test_assessment_only_also_verifies_configured_executor_event_actor(self):
        snapshot = self.prepared(assessment_only=True, assessment_labels={'state:needs-info'})
        outcome = {'authorized': True, 'reviewed_labels': ['state:needs-info'], 'desired_labels': ['state:needs-info']}
        self.api.actor = 'different-bot'
        report = self.apply(snapshot, {}, assessment=outcome, executor='maintainer')
        self.assertEqual(report['status'], 'partial')
        self.assertFalse(report['checkpoint_verified'])

    def test_inspecting_an_ordinary_comment_does_not_break_next_unchanged_skip(self):
        from label_issue_evidence import expand_evidence
        self.api.collections['comments']=[{'id':7,'body':'CLI details','user':{'login':'reader','type':'User'}}]
        snapshot=self.prepared()
        expand_evidence(snapshot,['comment:7'],api=self.api)
        result=self.result(snapshot)
        result['reasons'][0]['evidence'].append('comment:7')
        self.assertEqual(self.apply(snapshot,result)['status'],'applied')
        report=prepare(REPO,3,Path(self.temp.name)/'same',api=self.api,trusted_actors=self.trusted)
        self.assertEqual(report['status'],'unchanged')

    def test_hydration_reuses_current_verified_authority_across_source_kinds(self):
        self.api.item['pull_request']={'url':'pull'}
        self.api.pull['changed_files']=0
        self.api.collections['comments']=[{'id':7,'body':'Details','user':{'login':'reader'},'author_association':'MEMBER'}]
        self.api.collections['reviews']=[{'id':8,'body':'Review','user':{'login':'reader'}}]
        self.prepared()
        lookups=[path for path,_ in self.api.calls if path.endswith('/collaborators/reader/permission')]
        self.assertEqual(len(lookups),1)

    def test_pr_apply_hydrates_complete_files_reviews_and_review_comments(self):
        self.api.item['pull_request'] = {'url': 'pull'}
        self.api.collections['files'] = [{'filename': 'src/example.py', 'status': 'modified', 'additions': 1, 'deletions': 1, 'changes': 2, 'patch': '@@ -1 +1 @@\n-old\n+new'}]
        snapshot = self.prepared()
        self.assertEqual(snapshot['kind'], 'pull_request')
        self.assertEqual(snapshot['evidence_index']['reviews']['coverage'], 'complete')
        self.assertEqual(snapshot['evidence_index']['review_comments']['coverage'], 'complete')
        self.assertEqual(self.apply(snapshot)['status'], 'applied')

    def test_deterministic_review_hydration_does_not_authorize_model_evidence(self):
        self.api.item['pull_request']={'url':'pull'}
        self.api.pull['changed_files']=0
        self.api.collections['reviews']=[{'id':8,'body':'unread review','user':{'login':'reader'}}]
        snapshot=self.prepared()
        self.assertFalse(snapshot['evidence_index']['reviews']['inspected'])
        self.assertFalse(snapshot['evidence_index']['review_comments']['inspected'])
        packet=json.loads(Path(snapshot['packet_path']).read_text())
        self.assertFalse(packet['evidence_index']['reviews']['inspected'])
        result=self.result(snapshot); result['reasons'][0]['evidence']=['reviews','labels']
        self.assertEqual(self.apply(snapshot,result)['status'],'held')
        self.assertEqual(self.api.writes,[])

    def test_assessment_only_body_and_discussion_drift_block_before_writes(self):
        for accepted in (True,False):
            for changed in ('body','discussion'):
                with self.subTest(accepted=accepted,changed=changed):
                    self.api=LiveAPI()
                    self.api.item['user']={'login':'maintainer' if accepted else 'reader'}
                    self.api.labels=['state:needs-info','area:old']
                    snapshot=self.prepared(assessment_only=True,assessment_labels={'state:needs-info'})
                    if changed=='body': self.api.item['body']='new unreviewed facts'
                    else: self.api.collections['comments'].append({'id':7,'body':'new discussion facts','user':{'login':'reader'}})
                    outcome={'authorized':True,'reviewed_labels':['state:needs-info'],'desired_labels':[]}
                    self.assertEqual(self.apply(snapshot,{},assessment=outcome)['status'],'stale')
                    self.assertEqual(self.api.writes,[])

    def test_assessment_only_material_drift_after_write_prevents_success(self):
        snapshot=self.prepared(assessment_only=True,assessment_labels={'state:needs-info'})
        outcome={'authorized':True,'reviewed_labels':['state:needs-info'],'desired_labels':['state:needs-info']}
        self.api.after_write=lambda api: api.collections['comments'].append({'id':7,'body':'new discussion','user':{'login':'reader'}})
        self.assertEqual(self.apply(snapshot,{},assessment=outcome)['status'],'partial')

    def test_prepare_rechecks_its_refreshed_snapshot_eligibility(self):
        for changed in ('unaccepted','excluded'):
            with self.subTest(changed=changed):
                self.api=LiveAPI(); reads=0
                def changing_api(path,**kwargs):
                    nonlocal reads
                    if path==ROOT+'/issues/3':
                        reads+=1
                        if reads==2:
                            if changed=='unaccepted':
                                self.api.item['user']={'login':'reader'}
                                self.api.labels.remove('state:accepted')
                            else: self.api.item.update(state='closed',state_reason='completed')
                    return self.api(path,**kwargs)
                report=prepare(REPO,3,Path(self.temp.name)/changed,api=changing_api,trusted_actors=self.trusted,force=True)
                self.assertEqual(report['status'],'skipped')
                self.assertFalse(report['classifier_required'])
                self.assertNotIn('snapshot',report)

    def test_uncertain_write_reads_labels_even_if_discussion_hydration_fails(self):
        snapshot=self.prepared()
        self.api.fail_write=True
        self.api.after_write=lambda api: setattr(api,'fail','/comments?')
        report=self.apply(snapshot)
        self.assertEqual(report['status'],'partial')
        self.assertIn('area:platform',report.get('observed_labels',[]))
        self.assertFalse(report['checkpoint_verified'])

    def test_failed_addition_never_executes_a_removal_phase(self):
        snapshot=self.prepared(); self.api.failed_additions_continue=True
        report=self.apply(snapshot)
        self.assertEqual(report['status'],'partial')
        self.assertIn('area:old',self.api.labels)
        self.assertFalse(any(event['__typename']=='UnlabeledEvent' for event in self.api.events))

    def test_substantive_drift_after_additions_preserves_old_classification(self):
        snapshot=self.prepared()
        self.api.after_write=lambda api: api.collections['comments'].append({'id':7,'body':'unseen','user':{'login':'reader'}})
        report=self.apply(snapshot)
        self.assertEqual(report['status'],'partial')
        self.assertIn('area:old',self.api.labels)
        self.assertIn('area:platform',self.api.labels)

    def test_read_reviews_and_review_comments_can_restrict_lifecycle(self):
        for collection,identity in [('reviews','review:8'),('review_comments','review-comment:8')]:
            with self.subTest(collection=collection):
                self.api=LiveAPI(); self.api.item['pull_request']={'url':'pull'}; self.api.pull['changed_files']=0
                self.api.collections[collection]=[{'id':8,'body':'We will not pursue this work.','user':{'login':'maintainer','type':'User'}}]
                snapshot=self.prepared()
                self.assertFalse(snapshot['evidence_index'][identity]['inspected'])
                expand_evidence(snapshot, [identity], api=self.api)
                result=self.result(snapshot); result['lifecycle']={'disposition':'excluded','evidence':[identity],'reason':'Recorded maintainer disposition.'}
                self.assertEqual(self.apply(snapshot,result)['status'],'skipped')
                self.assertEqual(self.api.writes,[])

    def test_unread_irrelevant_review_does_not_hold_preview(self):
        self.api.item['pull_request'] = {'url': 'pull'}
        self.api.pull['changed_files'] = 0
        self.api.collections['reviews'] = [{'id': 8, 'body': 'Thanks for following up.', 'user': {'login': 'maintainer', 'type': 'User'}}]
        snapshot = self.prepared()
        self.assertFalse(snapshot['evidence_index']['review:8']['inspected'])
        self.assertEqual(preview(snapshot, self.result(snapshot), api=self.api)['status'], 'preview')
        self.assertEqual(self.api.writes, [])

    def test_transport_fields_and_diagnostics_survive_public_prepare(self):
        def limited_api(path,**kwargs):
            raise GitHubError('API rate limit exceeded; deadline cannot fit wait',status=429,retryable=True,retry_at=1060,payload={'message':'API rate limit exceeded'})
        limited_api.diagnostics={'requests':1,'elapsed_seconds':2}
        report=prepare(REPO,3,Path(self.temp.name),api=limited_api,trusted_actors=self.trusted)
        self.assertEqual(report['status'],'error')
        self.assertEqual(report.get('error',{}).get('status'),429)
        self.assertEqual(report['error']['retry_at'],1060)
        self.assertTrue(report['error']['retryable'])
        self.assertIn('API rate limit exceeded',report['error']['message'])
        self.assertEqual(report['telemetry']['requests'],1)

    def test_none_bookkeeping_selection_still_removes_approved_leftover(self):
        self.api.labels.append('meta:labeler-checkpoint')
        snapshot=self.prepared()
        report=self.apply(snapshot,bookkeeping_label=None)
        self.assertEqual(report['status'],'applied')
        self.assertNotIn('meta:labeler-checkpoint',self.api.labels)
        self.assertNotIn('meta:labeler-checkpoint',report['preserve'])

    def test_assessment_confirmation_binds_executor_even_without_rationale(self):
        snapshot=self.prepared(assessment_only=True,assessment_labels={'state:needs-info'})
        outcome={'authorized':True,'reviewed_labels':['state:needs-info'],'desired_labels':['state:needs-info']}
        confirmed=preview(snapshot,{},api=self.api,assessment=outcome,executor='maintainer')
        self.trusted.add('other'); self.api.actor='other'
        report=self.apply(snapshot,{},assessment=outcome,executor='other',expected_preview=confirmed)
        self.assertEqual(report['status'],'stale')
        self.assertEqual(self.api.writes,[])

    def test_cli_human_summary_keeps_stdout_as_json(self):
        snapshot=self.prepared(); result=self.result(snapshot)
        result['ambiguity']={'boundary':'Scope','chosen':{'labels':['area:platform'],'confidence':'medium'},
            'alternative':{'labels':['topic:sdk'],'confidence':'low'},'evidence':['body']}
        path=Path(self.temp.name)/'result.json'; path.write_text(json.dumps(result))
        out,err=io.StringIO(),io.StringIO()
        with mock.patch('sys.stdout',out),mock.patch('sys.stderr',err):
            code=main(['preview','--snapshot',str(Path(self.temp.name)/'manifest.json'),'--result',str(path),'--human'],api=self.api)
        self.assertEqual(code,0)
        self.assertEqual(json.loads(out.getvalue())['status'],'preview')
        self.assertIn('Ambiguity: chose area:platform (med conf) over topic:sdk (low conf)',err.getvalue())

    def test_deadline_429_transport_fields_survive_actual_client_to_prepare(self):
        from label_issue_github import GitHubClient
        from label_issue_github_test import Clock, Runner, response
        clock=Clock()
        client=GitHubClient(runner=Runner(response({'message':'quota exhausted'},429,{'Retry-After':'60'})),
            monotonic=lambda:clock.now,wall_clock=lambda:1000+clock.now,sleeper=clock.sleep,jitter=lambda:0,invocation_timeout=20)
        report=prepare(REPO,3,Path(self.temp.name),api=client,trusted_actors=self.trusted)
        self.assertEqual(report['error']['status'],429)
        self.assertEqual(report['error']['retry_at'],1060)
        self.assertTrue(report['error']['retryable'])
        self.assertIn('quota exhausted',report['error']['message'])
        self.assertEqual(report['telemetry']['requests'],1)

    def test_prepare_never_skips_valid_candidate_with_approved_temporary_leftover(self):
        import label_issue_checkpoint as cp
        import label_issue as core
        self.api.labels.append('meta:labeler-checkpoint')
        snapshot=self.prepared()
        self.api.labels.append('area:platform')
        fp=cp.fingerprint(core._material(snapshot),set(self.api.labels),core._version(snapshot))
        operations=[{'actor':'maintainer','action':'add','label_id':'LA'}]
        rationale=cp.encode_checkpoint(fp,boundary_id='',operations_digest=cp.operation_digest(operations),event_count=1)
        self.api.events.append({'__typename':'LabeledEvent','id':'legacy-candidate','createdAt':'2026-11-07T00:00:00Z',
            'actor':{'login':'maintainer'},'label':{'id':'LA','name':'area:platform'},'intent':{'rationale':rationale}})
        proof=cp.collect_label_events('node','',api=self.api)
        found=cp.find_checkpoint('node',api=self.api,trusted_actors=self.trusted)
        material=core._material(snapshot); material['existing_labels']=list(self.api.labels)
        self.assertTrue(cp.checkpoint_matches(found['checkpoint'],material,set(self.api.labels),core._version(snapshot),label_events=proof))
        report=prepare(REPO,3,Path(self.temp.name)/'leftover',api=self.api,trusted_actors=self.trusted)
        self.assertEqual(report['status'],'ready')
        self.assertFalse(report['checkpoint_verified'])

    @mock.patch('sys.stdout', new_callable=io.StringIO)
    def test_successful_cli_preview_returns_zero_without_mutating(self, _stdout):
        snapshot = self.prepared()
        root = Path(self.temp.name)
        result_path = root / 'classification.json'
        result_path.write_text(json.dumps(self.result(snapshot)))
        report_path = root / 'preview.json'
        code = main(['preview', '--snapshot', str(root / 'manifest.json'),
                     '--result', str(result_path), '--output', str(report_path)], api=self.api)
        self.assertEqual(json.loads(report_path.read_text())['status'], 'preview')
        self.assertEqual(code, 0)
        self.assertEqual(self.api.writes, [])

    @mock.patch('sys.stdout', new_callable=io.StringIO)
    def test_cli_assessment_path_and_exit_status(self, _stdout):
        self.api.item['user'] = {'login': 'reader'}
        self.api.labels = ['state:needs-info']
        root = Path(self.temp.name)
        policy = root / 'policy.json'
        policy.write_text(json.dumps(['state:needs-info']))
        code = main(['prepare', '--repo', REPO, '--item', '3', '--output', str(root / 'packet'), '--trusted-actor', 'maintainer', '--assessment-only', '--assessment-policy', str(policy)], api=self.api)
        self.assertEqual(code, 0)
        assessment = root / 'assessment.json'
        assessment.write_text(json.dumps({'authorized': True, 'reviewed_labels': ['state:needs-info'], 'desired_labels': []}))
        code = main(['apply', '--snapshot', str(root / 'packet' / 'manifest.json'), '--assessment', str(assessment), '--trusted-actor', 'maintainer', '--output', str(root / 'result.json')], api=self.api)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads((root / 'result.json').read_text())['status'], 'applied')
if __name__ == '__main__':
    unittest.main()
