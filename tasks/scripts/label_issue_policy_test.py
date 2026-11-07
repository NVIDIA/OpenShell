# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Behavioral tests for classification validation and bounded reconciliation."""
import copy
import unittest

from label_issue_policy import format_report, load_taxonomy, plan_labels, validate_result


ROSTER = '''## Areas
### area:runtime
Execution, proxy policy.
### area:platform
API and SDKs.
## Topics
### topic:documentation
Documentation.
### topic:networking
Network transport.
### topic:policy
Policy enforcement.
### topic:sdk
Language bindings.
#### topic:sdk:python
Python SDK.
### topic:ux
User interaction.
### topic:dx
Contributor experience.
'''
NAMES = ['area:runtime', 'area:platform', 'topic:documentation', 'topic:networking',
         'topic:policy', 'topic:sdk', 'topic:sdk:python', 'topic:ux', 'topic:dx',
         'state:accepted', 'state:triage-needed', 'state:needs-info']


def snapshot():
    return dict(schema_version=1, repository='NVIDIA/OpenShell', number=12,
                kind='issue', snapshot_id='snap-1', taxonomy=load_taxonomy(
                    ROSTER, [{'name': name, 'id': name, 'assessment': name in ['state:triage-needed', 'state:needs-info']} for name in NAMES]),
                existing_labels=['area:gateway', 'state:accepted', 'human:priority'],
                evidence_index={'body': {'kind': 'body', 'inspected': True, 'source_digest': 'a' * 64,
                    'inspection': {'source_digest': 'a' * 64, 'via': 'packet'}},
                                'comment:1': {'inspected': False},
                                'labels': {'kind': 'reconciliation', 'inspected': True, 'source_digest': 'd' * 64,
                    'inspection': {'source_digest': 'd' * 64, 'via': 'packet'}}},
                eligibility={'accepted': True, 'lifecycle': 'eligible'})


def result():
    return dict(schema_version=1, repository='NVIDIA/OpenShell', number=12,
                kind='issue', snapshot_id='snap-1', area='area:runtime',
                topics=['topic:policy'], reasons=[dict(
                    labels=['area:runtime', 'topic:policy'], evidence=['body'],
                    reason='Proxy enforcement changes.')], ambiguity=None)


class PolicyTests(unittest.TestCase):
    def test_taxonomy_reads_nested_headings_and_scopes_without_live_only_entries(self):
        tax = load_taxonomy(ROSTER, [{'name': 'area:invented'}])
        self.assertIn('topic:sdk:python', tax['topics'])
        self.assertIn('Execution, proxy policy.', tax['areas']['area:runtime'])
        self.assertNotIn('area:invented', tax['areas'])

    def test_invalid_area_cardinality_rejected_for_both_item_types(self):
        for kind in ['issue', 'pull_request']:
            for area in [None, [], '', ['area:runtime', 'area:platform']]:
                with self.subTest(kind=kind, area=area):
                    snap, decision = snapshot(), result()
                    snap['kind'] = decision['kind'] = kind
                    decision['area'] = area
                    self.assertFalse(validate_result(snap, decision)['valid'])

    def test_invalid_classification_and_arbitrary_commands_rejected(self):
        for changes in [dict(topics=['topic:policy', 'topic:policy']),
                        dict(topics=['retired:topic:l7']),
                        dict(area='state:accepted'), dict(commands=['post comment']),
                        dict(add=['state:accepted']), dict(number=13),
                        dict(snapshot_id='another'), dict(repository='other/repo'),
                        dict(kind='pull_request'), dict(schema_version=2)]:
            with self.subTest(changes=changes):
                self.assertFalse(validate_result(snapshot(), result() | changes)['valid'])

    def test_reasons_require_inspected_substantive_evidence_and_cover_desired_labels(self):
        for evidence in [[], ['unknown'], ['comment:1'], ['labels']]:
            decision = result()
            decision['reasons'][0]['evidence'] = evidence
            self.assertFalse(validate_result(snapshot(), decision)['valid'])
        decision = result()
        decision['reasons'][0]['labels'] = ['area:runtime']
        self.assertFalse(validate_result(snapshot(), decision)['valid'])

    def test_missing_canonical_and_live_labels_are_blocking_prerequisites(self):
        snap, decision = snapshot(), result()
        del snap['taxonomy']['definitions']['topic:policy']
        decision['topics'].append('topic:unprepared')
        decision['reasons'][0]['labels'].append('topic:unprepared')
        report = plan_labels(snap, decision)
        self.assertEqual(report['status'], 'prerequisite')
        self.assertTrue(any('topic:policy' in text for text in report['missing_prerequisites']))
        self.assertTrue(any('topic:unprepared' in text for text in report['missing_prerequisites']))

    def test_reconciliation_removes_only_classification_and_preserves_human_labels(self):
        snap = snapshot()
        snap['existing_labels'] += ['retired:topic:l7', 'state:running', 'roadmap:next']
        report = plan_labels(snap, result())
        self.assertEqual(report['add'], ['area:runtime', 'topic:policy'])
        self.assertEqual(report['remove'], ['area:gateway', 'retired:topic:l7'])
        self.assertEqual(report['preserve'], ['human:priority', 'roadmap:next', 'state:accepted', 'state:running'])
        self.assertNotIn('comment', report)

    def test_docs_migration_uses_content_and_does_not_treat_old_label_as_evidence(self):
        snap = snapshot()
        snap['existing_labels'] = ['area:docs']
        report = plan_labels(snap, result())
        self.assertEqual(report['status'], 'preview')
        self.assertNotIn('topic:documentation', report['add'])
        decision = result()
        decision['topics'].append('topic:documentation')
        decision['reasons'][0]['labels'].append('topic:documentation')
        report = plan_labels(snap, decision)
        self.assertEqual(report['status'], 'preview')
        self.assertEqual(report['remove'], ['area:docs'])

    def test_legacy_names_do_not_force_blind_substitution(self):
        snap = snapshot()
        snap['existing_labels'] = ['retired:topic:compatibility', 'retired:topic:l7']
        decision = result()
        report = plan_labels(snap, decision)
        self.assertEqual(report['add'], ['area:runtime', 'topic:policy'])
        self.assertEqual(report['remove'], ['retired:topic:compatibility', 'retired:topic:l7'])

    def test_nested_sdk_requires_broad_subscription_topic(self):
        decision = result()
        decision['topics'] = ['topic:sdk:python']
        decision['reasons'][0]['labels'] = ['area:runtime', 'topic:sdk:python']
        self.assertFalse(validate_result(snapshot(), decision)['valid'])
        decision['topics'].append('topic:sdk')
        decision['reasons'][0]['labels'].append('topic:sdk')
        self.assertTrue(validate_result(snapshot(), decision)['valid'])

    def test_malformed_names_need_explicit_observed_evidenced_removals(self):
        snap = snapshot()
        snap['existing_labels'] += ['areaa:runtime', 'state:area-review']
        snap['malformed_classification_labels'] = ['areaa:runtime']
        self.assertIn('areaa:runtime', plan_labels(snap, result())['preserve'])
        decision = result()
        decision['removals'] = [dict(label='areaa:runtime', evidence=['labels', 'body'], reason='Misspelled classification association.')]
        report = plan_labels(snap, decision)
        self.assertIn('areaa:runtime', report['remove'])
        self.assertIn('state:area-review', report['preserve'])
        decision['removals'][0]['label'] = 'nonexistent'
        self.assertFalse(validate_result(snap, decision)['valid'])
        decision['removals'][0]['label'] = 'state:accepted'
        self.assertFalse(validate_result(snap, decision)['valid'])

    def test_explicit_removals_reject_unrelated_labels_even_with_content_evidence(self):
        for label in ['bug', 'help wanted', 'priority:high', 'areaa:runtime']:
            with self.subTest(label=label):
                snap, decision = snapshot(), result()
                snap['existing_labels'].append(label)
                decision['removals'] = [dict(label=label, evidence=['labels', 'body'],
                    reason='Classifier claims this is malformed classification.')]
                self.assertFalse(validate_result(snap, decision)['valid'])
                report = plan_labels(snap, decision)
                self.assertEqual(report['status'], 'held')
                self.assertEqual(report['remove'], [])
                self.assertIn(label, report['preserve'])

    def test_classifier_cannot_supply_its_own_malformed_candidate_allowlist(self):
        snap, decision = snapshot(), result()
        snap['existing_labels'].append('priority:high')
        decision['malformed_classification_labels'] = ['priority:high']
        decision['removals'] = [dict(label='priority:high', evidence=['labels', 'body'],
            reason='Classifier claims classification.')]
        self.assertFalse(validate_result(snap, decision)['valid'])

    def test_trusted_malformed_candidates_still_require_observation_and_evidence(self):
        for label, evidence in [('areaa:runtime', ['labels']),
                                ('not-observed', ['labels', 'body']),
                                ('state:accepted', ['labels', 'body'])]:
            with self.subTest(label=label, evidence=evidence):
                snap, decision = snapshot(), result()
                snap['existing_labels'].append('areaa:runtime')
                snap['malformed_classification_labels'] = [label]
                decision['removals'] = [dict(label=label, evidence=evidence,
                    reason='Explicit candidate.')]
                self.assertFalse(validate_result(snap, decision)['valid'])

    def test_medium_confidence_formats_locally_without_holding(self):
        decision = result()
        decision['topics'].append('topic:ux')
        decision['reasons'][0]['labels'].append('topic:ux')
        decision['ambiguity'] = dict(boundary='Interaction', chosen=dict(labels=['topic:ux'], confidence='medium'),
                                     alternative=dict(labels=['topic:dx'], confidence='low'), evidence=['body'])
        report = plan_labels(snapshot(), decision)
        self.assertEqual(report['status'], 'preview')
        self.assertIn('Ambiguity: chose topic:ux (med conf) over topic:dx (low conf)', format_report(report))

    def test_unaccepted_and_lifecycle_excluded_do_not_change_classification(self):
        for eligibility in [dict(accepted=False, lifecycle='eligible'),
                            dict(accepted=True, lifecycle='excluded'),
                            dict(accepted=True, lifecycle='hold')]:
            snap = snapshot()
            snap['eligibility'] = eligibility
            report = plan_labels(snap, result())
            self.assertEqual(report['add'], [])
            self.assertEqual(report['remove'], [])
            self.assertIn(report['status'], ['skipped', 'held'])

    def test_authorized_assessment_changes_only_explicit_reviewed_subset_preacceptance(self):
        snap = snapshot()
        snap['eligibility']['accepted'] = False
        snap['existing_labels'].append('state:triage-needed')
        assessment = dict(authorized=True, reviewed_labels=['state:triage-needed', 'state:needs-info'],
                          desired_labels=['state:needs-info'])
        report = plan_labels(snap, {}, assessment=assessment)
        self.assertEqual(report['add'], ['state:needs-info'])
        self.assertEqual(report['remove'], ['state:triage-needed'])
        self.assertIn('state:accepted', report['preserve'])
        assessment['reviewed_labels'].append('state:accepted')
        report = plan_labels(snap, {}, assessment=assessment)
        self.assertEqual(report['status'], 'held')
        self.assertEqual(report['remove'], [])

    def test_assessment_requires_authorization_and_disallows_nonassessment_labels(self):
        for assessment in [dict(authorized=False, reviewed_labels=['state:needs-info'], desired_labels=[]),
                           dict(authorized=True, reviewed_labels=['roadmap:next'], desired_labels=[]),
                           dict(authorized=True, reviewed_labels=['state:triage-needed'], desired_labels=['state:needs-info'])]:
            with self.subTest(assessment=assessment):
                report = plan_labels(snapshot(), result(), assessment=assessment)
                self.assertEqual(report['status'], 'held')
                self.assertEqual(report['add'], [])

    def test_untrusted_or_missing_assessment_marker_cannot_authorize_writes(self):
        snap = snapshot()
        del snap['taxonomy']['definitions']['state:needs-info']['assessment']
        report = plan_labels(snap, result(), assessment=dict(
            authorized=True, reviewed_labels=['state:needs-info'],
            desired_labels=['state:needs-info']))
        self.assertEqual(report['status'], 'held')
        self.assertEqual(report['add'], [])

    def test_malformed_json_field_shapes_fail_validation_without_crashing(self):
        for changes in [dict(kind=[]), dict(topics=[{}]), dict(reasons=[None]),
                        dict(removals=[{}]), dict(ambiguity={}),
                        dict(ambiguity=dict(boundary='Boundary', evidence=['body'],
                            chosen=dict(labels=['topic:policy'], confidence={}),
                            alternative=dict(labels=['topic:dx'], confidence='low')))]:
            with self.subTest(changes=changes):
                self.assertFalse(validate_result(snapshot(), result() | changes)['valid'])

    def test_all_confidences_produce_only_local_reports(self):
        for confidence in ['high', 'medium', 'low']:
            decision = result()
            decision['ambiguity'] = dict(boundary='Policy versus transport', evidence=['body'],
                chosen=dict(labels=['topic:policy'], confidence=confidence),
                alternative=dict(labels=['topic:networking'], confidence='low'))
            report = plan_labels(snapshot(), decision)
            self.assertEqual(report['status'], 'preview')
            self.assertIn('Ambiguity: chose topic:policy', format_report(report))
            self.assertEqual(set(report), {'schema_version', 'repository', 'number', 'kind',
                'snapshot_id', 'status', 'add', 'remove', 'preserve', 'final_labels',
                'bookkeeping', 'ambiguity', 'missing_prerequisites', 'diagnostics'})

    def test_inspected_flag_without_current_source_provenance_cannot_justify_reasons(self):
        for declaration in [None, {'source_digest': 'b' * 64, 'via': 'packet'},
                            {'source_digest': 'a' * 64, 'via': 'fetched'}]:
            snap = snapshot()
            snap['evidence_index']['body']['source_digest'] = 'a' * 64
            snap['evidence_index']['body'].pop('inspection', None)
            if declaration is not None:
                snap['evidence_index']['body']['inspection'] = declaration
            self.assertFalse(validate_result(snap, result())['valid'])

    def test_pure_membership_indexes_require_actual_substantive_child_or_paths(self):
        for kind in ['comments', 'reviews', 'review_comments', 'timeline']:
            snap, decision = snapshot(), result()
            snap['evidence_index']['index'] = dict(kind=kind, content=['comment:1'],
                members=['comment:1'], inspected=True, source_digest='c' * 64,
                inspection={'source_digest': 'c' * 64, 'via': 'explicit_expansion'})
            decision['reasons'][0]['evidence'] = ['index']
            self.assertFalse(validate_result(snap, decision)['valid'])
        snap['evidence_index']['index']['kind'] = 'files'
        snap['evidence_index']['index']['content'] = ['patch:crates/runtime/src/proxy.rs']
        self.assertTrue(validate_result(snap, decision)['valid'])

    def test_validation_never_mutates_snapshot_or_result(self):
        snap, decision = snapshot(), result()
        before = copy.deepcopy((snap, decision))
        plan_labels(snap, decision)
        self.assertEqual((snap, decision), before)


if __name__ == '__main__':
    unittest.main()
