# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Pure validation and desired-state label planning. No GitHub mutations.

Taxonomy scopes come from the trusted roster. Legacy associations are removed
as classification state, never used to infer replacement labels: documentation
requires a content-derived area and topic, compatibility may concern drivers or
API contracts, and L7 may concern networking, policy, or both. The classifier
must support its chosen replacements with inspected substantive evidence.

Trusted label definitions may mark assessment labels with ``assessment: true``;
only that prepared subset is available to a separately authorized triage caller.
Explicit removals require membership in the trusted snapshot
``malformed_classification_labels`` allowlist, never a classifier-supplied list.
"""

from __future__ import annotations

import re

IDENTITY = ('schema_version', 'repository', 'number', 'kind', 'snapshot_id')
RESULT_KEYS = {*IDENTITY, 'area', 'topics', 'reasons', 'ambiguity', 'removals'}
LABEL = re.compile(r'(area|topic):[a-z0-9]+(?:[-:][a-z0-9]+)*\Z')
PROTECTED_PREFIXES = ('state:', 'roadmap:', 'agent:', 'execution:', 'owner:', 'human:')
CONFIDENCE = {'high': 'high conf', 'medium': 'med conf', 'low': 'low conf'}


def load_taxonomy(markdown: str, definitions: list[dict]) -> dict:
    """Read heading names/scopes without copying the roster into Python."""
    taxonomy = {'areas': {}, 'topics': {}, 'definitions': {}}
    active = None
    lines = []

    def save():
        if active:
            group = 'areas' if active.startswith('area:') else 'topics'
            taxonomy[group][active] = '\n'.join(lines).strip()

    for line in markdown.splitlines():
        heading = re.match(r'^#{1,6}\s+(.+?)\s*#*$', line)
        if heading:
            save()
            name = heading[1].strip().strip('`')
            active = name if LABEL.fullmatch(name) else None
            lines = []
        elif active and not line.lstrip().startswith('|'):
            lines.append(line)
    save()
    for definition in definitions:
        if not isinstance(definition, dict) or not isinstance(definition.get('name'), str):
            raise ValueError('Each label definition must have a name')
        name = definition['name']
        if name in taxonomy['definitions']:
            raise ValueError(f'Duplicate live label definition: {name}')
        taxonomy['definitions'][name] = dict(definition)
    return taxonomy


def _strings(value):
    return isinstance(value, list) and all(isinstance(x, str) and x for x in value)


def _classification(name):
    return name.startswith(('area:', 'topic:', 'retired:area:', 'retired:topic:'))


def _references(snapshot, refs, *, observation=False):
    if not _strings(refs) or not refs:
        return False
    index = snapshot.get('evidence_index', {})
    for ref in refs:
        artifact = index.get(ref)
        if not isinstance(artifact, dict) or artifact.get('inspected') is not True:
            return False
    substantive = [r for r in refs if r not in {'labels', 'existing_labels'}
                   and index[r].get('kind') not in {'labels', 'reconciliation'}]
    return bool(substantive) and (not observation or 'labels' in refs)


def validate_result(snapshot: dict, result: dict) -> dict:
    """Return validation errors separately from missing preparation prerequisites."""
    errors, missing = [], []
    if not isinstance(result, dict):
        return {'valid': False, 'errors': ['Result must be an object'], 'missing_prerequisites': []}
    if set(result) - RESULT_KEYS:
        errors.append('Unsupported result fields; commands are not accepted')
    for key in IDENTITY:
        if key not in result or type(result[key]) is not type(snapshot.get(key)) or result[key] != snapshot.get(key):
            errors.append(f'Result {key} does not match snapshot')
    if result.get('schema_version') != 1 or result.get('kind') not in ('issue', 'pull_request'):
        errors.append('Unsupported schema or item kind')
    area, topics = result.get('area'), result.get('topics')
    if not isinstance(area, str) or not LABEL.fullmatch(area) or not area.startswith('area:'):
        errors.append('Exactly one primary area string is required')
    if not _strings(topics) or len(topics) != len(set(topics)):
        errors.append('Topics must be a list of unique labels')
        topics = []
    for topic in topics:
        if not LABEL.fullmatch(topic) or not topic.startswith('topic:'):
            errors.append(f'Invalid desired topic: {topic}')
    desired = ({area} if isinstance(area, str) else set()) | set(topics)
    taxonomy = snapshot.get('taxonomy', {})
    canonical = set(taxonomy.get('areas', {})) | set(taxonomy.get('topics', {}))
    definitions = taxonomy.get('definitions', {})
    for label in sorted(desired):
        if LABEL.fullmatch(label):
            if label not in canonical:
                missing.append(f'Canonical taxonomy label unavailable: {label}')
            if label not in definitions:
                missing.append(f'Live label definition unavailable: {label}')
    if any(t.startswith('topic:sdk:') for t in topics) and 'topic:sdk' not in topics:
        errors.append('Language-specific SDK topics require topic:sdk')
    reasons = result.get('reasons')
    covered = set()
    if not isinstance(reasons, list) or not reasons:
        errors.append('Substantive evidence reasons are required')
        reasons = []
    for reason in reasons:
        if (not isinstance(reason, dict) or set(reason) != {'labels', 'evidence', 'reason'}
                or not _strings(reason.get('labels')) or not reason['labels']
                or not isinstance(reason.get('reason'), str) or not reason['reason'].strip()
                or not _references(snapshot, reason.get('evidence'))):
            errors.append('Each reason must reference inspected substantive evidence')
            continue
        if not set(reason['labels']) <= desired | set(snapshot.get('existing_labels', [])):
            errors.append('Reason references an unsupported label')
        covered.update(reason['labels'])
    if not desired <= covered:
        errors.append('Reasons must support every desired label')
    removals = result.get('removals', [])
    if not isinstance(removals, list):
        errors.append('Removals must be an explicit evidenced list')
        removals = []
    seen = set()
    for removal in removals:
        if not isinstance(removal, dict):
            errors.append('Malformed removal candidate')
            continue
        label = removal.get('label')
        if (set(removal) != {'label', 'evidence', 'reason'}
                or not isinstance(label, str) or label in seen
                or label not in snapshot.get('existing_labels', [])
                or label not in snapshot.get('malformed_classification_labels', [])
                or label in desired or label.startswith(PROTECTED_PREFIXES)
                or not isinstance(removal.get('reason'), str) or not removal['reason'].strip()
                or not _references(snapshot, removal.get('evidence'), observation=True)):
            errors.append('Removal requires a trusted malformed classification candidate, observed association and content, preserving workflow labels')
        if isinstance(label, str):
            seen.add(label)
    ambiguity = result.get('ambiguity')
    if 'ambiguity' not in result:
        errors.append('Ambiguity must be explicit, or null')
    if ambiguity is not None:
        if not isinstance(ambiguity, dict) or set(ambiguity) != {'boundary', 'chosen', 'alternative', 'evidence'}:
            errors.append('Invalid ambiguity record')
        else:
            valid = isinstance(ambiguity['boundary'], str) and bool(ambiguity['boundary'].strip())
            for option in ('chosen', 'alternative'):
                choice = ambiguity[option]
                valid = valid and isinstance(choice, dict)
                if not isinstance(choice, dict):
                    continue
                valid = (valid and set(choice) == {'labels', 'confidence'}
                         and _strings(choice.get('labels')) and bool(choice['labels'])
                         and isinstance(choice.get('confidence'), str)
                         and choice['confidence'] in CONFIDENCE)
                if _strings(choice.get('labels')):
                    valid = valid and len(choice['labels']) == len(set(choice['labels']))
                    valid = valid and set(choice['labels']) <= (desired if option == 'chosen' else canonical)
            if not valid or not _references(snapshot, ambiguity['evidence']):
                errors.append('Ambiguity requires valid choices and inspected evidence')
    return {'valid': not errors, 'errors': errors, 'missing_prerequisites': missing}


def _assessment(snapshot, assessment):
    if not isinstance(assessment, dict) or set(assessment) != {'authorized', 'reviewed_labels', 'desired_labels'}:
        return None
    reviewed, desired = assessment['reviewed_labels'], assessment['desired_labels']
    if assessment['authorized'] is not True or not _strings(reviewed) or not _strings(desired):
        return None
    definitions = snapshot.get('taxonomy', {}).get('definitions', {})
    if len(reviewed) != len(set(reviewed)) or len(desired) != len(set(desired)) or not set(desired) <= set(reviewed):
        return None
    for label in reviewed:
        if (label == 'state:accepted' or not label.startswith('state:')
                or definitions.get(label, {}).get('assessment') is not True):
            return None
    return set(reviewed), set(desired)


def plan_labels(snapshot: dict, result: dict, *, assessment: dict | None = None) -> dict:
    """Plan only supported label differences; return no operations on a hold."""
    existing = set(snapshot.get('existing_labels', []))
    report = {key: snapshot.get(key) for key in IDENTITY}
    report.update(status='preview', add=[], remove=[], preserve=sorted(existing),
                  final_labels=sorted(existing), bookkeeping=[], ambiguity=None,
                  missing_prerequisites=[], diagnostics=[])
    reviewed, assessment_desired = set(), set()
    if assessment is not None:
        assessed = _assessment(snapshot, assessment)
        if assessed is None:
            report.update(status='held', diagnostics=['Assessment requires authorization and a trusted reviewed assessment-only subset'])
            return report
        reviewed, assessment_desired = assessed
    eligibility = snapshot.get('eligibility', {})
    lifecycle = eligibility.get('lifecycle')
    accepted = eligibility.get('accepted') is True
    if lifecycle not in {'eligible', 'excluded', 'hold'} or type(eligibility.get('accepted')) is not bool:
        report.update(status='held', diagnostics=['Missing or invalid eligibility facts'])
        return report
    if lifecycle != 'eligible':
        report.update(status='held' if lifecycle == 'hold' else 'skipped',
                      diagnostics=[eligibility.get('reason', f'Lifecycle {lifecycle}')])
        return report
    desired, remove = set(), set()
    if accepted:
        validation = validate_result(snapshot, result)
        report['missing_prerequisites'] = validation['missing_prerequisites']
        if not validation['valid']:
            report.update(status='held', diagnostics=validation['errors'])
            return report
        desired = {result['area'], *result['topics']}
        remove = {label for label in existing if _classification(label)} - desired
        remove.update(removal['label'] for removal in result.get('removals', []))
        report['ambiguity'] = result.get('ambiguity')
    elif assessment is None:
        report.update(status='skipped', diagnostics=['Accepted work required for classification'])
        return report
    remove |= (existing & reviewed) - assessment_desired
    desired |= assessment_desired
    report['add'] = sorted(desired - existing)
    report['remove'] = sorted(remove)
    report['preserve'] = sorted(existing - remove)
    report['final_labels'] = sorted((existing - remove) | desired)
    if report['missing_prerequisites']:
        report['status'] = 'prerequisite'
    return report


def format_report(report: dict) -> str:
    """Render a local report; never return commands or ticket comments."""
    lines = [f"{report.get('repository')}#{report.get('number')} — {report.get('status')}"]
    for key in ('add', 'remove', 'preserve'):
        lines.append(f"{key.title()}: {', '.join(report.get(key, [])) or 'none'}")
    ambiguity = report.get('ambiguity')
    if ambiguity:
        chosen, other = ambiguity['chosen'], ambiguity['alternative']
        lines.append(f"Ambiguity: chose {', '.join(chosen['labels'])} ({CONFIDENCE[chosen['confidence']]}) "
                     f"over {', '.join(other['labels'])} ({CONFIDENCE[other['confidence']]})")
    else:
        lines.append('Ambiguity: none')
    for title, key in [('Bookkeeping', 'bookkeeping'), ('Missing prerequisite', 'missing_prerequisites'), ('Diagnostic', 'diagnostics')]:
        for entry in report.get(key, []):
            lines.append(f'{title}: {entry}')
    return '\n'.join(lines)
