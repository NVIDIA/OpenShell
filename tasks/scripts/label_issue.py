# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Preview-first label reconciliation, with no model invocation or ticket comments.

One coordinated manual executor per item is required. POSIX flock serializes local
processes only; optimistic material/event checks detect other writers, without
claiming cross-host locking or atomic GitHub transactions. Mutations use one HTTP request with serial top-level GraphQL aliases, one label
per alias. Alias order establishes the event transcript without assuming order
inside a label array. The mutations remain separate, non-atomic operations.
"""
from __future__ import annotations
import argparse
import copy
import fcntl
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
import label_issue_checkpoint as checkpoint
import label_issue_evidence as evidence
from label_issue_github import GitHubClient
from label_issue_policy import is_inspected_source, plan_labels
# Bump for classifier/skill/migration semantic changes; trusted document hashes
# are bound separately, without binding unrelated repository HEAD changes.
POLICY_VERSION = 'openshell-labeler-policy-v2'
DEFAULT_BOOKKEEPING_LABEL = 'meta:labeler-checkpoint'
# Configuration selects this reviewed authority; alternate names need code review.
APPROVED_BOOKKEEPING_LABELS = frozenset({DEFAULT_BOOKKEEPING_LABEL})
ADD_QUERY = 'mutation($input: AddLabelsToLabelableInput!) {\n apply: addLabelsToLabelable(input: $input) { labelable { __typename } }\n}'
REMOVE_QUERY = 'mutation($input: RemoveLabelsFromLabelableInput!) {\n apply: removeLabelsFromLabelable(input: $input) { labelable { __typename } }\n}'
TIMELINE_QUERY = 'query($item: ID!, $before: String) { node(id: $item) {\n __typename\n ... on Issue { CONNECTION }\n ... on PullRequest { CONNECTION }\n} }'.replace('CONNECTION', 'timelineItems(last: 100, before: $before,\n itemTypes: [CLOSED_EVENT, REOPENED_EVENT]) {\n nodes { __typename ... on ClosedEvent { id createdAt actor { login }\n closer { __typename ... on PullRequest { number merged mergedAt repository { nameWithOwner } } }\n } ... on ReopenedEvent { id createdAt actor { login } } }\n pageInfo { hasPreviousPage startCursor }\n}')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def _report(source, status, message=None):
    report = {key: source.get(key) for key in ('schema_version', 'repository', 'number', 'kind', 'snapshot_id')}
    report.update(status=status, add=[], remove=[], preserve=sorted(source.get('existing_labels', [])), bookkeeping=[], ambiguity=None, missing_prerequisites=[], diagnostics=[], ordered_writes=[], checkpoint_verified=False, classifier_required=False)
    if message:
        report['diagnostics'].append(message)
    return report


def _version(snapshot):
    return POLICY_VERSION + ':' + snapshot['policy_version']


def _trusted(actors):
    if not isinstance(actors, (set, frozenset)) or not actors or (not all((isinstance(actor, str) and actor for actor in actors))):
        raise ValueError('At least one explicitly trusted labeling actor is required')
    return {actor.casefold() for actor in actors}


def _relevant_timeline(item_id, api):
    before, cursors, identities, events = (None, set(), set(), [])
    for _ in range(100):
        payload = api('graphql', method='POST', data={'query': TIMELINE_QUERY, 'variables': {'item': item_id, 'before': before}})
        if not isinstance(payload, dict) or payload.get('errors'):
            raise ValueError('Relevant lifecycle timeline query failed')
        node = payload.get('data', {}).get('node')
        if not isinstance(node, dict) or node.get('__typename') not in {'Issue', 'PullRequest'}:
            raise ValueError('Relevant timeline item is unavailable')
        connection = node.get('timelineItems', {})
        nodes, page = (connection.get('nodes'), connection.get('pageInfo', {}))
        if not isinstance(nodes, list) or len(nodes) > 100 or type(page.get('hasPreviousPage')) is not bool:
            raise ValueError('Malformed relevant timeline page')
        for event in nodes:
            if not isinstance(event, dict) or event.get('__typename') not in {'ClosedEvent', 'ReopenedEvent'} or (not event.get('id')) or (not event.get('createdAt')) or (event['id'] in identities):
                raise ValueError('Malformed/repeated lifecycle event')
            identities.add(event['id'])
        events = nodes + events
        if not page['hasPreviousPage']:
            encoded = _canonical(events)
            return {'kind': 'relevant_timeline', 'coverage': 'complete', 'source_digest': hashlib.sha256(encoded).hexdigest(), 'source_bytes': len(encoded)}
        before = page.get('startCursor')
        if not isinstance(before, str) or not before or before in cursors or (not nodes):
            raise ValueError('Invalid relevant timeline cursor')
        cursors.add(before)
    raise ValueError('Relevant timeline page budget exhausted')


def _hydrate(snapshot, api, template=None):
    previous_inspection = {identity: (source.get('source_digest'), source.get('inspected', False))
                           for identity, source in snapshot['evidence_index'].items()}
    collections = ['comments']
    if snapshot['kind'] == 'pull_request':
        collections += ['files', 'reviews', 'review_comments']
    for identity in collections:
        source = snapshot['evidence_index'][identity]
        if source.get('coverage') != 'complete' or 'members' not in source:
            evidence.expand_evidence(snapshot, [identity], api=api)
    # Deterministic collection fetching is not a model read. Preserve only
    # unchanged prior inspection, including the parent collection artifacts.
    for identity, source in snapshot['evidence_index'].items():
        digest, inspected = previous_inspection.get(identity, (None, False))
        source['inspected'] = bool(inspected and digest == source.get('source_digest'))
    # Authority is a fetched fact, independent of which source the model reads.
    # Resolve each distinct actor once in this hydration pass; do not mark any
    # new source inspected merely because deterministic checks fetched its role.
    authorities = {}
    for source in snapshot['evidence_index'].values():
        user = source.get('source_user') or {}
        authority = source.get('actor_authority') or {}
        login = user.get('login', '').casefold()
        if authority.get('verified') is True and authority.get('login', '').casefold() == login:
            authorities[login] = copy.deepcopy(authority)
    author = (snapshot['item_material'].get('user') or {}).get('login', '')
    for source in snapshot['evidence_index'].values():
        if source.get('kind') not in {'comment', 'review', 'review_comment'}:
            continue
        user = source.get('source_user') or {}
        login = user.get('login', '').casefold()
        if login not in authorities:
            authorities[login] = evidence._authority(snapshot['repository'], user, author,
                set(snapshot['trusted_maintainers']), api)
        source['actor_authority'] = copy.deepcopy(authorities[login])
    if template:
        for identity, previous in template['evidence_index'].items():
            current = snapshot['evidence_index'].get(identity)
            if current and is_inspected_source(previous) and previous.get('source_digest') == current.get('source_digest'):
                current['inspected'] = True
                current['inspection'] = copy.deepcopy(previous['inspection'])
    snapshot['relevant_timeline'] = _relevant_timeline(snapshot['item_id'], api)
    _persist(snapshot)
    return snapshot


def _material(snapshot):
    material = evidence.material_state(snapshot)
    material['relevant_timeline'] = copy.deepcopy(snapshot['relevant_timeline'])
    return material


def _persist(snapshot):
    # Keep delivery packets/inspection metadata consistent with the manifest.
    evidence._persist(snapshot)


def prepare(repository: str, number: int, directory: Path, *, api, force: bool=False, trusted_actors: set[str], assessment_only=False, assessment_labels=frozenset()) -> dict:
    """Discover checkpoints before hydration; verified unchanged returns no packet."""
    facts = {'repository': repository, 'number': number}
    try:
        actors = _trusted(trusted_actors)
        facts = evidence.preflight(repository, number, api=api, force=force)
        eligibility = facts['eligibility']
        if eligibility['lifecycle'] != 'eligible':
            return _report(facts, 'held' if eligibility['lifecycle'] == 'hold' else 'skipped', eligibility['reason'])
        if not eligibility['accepted'] and (not assessment_only):
            return _report(facts, 'skipped', 'Accepted work required for classification; assessment-only preparation is available')
        discovery = checkpoint.find_checkpoint(facts['item_id'], api=api, trusted_actors=actors) if not force and (not assessment_only) else {'status': 'bypassed'}
        snapshot = evidence.prepare_snapshot(facts['repository'], facts['number'], directory, api=api, assessment_labels=assessment_labels, defer_delivery=True)
        refreshed_eligibility = snapshot['eligibility']
        if refreshed_eligibility['lifecycle'] != 'eligible':
            return _report(snapshot, 'held' if refreshed_eligibility['lifecycle'] == 'hold' else 'skipped', refreshed_eligibility['reason'])
        if not refreshed_eligibility['accepted'] and not assessment_only:
            return _report(snapshot, 'skipped', 'Acceptance changed during preparation; classification is not authorized')
        snapshot['_assessment_labels'] = sorted(assessment_labels)
        snapshot['assessment_only'] = bool(assessment_only)
        _hydrate(snapshot, api)
        if not assessment_only:
            material = _material(snapshot)
            if discovery['status'] == 'found':
                candidate = discovery['checkpoint']
                if candidate.get('version') == 2:
                    events = checkpoint.collect_label_events(snapshot['item_id'], candidate['boundary_id'], api=api)
                    if checkpoint.checkpoint_matches(candidate, material, set(snapshot['existing_labels']), _version(snapshot), label_events=events):
                        report = _report(snapshot, 'unchanged', 'Verified checkpoint; no classification or writes required')
                        report.update(checkpoint_verified=True, telemetry=getattr(api, 'diagnostics', {}), checkpoint_lookup=discovery['diagnostics'])
                        return report
            snapshot['label_event_boundary'] = checkpoint.latest_label_event(snapshot['item_id'], api=api)['boundary_id']
        if assessment_only:
            snapshot['label_event_boundary'] = checkpoint.latest_label_event(snapshot['item_id'], api=api)['boundary_id']
        # Initial exposure is finalized only after all hydration metadata and
        # boundary facts are present in the packet actually returned.
        snapshot.pop('_preparing', None)
        _persist(snapshot)
        report = _report(snapshot, 'ready')
        report['classifier_required'] = not assessment_only
        report.update(snapshot=snapshot, snapshot_path=str(Path(snapshot['_directory']) / 'manifest.json'), checkpoint_lookup=discovery, telemetry=getattr(api, 'diagnostics', {}))
        return report
    except Exception as exc:
        return _report(facts, 'error', str(exc))

@contextmanager
def _fresh(snapshot, api):
    with tempfile.TemporaryDirectory(prefix='openshell-label-refresh-') as directory:
        current = evidence.prepare_snapshot(snapshot['repository'], snapshot['number'], Path(directory), api=api, assessment_labels=set(snapshot.get('_assessment_labels', [])), defer_delivery=True)
        current['assessment_only'] = snapshot.get('assessment_only', False)
        _hydrate(current, api, template=snapshot)
        yield current


def _lifecycle(snapshot, result):
    result = copy.deepcopy(result)
    interpretation = result.pop('lifecycle', None)
    if interpretation is None:
        return (result, None)
    if not isinstance(interpretation, dict) or set(interpretation) != {'disposition', 'evidence', 'reason'} or interpretation['disposition'] not in {'hold', 'excluded'} or (not isinstance(interpretation['reason'], str)) or (not interpretation['reason'].strip()) or (not isinstance(interpretation['evidence'], list)) or (not interpretation['evidence']):
        return (result, _report(snapshot, 'held', 'Invalid restricting lifecycle interpretation'))
    for identity in interpretation['evidence']:
        entry = snapshot['evidence_index'].get(identity, {}) if isinstance(identity, str) else {}
        authority = entry.get('actor_authority', {})
        if not is_inspected_source(entry) or entry.get('kind') not in {'comment', 'review', 'review_comment'} or (entry.get('source_user') or {}).get('type') == 'Bot' or (authority.get('verified') is not True) or (authority.get('role') not in {'author', 'maintainer'}):
            return (result, _report(snapshot, 'held', 'Lifecycle interpretation requires inspected recorded human author/maintainer evidence'))
    mechanical = snapshot['eligibility']['lifecycle']
    status = 'skipped' if mechanical == 'excluded' or interpretation['disposition'] == 'excluded' else 'held'
    return (result, _report(snapshot, status, interpretation['reason']))


def _mutation(snapshot, action, label, label_id, *, rationale=None, bookkeeping=False):
    inputs = {'labelableId': snapshot['item_id']}
    if action == 'add':
        entry = {'labelId': label_id}
        if rationale is not None:
            entry['rationale'] = rationale
        inputs['labels'] = [entry]
    else:
        inputs['labelIds'] = [label_id]
    return {'action': action, 'label': label, 'label_id': label_id, 'bookkeeping': bookkeeping, 'path': 'graphql', 'method': 'POST', 'data': {'query': ADD_QUERY if action == 'add' else REMOVE_QUERY, 'variables': {'input': inputs}}}


def _batch(operations):
    variables, declarations, fields = ({}, [], [])
    for position, operation in enumerate(operations):
        alias = f'op{position}'
        operation['alias'] = alias
        addition = operation['action'] == 'add'
        kind = 'AddLabelsToLabelableInput' if addition else 'RemoveLabelsFromLabelableInput'
        field = 'addLabelsToLabelable' if addition else 'removeLabelsFromLabelable'
        declarations.append(f'${alias}: {kind}!')
        fields.append(f'{alias}: {field}(input: ${alias}) {{ labelable {{ __typename }} }}')
        variables[alias] = copy.deepcopy(operation['data']['variables']['input'])
    query = 'mutation(' + ', '.join(declarations) + ') {\n' + '\n'.join(fields) + '\n}'
    return {'path': 'graphql', 'method': 'POST', 'data': {'query': query, 'variables': variables}}


def _plan(snapshot, result, api, assessment, bookkeeping_label, executor):
    result, restriction = _lifecycle(snapshot, result)
    if restriction:
        return restriction
    planning = copy.deepcopy(snapshot)
    assessment_only = bool(snapshot.get('assessment_only'))
    if assessment_only:
        if result:
            return _report(snapshot, 'held', 'Assessment-only preparation accepts no classification result')
        planning['eligibility']['accepted'] = False
    if not assessment_only and bookkeeping_label is not None and (bookkeeping_label not in APPROVED_BOOKKEEPING_LABELS):
        report = _report(snapshot, 'prerequisite', 'Bookkeeping label is not in the reviewed approved allowlist')
        report['missing_prerequisites'] = ['Use the approved dedicated meta:labeler-checkpoint label; alternate names require a reviewed code change']
        return report
    report = plan_labels(planning, result, assessment=assessment)
    report.update(ordered_writes=[], checkpoint_verified=False, assessment_only=assessment_only)
    if report['status'] != 'preview':
        return report
    identity = api('user')['login'] if executor is None else executor
    if not isinstance(identity, str) or not identity or identity.strip() != identity:
        return _report(snapshot, 'held', 'Executor must be a separately configured GitHub login')
    actor = identity.casefold()
    report['executor'] = actor
    definitions = snapshot['taxonomy']['definitions']
    operations = []

    def add(action, label, bookkeeping=False):
        definition = definitions.get(label, {})
        label_id = definition.get('node_id')
        if not isinstance(label_id, str) or not label_id:
            report['missing_prerequisites'].append(f'GraphQL node_id missing for label {label}')
            return
        operations.append(_mutation(snapshot, action, label, label_id, bookkeeping=bookkeeping))
    existing = set(snapshot['existing_labels'])
    final = set(report['final_labels'])
    if not assessment_only and bookkeeping_label and (bookkeeping_label in existing):
        if not bookkeeping_label.startswith('meta:'):
            return _report(snapshot, 'held', 'Bookkeeping must use an explicitly configured dedicated meta: label')
        add('remove', bookkeeping_label, True)
        final.discard(bookkeeping_label)
    for label in report['add']:
        add('add', label)
    if not assessment_only and (not report['add']):
        if not bookkeeping_label or not bookkeeping_label.startswith('meta:'):
            report['missing_prerequisites'].append('Approved dedicated bookkeeping label is required')
        else:
            add('add', bookkeeping_label, True)
    for label in report['remove']:
        if not (not assessment_only and label == bookkeeping_label and (label in existing)):
            add('remove', label)
    if not assessment_only and (not report['add']) and bookkeeping_label:
        add('remove', bookkeeping_label, True)
        final.discard(bookkeeping_label)
    if report['missing_prerequisites']:
        report['status'] = 'prerequisite'
        return report
    if not assessment_only:
        transcript = [{'actor': actor, 'action': operation['action'], 'label_id': operation['label_id']} for operation in operations]
        fp = checkpoint.fingerprint(_material(snapshot), final, _version(snapshot))
        rationale = checkpoint.encode_checkpoint(fp, boundary_id=snapshot['label_event_boundary'], operations_digest=checkpoint.operation_digest(transcript), event_count=len(transcript))
        additions = [operation for operation in operations if operation['action'] == 'add']
        additions[-1]['data']['variables']['input']['labels'][0]['rationale'] = rationale
        report['candidate_rationale'] = rationale
    report['final_labels'] = sorted(final)
    report['ordered_writes'] = operations
    if operations:
        report['mutation_request'] = _batch(operations)
    report['bookkeeping'] = [f"{operation['action']} {operation['label']}" for operation in operations if operation['bookkeeping']]
    return report


def _same_material(before, current, labels):
    return checkpoint.fingerprint(_material(before), set(labels), _version(before)) == checkpoint.fingerprint(_material(current), set(labels), _version(current))


def _preview(snapshot, result, api, assessment, bookkeeping_label, executor):
    if not isinstance(result, dict):
        return _report(snapshot, 'held', 'Result must be a JSON object')
    with _fresh(snapshot, api) as current:
        if current['eligibility']['lifecycle'] != 'eligible':
            return _report(snapshot, 'held' if current['eligibility']['lifecycle'] == 'hold' else 'skipped', current['eligibility']['reason'])
        if set(snapshot['existing_labels']) != set(current['existing_labels']):
            return _report(snapshot, 'stale', 'Live labels changed since preparation')
        if not _same_material(snapshot, current, set(snapshot['existing_labels'])):
            return _report(snapshot, 'stale', 'Prepared substantive inputs changed; prepare and review again')
        boundary = checkpoint.latest_label_event(snapshot['item_id'], api=api)['boundary_id']
        if boundary != snapshot.get('label_event_boundary'):
            return _report(snapshot, 'stale', 'External label events changed since preparation')
        return _plan(snapshot, result, api, assessment, bookkeeping_label, executor)


def preview(snapshot: dict, result: dict, *, api, assessment: dict | None=None, bookkeeping_label: str | None=DEFAULT_BOOKKEEPING_LABEL, executor: str | None=None) -> dict:
    """Show exact ordered request payloads without any external mutation."""
    try:
        return _preview(snapshot, result, api, assessment, bookkeeping_label, executor)
    except checkpoint.IncompleteMaterial as exc:
        report = _report(snapshot, 'prerequisite', str(exc))
        report['missing_prerequisites'] = [str(exc)]
        return report
    except Exception as exc:
        return _report(snapshot, 'error', str(exc))


def _lock_path(repository, number):
    directory = Path(tempfile.gettempdir()) / 'openshell-label-issue-locks'
    directory.mkdir(mode=448, exist_ok=True)
    identity = hashlib.sha256(f'{repository.casefold()}#{int(number)}'.encode()).hexdigest()
    return directory / (identity + '.lock')

@contextmanager
def _item_lock(repository, number):
    flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(_lock_path(repository, number), flags, 384)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def _live_labels(snapshot, api):
    return sorted((entry['name'] for entry in api(f"repos/{snapshot['repository']}/issues/{snapshot['number']}/labels?per_page=100", pages=True)))


def apply(snapshot: dict, result: dict, *, api, trusted_actors: set[str], bookkeeping_label: str | None=DEFAULT_BOOKKEEPING_LABEL, assessment: dict | None=None, expected_preview: dict | None=None, executor: str | None=None) -> dict:
    """Recheck under a local lock, write once, then separately verify live facts."""
    report = _report(snapshot, 'error')
    attempted = False
    try:
        actors = _trusted(trusted_actors)
        with _item_lock(snapshot['repository'], snapshot['number']):
            report = preview(snapshot, result, api=api, assessment=assessment, bookkeeping_label=bookkeeping_label, executor=executor)
            if report['status'] != 'preview':
                return report
            if expected_preview is not None:
                if not isinstance(expected_preview, dict) or expected_preview.get('status') != 'preview':
                    return _report(snapshot, 'held', 'Expected preview must be the separately confirmed preview report')
                confirmed = ('mutation_request', 'ordered_writes')
                if any((expected_preview.get(key) != report.get(key) for key in confirmed)):
                    return _report(snapshot, 'stale', 'The current exact mutation payload differs from the confirmed preview')
            if report['executor'] not in actors:
                return _report(snapshot, 'held', 'Authenticated executor is not an explicitly trusted labeling actor')
            if not report['ordered_writes']:
                report['status'] = 'no-op'
                return report
            failure = None
            request = report['mutation_request']
            attempted = True
            try:
                payload = api(request['path'], method=request['method'], data=request['data'])
                if not isinstance(payload, dict) or payload.get('errors') or (not isinstance(payload.get('data'), dict)) or any((not isinstance(payload['data'].get(operation['alias']), dict) for operation in report['ordered_writes'])):
                    raise ValueError('GraphQL mutation returned errors or incomplete aliases')
            except Exception as exc:
                failure = exc
            # Recovery labels do not depend on unrelated source hydration.
            report['observed_labels'] = _live_labels(snapshot, api)
            with _fresh(snapshot, api) as current:
                observed = _live_labels(snapshot, api)
                report['observed_labels'] = observed
                if report['assessment_only']:
                    proof = checkpoint.collect_label_events(snapshot['item_id'], snapshot['label_event_boundary'], api=api)
                    actual = [{'actor': event['actor']['login'], 'action': 'add' if event['__typename'] == 'LabeledEvent' else 'remove', 'label_id': event['label']['id']} for event in proof.get('events', [])]
                    expected = [{'actor': report['executor'], 'action': operation['action'], 'label_id': operation['label_id']} for operation in report['ordered_writes']]
                    stable = _same_material(snapshot, current, set(report['final_labels']))
                    verified = failure is None and set(observed) == set(report['final_labels']) and stable and (proof['status'] == 'complete') and (checkpoint.operation_digest(actual) == checkpoint.operation_digest(expected))
                else:
                    discovery = checkpoint.find_checkpoint(snapshot['item_id'], api=api, trusted_actors=actors)
                    verified = False
                    if discovery['status'] == 'found':
                        candidate = discovery['checkpoint']
                        if candidate.get('version') == 2:
                            events = checkpoint.collect_label_events(snapshot['item_id'], candidate['boundary_id'], api=api)
                            material = _material(current)
                            material['existing_labels'] = observed
                            verified = failure is None and set(observed) == set(report['final_labels']) and (candidate.get('rationale') == report['candidate_rationale']) and checkpoint.checkpoint_matches(candidate, material, set(observed), _version(current), label_events=events)
                    report['checkpoint_verified'] = bool(verified)
                report['status'] = 'applied' if verified else 'partial'
                if failure:
                    report['diagnostics'].append(f'Write failed/uncertain; fresh state read, no replay: {failure}')
                if not verified:
                    report['diagnostics'].append('Completion was not verified; reprepare and reconcile live state')
                report['telemetry'] = getattr(api, 'diagnostics', {})
                return report
    except BlockingIOError:
        return _report(snapshot, 'held', 'Another local executor holds this item lock; coordinate one executor per item')
    except Exception as exc:
        report.update(status='partial' if attempted else 'error', checkpoint_verified=False)
        report['diagnostics'].append(str(exc))
        return report


def main(argv=None, *, api=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('prepare', 'expand', 'preview', 'apply'):
        sub = commands.add_parser(command)
        sub.add_argument('--output', type=Path)
        if command == 'prepare':
            sub.add_argument('--repo', required=True)
            sub.add_argument('--item', required=True, type=int)
            sub.add_argument('--force', action='store_true')
            sub.add_argument('--assessment-only', action='store_true')
        else:
            sub.add_argument('--snapshot', required=True, type=Path)
        if command == 'expand':
            sub.add_argument('--evidence-id', action='append', required=True)
        if command in {'preview', 'apply'}:
            sub.add_argument('--result', type=Path)
            sub.add_argument('--assessment', type=Path)
            sub.add_argument('--bookkeeping-label', default=DEFAULT_BOOKKEEPING_LABEL)
            sub.add_argument('--executor', help='Separately trusted caller configuration for tokens without GET /user; actual event actor must match')
        if command in {'prepare', 'apply'}:
            sub.add_argument('--trusted-actor', action='append', required=True)
        if command == 'apply':
            sub.add_argument('--expected-preview', type=Path)
        if command == 'prepare':
            sub.add_argument('--assessment-policy', type=Path)
    args = parser.parse_args(argv)
    api = api if api is not None else GitHubClient()

    def read(path):
        return json.loads(path.read_text(encoding='utf-8'))
    try:
        if args.command == 'prepare':
            if args.output is None:
                parser.error('prepare requires --output DIRECTORY')
            policy = read(args.assessment_policy) if args.assessment_policy else []
            if not isinstance(policy, list) or not all((isinstance(label, str) for label in policy)):
                raise ValueError('Assessment policy must be a separately reviewed JSON label-name list')
            report = prepare(args.repo, args.item, args.output, api=api, force=args.force, trusted_actors=set(args.trusted_actor), assessment_only=args.assessment_only, assessment_labels=set(policy))
            printable = {key: value for key, value in report.items() if key != 'snapshot'}
        else:
            snapshot = read(args.snapshot)
            if args.command == 'expand':
                evidence.expand_evidence(snapshot, args.evidence_id, api=api)
                report = _report(snapshot, 'ready')
                report.update(snapshot_path=str(args.snapshot), packet_path=snapshot['packet_path'])
            else:
                result = read(args.result) if args.result else {}
                assessment = read(args.assessment) if args.assessment else None
                function = apply if args.command == 'apply' else preview
                options = {'trusted_actors': set(args.trusted_actor), 'expected_preview': read(args.expected_preview) if args.expected_preview else None} if args.command == 'apply' else {}
                report = function(snapshot, result, api=api, assessment=assessment, bookkeeping_label=args.bookkeeping_label, executor=args.executor, **options)
            printable = report
        if args.output and args.command != 'prepare':
            args.output.write_text(json.dumps(printable, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        print(json.dumps(printable, ensure_ascii=False))
        status = report['status']
        return 0 if status in {'ready', 'applied', 'no-op', 'unchanged', 'skipped'} else 2 if status in {'held', 'prerequisite', 'stale'} else 1
    except Exception as exc:
        print(json.dumps({'status': 'error', 'diagnostics': [str(exc)]}))
        return 1
if __name__ == '__main__':
    raise SystemExit(main())
