# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Encode, discover and verify checkpoints in GitHub label-event metadata.

Proofs bind substantive facts, final labels and ordered operations after an
event boundary. Collections require complete member coverage; source digests
establish freshness, not reading. The caller supplies filtered CLOSED/REOPENED
facts as ``relevant_timeline``. V1 metadata is decode-only.

One coordinated executor is required: GitHub removals have no nonce, so identical
same-actor removals are indistinguishable. Extra/interleaved events fail proof.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import re
import time

PREFIX = 'openshell-labeler:'
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
PAGE_LIMIT = 10
COLLECTIONS = {'comments', 'files', 'reviews', 'review_comments'}
ACTIONS = {'LabeledEvent': 'add', 'UnlabeledEvent': 'remove'}


class IncompleteMaterial(ValueError):
    """Current source coverage cannot establish a trustworthy unchanged result."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _is_digest(value):
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def operation_digest(operations: list[dict]) -> str:
    """Hash ordered actor/action/GraphQL-label-ID events, not mutable label names."""
    normalized = []
    if not isinstance(operations, list) or not operations:
        raise ValueError('At least one event-generating operation is required')
    for operation in operations:
        if (not isinstance(operation, dict)
                or set(operation) != {'actor', 'action', 'label_id'}
                or not isinstance(operation['actor'], str) or not operation['actor']
                or operation['action'] not in ('add', 'remove')
                or not isinstance(operation['label_id'], str) or not operation['label_id']):
            raise ValueError('Invalid checkpoint operation transcript')
        normalized.append({**operation, 'actor': operation['actor'].casefold()})
    return _digest(normalized)


def _source(entry):
    if (not isinstance(entry, dict) or entry.get('coverage') != 'complete'
            or not _is_digest(entry.get('source_digest'))
            or type(entry.get('source_bytes')) is not int or entry['source_bytes'] < 0):
        raise IncompleteMaterial('Source coverage/digest/byte count is unresolved or incomplete')
    semantic_digest = entry.get('semantic_digest', entry['source_digest'])
    if not _is_digest(semantic_digest):
        raise IncompleteMaterial('Source semantic digest is unresolved')
    return {'source_digest': semantic_digest, **{key: copy.deepcopy(entry[key]) for key in (
        'kind', 'coverage', 'actor_authority', 'source_user', 'source_association') if key in entry}}


def _verified_derivative(identity, entry, index, material):
    """Recognize producer-bound excerpts, never arbitrary parent_id assertions."""
    if entry.get('kind') == 'text_slice' and entry.get('coverage') == 'slice':
        match = re.fullmatch(r'text:(.+):([0-9a-f]{64}):(\d+):(\d+)', identity)
        if not match:
            return False
        parent, digest, start, end = match.groups()
        if (entry.get('parent_id') != parent or entry.get('parent_digest') != digest
                or entry.get('start') != int(start) or entry.get('end') != int(end)
                or not 0 <= int(start) < int(end)):
            return False
        source = index.get(parent)
        if not isinstance(source, dict) or source.get('source_digest') != digest:
            return False
        _source(source)
        return True
    if entry.get('kind') == 'source' and entry.get('coverage') == 'slice':
        match = re.fullmatch(r'source:(.+):(\d+):(\d+)', identity)
        if not match:
            return False
        path, start, end = match.groups()
        return (entry.get('path') == path and entry.get('start') == int(start)
                and entry.get('end') == int(end) and 1 <= int(start) <= int(end)
                and isinstance(material.get('head'), str) and bool(material['head'])
                and entry.get('revision') == material['head']
                and path in material.get('changed_paths', []))
    return False


def _normalized(material):
    if not isinstance(material, dict) or material.get('stale'):
        raise IncompleteMaterial('Material is missing or stale')
    kind = material.get('kind')
    if kind not in ('issue', 'pull_request'):
        raise IncompleteMaterial('Material has no supported item kind')
    relevant = _source(material.get('relevant_timeline'))
    index = material.get('evidence_index')
    if not isinstance(index, dict):
        raise IncompleteMaterial('Material evidence index is missing')
    required = {'body', 'comments'}
    if kind == 'pull_request':
        required |= {'files', 'reviews', 'review_comments'}
    if not required <= index.keys():
        raise IncompleteMaterial('Required source collection is unresolved')
    # Validate coverage of required sources and every fetched collection member
    # independently of all reconciliation/derivative suppression below.
    primary = set(required)
    memberships = {}
    for identity in COLLECTIONS & index.keys():
        entry = index[identity]
        _source(entry)
        members = entry.get('members')
        if (not isinstance(members, list) or not all(isinstance(member, str) for member in members)
                or len(members) != len(set(members)) or not set(members) <= index.keys()):
            raise IncompleteMaterial('Collection membership is unresolved')
        memberships[identity] = members
        primary.update(members)
    for identity in primary:
        _source(index[identity])
    raw_timeline = index.get('timeline', {})
    timeline_members = raw_timeline.get('members', []) if isinstance(raw_timeline, dict) else []
    sources = {}
    for identity, entry in index.items():
        if not isinstance(entry, dict):
            raise IncompleteMaterial('Malformed source artifact')
        if identity not in primary:
            if identity == 'labels' and entry.get('kind') == 'reconciliation':
                continue
            if identity == 'timeline' and entry.get('kind') == 'timeline':
                continue
            if (identity.startswith('event:') and entry.get('kind') == 'timeline_event'
                    and isinstance(timeline_members, list) and identity in timeline_members):
                continue
            if _verified_derivative(identity, entry, index, material):
                continue
        normalized = _source(entry)
        if identity in memberships:
            normalized['members'] = memberships[identity]
        sources[identity] = normalized
    omitted = {'existing_labels', 'malformed_classification_labels', 'evidence_index',
               'relevant_timeline', 'label_event_boundary', 'updatedAt', 'updated_at', 'stale'}
    normalized = {key: copy.deepcopy(value) for key, value in material.items() if key not in omitted}
    normalized['evidence_index'] = sources
    normalized['relevant_timeline'] = relevant
    return normalized


def fingerprint(material: dict, final_labels: set[str], policy_version: str) -> str:
    """Hash complete fetched facts and final labels, independent of read flags.

    Raises IncompleteMaterial for unresolved/partial source coverage. The caller
    must not translate this condition into an unchanged success.
    """
    if (not isinstance(final_labels, (set, frozenset))
            or not all(isinstance(label, str) and label for label in final_labels)
            or not isinstance(policy_version, str) or not policy_version):
        raise ValueError('Final labels and policy version are required')
    return _digest({'schema_version': 2, 'policy_version': policy_version,
                    'final_labels': sorted(final_labels),
                    'material': _normalized(material)})


def encode_checkpoint(fingerprint: str, *, boundary_id: str,
                      operations_digest: str, event_count: int) -> str:
    """Encode a v2 operation proof in at most 280 ASCII bytes."""
    if not _is_digest(fingerprint):
        raise ValueError('Checkpoint fingerprint must be a SHA-256 hex digest')
    if (not isinstance(boundary_id, str) or not _is_digest(operations_digest)
            or type(event_count) is not int or not 1 <= event_count <= PAGE_LIMIT * 100):
        raise ValueError('V2 requires a boundary, operations digest and bounded event count')
    boundary = base64.urlsafe_b64encode(boundary_id.encode('utf-8')).decode().rstrip('=') or '-'
    rationale = f'{PREFIX}v2:{fingerprint}:{boundary}:{operations_digest}:{event_count}'
    if len(rationale) > 280:
        raise ValueError('Checkpoint rationale exceeds 280 characters')
    return rationale


def decode_checkpoint(rationale: str) -> dict | None:
    """Strictly decode metadata; decoded data alone does not establish trust."""
    if not isinstance(rationale, str) or len(rationale) > 280:
        return None
    parts = rationale.split(':')
    if len(parts) == 3 and parts[:2] == ['openshell-labeler', 'v1'] and _is_digest(parts[2]):
        return {'version': 1, 'fingerprint': parts[2]}
    if (len(parts) != 6 or parts[:2] != ['openshell-labeler', 'v2']
            or not _is_digest(parts[2]) or not _is_digest(parts[4])
            or not re.fullmatch(r'[1-9][0-9]{0,3}', parts[5])):
        return None
    if int(parts[5]) > PAGE_LIMIT * 100:
        return None
    encoded = parts[3]
    try:
        if encoded == '-':
            boundary = ''
        else:
            if not re.fullmatch(r'[A-Za-z0-9_-]+', encoded):
                return None
            boundary = base64.b64decode(encoded + '=' * (-len(encoded) % 4),
                                        altchars=b'-_', validate=True).decode('utf-8')
            if not boundary or base64.urlsafe_b64encode(boundary.encode()).decode().rstrip('=') != encoded:
                return None
    except (ValueError, UnicodeError, binascii.Error):
        return None
    return dict(version=2, fingerprint=parts[2], boundary_id=boundary,
                operations_digest=parts[4], event_count=int(parts[5]))


def _query(*, additions_only, last=100):
    item_types = 'LABELED_EVENT' if additions_only else 'LABELED_EVENT, UNLABELED_EVENT'
    connection = '''timelineItems(last: 100, before: $before, itemTypes: [TYPES]) {
      nodes {
        __typename
        ... on LabeledEvent { id createdAt actor { login } label { id name } intent { rationale } }
        ... on UnlabeledEvent { id createdAt actor { login } label { id name } }
      }
      pageInfo { hasPreviousPage startCursor }
    }'''.replace('TYPES', item_types).replace('last: 100', f'last: {last}')
    return ('query($item: ID!, $before: String) { node(id: $item) { __typename '
            '... on Issue { ' + connection + ' } ... on PullRequest { ' + connection + ' } } }')


def _validate_event(event):
    if (not isinstance(event, dict)
            or event.get('__typename') not in ('LabeledEvent', 'UnlabeledEvent')
            or not isinstance(event.get('id'), str) or not event['id']
            or not isinstance(event.get('createdAt'), str) or not event['createdAt']):
        raise ValueError('Malformed label timeline event')
    # GitHub retains historical events when their actor or label is deleted.
    for key, field in [('actor', 'login'), ('label', 'id')]:
        value = event.get(key)
        if value is not None and (not isinstance(value, dict)
                                  or not isinstance(value.get(field), str) or not value[field]):
            raise ValueError('Malformed label event actor/label')


def _event_operation(event):
    _validate_event(event)
    actor, label = event.get('actor'), event.get('label')
    if actor is None or label is None:
        raise ValueError('Label event lacks attributable actor/label')
    return dict(actor=actor['login'].casefold(), action=ACTIONS[event['__typename']], label_id=label['id'])


def _read_page(item_id, before, *, api, additions_only, last=100):
    payload = api('graphql', method='POST', data={
        'query': _query(additions_only=additions_only, last=last),
        'variables': {'item': item_id, 'before': before}})
    if not isinstance(payload, dict) or payload.get('errors'):
        raise ValueError('GraphQL checkpoint query failed')
    data = payload.get('data')
    if not isinstance(data, dict):
        raise ValueError('Malformed GraphQL checkpoint data')
    node = data.get('node')
    if not isinstance(node, dict) or node.get('__typename') not in ('Issue', 'PullRequest'):
        raise ValueError('Checkpoint item is missing or unsupported')
    connection = node.get('timelineItems')
    if not isinstance(connection, dict) or not isinstance(connection.get('nodes'), list):
        raise ValueError('Malformed checkpoint timeline connection')
    page = connection.get('pageInfo')
    if (not isinstance(page, dict) or type(page.get('hasPreviousPage')) is not bool
            or page['hasPreviousPage'] and (not isinstance(page.get('startCursor'), str)
                                          or not page['startCursor'] or not connection['nodes'])
            or len(connection['nodes']) > last):
        raise ValueError('Malformed checkpoint pagination metadata')
    for event in connection['nodes']:
        _validate_event(event)
        if additions_only and event['__typename'] != 'LabeledEvent':
            raise ValueError('Unexpected event type in filtered additions')
    return connection['nodes'], page


def find_checkpoint(item_id: str, *, api, trusted_actors: set[str]) -> dict:
    """Discover newest trusted candidate; removed labels remain discoverable."""
    started, before = time.monotonic(), None
    cursors, identities = set(), set()
    trusted = {actor.casefold() for actor in trusted_actors}
    for page_number in range(1, PAGE_LIMIT + 1):
        nodes, page = _read_page(item_id, before, api=api, additions_only=True)
        for event in reversed(nodes):
            if event['id'] in identities:
                raise ValueError('Repeated checkpoint event across pages')
            identities.add(event['id'])
            if event.get('actor') is None or event.get('label') is None:
                continue
            actor = event['actor']['login'].casefold()
            intent = event.get('intent')
            rationale = intent.get('rationale') if isinstance(intent, dict) else None
            decoded = decode_checkpoint(rationale)
            if actor in trusted and decoded:
                return {'status': 'found', 'checkpoint': {
                    **decoded, 'trusted': True, 'item_id': item_id, 'event_id': event['id'],
                    'actor': actor, 'label_id': event['label']['id'],
                    'created_at': event['createdAt'], 'rationale': rationale},
                    'diagnostics': {'checkpoint_pages': page_number,
                                    'elapsed_seconds': time.monotonic() - started}}
        if not page['hasPreviousPage']:
            return {'status': 'not_found', 'diagnostics': {
                'checkpoint_pages': page_number, 'elapsed_seconds': time.monotonic() - started}}
        before = page['startCursor']
        if before in cursors:
            raise ValueError('Repeated checkpoint pagination cursor')
        cursors.add(before)
    return {'status': 'exhausted', 'diagnostics': {
        'checkpoint_pages': PAGE_LIMIT, 'elapsed_seconds': time.monotonic() - started}}


def collect_label_events(item_id: str, boundary_id: str, *, api,
                         max_pages: int = PAGE_LIMIT) -> dict:
    """Read both label actions after a boundary, oldest first, without mutation."""
    if type(max_pages) is not int or not 1 <= max_pages <= PAGE_LIMIT or not isinstance(boundary_id, str):
        raise ValueError('Invalid event proof bound/boundary')
    started, before = time.monotonic(), None
    cursors, identities, newest_first = set(), set(), []
    for page_number in range(1, max_pages + 1):
        nodes, page = _read_page(item_id, before, api=api, additions_only=False)
        found = False
        for event in reversed(nodes):
            if event['id'] in identities:
                raise ValueError('Repeated label proof event across pages')
            identities.add(event['id'])
            if event['id'] == boundary_id:
                found = True
                break
            newest_first.append(event)
        if found or not page['hasPreviousPage']:
            status = 'complete' if found or boundary_id == '' else 'not_found'
            break
        before = page['startCursor']
        if before in cursors:
            raise ValueError('Repeated label proof pagination cursor')
        cursors.add(before)
    else:
        status = 'exhausted'
    return {'status': status, 'boundary_id': boundary_id, 'item_id': item_id,
            'events': list(reversed(newest_first)),
            'diagnostics': {'event_proof_pages': page_number,
                            'elapsed_seconds': time.monotonic() - started}}


def checkpoint_matches(checkpoint: dict, material: dict, final_labels: set[str],
                       policy_version: str, *, label_events: dict | None = None) -> bool:
    """Require trusted v2 candidate, exact operation proof and separate live facts."""
    if not isinstance(checkpoint, dict) or checkpoint.get('trusted') is not True or checkpoint.get('version') != 2:
        return False
    if not isinstance(label_events, dict) or label_events.get('status') != 'complete':
        return False
    if (checkpoint.get('item_id') != material.get('item_id')
            or label_events.get('item_id') != material.get('item_id')
            or label_events.get('boundary_id') != checkpoint.get('boundary_id')):
        return False
    eligibility = material.get('eligibility', {})
    if eligibility.get('accepted') is not True or eligibility.get('lifecycle') != 'eligible':
        return False
    try:
        if set(material.get('existing_labels', [])) != final_labels:
            return False
        decoded = decode_checkpoint(checkpoint.get('rationale'))
        if not decoded or any(checkpoint.get(key) != value for key, value in decoded.items()):
            return False
        events = label_events.get('events')
        if not isinstance(events, list) or len(events) != checkpoint.get('event_count'):
            return False
        if len({event['id'] for event in events}) != len(events):
            return False
        candidates = [event for event in events if event['id'] == checkpoint.get('event_id')]
        if len(candidates) != 1:
            return False
        candidate = candidates[0]
        if (candidate.get('__typename') != 'LabeledEvent'
                or candidate.get('actor', {}).get('login', '').casefold() != checkpoint.get('actor')
                or candidate.get('label', {}).get('id') != checkpoint.get('label_id')
                or candidate.get('intent', {}).get('rationale') != checkpoint.get('rationale')):
            return False
        operations = [_event_operation(event) for event in events]
        if any(operation['actor'] != checkpoint.get('actor') for operation in operations):
            return False
        return (operation_digest(operations) == checkpoint.get('operations_digest')
                and fingerprint(material, final_labels, policy_version) == checkpoint.get('fingerprint'))
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def latest_label_event(item_id: str, *, api) -> dict:
    """Get a preparation/recheck boundary without reading historical timelines."""
    started = time.monotonic()
    nodes, _page = _read_page(item_id, None, api=api, additions_only=False, last=1)
    return {'boundary_id': nodes[-1]['id'] if nodes else '', 'item_id': item_id,
            'diagnostics': {'boundary_pages': 1,
                            'elapsed_seconds': time.monotonic() - started}}
