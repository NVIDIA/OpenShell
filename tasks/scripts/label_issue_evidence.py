# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read-only evidence preparation; fetched sources and inspected facts stay distinct."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import subprocess
import uuid
from pathlib import Path
from urllib.parse import quote, urlsplit

from accepted_work import CLOSING_ISSUES_QUERY, check_issue_accepted_work, check_pr_accepted_work
from check_maintainer_approval import parse_maintainers
from label_issue_policy import load_taxonomy

LIMIT = 2 * 1024 * 1024
CLOSED_EVENTS_QUERY = '''query($owner: String!, $repo: String!, $number: Int!, $cursor: String) {
 repository(owner: $owner, name: $repo) { issue(number: $number) {
  timelineItems(itemTypes: [CLOSED_EVENT, REOPENED_EVENT], last: 100, before: $cursor) {
   nodes { __typename ... on ClosedEvent { id createdAt actor { login }
    closer { __typename ... on PullRequest { number merged mergedAt repository { nameWithOwner } } }
   } ... on ReopenedEvent { id createdAt actor { login } } }
   pageInfo { hasPreviousPage startCursor }
  }
 } }
}'''


def _identity(repository, number):
    if not isinstance(repository, str) or isinstance(number, bool):
        raise ValueError('Invalid repository or issue number')
    try:
        numeric = int(str(number))
    except (TypeError, ValueError) as exc:
        raise ValueError('Invalid issue number') from exc
    if repository.startswith('https://'):
        parsed = urlsplit(repository)
        parts = parsed.path.strip('/').split('/')
        if parsed.netloc.lower() != 'github.com' or len(parts) not in (2, 4):
            raise ValueError('Invalid repository URL')
        if len(parts) == 4 and (parts[2] not in ('issues', 'pull') or parts[3] != str(numeric)):
            raise ValueError('Item URL does not match number')
        repository = '/'.join(parts[:2])
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or numeric < 1:
        raise ValueError('Invalid repository or issue number')
    return repository, numeric


def _roster(repository, path, revision, api):
    value = api(f'repos/{repository}/contents/{path}?ref={quote(revision, safe="")}')
    if value.get('encoding') != 'base64' or value.get('truncated'):
        raise ValueError(f'Incomplete trusted {path}')
    raw = base64.b64decode(value['content'])
    if len(raw) > LIMIT:
        raise ValueError(f'Oversized trusted {path}')
    return raw.decode('utf-8')


def _authority(repository, user, author, maintainers, api):
    login = (user or {}).get('login', '')
    role = 'unknown'
    permission = 'none'
    if login.lower() in maintainers:
        role, permission = 'maintainer', 'maintain'
    elif login:
        try:
            permission = api(f'repos/{repository}/collaborators/{quote(login, safe="")}/permission')['permission']
        except subprocess.CalledProcessError as exc:
            if '(HTTP 404)' not in (exc.stderr or ''):
                raise
        if permission in {'write', 'maintain', 'admin'}:
            role = 'maintainer'
        elif login.lower() == author.lower():
            role = 'author'
    return {'login': login, 'role': role, 'permission': permission,
            'is_author': bool(login) and login.lower() == author.lower(), 'verified': True}


def _closed_event(repository, number, api):
    owner, repo = repository.split('/')
    cursor, seen = None, set()
    for _ in range(100):
        result = api('graphql', method='POST', data={'query': CLOSED_EVENTS_QUERY,
            'variables': {'owner': owner, 'repo': repo, 'number': number, 'cursor': cursor}})
        if result.get('errors'):
            raise ValueError('Could not resolve closure provenance')
        connection = result['data']['repository']['issue']['timelineItems']
        for event in reversed(connection['nodes']):
            if event['__typename'] == 'ClosedEvent':
                return event
        page = connection['pageInfo']
        if not page['hasPreviousPage']:
            return None
        cursor = page['startCursor']
        if not cursor or cursor in seen:
            raise ValueError('Invalid closure-event cursor')
        seen.add(cursor)
    raise ValueError('Closure-event page budget exhausted')


def preflight(repository: str, number: int, *, api, force: bool = False) -> dict:
    """Fresh acceptance/lifecycle facts; force never relaxes either boundary."""
    repository, number = _identity(repository, number)
    root = f'repos/{repository}'
    repo = api(root)
    revision = api(f'{root}/commits/{quote(repo["default_branch"], safe="")}')['sha']
    maintainers_text = _roster(repository, 'MAINTAINERS.md', revision, api)
    maintainers = parse_maintainers(maintainers_text)
    issue = api(f'{root}/issues/{number}')
    kind = 'pull_request' if 'pull_request' in issue else 'issue'
    item = api(f'{root}/pulls/{number}') if kind == 'pull_request' else issue
    accepted = (check_pr_accepted_work(repository, item, maintainers, api=api)
                if kind == 'pull_request' else check_issue_accepted_work(repository, issue, maintainers, api=api))
    lifecycle, reason, event, authority = 'eligible', 'Open work', None, None
    if kind == 'pull_request' and (item.get('merged_at') or item.get('merged')):
        lifecycle, reason = 'excluded', 'Pull request merged (including reverted merges)'
    elif issue.get('state') == 'closed':
        lifecycle, reason = 'hold', 'Closed item requires evidence-backed human disposition'
        if kind == 'issue' and issue.get('state_reason') == 'completed':
            lifecycle, reason = 'excluded', 'Issue completed'
        elif kind == 'issue':
            event = _closed_event(repository, number, api)
            closer = (event or {}).get('closer') or {}
            if closer.get('__typename') == 'PullRequest' and closer.get('merged'):
                lifecycle, reason = 'excluded', 'Issue resolved by merged closing pull request'
            else:
                actor = issue.get('closed_by') or (event or {}).get('actor') or {}
                author = (issue.get('user') or {}).get('login', '')
                authority = _authority(repository, actor, author, maintainers, api)
                if issue.get('state_reason') in {'not_planned', 'duplicate'} and authority['role'] == 'maintainer':
                    lifecycle, reason = 'excluded', 'Deliberate maintainer closure'
                elif actor.get('type') == 'Bot' and actor.get('login', '').lower() == 'stale[bot]':
                    lifecycle, reason = 'eligible', 'Verified stale-bot closure alone is not resolution'
    return {'repository': repository, 'number': number, 'kind': kind,
            'item_id': issue['node_id'], 'revision': revision, 'item': item, 'issue': issue,
            'maintainers': sorted(maintainers), 'maintainers_text': maintainers_text,
            'closure_event': event, 'closure_authority': authority,
            'eligibility': {'accepted': accepted, 'lifecycle': lifecycle, 'reason': reason}}


def _artifact(kind, content, *, inspected=True, coverage='complete', **extra):
    encoded = json.dumps(content, ensure_ascii=False, sort_keys=True).encode('utf-8')
    digest = hashlib.sha256(encoded).hexdigest()
    if len(encoded) > LIMIT - 4096:
        # Slice characters, not encoded JSON bytes, then re-encode valid JSON.
        text = encoded.decode('utf-8')
        low, high = 0, min(len(text), LIMIT)
        while low < high:
            middle = (low + high + 1) // 2
            if len(json.dumps(text[:middle], ensure_ascii=False).encode()) <= LIMIT - 4096:
                low = middle
            else:
                high = middle - 1
        content, coverage = text[:low], 'truncated'
    return {'kind': kind, 'content': content, 'inspected': inspected, 'coverage': coverage,
            'source_digest': digest, 'source_bytes': len(encoded), **extra}


def _persist(snapshot):
    directory = Path(snapshot['_directory'])
    artifacts = directory / 'artifacts'
    artifacts.mkdir(exist_ok=True)
    for artifact_id, entry in snapshot['evidence_index'].items():
        path = artifacts / (hashlib.sha256(artifact_id.encode()).hexdigest() + '.json')
        entry['artifact_path'] = str(path)
        path.write_text(json.dumps(entry['content'], ensure_ascii=False), encoding='utf-8')
    snapshot['packet_path'] = str(directory / 'packet.json')
    packet = {key: copy.deepcopy(snapshot[key]) for key in (
        'schema_version', 'repository', 'number', 'kind', 'snapshot_id', 'item_id',
        'eligibility', 'existing_labels', 'head', 'changed_paths', 'lifecycle_evidence')}
    packet['scopes'] = {key: snapshot['taxonomy'][key] for key in ('areas', 'topics')}
    packet['evidence_index'] = {artifact_id: {key: value for key, value in entry.items()
        if key != 'content' or entry['inspected']} for artifact_id, entry in snapshot['evidence_index'].items()}
    (directory / 'packet.json').write_text(json.dumps(packet, indent=2, ensure_ascii=False), encoding='utf-8')
    (directory / 'manifest.json').write_text(json.dumps(snapshot, indent=2, ensure_ascii=False), encoding='utf-8')


def _one_edit(left, right):
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        diff = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
        return (len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1
                and left[diff[0]] == right[diff[1]] and left[diff[1]] == right[diff[0]]))
    shorter, longer = sorted((left, right), key=len)
    return any(longer[:i] + longer[i + 1:] == shorter for i in range(len(longer)))


def _malformed(labels, taxonomy):
    found = []
    for label in labels:
        namespace, separator, suffix = label.partition(':')
        if not separator or namespace in {'area', 'topic', 'retired'}:
            continue
        for family, canonical in (('area', taxonomy['areas']), ('topic', taxonomy['topics'])):
            if _one_edit(namespace, family) and f'{family}:{suffix}' in canonical:
                found.append(label)
    return sorted(set(found))


def _linked_issues(repository, number, api):
    owner, repo = repository.split('/')
    cursor, seen, found = None, set(), []
    for _ in range(100):
        response = api('graphql', method='POST', data={'query': CLOSING_ISSUES_QUERY,
            'variables': {'owner': owner, 'repo': repo, 'number': number, 'cursor': cursor}})
        if response.get('errors'):
            raise ValueError('Could not load closing issues')
        connection = response['data']['repository']['pullRequest']['closingIssuesReferences']
        for reference in connection['nodes']:
            source, linked_number = reference['repository']['nameWithOwner'], reference['number']
            # Native references may be cross-repository: record identity, but
            # never treat them as accepted-work authorization for this repository.
            source, linked_number = _identity(source, linked_number)
            issue = api(f'repos/{source}/issues/{linked_number}')
            if 'pull_request' in issue:
                raise ValueError('Closing issue reference resolved to a pull request')
            labels = api(f'repos/{source}/issues/{linked_number}/labels?per_page=100', pages=True)
            found.append({'repository': source, 'number': linked_number, 'item_id': issue['node_id'],
                          'title': issue.get('title'), 'body': issue.get('body'), 'state': issue['state'],
                          'state_reason': issue.get('state_reason'), 'user': issue.get('user'),
                          'assignees': issue.get('assignees', []), 'labels': sorted(x['name'] for x in labels)})
        page = connection['pageInfo']
        if not page['hasNextPage']:
            return found
        cursor = page['endCursor']
        if not cursor or cursor in seen:
            raise ValueError('Invalid closing-issue cursor')
        seen.add(cursor)
    raise ValueError('Closing-issue page budget exhausted')


def _item_material(item):
    keys = ('title', 'body', 'state', 'state_reason', 'closed_at', 'merged_at', 'merged',
            'user', 'assignees', 'draft', 'head', 'base', 'changed_files')
    result = {key: copy.deepcopy(item[key]) for key in keys if key in item}
    for key in ('head', 'base'):
        if key in result:
            result[key] = {k: result[key][k] for k in ('sha', 'ref') if k in result[key]}
    return result


def prepare_snapshot(repository: str, number: int, directory: Path, *, api,
                     assessment_labels=frozenset()) -> dict:
    """Create a local packet. assessment_labels must come from a reviewed caller."""
    facts = preflight(repository, number, api=api)
    repository, number = facts['repository'], facts['number']
    root = f'repos/{repository}'
    roster = _roster(repository, 'REVIEWERS.md', facts['revision'], api)
    contribution_policy = _roster(repository, 'CONTRIBUTING.md', facts['revision'], api)
    definitions = copy.deepcopy(api(f'{root}/labels?per_page=100', pages=True))
    for definition in definitions:
        definition.pop('assessment', None)
        if definition['name'] in assessment_labels:
            definition['assessment'] = True
    taxonomy = load_taxonomy(roster, definitions)
    labels = sorted(x['name'] for x in api(f'{root}/issues/{number}/labels?per_page=100', pages=True))
    item = facts['item']
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=True)
    index = {'body': _artifact('body', {'title': item.get('title'), 'body': item.get('body')}),
             'labels': _artifact('reconciliation', labels)}
    routes = {'comments': f'issues/{number}/comments', 'timeline': f'issues/{number}/timeline'}
    if facts['kind'] == 'pull_request':
        routes.update(files=f'pulls/{number}/files', reviews=f'pulls/{number}/reviews',
                      review_comments=f'pulls/{number}/comments')
    for key, route in routes.items():
        index[key] = _artifact(key, None, inspected=False, coverage='not_inspected',
                               endpoint=f'{root}/{route}?per_page=100')
    linked = _linked_issues(repository, number, api) if facts['kind'] == 'pull_request' else []
    for issue in linked:
        index[f'issue:{issue["repository"]}#{issue["number"]}'] = _artifact('linked_issue', issue)
    policy_text = json.dumps({'protocol': 1, 'maintainers': facts['maintainers_text'],
                              'reviewers': roster, 'contribution_policy': contribution_policy}, sort_keys=True)
    snapshot = {'schema_version': 1, 'repository': repository, 'number': number, 'kind': facts['kind'],
                'snapshot_id': str(uuid.uuid4()), 'item_id': facts['item_id'],
                'policy_revision': facts['revision'], 'policy_version': hashlib.sha256(policy_text.encode()).hexdigest(),
                'taxonomy': taxonomy, 'existing_labels': labels, 'trusted_maintainers': facts['maintainers'],
                'malformed_classification_labels': _malformed(labels, taxonomy), 'eligibility': facts['eligibility'],
                'head': (item.get('head') or {}).get('sha'), 'changed_paths': [],
                'linked_closing_issues': linked, 'item_material': _item_material(item),
                'lifecycle_facts': {'closure_event': facts['closure_event'], 'closure_authority': facts['closure_authority']},
                'lifecycle_evidence': [], 'evidence_index': index, '_directory': str(directory)}
    if facts['closure_event']:
        index['closure'] = _artifact('lifecycle', facts['closure_event'], actor_authority=facts['closure_authority'])
        snapshot['lifecycle_evidence'].append('closure')
    # Classification preparation may read discussion metadata even on open
    # items: recorded author abandonment or maintainer rejection must remain
    # available for the caller's restricting lifecycle interpretation.
    expand_evidence(snapshot, ['comments'], api=api)
    index['comments']['inspected'] = False
    author = (facts['issue'].get('user') or {}).get('login', '').lower()
    for artifact_id, entry in list(index.items()):
        if entry['kind'] != 'comment':
            continue
        login = (entry.get('source_user') or {}).get('login', '').lower()
        if (login == author or login in facts['maintainers']
                or entry.get('source_association') in {'OWNER', 'MEMBER', 'COLLABORATOR'}):
            expand_evidence(snapshot, [artifact_id], api=api)
            if entry['actor_authority']['role'] in {'author', 'maintainer'}:
                snapshot['lifecycle_evidence'].append(artifact_id)
    if facts['kind'] == 'pull_request':
        expand_evidence(snapshot, ['files'], api=api)
        index['files']['inspected'] = False
    _persist(snapshot)
    return snapshot


def _patch_coverage(entry):
    patch = entry.get('patch')
    if not isinstance(patch, str) or not patch or not re.search(r'^@@ ', patch, flags=re.M) or entry.get('truncated') or entry.get('patch_truncated'):
        return 'partial'
    plus = minus = 0
    for line in patch.splitlines():
        if line.startswith('+'):
            plus += 1
        elif line.startswith('-'):
            minus += 1
    if plus != entry.get('additions') or minus != entry.get('deletions'):
        return 'partial'
    # Changed-line counts detect omissions even when the provider sets no flag.
    for old_count, new_count, body in re.findall(r'@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@[^\n]*\n(.*?)(?=\n@@|\Z)', patch, re.S):
        lines = body.splitlines()
        old = sum(line.startswith(('-', ' ')) for line in lines)
        new = sum(line.startswith(('+', ' ')) for line in lines)
        if old != int(old_count or 1) or new != int(new_count or 1):
            return 'partial'
    return 'complete'


def _source_slice(snapshot, artifact_id, api):
    match = re.fullmatch(r'source:(.+):(\d+):(\d+)', artifact_id)
    if not match or snapshot['kind'] != 'pull_request' or not snapshot.get('head'):
        raise ValueError('Invalid focused source request')
    path, start, end = match[1], int(match[2]), int(match[3])
    if (path.startswith('/') or any(part in {'.', '..', ''} for part in path.split('/'))
            or path not in snapshot['changed_paths'] or not 1 <= start <= end):
        raise ValueError('Source slices must name a changed path and valid lines')
    value = api(f'repos/{snapshot["repository"]}/contents/{quote(path, safe="/")}?ref={quote(snapshot["head"], safe="")}')
    if value.get('encoding') != 'base64' or value.get('truncated'):
        raise ValueError('Provider omitted requested source; request a smaller source through another supported endpoint')
    text = base64.b64decode(value['content']).decode('utf-8')
    content = ''.join(text.splitlines(keepends=True)[start - 1:end])
    return _artifact('source', content, coverage='slice', path=path, start=start, end=end, revision=snapshot['head'])


def expand_evidence(snapshot: dict, evidence_ids: list[str], *, api) -> dict:
    """Expand collections into stable source IDs, then inspect selected sources."""
    index = snapshot['evidence_index']
    for artifact_id in evidence_ids:
        if artifact_id.startswith('source:'):
            index[artifact_id] = _source_slice(snapshot, artifact_id, api)
            continue
        if artifact_id not in index:
            raise ValueError(f'Unknown evidence ID: {artifact_id}')
        artifact = index[artifact_id]
        endpoint = artifact.get('endpoint')
        if not endpoint:
            artifact['inspected'] = True
            if artifact.get('kind') in {'comment', 'review', 'review_comment'}:
                author = (snapshot['item_material'].get('user') or {}).get('login', '')
                artifact['actor_authority'] = _authority(snapshot['repository'], artifact.get('source_user'), author,
                                                       set(snapshot['trusted_maintainers']), api)
            continue
        try:
            content = api(endpoint, pages=True)
            if not isinstance(content, list):
                raise ValueError('Collection must be a paginated list')
        except Exception:
            artifact.update(inspected=False, coverage='incomplete')
            _persist(snapshot)
            raise
        coverage, source_ids = 'complete', []
        prefixes = {'comments': ('comment', 'comment'), 'reviews': ('review', 'review'),
                    'review_comments': ('review-comment', 'review_comment'), 'timeline': ('event', 'timeline_event')}
        for entry in content:
            if artifact_id == 'files':
                source_id, kind = 'patch:' + entry['filename'], 'patch'
                source_coverage = _patch_coverage(entry)
                if source_coverage != 'complete':
                    coverage = 'partial'
            else:
                prefix, kind = prefixes[artifact_id]
                if entry.get('id') is None:
                    raise ValueError('Evidence source lacks stable identity')
                source_id, source_coverage = f'{prefix}:{entry["id"]}', 'complete'
            index[source_id] = _artifact(kind, entry, inspected=(kind == 'timeline_event'), coverage=source_coverage,
                                         source_user={key: value for key, value in (entry.get('user') or {}).items() if key in {'login', 'type'}},
                                         source_association=entry.get('author_association'))
            source_ids.append(source_id)
        if artifact_id == 'files':
            snapshot['changed_paths'] = [entry['filename'] for entry in content]
            if len(content) != snapshot['item_material'].get('changed_files'):
                coverage = 'incomplete'
        artifact.update(_artifact(artifact['kind'], source_ids, coverage=coverage, endpoint=endpoint))
    _persist(snapshot)
    return snapshot


def material_state(snapshot: dict) -> dict:
    """Actual prepared/inspected facts and unseen-source markers, never updatedAt.

    Source identities/digests are retained even when not inspected: checkpoints
    must not claim that unseen source content was examined. Local paths and
    trusted-read commit provenance are not semantic policy changes.
    """
    keys = ('repository', 'number', 'kind', 'item_id', 'policy_version', 'taxonomy',
            'existing_labels', 'eligibility', 'head', 'changed_paths', 'item_material',
            'linked_closing_issues', 'lifecycle_facts', 'malformed_classification_labels')
    result = copy.deepcopy({key: snapshot[key] for key in keys if key in snapshot})
    result['evidence_index'] = {}
    for artifact_id, entry in snapshot.get('evidence_index', {}).items():
        result['evidence_index'][artifact_id] = {key: copy.deepcopy(value) for key, value in entry.items()
            if key not in {'artifact_path', 'endpoint'} and (key != 'content' or entry.get('inspected'))}
    return result
