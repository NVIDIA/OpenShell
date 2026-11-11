# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read-only stale issue closure provenance shared by labeling tools.

Pass GitHub issue metadata, its current ClosedEvent and the immediately preceding
comment from the close/reopen/comment timeline. Unmarked historical closures fail
closed; neither prose nor day counts provide a legacy fallback.
"""
from __future__ import annotations

from datetime import datetime

STALE_CLOSURE_MARKER = '<!-- openshell:stale-closure:v1 -->'
STALE_BOT = 'github-actions[bot]'
# actions/stale posts the comment before closing via a separate API request.
MAX_CLOSE_DELAY_SECONDS = 300


def is_stale_closed(issue: dict, event: dict | None, comment: dict | None = None) -> bool:
    """Require a marked, unedited bot comment bound to the current bot closure.

    The marker is a protocol identifier, not a signature. Identity, timeline
    adjacency (the caller's contract), and timestamps must also match. Callers
    must use trusted API responses, never item-supplied provenance objects.
    """
    actor = issue.get('closed_by') or {}
    if not (issue.get('state') == 'closed'
            and issue.get('state_reason') == 'not_planned'
            and 'state:stale' in {label['name'] for label in issue.get('labels', [])}
            and actor.get('type') == 'Bot'
            and actor.get('login', '').lower() == STALE_BOT
            and issue.get('closed_at') and event and comment
            and event.get('__typename') == 'ClosedEvent'
            and not event.get('closer')
            and event.get('createdAt') == issue['closed_at']
            and (event.get('actor') or {}).get('login', '').lower() == STALE_BOT
            and comment.get('__typename') == 'IssueComment'
            and (comment.get('author') or {}).get('__typename') == 'Bot'
            and (comment.get('author') or {}).get('login', '').lower() == STALE_BOT
            and STALE_CLOSURE_MARKER in (comment.get('body') or '').splitlines()
            and comment.get('createdAt') == comment.get('updatedAt')):
        return False
    try:
        closed = datetime.fromisoformat(issue['closed_at'].replace('Z', '+00:00'))
        posted = datetime.fromisoformat(comment['createdAt'].replace('Z', '+00:00'))
        if closed.tzinfo is None or posted.tzinfo is None:
            return False
        return 0 <= (closed - posted).total_seconds() <= MAX_CLOSE_DELAY_SECONDS
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
