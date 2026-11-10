"""Cross-host item mutex using atomic GitHub ref creation.

All mutation callers must share this guard. Locks never expire or get stolen.
A failed/uncertain operation leaves the ref for explicit operator reconciliation.
The ref points to a unique owner commit for audit; it is not a checkpoint.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import uuid
from contextlib import contextmanager

from labeling_agent_events import REPOSITORY


class ItemBusy(RuntimeError):
    """Another executor or an unresolved failed operation owns this item."""


@contextmanager
def item_lock(repository: str, number: int, parent: str, tree: str, *, api):
    """Hold a repository-scoped ref until successful execution and release.

    parent/tree are a trusted repository commit and its tree, never PR-head code.
    api follows check_review_readiness._api's path/method/data contract. No write
    is retried: even a lost acquisition response needs operator inspection.
    """
    if not REPOSITORY.fullmatch(repository) or type(number) is not int or number < 1:
        raise ValueError("expected repository and positive item number")
    if not re.fullmatch(r"[0-9a-f]{40}", parent) or not tree:
        raise ValueError("trusted parent commit and tree are required")
    root = f"repos/{repository}/git"
    ref = f"labeler-locks/{number}"
    run_id = os.environ.get("GITHUB_RUN_ID")
    if run_id:
        execution = (f"https://github.com/{repository}/actions/runs/{run_id} "
                     f"attempt {os.environ.get('GITHUB_RUN_ATTEMPT', 'unknown')}")
    else:
        execution = f"host={socket.gethostname()} pid={os.getpid()}"
    owner = api(
        f"{root}/commits", method="POST",
        data={"message": f"Labeling lock for #{number}: {uuid.uuid4()}\n\nOwner: {execution}",
              "tree": tree, "parents": [parent]},
    )["sha"]
    try:
        api(f"{root}/refs", method="POST",
            data={"ref": f"refs/{ref}", "sha": owner})
    except subprocess.CalledProcessError as exc:
        # 422 also covers malformed refs/rate limiting. Do not call every 422 busy.
        if "HTTP 422" in (exc.stderr or ""):
            try:
                api(f"{root}/ref/{ref}")
            except subprocess.CalledProcessError:
                raise exc
            raise ItemBusy(f"Item #{number} is locked; inspect refs/{ref}") from exc
        raise
    # Exceptions deliberately bypass release. Cancellation/crash has the same
    # conservative outcome. Operators must stop the old owner before removal.
    yield
    current = api(f"{root}/ref/{ref}")
    if current["object"]["sha"] != owner:
        raise RuntimeError("Labeling lock ownership changed; refusing deletion")
    api(f"{root}/refs/{ref}", method="DELETE")
