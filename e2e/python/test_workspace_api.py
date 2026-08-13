# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import contextlib
import uuid
from typing import TYPE_CHECKING

import grpc
import pytest

if TYPE_CHECKING:
    from openshell import WorkspaceClient


def test_workspace_crud(workspace_client: WorkspaceClient) -> None:
    name = f"ws-crud-{uuid.uuid4().hex[:8]}"

    try:
        ws = workspace_client.create(name)
        assert ws.name == name
        assert ws.phase == "WORKSPACE_PHASE_ACTIVE"

        fetched = workspace_client.get(name)
        assert fetched.name == name
        assert fetched.phase == "WORKSPACE_PHASE_ACTIVE"
    finally:
        with contextlib.suppress(Exception):
            workspace_client.delete(name)


def test_workspace_create_with_labels(workspace_client: WorkspaceClient) -> None:
    name = f"ws-lbl-{uuid.uuid4().hex[:8]}"

    try:
        ws = workspace_client.create(name, labels={"env": "test", "team": "infra"})
        assert ws.labels["env"] == "test"
        assert ws.labels["team"] == "infra"

        fetched = workspace_client.get(name)
        assert fetched.labels["env"] == "test"
        assert fetched.labels["team"] == "infra"
    finally:
        with contextlib.suppress(Exception):
            workspace_client.delete(name)


def test_workspace_list_includes_created(workspace_client: WorkspaceClient) -> None:
    name = f"ws-list-{uuid.uuid4().hex[:8]}"

    try:
        workspace_client.create(name)

        names = {ws.name for ws in workspace_client.list()}
        assert name in names
        assert "default" in names
    finally:
        with contextlib.suppress(Exception):
            workspace_client.delete(name)


def test_workspace_delete_nonexistent_raises_not_found(
    workspace_client: WorkspaceClient,
) -> None:
    with pytest.raises(grpc.RpcError) as exc_info:
        workspace_client.delete(f"no-such-ws-{uuid.uuid4().hex[:8]}")
    assert exc_info.value.code() == grpc.StatusCode.NOT_FOUND


def test_workspace_get_nonexistent_raises_not_found(
    workspace_client: WorkspaceClient,
) -> None:
    with pytest.raises(grpc.RpcError) as exc_info:
        workspace_client.get(f"no-such-ws-{uuid.uuid4().hex[:8]}")
    assert exc_info.value.code() == grpc.StatusCode.NOT_FOUND
