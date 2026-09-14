# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import contextlib
import uuid
from typing import TYPE_CHECKING

import grpc
import pytest

from openshell._proto import openshell_pb2

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

        names = {ws.name for ws in workspace_client.list_all()}
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


def test_workspace_request_id_replays_without_deleting_replacement(
    workspace_client: WorkspaceClient,
) -> None:
    name = f"ws-replay-{uuid.uuid4().hex[:8]}"
    # Exercise the generated wire fields before curated request-ID helpers land.
    stub = workspace_client._stub
    create = openshell_pb2.CreateWorkspaceRequest(
        name=name, request_id=str(uuid.uuid4())
    )
    delete = openshell_pb2.DeleteWorkspaceRequest(
        name=name, request_id=str(uuid.uuid4())
    )
    try:
        original = stub.CreateWorkspace(create, timeout=20)
        replay, call = stub.CreateWorkspace.with_call(create, timeout=20)
        assert original == replay
        assert dict(call.initial_metadata())["openshell-replayed"] == "true"

        mismatch = openshell_pb2.CreateWorkspaceRequest(
            name=name, request_id=create.request_id, labels={"changed": "true"}
        )
        with pytest.raises(grpc.RpcError) as exc_info:
            stub.CreateWorkspace(mismatch, timeout=20)
        assert exc_info.value.code() == grpc.StatusCode.FAILED_PRECONDITION

        removed = stub.DeleteWorkspace(delete, timeout=20)
        replacement = stub.CreateWorkspace(
            openshell_pb2.CreateWorkspaceRequest(name=name), timeout=20
        )
        assert replacement.workspace.metadata.id != original.workspace.metadata.id
        assert stub.DeleteWorkspace(delete, timeout=20) == removed
        fetched = stub.GetWorkspace(openshell_pb2.GetWorkspaceRequest(name=name), timeout=20)
        assert fetched.workspace.metadata.id == replacement.workspace.metadata.id
    finally:
        with contextlib.suppress(Exception):
            workspace_client.delete(name)
