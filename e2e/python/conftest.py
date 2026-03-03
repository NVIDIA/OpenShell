# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

import grpc
import pytest

from navigator import InferenceRouteClient, Sandbox, SandboxClient

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


@pytest.fixture(scope="session")
def cluster_name() -> str | None:
    return os.environ.get("NAVIGATOR_CLUSTER")


@pytest.fixture(scope="session")
def sandbox_client(cluster_name: str | None) -> Iterator[SandboxClient]:
    with SandboxClient.from_active_cluster(cluster=cluster_name) as client:
        yield client


@pytest.fixture(scope="session", autouse=True)
def ensure_sandbox_persistence_ready(sandbox_client: SandboxClient) -> None:
    for _ in range(60):
        try:
            sandbox_client.list_ids(limit=1)
            return
        except grpc.RpcError as exc:
            details = exc.details() or ""
            if exc.code() == grpc.StatusCode.UNAVAILABLE:
                time.sleep(2)
                continue
            if (
                exc.code() == grpc.StatusCode.INTERNAL
                and "no such table: objects" in details
            ):
                time.sleep(1)
                continue
            raise

    pytest.fail(
        "navigator-server persistence is not initialized (missing sqlite objects table); "
        "redeploy the active cluster and rerun e2e sandbox tests"
    )


@pytest.fixture
def sandbox(cluster_name: str | None) -> Callable[..., Sandbox]:
    def _create(*, spec: object | None = None, delete_on_exit: bool = True) -> Sandbox:
        return Sandbox(
            cluster=cluster_name,
            spec=spec,
            delete_on_exit=delete_on_exit,
            # The sandbox image is large (Python, Node.js, coding agents) so the
            # first pod in the cluster may need extra time for the image pull.
            ready_timeout_seconds=300.0,
        )

    return _create


@pytest.fixture(scope="session")
def inference_client(sandbox_client: SandboxClient) -> InferenceRouteClient:
    return InferenceRouteClient.from_sandbox_client(sandbox_client)


@pytest.fixture(scope="session")
def mock_inference_route(
    inference_client: InferenceRouteClient,
) -> Iterator[str]:
    name = "e2e-mock-local"
    routing_hint = "e2e_mock_local"
    # Clean up any leftover route from a previous run.
    try:
        inference_client.delete(name)
    except grpc.RpcError:
        pass

    inference_client.create(
        name=name,
        routing_hint=routing_hint,
        base_url="mock://e2e",
        protocols=["openai_chat_completions"],
        api_key="mock",
        model_id="mock/test-model",
        enabled=True,
    )
    yield name
    try:
        inference_client.delete(name)
    except grpc.RpcError:
        pass


@pytest.fixture(scope="session")
def mock_anthropic_route(
    inference_client: InferenceRouteClient,
) -> Iterator[str]:
    name = "e2e-mock-anthropic"
    routing_hint = "e2e_mock_anthropic"
    try:
        inference_client.delete(name)
    except grpc.RpcError:
        pass

    inference_client.create(
        name=name,
        routing_hint=routing_hint,
        base_url="mock://e2e-anthropic",
        protocols=["anthropic_messages"],
        api_key="mock",
        model_id="mock/claude-test",
        enabled=True,
    )
    yield name
    try:
        inference_client.delete(name)
    except grpc.RpcError:
        pass


@pytest.fixture(scope="session")
def mock_disallowed_route(
    inference_client: InferenceRouteClient,
) -> Iterator[str]:
    """Route that exists but is NOT in any sandbox's allowed_routes."""
    name = "e2e-mock-disallowed"
    routing_hint = "e2e_mock_disallowed"
    try:
        inference_client.delete(name)
    except grpc.RpcError:
        pass

    inference_client.create(
        name=name,
        routing_hint=routing_hint,
        base_url="mock://e2e-disallowed",
        protocols=["openai_chat_completions"],
        api_key="mock",
        model_id="mock/disallowed-model",
        enabled=True,
    )
    yield name
    try:
        inference_client.delete(name)
    except grpc.RpcError:
        pass


@pytest.fixture
def run_python() -> Callable[[Sandbox, str], tuple[int, str, str]]:
    def _run(sandbox: Sandbox, code: str) -> tuple[int, str, str]:
        result = sandbox.exec(["python", "-c", code], timeout_seconds=20)
        return result.exit_code, result.stdout, result.stderr

    return _run
