from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

import grpc
import pytest

from navigator import Sandbox, SandboxClient

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
        )

    return _create


@pytest.fixture
def run_python() -> Callable[[Sandbox, str], tuple[int, str, str]]:
    def _run(sandbox: Sandbox, code: str) -> tuple[int, str, str]:
        result = sandbox.exec(["python", "-c", code], timeout_seconds=20)
        return result.exit_code, result.stdout, result.stderr

    return _run
