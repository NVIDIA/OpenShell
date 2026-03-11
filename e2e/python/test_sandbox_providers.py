# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""E2e tests for provider credential injection into sandboxes.

Provider credentials are fetched at runtime by the sandbox supervisor via the
GetSandboxProviderEnvironment gRPC call.  They should appear as environment
variables inside the sandbox process, but must NOT be present in the persisted
sandbox spec's environment map (they are never baked into the K8s pod spec).
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

import grpc
import pytest

from openshell._proto import datamodel_pb2, navigator_pb2, sandbox_pb2

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from openshell import Sandbox, SandboxClient


def _default_policy() -> sandbox_pb2.SandboxPolicy:
    return sandbox_pb2.SandboxPolicy(
        version=1,
        filesystem=sandbox_pb2.FilesystemPolicy(
            include_workdir=True,
            read_only=["/usr", "/lib", "/etc", "/app"],
            read_write=["/sandbox", "/tmp"],
        ),
        landlock=sandbox_pb2.LandlockPolicy(compatibility="best_effort"),
        process=sandbox_pb2.ProcessPolicy(
            run_as_user="sandbox", run_as_group="sandbox"
        ),
    )


@contextmanager
def provider(
    stub: object,
    *,
    name: str,
    provider_type: str,
    credentials: dict[str, str],
) -> Iterator[str]:
    """Create a provider for the duration of the block, then delete it."""
    # Clean up any leftover from a previous run.
    _delete_provider(stub, name)
    stub.CreateProvider(
        navigator_pb2.CreateProviderRequest(
            provider=datamodel_pb2.Provider(
                name=name,
                type=provider_type,
                credentials=credentials,
            )
        )
    )
    try:
        yield name
    finally:
        _delete_provider(stub, name)


def _delete_provider(stub: object, name: str) -> None:
    """Delete a provider, ignoring not-found errors."""
    try:
        stub.DeleteProvider(navigator_pb2.DeleteProviderRequest(name=name))
    except grpc.RpcError as exc:
        if hasattr(exc, "code") and exc.code() == grpc.StatusCode.NOT_FOUND:
            pass
        else:
            raise


# TODO: Once the sandbox supervisor sets provider credentials (rather than the
# server injecting them via exec environment), these tests will no longer be
# able to read credential values directly.  Update the assertions to verify
# that the env vars are *present* (e.g. non-empty) without checking exact
# values, since the supervisor will be the sole source of truth.


def test_provider_credentials_available_as_env_vars(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Sandbox process can read provider credentials as environment variables."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-provider-env",
        provider_type="claude",
        credentials={"ANTHROPIC_API_KEY": "sk-e2e-test-key-12345"},
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_default_policy(),
            providers=[provider_name],
        )

        def read_env_var() -> str:
            import os

            return os.environ.get("ANTHROPIC_API_KEY", "NOT_SET")

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(read_env_var)
            assert result.exit_code == 0, result.stderr
            assert result.stdout.strip() == "sk-e2e-test-key-12345"


def test_generic_provider_credentials_available_as_env_vars(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Generic provider credentials are injected as arbitrary sandbox env vars."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-generic-provider-env",
        provider_type="generic",
        credentials={
            "CUSTOM_SERVICE_TOKEN": "token-generic-123",
            "CUSTOM_SERVICE_URL": "https://internal.example.test/api",
        },
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_default_policy(),
            providers=[provider_name],
        )

        def read_generic_env_vars() -> str:
            import os

            token = os.environ.get("CUSTOM_SERVICE_TOKEN", "NOT_SET")
            url = os.environ.get("CUSTOM_SERVICE_URL", "NOT_SET")
            return f"{token}|{url}"

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(read_generic_env_vars)
            assert result.exit_code == 0, result.stderr
            assert (
                result.stdout.strip()
                == "token-generic-123|https://internal.example.test/api"
            )


def test_nvidia_provider_injects_nvidia_api_key_env_var(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """NVIDIA provider projects NVIDIA_API_KEY into sandbox process env."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-nvidia-provider-env",
        provider_type="nvidia",
        credentials={"NVIDIA_API_KEY": "nvapi-e2e-test-key"},
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_default_policy(),
            providers=[provider_name],
        )

        def read_nvidia_key() -> str:
            import os

            return os.environ.get("NVIDIA_API_KEY", "NOT_SET")

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(read_nvidia_key)
            assert result.exit_code == 0, result.stderr
            assert result.stdout.strip() == "nvapi-e2e-test-key"


def test_create_sandbox_rejects_unknown_provider(
    sandbox_client: SandboxClient,
) -> None:
    """CreateSandbox fails fast when a provider name does not exist."""
    spec = datamodel_pb2.SandboxSpec(
        policy=_default_policy(),
        providers=["nonexistent-provider-xyz"],
    )
    with pytest.raises(grpc.RpcError) as exc_info:
        sandbox_client.create(spec=spec)

    assert exc_info.value.code() == grpc.StatusCode.FAILED_PRECONDITION
    assert "nonexistent-provider-xyz" in exc_info.value.details()


def test_credentials_not_in_persisted_spec_environment(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Provider credentials should NOT appear in the sandbox spec's environment map."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-no-persist",
        provider_type="claude",
        credentials={"ANTHROPIC_API_KEY": "sk-should-not-persist"},
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_default_policy(),
            providers=[provider_name],
        )

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            # Fetch the sandbox record from the server and inspect spec.environment.
            fetched = sandbox_client._stub.GetSandbox(
                navigator_pb2.GetSandboxRequest(name=sb.sandbox.name)
            )
            persisted_env = dict(fetched.sandbox.spec.environment)
            assert "ANTHROPIC_API_KEY" not in persisted_env, (
                "credentials should not be persisted in sandbox spec environment"
            )


# ---------------------------------------------------------------------------
# Provider update merge semantics
# ---------------------------------------------------------------------------


def test_update_provider_preserves_unset_credentials_and_config(
    sandbox_client: SandboxClient,
) -> None:
    """Updating one credential must not clobber other credentials or config."""
    stub = sandbox_client._stub
    name = "merge-test-preserve"
    _delete_provider(stub, name)

    try:
        stub.CreateProvider(
            navigator_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="generic",
                    credentials={"KEY_A": "val-a", "KEY_B": "val-b"},
                    config={"BASE_URL": "https://example.com"},
                )
            )
        )

        # Update only KEY_A; send empty config map (= no change).
        stub.UpdateProvider(
            navigator_pb2.UpdateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="",
                    credentials={"KEY_A": "rotated-a"},
                )
            )
        )

        got = stub.GetProvider(navigator_pb2.GetProviderRequest(name=name))
        p = got.provider
        assert p.credentials["KEY_A"] == "rotated-a"
        assert p.credentials["KEY_B"] == "val-b", "KEY_B should be preserved"
        assert p.config["BASE_URL"] == "https://example.com", (
            "config should be preserved"
        )
    finally:
        _delete_provider(stub, name)


def test_update_provider_empty_maps_preserves_all(
    sandbox_client: SandboxClient,
) -> None:
    """Sending empty credential and config maps should be a no-op."""
    stub = sandbox_client._stub
    name = "merge-test-noop"
    _delete_provider(stub, name)

    try:
        stub.CreateProvider(
            navigator_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="generic",
                    credentials={"TOKEN": "secret"},
                    config={"URL": "https://api.example.com"},
                )
            )
        )

        stub.UpdateProvider(
            navigator_pb2.UpdateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="",
                )
            )
        )

        got = stub.GetProvider(navigator_pb2.GetProviderRequest(name=name))
        p = got.provider
        assert p.credentials["TOKEN"] == "secret"
        assert p.config["URL"] == "https://api.example.com"
    finally:
        _delete_provider(stub, name)


def test_update_provider_merges_config_preserves_credentials(
    sandbox_client: SandboxClient,
) -> None:
    """Updating only config should not touch credentials."""
    stub = sandbox_client._stub
    name = "merge-test-config-only"
    _delete_provider(stub, name)

    try:
        stub.CreateProvider(
            navigator_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="generic",
                    credentials={"API_KEY": "original-key"},
                    config={"ENDPOINT": "https://old.example.com"},
                )
            )
        )

        # Send only config update, empty credentials map.
        stub.UpdateProvider(
            navigator_pb2.UpdateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="",
                    config={"ENDPOINT": "https://new.example.com"},
                )
            )
        )

        got = stub.GetProvider(navigator_pb2.GetProviderRequest(name=name))
        p = got.provider
        assert p.credentials["API_KEY"] == "original-key", (
            "credentials should be untouched"
        )
        assert p.config["ENDPOINT"] == "https://new.example.com"
    finally:
        _delete_provider(stub, name)


def test_update_provider_rejects_type_change(
    sandbox_client: SandboxClient,
) -> None:
    """Attempting to change a provider's type must be rejected."""
    stub = sandbox_client._stub
    name = "merge-test-type-reject"
    _delete_provider(stub, name)

    try:
        stub.CreateProvider(
            navigator_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="generic",
                    credentials={"KEY": "val"},
                )
            )
        )

        with pytest.raises(grpc.RpcError) as exc_info:
            stub.UpdateProvider(
                navigator_pb2.UpdateProviderRequest(
                    provider=datamodel_pb2.Provider(
                        name=name,
                        type="nvidia",
                    )
                )
            )
        assert exc_info.value.code() == grpc.StatusCode.INVALID_ARGUMENT
        assert "type cannot be changed" in exc_info.value.details()
    finally:
        _delete_provider(stub, name)
