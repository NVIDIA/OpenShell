# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""E2E tests for supervisor-managed provider placeholders in sandboxes.

Provider credentials are fetched at runtime by the sandbox supervisor via the
GetSandboxProviderEnvironment gRPC call. Sandboxed child processes should see
placeholder values (not raw secrets). Credentials must never be present in the
persisted sandbox spec environment map.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import TYPE_CHECKING

import grpc
import pytest

from openshell._proto import datamodel_pb2, openshell_pb2, sandbox_pb2

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from openshell import Sandbox, SandboxClient


# ---------------------------------------------------------------------------
# Policy helpers
# ---------------------------------------------------------------------------


def _is_placeholder_for_env_key(value: str, key: str) -> bool:
    """Return true when value is an OpenShell credential placeholder for key."""
    prefix = "openshell:resolve:env:"
    if value == f"{prefix}{key}":
        return True
    token = value.removeprefix(prefix)
    if token == value:
        return False
    return token.startswith("v") and token.endswith(f"_{key}")


def _default_policy() -> sandbox_pb2.SandboxPolicy:
    """Build a sandbox policy with standard filesystem/process/landlock settings."""
    return sandbox_pb2.SandboxPolicy(
        version=1,
        filesystem=sandbox_pb2.FilesystemPolicy(
            include_workdir=True,
            read_only=["/usr", "/lib", "/etc", "/app", "/dev/urandom"],
            read_write=["/sandbox", "/tmp"],
        ),
        landlock=sandbox_pb2.LandlockPolicy(compatibility="best_effort"),
        process=sandbox_pb2.ProcessPolicy(
            run_as_user="sandbox", run_as_group="sandbox"
        ),
    )


# ---------------------------------------------------------------------------
# Provider lifecycle helper
# ---------------------------------------------------------------------------


@contextmanager
def provider(
    stub: object,
    *,
    name: str,
    provider_type: str,
    credentials: dict[str, str],
) -> Iterator[str]:
    """Create a provider for the duration of the block, then delete it."""
    _delete_provider(stub, name)
    stub.CreateProvider(
        openshell_pb2.CreateProviderRequest(
            provider=datamodel_pb2.Provider(
                metadata=datamodel_pb2.ObjectMeta(name=name),
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
        stub.DeleteProvider(openshell_pb2.DeleteProviderRequest(name=name))
    except grpc.RpcError as exc:
        if hasattr(exc, "code") and exc.code() == grpc.StatusCode.NOT_FOUND:
            pass
        else:
            raise


@pytest.fixture
def providers_v2_enabled(
    sandbox_client: SandboxClient,
    _gateway_config_guard: None,
) -> Iterator[None]:
    """Enable the gateway-global ``providers_v2_enabled`` opt-in for one test.

    Composing a provider's network policy onto a sandbox is gated behind this
    setting, which defaults off; the built-in github profile's git-transport
    rules only reach the sandbox with it enabled.

    The setting is gateway-global. Exclusivity against other xdist workers is
    provided by the ``exclusive_gateway_config`` marker plus the autouse
    ``_gateway_config_guard`` guard (see conftest): no concurrent worker is
    mid-test while this fixture mutates and restores the setting, so none can
    observe the transient value. Depending on the guard here also orders the
    exclusive lock acquisition before the mutation.

    ``GetGatewayConfig`` returns known keys even when unset, with an empty
    ``SettingValue`` (no populated oneof), so the setting is treated as present
    only when its value oneof is set; otherwise restore is a delete. ``global``
    is a Python keyword, so it is passed through a dict expansion.
    """
    stub = sandbox_client._stub
    key = "providers_v2_enabled"
    config = stub.GetGatewayConfig(sandbox_pb2.GetGatewayConfigRequest())
    prior_value = sandbox_pb2.SettingValue()
    had_prior = (
        key in config.settings
        and config.settings[key].WhichOneof("value") is not None
    )
    if had_prior:
        prior_value.CopyFrom(config.settings[key])

    stub.UpdateConfig(
        openshell_pb2.UpdateConfigRequest(
            setting_key=key,
            setting_value=sandbox_pb2.SettingValue(bool_value=True),
            **{"global": True},
        )
    )
    try:
        yield
    finally:
        if had_prior:
            stub.UpdateConfig(
                openshell_pb2.UpdateConfigRequest(
                    setting_key=key,
                    setting_value=prior_value,
                    **{"global": True},
                )
            )
        else:
            stub.UpdateConfig(
                openshell_pb2.UpdateConfigRequest(
                    setting_key=key,
                    delete_setting=True,
                    **{"global": True},
                )
            )


# ===========================================================================
# Tests: placeholder visibility
# ===========================================================================


def test_provider_credentials_available_as_env_vars(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Sandbox child processes see provider env vars as placeholders."""
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
            value = result.stdout.strip()
            assert _is_placeholder_for_env_key(value, "ANTHROPIC_API_KEY")
            assert value != "sk-e2e-test-key-12345"


def test_generic_provider_credentials_available_as_env_vars(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Generic provider env vars are placeholders, not raw secrets."""
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
            token, url = result.stdout.strip().split("|")
            assert _is_placeholder_for_env_key(token, "CUSTOM_SERVICE_TOKEN")
            assert _is_placeholder_for_env_key(url, "CUSTOM_SERVICE_URL")


def test_nvidia_provider_injects_nvidia_api_key_env_var(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """NVIDIA provider projects a placeholder env value into child processes."""
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
            assert _is_placeholder_for_env_key(
                result.stdout.strip(), "NVIDIA_API_KEY"
            )


def test_attach_detach_updates_credentials_for_later_exec_launches(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Later exec launches see provider attach/detach credential changes."""
    stub = sandbox_client._stub
    provider_name = "e2e-test-attach-detach-env"

    with provider(
        stub,
        name=provider_name,
        provider_type="generic",
        credentials={"CUSTOM_ATTACH_TOKEN": "token-attach-detach"},
    ):
        spec = datamodel_pb2.SandboxSpec(policy=_default_policy(), providers=[])

        def read_attach_token() -> str:
            import os

            return os.environ.get("CUSTOM_ATTACH_TOKEN", "NOT_SET")

        def exec_token(sb: Sandbox) -> str:
            result = sb.exec_python(read_attach_token)
            assert result.exit_code == 0, result.stderr
            return result.stdout.strip()

        def wait_for_token(sb: Sandbox, expected: str) -> None:
            deadline = time.monotonic() + 35
            last = None
            while time.monotonic() < deadline:
                last = exec_token(sb)
                if expected == "NOT_SET":
                    matched = last == expected
                else:
                    matched = _is_placeholder_for_env_key(last, "CUSTOM_ATTACH_TOKEN")
                if matched:
                    return
                time.sleep(2)
            pytest.fail(f"expected {expected!r}, last exec saw {last!r}")

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            assert exec_token(sb) == "NOT_SET"

            try:
                stub.AttachSandboxProvider(
                    openshell_pb2.AttachSandboxProviderRequest(
                        sandbox_name=sb.sandbox.name,
                        provider_name=provider_name,
                    )
                )
                wait_for_token(
                    sb,
                    "openshell:resolve:env:CUSTOM_ATTACH_TOKEN",
                )

                stub.DetachSandboxProvider(
                    openshell_pb2.DetachSandboxProviderRequest(
                        sandbox_name=sb.sandbox.name,
                        provider_name=provider_name,
                    )
                )
                wait_for_token(sb, "NOT_SET")
            finally:
                try:
                    stub.DetachSandboxProvider(
                        openshell_pb2.DetachSandboxProviderRequest(
                            sandbox_name=sb.sandbox.name,
                            provider_name=provider_name,
                        )
                    )
                except grpc.RpcError as exc:
                    if exc.code() != grpc.StatusCode.NOT_FOUND:
                        raise


# ===========================================================================
# Tests: security & edge cases
# ===========================================================================


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
    assert "nonexistent-provider-xyz" in (exc_info.value.details() or "")


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
            fetched = sandbox_client._stub.GetSandbox(
                openshell_pb2.GetSandboxRequest(name=sb.sandbox.name)
            )
            persisted_env = dict(fetched.sandbox.spec.environment)
            assert "ANTHROPIC_API_KEY" not in persisted_env, (
                "credentials should not be persisted in sandbox spec environment"
            )


# ===========================================================================
# Tests: provider update merge semantics
# ===========================================================================


def test_update_provider_preserves_unset_credentials_and_config(
    sandbox_client: SandboxClient,
) -> None:
    """Updating one credential must not clobber other credentials or config."""
    stub = sandbox_client._stub
    name = "merge-test-preserve"
    _delete_provider(stub, name)

    try:
        stub.CreateProvider(
            openshell_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="generic",
                    credentials={"KEY_A": "val-a", "KEY_B": "val-b"},
                    config={"BASE_URL": "https://example.com"},
                )
            )
        )

        stub.UpdateProvider(
            openshell_pb2.UpdateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="",
                    credentials={"KEY_A": "rotated-a"},
                )
            )
        )

        got = stub.GetProvider(openshell_pb2.GetProviderRequest(name=name))
        p = got.provider
        # Credential keys are preserved but values are redacted.
        assert len(p.credentials) > 0, "credential keys should be preserved"
        for key, val in p.credentials.items():
            assert val == "REDACTED", (
                f"credential '{key}' should be REDACTED, got '{val}'"
            )
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
            openshell_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="generic",
                    credentials={"TOKEN": "secret"},
                    config={"URL": "https://api.example.com"},
                )
            )
        )

        stub.UpdateProvider(
            openshell_pb2.UpdateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="",
                )
            )
        )

        got = stub.GetProvider(openshell_pb2.GetProviderRequest(name=name))
        p = got.provider
        # Credential keys are preserved but values are redacted.
        assert len(p.credentials) > 0, "credential keys should be preserved"
        for key, val in p.credentials.items():
            assert val == "REDACTED", (
                f"credential '{key}' should be REDACTED, got '{val}'"
            )
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
            openshell_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="generic",
                    credentials={"API_KEY": "original-key"},
                    config={"ENDPOINT": "https://old.example.com"},
                )
            )
        )

        stub.UpdateProvider(
            openshell_pb2.UpdateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="",
                    config={"ENDPOINT": "https://new.example.com"},
                )
            )
        )

        got = stub.GetProvider(openshell_pb2.GetProviderRequest(name=name))
        p = got.provider
        # Credential keys are preserved but values are redacted.
        assert len(p.credentials) > 0, "credential keys should be preserved"
        for key, val in p.credentials.items():
            assert val == "REDACTED", (
                f"credential '{key}' should be REDACTED, got '{val}'"
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
            openshell_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="generic",
                    credentials={"KEY": "val"},
                )
            )
        )

        with pytest.raises(grpc.RpcError) as exc_info:
            stub.UpdateProvider(
                openshell_pb2.UpdateProviderRequest(
                    provider=datamodel_pb2.Provider(
                        metadata=datamodel_pb2.ObjectMeta(name=name),
                        type="nvidia",
                    )
                )
            )
        assert exc_info.value.code() == grpc.StatusCode.INVALID_ARGUMENT
        assert "type cannot be changed" in exc_info.value.details()
    finally:
        _delete_provider(stub, name)


# ===========================================================================
# Tests: git transport network policy
# ===========================================================================


@pytest.mark.exclusive_gateway_config
@pytest.mark.usefixtures("providers_v2_enabled")
def test_github_provider_allows_https_git_clone(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Built-in github provider permits anonymous HTTPS clone/fetch (#1769).

    Git smart HTTP clone/fetch issues a POST to ``*/git-upload-pack``. The
    read-only preset (GET/HEAD/OPTIONS) denied that POST, so ``git clone`` over
    HTTPS failed. Attaching the github provider composes its network policy onto
    the sandbox, exercising provider attachment, effective-policy composition,
    TLS interception, and real git behavior end to end. git delegates HTTPS to a
    ``git-remote-https`` helper whose ancestor is ``/usr/bin/git``, so the
    profile's git binary covers it via ancestor matching. The
    ``providers_v2_enabled`` fixture turns on the gateway-global gate that
    composes the provider's network policy.
    """
    with provider(
        sandbox_client._stub,
        name="e2e-test-github-clone",
        provider_type="github",
        # A required credential value is needed to create the provider, but an
        # anonymous clone of a public repo never uses it: git only sends the
        # token when a credential helper is configured.
        credentials={"GITHUB_TOKEN": "e2e-placeholder-unused"},
    ) as provider_name:
        # git opens /dev/null O_RDWR, so it must be read-write; the shared
        # _default_policy only grants /dev/urandom. Everything else (binaries,
        # CA bundle, clone target) is covered by the standard allowlist.
        policy = _default_policy()
        policy.filesystem.read_write.append("/dev/null")
        spec = datamodel_pb2.SandboxSpec(
            policy=policy,
            providers=[provider_name],
        )

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            clone = sb.exec(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "https://github.com/octocat/Hello-World.git",
                    "/tmp/hello-world",
                ],
                timeout_seconds=120,
            )
            assert clone.exit_code == 0, (
                "git clone over HTTPS should succeed with the github provider "
                f"attached; stdout={clone.stdout!r} stderr={clone.stderr!r}"
            )

            # A completed clone materializes .git/HEAD, proving ref discovery
            # (GET) and upload-pack (POST) both succeeded, not just a handshake.
            head = sb.exec(["cat", "/tmp/hello-world/.git/HEAD"])
            assert head.exit_code == 0, (
                f"cloned repo is missing .git/HEAD; stderr={head.stderr!r}"
            )
