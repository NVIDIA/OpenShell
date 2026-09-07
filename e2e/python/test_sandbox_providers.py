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

    from openshell import Sandbox, SandboxClient, WorkspaceClient


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
    return token.startswith(("v", "s")) and token.endswith(f"_{key}")


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


def test_profileless_provider_creation_is_rejected(
    sandbox_client: SandboxClient,
) -> None:
    """New providers must reference a built-in or imported profile."""
    with pytest.raises(grpc.RpcError) as exc_info:
        sandbox_client._stub.CreateProvider(
            openshell_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(
                        name="e2e-test-profileless-provider"
                    ),
                    type="generic",
                    credentials={"CUSTOM_SERVICE_TOKEN": "token-generic-123"},
                )
            )
        )
    assert exc_info.value.code() == grpc.StatusCode.INVALID_ARGUMENT
    assert "provider profile 'generic' was not found" in exc_info.value.details()


def test_endpointless_profile_credentials_fail_closed_without_policy_binding(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Endpointless profile credentials are withheld without an explicit binding."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-google-cloud-without-policy-binding",
        provider_type="google-cloud",
        credentials={"GCP_ADC_ACCESS_TOKEN": "gcp-e2e-token"},
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_default_policy(),
            providers=[provider_name],
        )

        def read_gcp_token() -> str:
            import os

            return os.environ.get("GCP_ADC_ACCESS_TOKEN", "NOT_SET")

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(read_gcp_token)
            assert result.exit_code == 0, result.stderr
            assert result.stdout.strip() == "NOT_SET"


def test_endpointless_profile_credentials_use_explicit_policy_binding(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """An endpointless profile emits credentials only with an explicit binding."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-google-cloud-policy-binding",
        provider_type="google-cloud",
        credentials={"GCP_ADC_ACCESS_TOKEN": "gcp-e2e-token"},
    ) as provider_name:
        policy = _default_policy()
        policy.network_policies["gcp_storage"].CopyFrom(
            sandbox_pb2.NetworkPolicyRule(
                name="gcp_storage",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        host="storage.googleapis.com",
                        port=443,
                        protocol="rest",
                        access="full",
                        credential_binding=sandbox_pb2.NetworkCredentialBinding(
                            provider=provider_name
                        ),
                    )
                ],
            )
        )
        spec = datamodel_pb2.SandboxSpec(
            policy=policy,
            providers=[provider_name],
        )

        def read_gcp_token() -> str:
            import os

            return os.environ.get("GCP_ADC_ACCESS_TOKEN", "NOT_SET")

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(read_gcp_token)
            assert result.exit_code == 0, result.stderr
            assert _is_placeholder_for_env_key(
                result.stdout.strip(), "GCP_ADC_ACCESS_TOKEN"
            )


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
            assert _is_placeholder_for_env_key(result.stdout.strip(), "NVIDIA_API_KEY")


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
        provider_type="nvidia",
        credentials={"NVIDIA_API_KEY": "token-attach-detach"},
    ):
        spec = datamodel_pb2.SandboxSpec(policy=_default_policy(), providers=[])

        def read_attach_token() -> str:
            import os

            return os.environ.get("NVIDIA_API_KEY", "NOT_SET")

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
                    matched = _is_placeholder_for_env_key(last, "NVIDIA_API_KEY")
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
                    "openshell:resolve:env:NVIDIA_API_KEY",
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
        sandbox_client.create(workspace="default", spec=spec)

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
                    type="codex",
                    credentials={
                        "CODEX_AUTH_ACCESS_TOKEN": "val-a",
                        "CODEX_AUTH_REFRESH_TOKEN": "val-b",
                        "CODEX_AUTH_ACCOUNT_ID": "account-id",
                    },
                    config={"BASE_URL": "https://example.com"},
                )
            )
        )

        stub.UpdateProvider(
            openshell_pb2.UpdateProviderRequest(
                provider=datamodel_pb2.Provider(
                    metadata=datamodel_pb2.ObjectMeta(name=name),
                    type="",
                    credentials={"CODEX_AUTH_ACCESS_TOKEN": "rotated-a"},
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
                    type="openai",
                    credentials={"OPENAI_API_KEY": "secret"},
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
                    type="openai",
                    credentials={"OPENAI_API_KEY": "original-key"},
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
                    type="openai",
                    credentials={"OPENAI_API_KEY": "val"},
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
    profile's git binary covers it via ancestor matching.
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


# ===========================================================================
# Tests: provider profile platform vs workspace scope isolation
# ===========================================================================


def test_provider_profile_platform_vs_workspace_isolation(
    sandbox_client: "SandboxClient",
) -> None:
    """Platform-scoped profiles are visible in workspace listings; workspace profiles are not visible in platform listings."""
    stub = sandbox_client._stub
    platform_id = "e2e-platform-profile"
    workspace_id = "e2e-workspace-profile"

    def _make_profile(profile_id: str) -> openshell_pb2.ProviderProfileImportItem:
        return openshell_pb2.ProviderProfileImportItem(
            profile=openshell_pb2.ProviderProfile(
                id=profile_id,
                display_name=f"{profile_id} display",
                category=openshell_pb2.PROVIDER_PROFILE_CATEGORY_OTHER,
            ),
            source=f"{profile_id}.yaml",
        )

    def _cleanup() -> None:
        for pid, ws in [(platform_id, ""), (workspace_id, "default")]:
            try:
                stub.DeleteProviderProfile(
                    openshell_pb2.DeleteProviderProfileRequest(id=pid, workspace=ws)
                )
            except grpc.RpcError:
                pass

    _cleanup()
    try:
        resp = stub.ImportProviderProfiles(
            openshell_pb2.ImportProviderProfilesRequest(
                profiles=[_make_profile(platform_id)],
                workspace="",
            )
        )
        assert resp.imported, "platform-scoped import should succeed"

        resp = stub.ImportProviderProfiles(
            openshell_pb2.ImportProviderProfilesRequest(
                profiles=[_make_profile(workspace_id)],
                workspace="default",
            )
        )
        assert resp.imported, "workspace-scoped import should succeed"

        platform_list = stub.ListProviderProfiles(
            openshell_pb2.ListProviderProfilesRequest(limit=200, workspace="")
        )
        platform_ids = [p.id for p in platform_list.profiles]
        assert platform_id in platform_ids, (
            "platform profile should appear in platform list"
        )
        assert workspace_id not in platform_ids, (
            "workspace profile should NOT appear in platform list"
        )

        workspace_list = stub.ListProviderProfiles(
            openshell_pb2.ListProviderProfilesRequest(limit=200, workspace="default")
        )
        workspace_ids = [p.id for p in workspace_list.profiles]
        assert workspace_id in workspace_ids, (
            "workspace profile should appear in workspace list"
        )
        assert platform_id in workspace_ids, (
            "platform profile should appear in workspace list (visible as fallback)"
        )
    finally:
        _cleanup()


def test_cross_workspace_profile_ids_do_not_collide(
    sandbox_client: "SandboxClient",
    workspace_client: "WorkspaceClient",
) -> None:
    """Same profile ID in two workspaces must not cause a catalog collision."""
    import contextlib
    import uuid

    stub = sandbox_client._stub
    profile_id = f"e2e-xws-{uuid.uuid4().hex[:8]}"
    ws_a = f"ws-a-{uuid.uuid4().hex[:8]}"
    ws_b = f"ws-b-{uuid.uuid4().hex[:8]}"

    def _make_profile() -> openshell_pb2.ProviderProfileImportItem:
        return openshell_pb2.ProviderProfileImportItem(
            profile=openshell_pb2.ProviderProfile(
                id=profile_id,
                display_name=f"{profile_id} display",
                category=openshell_pb2.PROVIDER_PROFILE_CATEGORY_OTHER,
            ),
            source=f"{profile_id}.yaml",
        )

    workspace_client.create(ws_a)
    workspace_client.create(ws_b)
    try:
        resp_a = stub.ImportProviderProfiles(
            openshell_pb2.ImportProviderProfilesRequest(
                profiles=[_make_profile()],
                workspace=ws_a,
            )
        )
        assert resp_a.imported, "import into ws-a should succeed"

        resp_b = stub.ImportProviderProfiles(
            openshell_pb2.ImportProviderProfilesRequest(
                profiles=[_make_profile()],
                workspace=ws_b,
            )
        )
        assert resp_b.imported, "import into ws-b should succeed"

        list_a = stub.ListProviderProfiles(
            openshell_pb2.ListProviderProfilesRequest(limit=200, workspace=ws_a)
        )
        assert any(p.id == profile_id for p in list_a.profiles), (
            "profile should appear in ws-a"
        )

        list_b = stub.ListProviderProfiles(
            openshell_pb2.ListProviderProfilesRequest(limit=200, workspace=ws_b)
        )
        assert any(p.id == profile_id for p in list_b.profiles), (
            "profile should appear in ws-b"
        )
    finally:
        for ws in [ws_a, ws_b]:
            with contextlib.suppress(Exception):
                stub.DeleteProviderProfile(
                    openshell_pb2.DeleteProviderProfileRequest(
                        id=profile_id, workspace=ws
                    )
                )
            with contextlib.suppress(Exception):
                workspace_client.delete(ws)
