# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Privileged provider credential retrieval over the caller's gRPC channel."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from ._proto import datamodel_pb2, openshell_pb2, openshell_pb2_grpc
from .errors import _error_mapping_channel

if TYPE_CHECKING:
    from collections.abc import Sequence

    import grpc

    from .sandbox import SandboxClient


@dataclass(frozen=True)
class ProviderCredentialValue:
    """An exported runtime secret and its optional, UTC expiration.

    The value is omitted from repr, but explicit serialization still exposes it.
    Do not log or persist exported credentials in shared output.
    """

    value: str = field(repr=False)
    expiration_time: datetime | None = None


class ProviderClient:
    """Provider credential operations on a shared gRPC channel.

    Retrieval requires direct gateway mTLS with a trusted OU=operator certificate
    and no bearer authentication. The gateway must enable operator authentication.
    This client does not own or close the supplied channel.
    """

    def __init__(self, channel: grpc.Channel, *, timeout: float = 30.0) -> None:
        self._stub = openshell_pb2_grpc.OpenShellStub(_error_mapping_channel(channel))
        self._timeout = timeout

    @classmethod
    def from_sandbox_client(cls, client: SandboxClient) -> ProviderClient:
        """Reuse a client's transport and timeout; no sandbox is required."""
        return client.providers()

    def get_credentials(
        self,
        name: str,
        credential_keys: Sequence[str],
        *,
        workspace: str,
        minimum_remaining_lifetime: timedelta | None = None,
    ) -> dict[str, ProviderCredentialValue]:
        """Export exactly the selected runtime keys, or raise without a result.

        Omitted or zero lifetime uses the gateway's five-minute margin; the
        maximum is 24 hours. The gateway refreshes eligible missing or short-lived
        outputs. Refresh effects can persist even when delivery fails. This
        method does not retry or cache secrets and never exports refresh inputs.
        """
        if not workspace or workspace.strip() != workspace:
            raise ValueError("an explicit canonical workspace is required")
        if not name or name.strip() != name or len(name.encode("utf-8")) > 253:
            raise ValueError("a canonical provider name is required")
        # Copy the selection so caller mutation cannot change response validation.
        if isinstance(credential_keys, str):
            raise ValueError("select between 1 and 32 unique runtime environment keys")
        keys = list(credential_keys)
        if (
            not 1 <= len(keys) <= 32
            or any(
                len(key) > 256 or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None
                for key in keys
            )
            or len(set(keys)) != len(keys)
        ):
            raise ValueError("select between 1 and 32 unique runtime environment keys")
        if minimum_remaining_lifetime is not None and not (
            timedelta(0) <= minimum_remaining_lifetime <= timedelta(days=1)
        ):
            raise ValueError(
                "minimum_remaining_lifetime must be between zero and 24 hours"
            )
        request = openshell_pb2.GetProviderCredentialsRequest(
            workspace_scope=datamodel_pb2.WorkspaceSelector(workspace=workspace),
            name=name,
            credential_keys=keys,
        )
        if minimum_remaining_lifetime is not None:
            request.minimum_remaining_lifetime.FromTimedelta(minimum_remaining_lifetime)
        response = self._stub.GetProviderCredentials(request, timeout=self._timeout)
        if set(response.credentials) != set(keys):
            raise ValueError("gateway returned an unexpected credential selection")
        return {
            key: ProviderCredentialValue(
                value=credential.value,
                expiration_time=(
                    credential.expiration_time.ToDatetime(tzinfo=UTC)
                    if credential.HasField("expiration_time")
                    else None
                ),
            )
            for key, credential in response.credentials.items()
        }
