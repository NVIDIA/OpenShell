# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Credential-driver bindings must share SDK datamodel types and dispatch RPCs."""

import grpc.aio
import pytest

from openshell._proto import credential_driver_pb2 as credentials
from openshell._proto import credential_driver_pb2_grpc as driver_grpc
from openshell._proto import datamodel_pb2 as datamodel
from openshell._proto import extension_pb2 as extension
from openshell._proto import openshell_pb2 as gateway


def test_driver_messages_share_sdk_descriptors() -> None:
    request = credentials.ResolveCredentialRequest(
        handle=datamodel.CredentialHandle(driver="test", handle="opaque"),
    )
    assert isinstance(request.handle, datamodel.CredentialHandle)
    assert request.handle.DESCRIPTOR is datamodel.CredentialHandle.DESCRIPTOR
    assert (
        credentials.GetCredentialDriverCapabilitiesRequest(
            gateway=extension.PeerMetadata()
        ).gateway.DESCRIPTOR
        is extension.PeerMetadata.DESCRIPTOR
    )
    assert (
        gateway.CreateProviderRequest().provider.DESCRIPTOR
        is datamodel.Provider.DESCRIPTOR
    )


@pytest.mark.asyncio
async def test_generated_servicer_and_stub_exchange() -> None:
    class Driver(driver_grpc.CredentialDriverServicer):
        async def StoreCredential(self, request, context):  # noqa: ARG002
            assert request.value == "registration-ticket"
            return credentials.StoreCredentialResponse(
                handle=datamodel.CredentialHandle(driver="test", handle="opaque")
            )

    server = grpc.aio.server()
    driver_grpc.add_CredentialDriverServicer_to_server(Driver(), server)
    address = "127.0.0.1"
    port = server.add_insecure_port(f"{address}:0")
    await server.start()
    try:
        async with grpc.aio.insecure_channel(f"{address}:{port}") as channel:
            stub = driver_grpc.CredentialDriverStub(channel)
            result = await stub.StoreCredential(
                credentials.StoreCredentialRequest(value="registration-ticket"),
                timeout=5,
            )
            assert isinstance(result.handle, datamodel.CredentialHandle)
            assert result.handle.handle == "opaque"
    finally:
        await server.stop(0)
