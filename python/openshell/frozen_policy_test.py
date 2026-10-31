# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Optional frozen-policy operations over the existing authenticated channel."""

from concurrent import futures
from contextlib import contextmanager

import grpc
import pytest

from openshell import GatewayError, SandboxClient, SandboxError
from openshell._proto import (
    datamodel_pb2,
    openshell_pb2,
    openshell_pb2_grpc,
    sandbox_pb2,
)


class LegacyService(openshell_pb2_grpc.OpenShellServicer):
    def __init__(self):
        self.create_calls = 0

    def CreateSandbox(self, request, context):
        del request
        self.create_calls += 1
        context.abort(grpc.StatusCode.INTERNAL, "ordinary creation must not be used")


class FrozenService(openshell_pb2_grpc.FrozenSandboxPoliciesServicer):
    def __init__(self, acknowledged=True):
        self.acknowledged = acknowledged
        self.create_request: openshell_pb2.CreateFrozenSandboxRequest | None = None
        self.get_request: openshell_pb2.GetFrozenSandboxPolicyRequest | None = None
        self.update_request: openshell_pb2.UpdateFrozenGlobalConfigRequest | None = None
        self.state = openshell_pb2.FrozenSandboxPolicyState(requested=True)

    def CreateSandbox(self, request, context):
        del context
        self.create_request = request
        response = openshell_pb2.FrozenSandboxResponse(
            sandbox=openshell_pb2.Sandbox(
                metadata=datamodel_pb2.ObjectMeta(
                    id="created-id", name=request.name, workspace="staging"
                )
            ),
            service_urls={"web": "https://web.example"},
        )
        if self.acknowledged is not None:
            response.frozen_policy.requested = self.acknowledged
        return response

    def GetPolicy(self, request, context):
        del context
        self.get_request = request
        return self.state

    def UpdateGlobalConfig(self, request, context):
        del context
        self.update_request = request
        return openshell_pb2.UpdateFrozenGlobalConfigResponse(
            update=openshell_pb2.UpdateConfigResponse(version=7),
            frozen_sandboxes=["staging/frozen"],
        )


@contextmanager
def client_for(service):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    legacy = LegacyService()
    openshell_pb2_grpc.add_OpenShellServicer_to_server(legacy, server)
    if service is not None:
        openshell_pb2_grpc.add_FrozenSandboxPoliciesServicer_to_server(service, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    try:
        with SandboxClient(f"127.0.0.1:{port}") as client:
            yield client, legacy
    finally:
        server.stop(0).wait()


@pytest.mark.parametrize("acknowledged", [None, False, True])
@pytest.mark.parametrize("template", [False, True])
def test_frozen_create_uses_optional_service_and_requires_acknowledgement(
    acknowledged, template
):
    service = FrozenService(acknowledged)
    with client_for(service) as (client, legacy):
        kwargs = {
            "workspace": "staging",
            "name": "frozen",
            "spec": openshell_pb2.SandboxSpec(
                providers=["github"], policy=sandbox_pb2.SandboxPolicy(version=1)
            ),
        }
        if template:
            kwargs["workload_template"] = "agent"
        create = (
            client.create_frozen_from_template if template else client.create_frozen
        )
        if acknowledged:
            sandbox = create(**kwargs)
            assert sandbox.service_urls == {"web": "https://web.example"}
        else:
            with pytest.raises(
                SandboxError, match="did not acknowledge frozen creation"
            ) as error:
                create(**kwargs)
            assert "created-id" in str(error.value)
        assert legacy.create_calls == 0
        request = service.create_request
        assert request is not None
        assert request.workspace_scope.workspace == "staging"
        assert list(request.spec.providers) == ["github"]
        assert request.spec.policy.version == 1
        assert request.workload_template == ("agent" if template else "")


def test_older_gateway_returns_unimplemented_without_creating():
    with client_for(None) as (client, legacy):
        with pytest.raises(GatewayError) as error:
            client.create_frozen(workspace="staging", name="frozen")
        assert error.value.code() == grpc.StatusCode.UNIMPLEMENTED
        assert legacy.create_calls == 0


def test_frozen_policy_pending_capture_and_global_exceptions():
    service = FrozenService()
    with client_for(service) as (client, _legacy):
        pending = client.get_frozen_policy("frozen", workspace="staging")
        assert pending.requested and pending.policy is None
        service.state.policy.CopyFrom(
            openshell_pb2.FrozenSandboxPolicy(
                policy=sandbox_pb2.SandboxPolicy(version=1),
                version=3,
                policy_hash="accepted-hash",
                policy_source=sandbox_pb2.POLICY_SOURCE_GLOBAL,
                global_policy_version=7,
            )
        )
        service.state.policy.frozen_time.FromMilliseconds(600_000)
        state = client.get_frozen_policy("frozen", workspace="staging")
        assert state.policy is not None
        assert state.policy.policy.version == 1
        assert state.policy.policy_hash == "accepted-hash"
        assert state.policy.frozen_at_ms == 600_000
        assert state.policy.policy_source == sandbox_pb2.POLICY_SOURCE_GLOBAL
        assert service.get_request is not None
        assert service.get_request.workspace_scope.workspace == "staging"
        request = openshell_pb2.UpdateFrozenGlobalConfigRequest(
            policy=sandbox_pb2.SandboxPolicy(version=1)
        )
        result = client.update_global_config(request)
        assert result.update.version == 7
        assert result.frozen_sandboxes == ("staging/frozen",)
        assert getattr(service.update_request, "global") is True
        assert getattr(request, "global") is False
