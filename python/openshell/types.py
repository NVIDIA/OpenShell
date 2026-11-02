# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Public imports for the protobuf-backed SDK inputs and complete RPC results.

These are the generated message classes, not independent copies of the schema.
Protobuf presence, enum, and oneof APIs remain available. Use bindings from the
same release as the gateway. Do not log messages containing credential material.
"""

from ._proto.datamodel_pb2 import ObjectMeta, Provider
from ._proto.openshell_pb2 import (
    AttachSandboxProviderResponse,
    DetachSandboxProviderResponse,
    GetSandboxLogsResponse,
    GetSandboxPolicyStatusResponse,
    ProviderMutationReceipt,
    ProviderReadinessState,
    ProviderReadinessStatus,
    ResourceRequirements,
    SandboxLogLine,
    SandboxPhase,
    SandboxPolicyRevision,
    SandboxSpec,
    SandboxStreamEvent,
    SandboxTemplate,
    SandboxWorkloadTemplate,
    ServiceEndpointResponse,
    UpdateConfigResponse,
)
from ._proto.sandbox_pb2 import GetSandboxConfigResponse, SandboxPolicy, SettingValue

__all__ = [
    "AttachSandboxProviderResponse",
    "DetachSandboxProviderResponse",
    "GetSandboxConfigResponse",
    "GetSandboxLogsResponse",
    "GetSandboxPolicyStatusResponse",
    "ObjectMeta",
    "Provider",
    "ProviderMutationReceipt",
    "ProviderReadinessState",
    "ProviderReadinessStatus",
    "ResourceRequirements",
    "SandboxLogLine",
    "SandboxPhase",
    "SandboxPolicy",
    "SandboxPolicyRevision",
    "SandboxSpec",
    "SandboxStreamEvent",
    "SandboxTemplate",
    "SandboxWorkloadTemplate",
    "ServiceEndpointResponse",
    "SettingValue",
    "UpdateConfigResponse",
]
