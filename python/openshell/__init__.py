# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""OpenShell - Agent execution and management SDK."""

from __future__ import annotations

from .sandbox import (
    ApproveAllResult,
    ClusterInferenceConfig,
    DraftChunkRef,
    DraftPolicyResult,
    ExecChunk,
    ExecResult,
    InferenceRouteClient,
    PolicyUpdateResult,
    ProviderRef,
    Sandbox,
    SandboxClient,
    SandboxError,
    SandboxFull,
    SandboxRef,
    SandboxSession,
    SandboxStatusRef,
    TlsConfig,
)

try:
    from importlib.metadata import version

    __version__ = version("openshell")
except Exception:
    __version__ = "0.0.0"

__all__ = [
    "ApproveAllResult",
    "ClusterInferenceConfig",
    "DraftChunkRef",
    "DraftPolicyResult",
    "ExecChunk",
    "ExecResult",
    "InferenceRouteClient",
    "PolicyUpdateResult",
    "ProviderRef",
    "Sandbox",
    "SandboxClient",
    "SandboxError",
    "SandboxFull",
    "SandboxRef",
    "SandboxSession",
    "SandboxStatusRef",
    "TlsConfig",
    "__version__",
]
