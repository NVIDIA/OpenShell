# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Navigator - Agent execution and management SDK."""

from __future__ import annotations

from navigator.sandbox import (
    ExecChunk,
    ExecResult,
    InferenceRouteClient,
    InferenceRouteRef,
    Sandbox,
    SandboxClient,
    SandboxError,
    SandboxRef,
    SandboxSession,
    TlsConfig,
)

try:
    from importlib.metadata import version

    __version__ = version("navigator")
except Exception:
    __version__ = "0.0.0"

__all__ = [
    "ExecChunk",
    "ExecResult",
    "InferenceRouteClient",
    "InferenceRouteRef",
    "Sandbox",
    "SandboxClient",
    "SandboxError",
    "SandboxRef",
    "SandboxSession",
    "TlsConfig",
    "__version__",
]
