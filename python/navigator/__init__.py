"""Navigator - Agent execution and management SDK."""

from __future__ import annotations

from navigator.inference import Inference
from navigator.sandbox import (
    ExecChunk,
    ExecResult,
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
    "Inference",
    "Sandbox",
    "SandboxClient",
    "SandboxError",
    "SandboxRef",
    "SandboxSession",
    "TlsConfig",
    "__version__",
]
