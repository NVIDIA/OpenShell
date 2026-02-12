"""Navigator - Agent execution and management SDK."""

from __future__ import annotations

from navigator.inference import Inference

try:
    from importlib.metadata import version

    __version__ = version("navigator")
except Exception:
    __version__ = "0.0.0"

__all__ = ["Inference", "__version__"]
