# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Cargo lockfile alignment check."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "check_cargo_lockfile_alignment",
    Path(__file__).with_name("check_cargo_lockfile_alignment.py"),
)
assert _SPEC and _SPEC.loader
alignment = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = alignment
_SPEC.loader.exec_module(alignment)

REGISTRY = 'source = "registry+https://github.com/rust-lang/crates.io-index"'


def lockfile(path: Path, packages: list[tuple[str, str, bool]]) -> None:
    """Write a lockfile of (name, version, from_registry) packages."""
    entries = []
    for name, version, from_registry in packages:
        entry = f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
        if from_registry:
            entry += REGISTRY + "\n"
        entries.append(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("version = 4\n\n" + "\n".join(entries))


def test_compat_key_follows_cargo_caret_rules() -> None:
    assert alignment.compat_key("1.52.1") == (1,)
    assert alignment.compat_key("0.44.0") == (0, 44)
    assert alignment.compat_key("0.0.3") == (0, 0, 3)
    assert alignment.compat_key("1.0.4+wasi-0.2.12") == (1,)


def test_reports_shared_registry_crates_at_other_versions(tmp_path: Path) -> None:
    lockfile(
        tmp_path / "Cargo.lock",
        [
            ("tokio", "1.52.1", True),
            ("rand", "0.8.6", True),
            ("rand", "0.9.4", True),
            ("openshell-sdk", "0.0.0", False),
        ],
    )
    lockfile(
        tmp_path / "ws" / "Cargo.lock",
        [
            ("tokio", "1.53.1", True),
            ("rand", "0.9.5", True),
            ("rand", "0.8.6", True),
            ("only-here", "2.0.0", True),
            ("openshell-sdk", "0.0.0", False),
        ],
    )

    found = alignment.mismatches(tmp_path, "ws")

    assert [(m.name, m.version, m.target()) for m in found] == [
        ("rand", "0.9.5", "0.9.4"),
        ("tokio", "1.53.1", "1.52.1"),
    ]


def test_no_target_without_a_compatible_root_version(tmp_path: Path) -> None:
    lockfile(tmp_path / "Cargo.lock", [("syn", "1.0.109", True)])
    lockfile(tmp_path / "ws" / "Cargo.lock", [("syn", "2.0.119", True)])

    (found,) = alignment.mismatches(tmp_path, "ws")

    assert found.target() is None


def test_aligned_lockfiles_pass(tmp_path: Path) -> None:
    lockfile(tmp_path / "Cargo.lock", [("tokio", "1.52.1", True)])
    lockfile(tmp_path / "ws" / "Cargo.lock", [("tokio", "1.52.1", True)])

    assert alignment.mismatches(tmp_path, "ws") == []
