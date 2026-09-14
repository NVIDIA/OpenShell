# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from zipfile import ZipFile

import pytest


def _load_verifier_module():
    path = Path(__file__).resolve().parents[1] / "tasks/scripts/verify-python-wheel.py"
    spec = importlib.util.spec_from_file_location("openshell_wheel_verifier", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load_verifier_module()


def _wheel_files() -> set[str]:
    files = {
        "openshell/__init__.py",
        "openshell/sandbox.py",
        "openshell/py.typed",
        "openshell/_proto/__init__.py",
    }
    for stem in ("datamodel", "inference", "openshell", "options", "sandbox"):
        files.add(f"openshell/_proto/{stem}_pb2.py")
        files.add(f"openshell/_proto/{stem}_pb2.pyi")
        files.add(f"openshell/_proto/{stem}_pb2_grpc.py")
    return files


def _write_wheel(
    directory: Path,
    *,
    version: str = "1.2.3",
    tag: str = "py3-none-any",
    files: set[str] | None = None,
    entry_points: str | None = None,
) -> Path:
    wheel = directory / f"openshell-{version}-{tag}.whl"
    dist_info = f"openshell-{version}.dist-info"
    with ZipFile(wheel, "w") as archive:
        for name in files if files is not None else _wheel_files():
            archive.writestr(name, "")
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.4\nName: openshell\nVersion: {version}\n",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            f"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: {tag}\n",
        )
        if entry_points is not None:
            archive.writestr(f"{dist_info}/entry_points.txt", entry_points)
    return wheel


def test_accepts_pure_python_sdk_wheel(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path)

    assert verifier.verify_wheel(wheel, "1.2.3") == wheel


def test_requires_exactly_one_wheel_in_directory(tmp_path: Path) -> None:
    _write_wheel(tmp_path, version="1.2.3")
    _write_wheel(tmp_path, version="1.2.4")

    with pytest.raises(ValueError, match="expected exactly one wheel"):
        verifier.verify_wheel(tmp_path)


def test_rejects_missing_generated_proto(tmp_path: Path) -> None:
    files = _wheel_files() - {"openshell/_proto/sandbox_pb2.py"}
    wheel = _write_wheel(tmp_path, files=files)

    with pytest.raises(ValueError, match=r"sandbox_pb2\.py"):
        verifier.verify_wheel(wheel)


def test_rejects_bundled_cli(tmp_path: Path) -> None:
    files = _wheel_files() | {"openshell-1.2.3.data/scripts/openshell"}
    wheel = _write_wheel(tmp_path, files=files)

    with pytest.raises(ValueError, match="contains an openshell executable"):
        verifier.verify_wheel(wheel)


def test_rejects_bundled_windows_cli(tmp_path: Path) -> None:
    files = _wheel_files() | {"openshell-1.2.3.data/scripts/openshell.exe"}
    wheel = _write_wheel(tmp_path, files=files)

    with pytest.raises(ValueError, match="contains an openshell executable"):
        verifier.verify_wheel(wheel)


def test_rejects_openshell_console_script(tmp_path: Path) -> None:
    wheel = _write_wheel(
        tmp_path,
        entry_points="[console_scripts]\nopenshell = openshell.cli:main\n",
    )

    with pytest.raises(ValueError, match="defines an openshell console script"):
        verifier.verify_wheel(wheel)


def test_rejects_native_extension(tmp_path: Path) -> None:
    files = _wheel_files() | {"openshell/_native.so"}
    wheel = _write_wheel(tmp_path, files=files)

    with pytest.raises(ValueError, match="contains native files"):
        verifier.verify_wheel(wheel)


def test_rejects_bytecode(tmp_path: Path) -> None:
    files = _wheel_files() | {"openshell/__pycache__/sandbox.cpython-314.pyc"}
    wheel = _write_wheel(tmp_path, files=files)

    with pytest.raises(ValueError, match="contains Python bytecode"):
        verifier.verify_wheel(wheel)


def test_rejects_platform_wheel(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path, tag="cp311-cp311-manylinux_2_28_x86_64")

    with pytest.raises(ValueError, match="not platform-independent"):
        verifier.verify_wheel(wheel)


def test_rejects_unexpected_version(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path)

    with pytest.raises(ValueError, match=r"expected version 1\.2\.4"):
        verifier.verify_wheel(wheel, "1.2.4")
