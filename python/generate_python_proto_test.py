# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exercise generation in a clean tree so stale bindings cannot hide failures."""

import ast
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("no_pyi", [False, True])
def test_generate_package_relative_bindings(tmp_path: Path, no_pyi: bool) -> None:
    root = Path(__file__).resolve().parents[1]
    shutil.copytree(root / "proto", tmp_path / "proto")
    output = tmp_path / "python/openshell/_proto"
    output.mkdir(parents=True)
    command = [
        sys.executable,
        str(root / "tasks/scripts/generate_python_proto.py"),
        *(["--no-pyi"] if no_pyi else []),
    ]
    subprocess.run(command, cwd=tmp_path, check=True, capture_output=True, text=True)

    stems = {
        "credential_driver",
        "datamodel",
        "extension",
        "openshell",
        "options",
        "sandbox",
    }
    suffixes = ["_pb2.py", "_pb2_grpc.py"]
    if not no_pyi:
        suffixes.append("_pb2.pyi")
    assert {path.name for path in output.iterdir()} == {
        f"{stem}{suffix}" for stem in stems for suffix in suffixes
    }
    for path in output.iterdir():
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                assert not any(alias.name.endswith("_pb2") for alias in node.names), (
                    f"Absolute generated import in {path.name}"
                )

    # Skipping type generation must also leave existing stubs untouched.
    sentinel = output / "credential_driver_pb2.pyi"
    sentinel.write_text("# existing type stub\n")
    subprocess.run(
        command if no_pyi else [*command, "--no-pyi"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    assert sentinel.read_text() == "# existing type stub\n"
