#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import sys
from configparser import ConfigParser
from configparser import Error as ConfigParserError
from email.parser import Parser
from pathlib import Path
from zipfile import BadZipFile, ZipFile

PROTO_STEMS = ("datamodel", "inference", "openshell", "options", "sandbox")
BYTECODE_SUFFIXES = (".pyc", ".pyo")
NATIVE_SUFFIXES = (".dll", ".dylib", ".exe", ".pyd", ".so")


def _find_wheel(path: Path) -> Path:
    if path.is_file():
        return path

    wheels = sorted(path.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError(f"expected exactly one wheel in {path}, found {len(wheels)}")
    return wheels[0]


def _required_files() -> set[str]:
    files = {
        "openshell/__init__.py",
        "openshell/sandbox.py",
        "openshell/py.typed",
        "openshell/_proto/__init__.py",
    }
    for stem in PROTO_STEMS:
        files.add(f"openshell/_proto/{stem}_pb2.py")
        files.add(f"openshell/_proto/{stem}_pb2.pyi")
        files.add(f"openshell/_proto/{stem}_pb2_grpc.py")
    return files


def _single_member(names: set[str], suffix: str) -> str:
    matches = [name for name in names if name.endswith(suffix)]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {suffix} file, found {len(matches)}")
    return matches[0]


def verify_wheel(path: Path, expected_version: str | None = None) -> Path:
    wheel = _find_wheel(path)
    if not wheel.name.endswith("-py3-none-any.whl"):
        raise ValueError(f"wheel is not platform-independent: {wheel.name}")

    with ZipFile(wheel) as archive:
        names = set(archive.namelist())
        missing = sorted(_required_files() - names)
        if missing:
            raise ValueError(f"wheel is missing required files: {', '.join(missing)}")

        scripts = sorted(
            name
            for name in names
            if not name.endswith("/")
            and Path(name).name in {"openshell", "openshell.exe"}
        )
        if scripts:
            raise ValueError(
                f"wheel contains an openshell executable: {', '.join(scripts)}"
            )

        entry_points = [
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        ]
        if len(entry_points) > 1:
            raise ValueError(
                f"expected at most one entry_points.txt file, found {len(entry_points)}"
            )
        if entry_points:
            parser = ConfigParser(interpolation=None)
            try:
                parser.read_string(archive.read(entry_points[0]).decode())
            except (ConfigParserError, UnicodeDecodeError) as error:
                raise ValueError(
                    "wheel contains invalid entry point metadata"
                ) from error
            if parser.has_option("console_scripts", "openshell"):
                raise ValueError("wheel defines an openshell console script")

        bytecode_files = sorted(
            name for name in names if name.endswith(BYTECODE_SUFFIXES)
        )
        if bytecode_files:
            raise ValueError(
                f"wheel contains Python bytecode: {', '.join(bytecode_files)}"
            )

        native_files = sorted(name for name in names if name.endswith(NATIVE_SUFFIXES))
        if native_files:
            raise ValueError(f"wheel contains native files: {', '.join(native_files)}")

        metadata_name = _single_member(names, ".dist-info/METADATA")
        metadata = Parser().parsestr(archive.read(metadata_name).decode())
        if metadata["Name"] != "openshell":
            raise ValueError(f"unexpected distribution name: {metadata['Name']}")

        version = metadata["Version"]
        filename_version = wheel.name.removesuffix("-py3-none-any.whl").removeprefix(
            "openshell-"
        )
        if version != filename_version:
            raise ValueError(
                f"wheel filename version {filename_version} does not match metadata {version}"
            )
        if expected_version is not None and version != expected_version:
            raise ValueError(f"expected version {expected_version}, found {version}")

        wheel_name = _single_member(names, ".dist-info/WHEEL")
        wheel_metadata = Parser().parsestr(archive.read(wheel_name).decode())
        if wheel_metadata.get_all("Tag", []) != ["py3-none-any"]:
            raise ValueError(
                f"unexpected wheel tags: {wheel_metadata.get_all('Tag', [])}"
            )
        if wheel_metadata["Root-Is-Purelib"] != "true":
            raise ValueError("wheel is not marked as pure Python")

    return wheel


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the OpenShell Python wheel")
    parser.add_argument(
        "path", type=Path, help="Wheel file or directory containing one wheel"
    )
    parser.add_argument("--expected-version")
    args = parser.parse_args()

    try:
        wheel = verify_wheel(args.path, args.expected_version)
    except (BadZipFile, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"Verified {wheel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
