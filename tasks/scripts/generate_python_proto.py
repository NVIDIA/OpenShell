# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Python protobuf stubs and make their imports package-relative."""

import re
import subprocess
import sys
from pathlib import Path

PROTO_FILES = [
    "proto/inference.proto",
    "proto/openshell.proto",
    "proto/datamodel.proto",
    "proto/options.proto",
    "proto/sandbox.proto",
]

LOCAL_MODULES = [f"{Path(path).stem}_pb2" for path in PROTO_FILES]
LOCAL_IMPORT = re.compile(
    rf"^import ({'|'.join(re.escape(module) for module in LOCAL_MODULES)}) as (\w+)$",
    re.MULTILINE,
)


def main() -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "grpc_tools.protoc",
            "-Iproto",
            "--python_out=python/openshell/_proto",
            "--pyi_out=python/openshell/_proto",
            "--grpc_python_out=python/openshell/_proto",
            *PROTO_FILES,
        ],
        check=True,
    )

    for module in LOCAL_MODULES:
        for suffix in (".py", ".pyi", "_grpc.py"):
            file_path = Path("python/openshell/_proto") / f"{module}{suffix}"
            text = LOCAL_IMPORT.sub(r"from . import \1 as \2", file_path.read_text())
            file_path.write_text(text)


if __name__ == "__main__":
    main()
