# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Python protobuf stubs and make their imports package-relative."""

import argparse
import re
import subprocess
import sys
from pathlib import Path

PROTO_FILES = [
    "proto/openshell.proto",
    "proto/datamodel.proto",
    "proto/options.proto",
    "proto/sandbox.proto",
    "proto/extension.proto",
    "proto/credential_driver.proto",
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-pyi", action="store_true", help="Skip type-stub generation"
    )
    args = parser.parse_args()
    output_dir = Path("python/openshell/_proto")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "grpc_tools.protoc",
            "-Iproto",
            "--python_out=python/openshell/_proto",
            *([] if args.no_pyi else ["--pyi_out=python/openshell/_proto"]),
            "--grpc_python_out=python/openshell/_proto",
            *PROTO_FILES,
        ],
        check=True,
    )

    # Rewrite only imports of our generated modules, leaving google.protobuf
    # imports intact. The same rule covers runtime modules and type stubs.
    modules = "|".join(re.escape(f"{Path(path).stem}_pb2") for path in PROTO_FILES)
    pattern = rf"^import ({modules})( as \w+)?$"
    suffixes = ["_pb2.py", "_pb2_grpc.py"]
    if not args.no_pyi:
        suffixes.append("_pb2.pyi")
    for proto in PROTO_FILES:
        for suffix in suffixes:
            file_path = output_dir / f"{Path(proto).stem}{suffix}"
            text = file_path.read_text()
            text = re.sub(pattern, r"from . import \1\2", text, flags=re.MULTILINE)
            file_path.write_text(text)


if __name__ == "__main__":
    main()
