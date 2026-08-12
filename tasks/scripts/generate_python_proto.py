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

LINE_REWRITES = {
    "python/openshell/_proto/inference_pb2.py": [
        (
            r"^import datamodel_pb2 as datamodel__pb2$",
            "from . import datamodel_pb2 as datamodel__pb2",
        ),
        (
            r"^import options_pb2 as options__pb2$",
            "from . import options_pb2 as options__pb2",
        ),
    ],
    "python/openshell/_proto/inference_pb2_grpc.py": [
        (
            r"^import inference_pb2 as inference__pb2$",
            "from . import inference_pb2 as inference__pb2",
        ),
    ],
    "python/openshell/_proto/openshell_pb2_grpc.py": [
        (
            r"^import openshell_pb2 as openshell__pb2$",
            "from . import openshell_pb2 as openshell__pb2",
        ),
        (
            r"^import sandbox_pb2 as sandbox__pb2$",
            "from . import sandbox_pb2 as sandbox__pb2",
        ),
    ],
    "python/openshell/_proto/openshell_pb2.py": [
        (
            r"^import datamodel_pb2 as datamodel__pb2$",
            "from . import datamodel_pb2 as datamodel__pb2",
        ),
        (
            r"^import options_pb2 as options__pb2$",
            "from . import options_pb2 as options__pb2",
        ),
        (
            r"^import sandbox_pb2 as sandbox__pb2$",
            "from . import sandbox_pb2 as sandbox__pb2",
        ),
    ],
    "python/openshell/_proto/datamodel_pb2.py": [
        (
            r"^import options_pb2 as options__pb2$",
            "from . import options_pb2 as options__pb2",
        ),
        (
            r"^import sandbox_pb2 as sandbox__pb2$",
            "from . import sandbox_pb2 as sandbox__pb2",
        ),
    ],
    "python/openshell/_proto/datamodel_pb2_grpc.py": [
        (
            r"^import datamodel_pb2 as datamodel__pb2$",
            "from . import datamodel_pb2 as datamodel__pb2",
        ),
    ],
    "python/openshell/_proto/sandbox_pb2_grpc.py": [
        (
            r"^import sandbox_pb2 as sandbox__pb2$",
            "from . import sandbox_pb2 as sandbox__pb2",
        ),
    ],
}


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

    for path, rules in LINE_REWRITES.items():
        file_path = Path(path)
        text = file_path.read_text()
        text = text.replace("from . from . import", "from . import")
        for pattern, replacement in rules:
            text = re.sub(pattern, replacement, text, flags=re.MULTILINE)
        file_path.write_text(text)


if __name__ == "__main__":
    main()
