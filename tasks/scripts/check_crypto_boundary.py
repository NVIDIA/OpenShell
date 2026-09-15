# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reject direct crypto backend use outside the facade on every host platform."""

import re
import subprocess
import sys
from pathlib import Path

BACKEND_USE = re.compile(
    r"\b(aws_lc_rs|ring)::|\bcrypto::aws_lc::|tls-aws-lc|tls-rustls-aws-lc-rs|"
    r'"aws[-_]lc[-_]rs"|^aws-lc-rs\s*='
)


def check(root: Path) -> int:
    """Scan tracked and unignored new sources without traversing build outputs."""
    paths = subprocess.check_output(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "crates",
            "examples",
            "e2e",
        ],
        cwd=root,
    )
    failed = False
    for name in sorted(set(paths.decode("utf-8").split("\0")) - {""}):
        path = Path(name)
        if "openshell-crypto" in path.parts:
            continue
        if path.suffix != ".rs" and path.name != "Cargo.toml":
            continue
        source = root / path
        # Git still lists tracked files removed from the working tree.
        if not source.exists():
            continue
        for number, line in enumerate(
            source.read_text(encoding="utf-8").splitlines(), 1
        ):
            if BACKEND_USE.search(line):
                print(f"{path.as_posix()}:{number}:{line}")
                failed = True
    if failed:
        print("Direct backend use must live in openshell-crypto.", file=sys.stderr)
    return int(failed)


if __name__ == "__main__":
    sys.exit(check(Path(__file__).resolve().parents[2]))
