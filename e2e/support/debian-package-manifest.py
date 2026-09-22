#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Read copied Debian/distroless package metadata without executing image tools."""

import sys
from pathlib import Path


def package_manifest(root: Path) -> list[str]:
    status = root / "status"
    sources = [status] if status.is_file() else []
    sources.extend(
        path
        for path in sorted((root / "status.d").glob("*"))
        if path.is_file() and not path.name.endswith(".md5sums")
    )
    packages = set()
    for source in sources:
        for stanza in source.read_text().strip().split("\n\n"):
            if not stanza.strip():
                continue
            fields = dict(
                line.split(": ", 1)
                for line in stanza.splitlines()
                if not line.startswith((" ", "\t")) and ": " in line
            )
            if "Status" in fields and not fields["Status"].endswith(" ok installed"):
                continue
            if not {"Package", "Version", "Architecture"} <= fields.keys():
                raise ValueError(f"Incomplete package metadata in {source}")
            name = fields["Package"]
            if fields.get("Multi-Arch") == "same":
                name += ":" + fields["Architecture"]
            packages.add(f"{name}={fields['Version']}")
    if not packages:
        raise ValueError(f"No installed Debian packages found in {root}")
    return sorted(packages)


if __name__ == "__main__":
    print("\n".join(package_manifest(Path(sys.argv[1]))))
