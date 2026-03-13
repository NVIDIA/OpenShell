#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Remove duplicate H1 that matches frontmatter title."""

import argparse
import re
from pathlib import Path


def remove_duplicate_h1(filepath: Path) -> bool:
    """Remove H1 after frontmatter if it duplicates the title. Returns True if changed."""
    content = filepath.read_text()

    if not content.strip().startswith("---"):
        return False

    # Extract title from frontmatter
    match = re.search(r"^---\s*\ntitle:\s*(.+?)\n", content, re.MULTILINE)
    if not match:
        return False

    title = match.group(1).strip().strip('"\'')
    pattern = rf"(---\s*\n.*?---\s*\n\n)#\s+{re.escape(title)}\s*\n+"
    new_content = re.sub(pattern, r"\1", content, count=1, flags=re.DOTALL)

    if new_content != content:
        filepath.write_text(new_content)
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Remove duplicate H1 that matches frontmatter title"
    )
    parser.add_argument(
        "pages_dir",
        type=Path,
        help="Path to pages directory",
    )
    args = parser.parse_args()

    pages_dir = args.pages_dir.resolve()
    if not pages_dir.exists():
        raise SystemExit(f"Error: pages directory not found at {pages_dir}")

    changed = []
    for mdx_file in sorted(pages_dir.rglob("*.mdx")):
        if remove_duplicate_h1(mdx_file):
            changed.append(mdx_file.relative_to(pages_dir))
            print(f"  Removed H1: {mdx_file.relative_to(pages_dir)}")

    print(f"\nRemoved duplicate H1 from {len(changed)} files")


if __name__ == "__main__":
    main()
