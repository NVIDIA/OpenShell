#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Expand {include} directives in MDX files. Run after copy_docs_to_fern.py.

Processes index.mdx, replacing {include} blocks with the actual content
of the referenced files (README.md).
"""

import argparse
import re
from pathlib import Path


def expand_include_in_content(
    content: str, file_path: Path, pages_dir: Path, docs_dir: Path
) -> str:
    """Replace {include} directives with file content. Paths are relative to the source doc."""
    # Match ```{include} path with optional options (e.g. :relative-docs:)
    pattern = r"```\{include\}\s+([^\s\n]+)(?:\s*\n(?::[^\n]+\n)*)?```"

    def replace_include(match: re.Match[str]) -> str:
        include_path_str = match.group(1).strip()
        # Include paths are relative to the source doc's directory in docs/
        # e.g. docs/index.md has ../README.md -> repo_root/README.md
        rel = file_path.relative_to(pages_dir)
        source_dir = docs_dir / rel.parent
        if rel.name == "index.mdx":
            source_dir = docs_dir
        resolved = (source_dir / include_path_str).resolve()

        if not resolved.exists():
            return f"<!-- Include file not found: {resolved} -->"
        return resolved.read_text()

    return re.sub(pattern, replace_include, content)


def expand_file(filepath: Path, pages_dir: Path, docs_dir: Path) -> bool:
    """Expand includes in a single file. Returns True if changes were made."""
    content = filepath.read_text()
    if "{include}" not in content:
        return False

    new_content = expand_include_in_content(content, filepath, pages_dir, docs_dir)
    if new_content != content:
        filepath.write_text(new_content)
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Expand {include} directives in MDX files"
    )
    parser.add_argument(
        "pages_dir",
        type=Path,
        help="Path to pages directory (e.g. fern/v0.1.0/pages)",
    )
    parser.add_argument(
        "--docs-dir",
        type=Path,
        default=None,
        help="Path to docs directory (default: repo_root/docs)",
    )
    args = parser.parse_args()

    pages_dir = args.pages_dir.resolve()
    if not pages_dir.exists():
        raise SystemExit(f"Error: pages directory not found at {pages_dir}")

    repo_root = pages_dir.parent.parent.parent
    docs_dir = args.docs_dir.resolve() if args.docs_dir else repo_root / "docs"

    expanded = []
    for pattern in ["index.mdx"]:
        filepath = pages_dir / pattern
        if filepath.exists() and expand_file(filepath, pages_dir, docs_dir):
            expanded.append(filepath.relative_to(pages_dir))
            print(f"  Expanded: {filepath.relative_to(pages_dir)}")

    print(f"\nExpanded {len(expanded)} files")


if __name__ == "__main__":
    main()
