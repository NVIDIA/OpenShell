#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Add frontmatter (title, description) to MDX files derived from first H1."""

import argparse
import re
from pathlib import Path


def derive_title(content: str) -> str:
    """Extract title from first # Heading."""
    match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
    if match:
        title = match.group(1).strip()
        title = re.sub(r"\{[^}]+\}`[^`]*`", "", title).strip()
        return title or "Untitled"
    return "Untitled"


def add_frontmatter(filepath: Path) -> bool:
    """Add frontmatter if missing. Returns True if changes were made."""
    content = filepath.read_text()

    if content.strip().startswith("---"):
        return False

    title = derive_title(content)
    title_escaped = title.replace('"', '\\"')
    frontmatter = f'---\ntitle: "{title_escaped}"\ndescription: ""\n---\n\n'
    body = content.lstrip()

    # Remove duplicate H1 that matches title (Fern uses frontmatter title)
    body = re.sub(r"^#\s+" + re.escape(title) + r"\s*\n+", "", body, count=1)

    new_content = frontmatter + body
    filepath.write_text(new_content)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Add frontmatter to MDX files"
    )
    parser.add_argument(
        "pages_dir",
        type=Path,
        help="Path to pages directory (e.g. fern/v0.2.0/pages)",
    )
    args = parser.parse_args()

    pages_dir = args.pages_dir.resolve()
    if not pages_dir.exists():
        raise SystemExit(f"Error: pages directory not found at {pages_dir}")

    changed = []
    for mdx_file in sorted(pages_dir.rglob("*.mdx")):
        if add_frontmatter(mdx_file):
            changed.append(mdx_file.relative_to(pages_dir))
            print(f"  Added frontmatter: {mdx_file.relative_to(pages_dir)}")

    print(f"\nAdded frontmatter to {len(changed)} files")


if __name__ == "__main__":
    main()
