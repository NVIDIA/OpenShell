#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fix MyST-style frontmatter for Fern compatibility.

Converts nested title: {page:, nav:} to simple title: string.
Removes MyST-specific frontmatter keys (topics, tags, content).
Keeps title and description only.
"""

import argparse
import re
from pathlib import Path


def fix_frontmatter(filepath: Path) -> bool:
    """Fix frontmatter in a single file. Returns True if changes were made."""
    content = filepath.read_text()
    if not content.strip().startswith("---"):
        return False

    fm_match = re.match(r"^---\s*\n(.*?)---\s*\n", content, re.DOTALL)
    if not fm_match:
        return False

    fm_block = fm_match.group(1)
    rest = content[fm_match.end():]

    title_match = re.search(r"^\s+page:\s*(.+)$", fm_block, re.MULTILINE)
    if not title_match:
        title_match = re.search(r"^title:\s*(.+)$", fm_block, re.MULTILINE)
        if title_match:
            title = title_match.group(1).strip().strip('"\'')
        else:
            return False
    else:
        title = title_match.group(1).strip().strip('"\'')

    desc_match = re.search(r"^description:\s*(.+)$", fm_block, re.MULTILINE)
    description = desc_match.group(1).strip() if desc_match else ""

    title_escaped = title.replace('"', '\\"')
    desc_escaped = description.replace('"', '\\"') if description else ""

    new_fm = f'---\ntitle: "{title_escaped}"\ndescription: "{desc_escaped}"\n---\n'
    new_content = new_fm + rest

    if new_content != content:
        filepath.write_text(new_content)
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fix MyST frontmatter for Fern compatibility"
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
        if fix_frontmatter(mdx_file):
            changed.append(mdx_file.relative_to(pages_dir))
            print(f"  Fixed: {mdx_file.relative_to(pages_dir)}")

    print(f"\nFixed frontmatter in {len(changed)} files")


if __name__ == "__main__":
    main()
