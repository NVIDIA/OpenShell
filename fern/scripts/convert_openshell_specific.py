#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Convert OpenShell-specific syntax for Fern MDX compatibility.

Handles: {doc} roles (internal doc links), escaping {variable} in code blocks,
and OpenShell-specific directives like policy_table.
"""

import argparse
import re
from pathlib import Path


def resolve_doc_path(path: str, file_dir: Path | None) -> str:
    """Resolve doc path to Fern URL."""
    path = path.replace("../", "").replace(".md", "").replace(".mdx", "").strip()
    if "/" not in path and file_dir:
        rel_parts = file_dir.parts
        path = "/".join(rel_parts) + "/" + path
    if not path.startswith("/"):
        path = "/" + path
    return path


def convert_doc_roles(content: str, filepath: Path | None = None) -> str:
    """Convert {doc}`display <path>` and {doc}`path` to internal links."""
    file_dir = None
    if filepath:
        try:
            pages_idx = filepath.parts.index("pages")
            file_dir = Path(*filepath.parts[pages_idx + 1 : filepath.parts.index(filepath.name)])
        except (ValueError, IndexError):
            pass

    def replace_doc_with_path(match: re.Match[str]) -> str:
        display = match.group(1).strip()
        path = match.group(2).strip()
        clean = resolve_doc_path(path, file_dir)
        return f"[{display}]({clean})"

    def replace_doc_path_only(match: re.Match[str]) -> str:
        path = match.group(1).strip()
        clean = resolve_doc_path(path, file_dir)
        display = path.split("/")[-1].replace("-", " ").replace("_", " ").title()
        return f"[{display}]({clean})"

    content = re.sub(r"\{doc\}`([^`]+?)\s*<([^>]+)>`", replace_doc_with_path, content)
    content = re.sub(r"\{doc\}`([^`]+)`", replace_doc_path_only, content)
    return content


def convert_ref_roles(content: str) -> str:
    """Convert {ref}`display <target>` and {ref}`target` to links or bold text."""
    def replace_ref_with_display(match: re.Match[str]) -> str:
        display = match.group(1).strip()
        return f"**{display}**"

    def replace_ref_only(match: re.Match[str]) -> str:
        target = match.group(1).strip()
        display = target.replace("-", " ").replace("_", " ").title()
        return f"**{display}**"

    content = re.sub(r"\{ref\}`([^`]+?)\s*<([^>]+)>`", replace_ref_with_display, content)
    content = re.sub(r"\{ref\}`([^`]+)`", replace_ref_only, content)
    return content


def remove_policy_table_directive(content: str) -> str:
    """Remove {policy_table} directives (custom Sphinx extension)."""
    content = re.sub(r"```\{policy_table\}.*?```", "", content, flags=re.DOTALL)
    content = re.sub(r":::\{policy_table\}.*?:::", "", content, flags=re.DOTALL)
    return content


def escape_mdx_curly_braces_in_code(content: str) -> str:
    """Escape {variable} patterns in code blocks so MDX doesn't parse as JSX."""
    def escape_in_code_block(match: re.Match[str]) -> str:
        lang = match.group(1) or ""
        code = match.group(2)
        code = re.sub(r"\{(\w+)\}", r"\\{\1\\}", code)
        return f"```{lang}\n{code}```"

    return re.sub(r"```(\w*)\n(.*?)```", escape_in_code_block, content, flags=re.DOTALL)


def convert_file(filepath: Path) -> bool:
    """Convert a single file. Returns True if changes were made."""
    content = filepath.read_text()
    original = content

    content = convert_doc_roles(content, filepath)
    content = convert_ref_roles(content)
    content = remove_policy_table_directive(content)

    if content != original:
        filepath.write_text(content)
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert OpenShell-specific syntax for Fern MDX"
    )
    parser.add_argument(
        "pages_dir",
        type=Path,
        help="Path to pages directory (e.g. fern/v0.1.0/pages)",
    )
    args = parser.parse_args()

    pages_dir = args.pages_dir.resolve()
    if not pages_dir.exists():
        raise SystemExit(f"Error: pages directory not found at {pages_dir}")

    changed = []
    for mdx_file in sorted(pages_dir.rglob("*.mdx")):
        if convert_file(mdx_file):
            changed.append(mdx_file.relative_to(pages_dir))
            print(f"  Converted: {mdx_file.relative_to(pages_dir)}")

    print(f"\nConverted {len(changed)} files")


if __name__ == "__main__":
    main()
