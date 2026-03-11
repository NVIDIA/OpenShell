#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Add or check SPDX license headers on source files.

Usage:
    # Add/update headers on all source files
    python scripts/update_license_headers.py

    # Check mode (CI / pre-commit) — exit 1 if any file is missing a header
    python scripts/update_license_headers.py --check

    # Operate on specific files only (useful for pre-commit on staged files)
    python scripts/update_license_headers.py path/to/file.rs path/to/other.py
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

COPYRIGHT_TEXT = (
    "Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved."
)
LICENSE_ID = "Apache-2.0"

# Map file extensions to their line-comment prefix.
COMMENT_STYLES: dict[str, str] = {
    ".rs": "//",
    ".proto": "//",
    ".py": "#",
    ".sh": "#",
    ".toml": "#",
    ".yaml": "#",
    ".yml": "#",
    ".rego": "#",
}

# Directories to skip entirely (relative to repo root).
EXCLUDE_DIRS: set[str] = {
    "target",
    "e2e/rust/target",
    ".venv",
    ".git",
    ".cache",
    "python/openshell/_proto",
    "deploy/helm/navigator/templates",
}

# Individual filenames to skip.
EXCLUDE_FILES: set[str] = {
    "Cargo.lock",
    "uv.lock",
    ".gitlab-ci.yml",
}

# Glob-style directory prefixes to also skip (CI / editor config dirs).
EXCLUDE_DIR_PREFIXES: tuple[str, ...] = (
    ".github/",
    ".agents/",
    ".claude/",
)

# ---------------------------------------------------------------------------
# Header generation
# ---------------------------------------------------------------------------


def make_header(comment: str) -> str:
    """Return the two-line SPDX header for a given comment prefix."""
    return (
        f"{comment} SPDX-FileCopyrightText: {COPYRIGHT_TEXT}\n"
        f"{comment} SPDX-License-Identifier: {LICENSE_ID}\n"
    )


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def find_repo_root() -> Path:
    """Walk up from CWD to find the directory containing .git."""
    path = Path.cwd()
    while path != path.parent:
        if (path / ".git").exists():
            return path
        path = path.parent
    return Path.cwd()


def is_excluded(rel: Path) -> bool:
    """Return True if a path should be skipped."""
    rel_str = str(rel)

    # Exact filename exclusions.
    if rel.name in EXCLUDE_FILES:
        return True

    # Directory exclusions.
    for exc_dir in EXCLUDE_DIRS:
        if rel_str == exc_dir or rel_str.startswith(exc_dir + "/"):
            return True

    # Prefix exclusions (CI config, editor config).
    for prefix in EXCLUDE_DIR_PREFIXES:
        if rel_str.startswith(prefix):
            return True

    return False


def is_dockerfile(path: Path) -> bool:
    """Return True for Dockerfile variants (matched by name, not extension)."""
    return path.name == "Dockerfile" or path.name.startswith("Dockerfile.")


def get_comment_style(path: Path) -> str | None:
    """Return the comment prefix for a file, or None if unsupported."""
    if is_dockerfile(path):
        return "#"
    return COMMENT_STYLES.get(path.suffix)


def discover_files(root: Path) -> list[Path]:
    """Walk the repo and return all files that should have headers."""
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)

        # Prune excluded directories (modifying dirnames in-place).
        dirnames[:] = [d for d in dirnames if not is_excluded(rel_dir / d)]

        for fname in filenames:
            fpath = Path(dirpath) / fname
            rel = fpath.relative_to(root)
            if is_excluded(rel):
                continue
            if get_comment_style(rel) is not None:
                results.append(fpath)

    return sorted(results)


# ---------------------------------------------------------------------------
# Header checking and insertion
# ---------------------------------------------------------------------------

SPDX_MARKER = "SPDX-License-Identifier"


def has_header(lines: list[str]) -> bool:
    """Check if the SPDX header is present in the first 10 lines."""
    for line in lines[:10]:
        if SPDX_MARKER in line:
            return True
    return False


def find_insertion_point(lines: list[str], path: Path) -> int:
    """Determine where to insert the header.

    Returns the line index where the header should be placed. The header
    will be inserted *before* this index, with a blank line after it.

    Special cases:
    - Shebang (#!/...) on line 0 → insert at line 1
    - Dockerfile `# syntax=` on line 0 → insert at line 1
    - Otherwise → insert at line 0
    """
    if not lines:
        return 0

    first = lines[0]

    # Shebang line — keep it on line 0, header goes after.
    if first.startswith("#!"):
        return 1

    # Dockerfile syntax directive.
    if is_dockerfile(path) and first.lower().startswith("# syntax="):
        return 1

    return 0


def insert_header(content: str, comment: str, path: Path) -> str:
    """Insert the SPDX header into file content, returning the new content."""
    header = make_header(comment)
    lines = content.splitlines(keepends=True)
    insert_at = find_insertion_point(lines, path)

    if insert_at == 0:
        # Header at top, blank line before existing content (if any).
        if lines:
            return header + "\n" + content
        return header
    else:
        # Insert after a first-line directive (shebang / # syntax=).
        before = lines[:insert_at]
        after = lines[insert_at:]
        return "".join(before) + "\n" + header + "\n" + "".join(after)


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------


def process_file(path: Path, root: Path, *, check: bool, verbose: bool) -> bool:
    """Process a single file. Returns True if the file is compliant."""
    rel = path.relative_to(root)
    comment = get_comment_style(rel)
    if comment is None:
        return True

    content = path.read_text(encoding="utf-8")
    lines = content.splitlines()

    if has_header(lines):
        if verbose:
            print(f"  ok: {rel}")
        return True

    if check:
        print(f"  MISSING: {rel}")
        return False

    # Insert the header.
    new_content = insert_header(content, comment, rel)
    path.write_text(new_content, encoding="utf-8")
    if verbose:
        print(f"  added: {rel}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Add or check SPDX license headers on source files.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check mode: exit 1 if any file is missing a header.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print status for every file processed.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Specific files to process (default: all files under repo root).",
    )
    args = parser.parse_args()

    root = find_repo_root()

    if args.paths:
        # Resolve relative paths and filter to supported + non-excluded files.
        files = []
        for p in args.paths:
            p = p.resolve()
            if not p.is_file():
                continue
            rel = p.relative_to(root)
            if is_excluded(rel):
                continue
            if get_comment_style(rel) is not None:
                files.append(p)
    else:
        files = discover_files(root)

    if args.check:
        print(f"Checking {len(files)} files for SPDX headers...")
    else:
        print(f"Processing {len(files)} files...")

    missing = []
    for f in files:
        if not process_file(f, root, check=args.check, verbose=args.verbose):
            missing.append(f)

    if args.check:
        if missing:
            print(f"\n{len(missing)} file(s) missing SPDX headers.")
            return 1
        print("All files have SPDX headers.")
        return 0

    added = len(missing)  # In non-check mode, missing list is empty; count via verbose
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
