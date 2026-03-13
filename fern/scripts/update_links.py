#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Update internal links: .md -> Fern paths, relative paths -> absolute."""

import argparse
import re
from pathlib import Path


def normalize_url(url: str) -> str:
    """Normalize a URL to Fern path format."""
    clean = url.replace(".md", "").replace(".mdx", "")
    if url.startswith(("http://", "https://", "#", "mailto:")):
        return url
    # Normalize asset paths to /assets/
    if "assets/" in clean or clean.startswith("./assets") or clean.startswith("../assets"):
        clean = "/assets/" + clean.split("assets/")[-1]
    # Normalize images/ to /assets/images/
    elif "images/" in clean or clean.startswith("./images") or clean.startswith("../images"):
        img_name = clean.split("images/")[-1] if "images/" in clean else clean.split("/")[-1]
        clean = "/assets/images/" + img_name
    # Repo root images
    elif clean.endswith(".png") and "/" not in clean:
        clean = "/assets/" + clean
    elif not clean.startswith("/"):
        clean = "/" + clean
    return clean


def update_links_in_content(content: str, file_dir: Path, pages_root: Path) -> str:
    """Update markdown links and image paths: .md/.mdx -> Fern paths."""

    def replace_link(match: re.Match[str]) -> str:
        text, url = match.group(1), match.group(2)
        clean = normalize_url(url)
        return f"[{text}]({clean})"

    def replace_image(match: re.Match[str]) -> str:
        alt, url = match.group(1), match.group(2)
        clean = normalize_url(url)
        return f"![{alt}]({clean})"

    # Process images first, then links (negative lookbehind avoids matching images)
    content = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", replace_image, content)
    content = re.sub(r"(?<!!)\[([^\]]*)\]\(([^)]+)\)", replace_link, content)
    return content


def update_file(filepath: Path, pages_root: Path) -> bool:
    """Update links in a single file. Returns True if changes were made."""
    content = filepath.read_text()
    file_dir = filepath.parent
    new_content = update_links_in_content(content, file_dir, pages_root)

    if new_content != content:
        filepath.write_text(new_content)
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Update internal links in MDX files"
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
        if update_file(mdx_file, pages_dir):
            changed.append(mdx_file.relative_to(pages_dir))
            print(f"  Updated: {mdx_file.relative_to(pages_dir)}")

    print(f"\nUpdated {len(changed)} files")


if __name__ == "__main__":
    main()
