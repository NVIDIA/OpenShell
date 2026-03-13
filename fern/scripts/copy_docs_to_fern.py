#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Copy docs/*.md to fern/<version>/pages/*.mdx preserving directory structure."""

import argparse
import shutil
from pathlib import Path

SKIP_FILES = {
    "conf.py",
    "Makefile",
    "helpers.py",
    "versions1.json",
    "project.json",
}
SKIP_DIRS = {"_templates", "_build", "_ext", ".venv", ".git", "__pycache__"}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Copy docs/*.md to fern/<version>/pages/*.mdx"
    )
    parser.add_argument(
        "version",
        help="Version folder name (e.g. v0.1.0)",
    )
    parser.add_argument(
        "--docs-dir",
        default="docs",
        help="Source docs directory (default: docs)",
    )
    parser.add_argument(
        "--fern-dir",
        default="fern",
        help="Fern root directory (default: fern)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent.parent
    docs_dir = repo_root / args.docs_dir
    fern_dir = repo_root / args.fern_dir
    pages_dir = fern_dir / args.version / "pages"

    if not docs_dir.exists():
        raise SystemExit(f"Error: docs directory not found at {docs_dir}")

    pages_dir.mkdir(parents=True, exist_ok=True)

    # Copy docs/assets to fern/assets if they exist
    docs_assets = docs_dir / "assets"
    fern_assets = fern_dir / "assets"
    if docs_assets.exists():
        for asset in docs_assets.rglob("*"):
            if asset.is_file():
                rel = asset.relative_to(docs_assets)
                dst = fern_assets / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(asset, dst)
        print(f"Copied assets from {docs_assets} to {fern_assets}")

    # Copy docs/images to fern/assets/images if they exist
    fern_images = fern_assets / "images"
    fern_images.mkdir(parents=True, exist_ok=True)

    docs_images = docs_dir / "images"
    if docs_images.exists():
        for img in docs_images.iterdir():
            if img.is_file():
                shutil.copy2(img, fern_images / img.name)
        print(f"Copied docs/images to {fern_images}")

    # Copy images from docs subdirs (e.g. docs/sandboxes/*.png)
    for ext in ["*.png", "*.jpg", "*.jpeg", "*.gif", "*.svg"]:
        for img_file in docs_dir.rglob(ext):
            if img_file.is_file() and not any(part in SKIP_DIRS for part in img_file.parts):
                shutil.copy2(img_file, fern_images / img_file.name)
                print(f"Copied {img_file.relative_to(docs_dir)} to {fern_images}")

    copied = 0
    for md_file in docs_dir.rglob("*.md"):
        rel = md_file.relative_to(docs_dir)

        if rel.name in SKIP_FILES:
            continue
        if any(part in SKIP_DIRS or part.startswith(".") for part in rel.parts):
            continue

        mdx_path = pages_dir / rel.with_suffix(".mdx")
        mdx_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(md_file, mdx_path)
        copied += 1
        print(f"  {rel} -> {args.version}/pages/{rel.with_suffix('.mdx')}")

    print(f"\nCopied {copied} files to {pages_dir}")


if __name__ == "__main__":
    main()
