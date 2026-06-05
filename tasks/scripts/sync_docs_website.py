#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "PyYAML==6.0.2",
# ]
# ///

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from collections.abc import MutableMapping, MutableSequence
from dataclasses import dataclass
from pathlib import Path

import yaml

SLUG_RE = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass
class VersionEntry:
    slug: str
    display_name: str
    path: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sync or remove one docs snapshot in the docs-website branch."
    )
    parser.add_argument("--operation", choices=["sync", "remove"], default="sync")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--docs-website-root", required=True, type=Path)
    parser.add_argument("--channel", required=True, choices=["dev", "latest", "version"])
    parser.add_argument("--source-ref", default="")
    parser.add_argument("--version-slug", default="")
    parser.add_argument("--display-name", default="")
    return parser.parse_args()


def clean_input(value: str | None) -> str:
    return (value or "").strip()


def resolve_slug(channel: str, version_slug: str) -> str:
    if channel == "dev":
        return "dev"
    if channel == "latest":
        return "latest"
    if not version_slug:
        raise ValueError("--version-slug is required when --channel=version")
    if not SLUG_RE.fullmatch(version_slug):
        raise ValueError(f"version slug contains unsupported characters: {version_slug}")
    return version_slug


def resolve_display_name(channel: str, slug: str, source_ref: str, override: str) -> str:
    if override:
        return override
    if channel == "dev":
        return "dev"
    if channel == "latest":
        return f"Latest ({source_ref})" if source_ref.startswith("v") else "Latest"
    return slug


def ensure_existing(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{label} does not exist: {path}")


def reset_directory(src: Path, dst: Path, *, preserve_components: bool) -> None:
    ensure_existing(src, "source directory")
    preserved_components: Path | None = None
    if preserve_components and (dst / "_components").is_dir():
        preserved_components = Path(tempfile.mkdtemp()) / "_components"
        shutil.copytree(dst / "_components", preserved_components)
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    if preserved_components is not None:
        if (dst / "_components").exists():
            shutil.rmtree(dst / "_components")
        shutil.copytree(preserved_components, dst / "_components")


def merge_directory(src: Path, dst: Path, *, overwrite: bool) -> None:
    if not src.exists():
        return
    if overwrite:
        shutil.copytree(src, dst, dirs_exist_ok=True)
        return
    for copied in src.rglob("*"):
        relative = copied.relative_to(src)
        target = dst / relative
        if copied.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(copied, target)


def copy_if_exists(src: Path, dst: Path) -> None:
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def read_yaml(path: Path) -> dict:
    ensure_existing(path, "YAML file")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected YAML mapping in {path}")
    return data


def write_yaml(path: Path, data: dict) -> None:
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def prefix_path(value: object, pages_dir: str) -> object:
    if not isinstance(value, str):
        return value
    if value.startswith(("../", "/", "http://", "https://")):
        return value
    return f"../{pages_dir}/{value}"


def prefix_navigation_paths(value: object, pages_dir: str) -> object:
    if isinstance(value, MutableMapping):
        for key in ("path", "folder"):
            if key in value:
                value[key] = prefix_path(value[key], pages_dir)
        for child in value.values():
            prefix_navigation_paths(child, pages_dir)
    elif isinstance(value, MutableSequence):
        for child in value:
            prefix_navigation_paths(child, pages_dir)
    return value


def version_navigation(source_index: Path, pages_dir: str) -> dict:
    return prefix_navigation_paths(read_yaml(source_index), pages_dir)


def parse_versions(raw_versions: object) -> list[VersionEntry]:
    if raw_versions is None:
        return []
    if not isinstance(raw_versions, list):
        raise ValueError("docs.yml versions must be a list")
    entries: list[VersionEntry] = []
    for raw in raw_versions:
        if not isinstance(raw, dict):
            continue
        slug = raw.get("slug")
        display_name = raw.get("display-name")
        path = raw.get("path")
        if isinstance(slug, str) and isinstance(display_name, str) and isinstance(path, str):
            entries.append(
                VersionEntry(slug=slug, display_name=display_name, path=path)
            )
    return entries


def ordered_entries(existing: list[VersionEntry], updated: VersionEntry) -> list[VersionEntry]:
    by_slug = {entry.slug: entry for entry in existing}
    by_slug[updated.slug] = updated
    existing_order = [entry.slug for entry in existing if entry.slug != updated.slug]

    order: list[str] = []
    for slug in ("latest", "dev"):
        if slug in by_slug:
            order.append(slug)
    for slug in existing_order:
        if slug not in order and slug in by_slug:
            order.append(slug)
    if updated.slug not in order:
        order.append(updated.slug)
    return [by_slug[slug] for slug in order]


def render_versions(entries: list[VersionEntry]) -> list[dict[str, str]]:
    return [
        {
            "display-name": entry.display_name,
            "path": entry.path,
            "slug": entry.slug,
        }
        for entry in entries
    ]


def component_dirs(fern_dir: Path) -> list[str]:
    dirs: list[str] = []
    preferred = ["pages-latest", "pages-dev"]
    all_page_dirs = sorted(path.name for path in fern_dir.glob("pages-*") if path.is_dir())
    for name in preferred + all_page_dirs:
        path = fern_dir / name / "_components"
        component = f"./{name}/_components"
        if path.is_dir() and component not in dirs:
            dirs.append(component)
    dirs.append("./components")
    return dirs


def update_docs_yml(docs_yml: Path, updated: VersionEntry, fern_dir: Path) -> None:
    data = read_yaml(docs_yml)
    data["experimental"] = {
        "mdx-components": component_dirs(fern_dir),
    }
    data["versions"] = render_versions(
        ordered_entries(parse_versions(data.get("versions")), updated)
    )
    write_yaml(docs_yml, data)


def remove_docs_yml_entry(docs_yml: Path, slug: str, fern_dir: Path) -> None:
    data = read_yaml(docs_yml)
    entries = [entry for entry in parse_versions(data.get("versions")) if entry.slug != slug]
    data["experimental"] = {
        "mdx-components": component_dirs(fern_dir),
    }
    data["versions"] = render_versions(entries)
    write_yaml(docs_yml, data)


def sync_docs(args: argparse.Namespace) -> None:
    if args.source_root is None:
        raise ValueError("--source-root is required when --operation=sync")
    source_root = args.source_root.resolve()
    docs_root = args.docs_website_root.resolve()
    source_docs = source_root / "docs"
    source_fern = source_root / "fern"
    target_fern = docs_root / "fern"

    ensure_existing(source_docs, "source docs")
    ensure_existing(source_fern, "source fern config")
    ensure_existing(target_fern, "docs website fern directory")

    channel = clean_input(args.channel)
    source_ref = clean_input(args.source_ref)
    if not source_ref:
        raise ValueError("--source-ref is required when --operation=sync")
    version_slug = clean_input(args.version_slug)
    display_override = clean_input(args.display_name)
    slug = resolve_slug(channel, version_slug)
    display_name = resolve_display_name(channel, slug, source_ref, display_override)
    pages_dir = f"pages-{slug}"
    refresh_shared = channel in {"dev", "latest"}

    reset_directory(
        source_docs,
        target_fern / pages_dir,
        preserve_components=not refresh_shared,
    )
    merge_directory(
        source_fern / "assets", target_fern / "assets", overwrite=refresh_shared
    )
    merge_directory(
        source_fern / "components", target_fern / "components", overwrite=refresh_shared
    )
    if refresh_shared:
        copy_if_exists(source_fern / "main.css", target_fern / "main.css")
        copy_if_exists(source_fern / "fern.config.json", target_fern / "fern.config.json")

    versions_dir = target_fern / "versions"
    versions_dir.mkdir(parents=True, exist_ok=True)
    write_yaml(
        versions_dir / f"{slug}.yml",
        version_navigation(source_docs / "index.yml", pages_dir),
    )

    update_docs_yml(
        target_fern / "docs.yml",
        VersionEntry(
            slug=slug,
            display_name=display_name,
            path=f"./versions/{slug}.yml",
        ),
        target_fern,
    )

    print(
        f"Synced {channel} docs from {source_ref} to fern/{pages_dir} "
        f"({display_name})"
    )


def remove_docs(args: argparse.Namespace) -> None:
    docs_root = args.docs_website_root.resolve()
    target_fern = docs_root / "fern"

    ensure_existing(target_fern, "docs website fern directory")

    channel = clean_input(args.channel)
    version_slug = clean_input(args.version_slug)
    slug = resolve_slug(channel, version_slug)

    pages_dir = target_fern / f"pages-{slug}"
    if pages_dir.exists():
        shutil.rmtree(pages_dir)

    version_file = target_fern / "versions" / f"{slug}.yml"
    if version_file.exists():
        version_file.unlink()

    remove_docs_yml_entry(target_fern / "docs.yml", slug, target_fern)

    print(f"Removed {slug} docs from docs website branch")


def main() -> None:
    try:
        args = parse_args()
        if args.operation == "sync":
            sync_docs(args)
        else:
            remove_docs(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
