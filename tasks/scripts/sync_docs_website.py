#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "packaging==25.0",
#   "PyYAML==6.0.2",
# ]
# ///

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import yaml
from packaging.version import InvalidVersion, Version

SLUG_RE = re.compile(r"^[A-Za-z0-9._-]+$")
DISPLAY_VERSION_RE = re.compile(r"\bv?(\d+\.\d+\.\d+(?:[.-]?[A-Za-z0-9]+)*)\b")
VERSION_AVAILABILITIES = {"beta", "deprecated", "ga", "stable"}
SNAPSHOT_METADATA_FILE = ".docs-snapshots.yml"
YamlMapping = dict[str, object]


@dataclass
class VersionEntry:
    slug: str
    display_name: str
    path: str
    availability: str | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sync or remove docs snapshots in the docs-website branch."
    )
    parser.add_argument("--operation", choices=["sync", "remove"], default="sync")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--docs-website-root", required=True, type=Path)
    parser.add_argument(
        "--channel", required=True, choices=["dev", "latest", "stable", "version"]
    )
    parser.add_argument("--source-ref", default="")
    parser.add_argument("--release-version", default="")
    parser.add_argument("--version-slug", default="")
    parser.add_argument("--display-name", default="")
    parser.add_argument("--availability", default="")
    parser.add_argument("--allow-rollback", action="store_true")
    return parser.parse_args()


def clean_input(value: str | None) -> str:
    return (value or "").strip()


def resolve_slug(channel: str, version_slug: str) -> str:
    if channel == "dev":
        return "dev"
    if channel == "latest":
        return "latest"
    if not version_slug:
        raise ValueError(
            "--version-slug is required when --channel=stable or --channel=version"
        )
    if not SLUG_RE.fullmatch(version_slug):
        raise ValueError(
            f"version slug contains unsupported characters: {version_slug}"
        )
    return version_slug


def resolve_display_name(
    channel: str, slug: str, source_ref: str, override: str
) -> str:
    if override:
        return override
    if channel == "dev":
        return "dev"
    if channel == "latest":
        return f"Latest ({source_ref})" if source_ref.startswith("v") else "Latest"
    return slug


def resolve_availability(channel: str, override: str) -> str | None:
    availability = override or ("beta" if channel == "dev" else "")
    if not availability:
        return None
    if availability not in VERSION_AVAILABILITIES:
        supported = ", ".join(sorted(VERSION_AVAILABILITIES))
        raise ValueError(
            f"unsupported version availability {availability!r}; expected one of: {supported}"
        )
    return availability


def parse_release_version(value: str) -> Version:
    try:
        return Version(value.removeprefix("v"))
    except InvalidVersion as exc:
        raise ValueError(f"invalid release version: {value}") from exc


def default_stable_availability(release_version: str) -> str | None:
    if parse_release_version(release_version) >= Version("0.1.0"):
        return "stable"
    return None


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


def read_yaml(path: Path) -> YamlMapping:
    ensure_existing(path, "YAML file")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected YAML mapping in {path}")
    return cast("YamlMapping", data)


def write_yaml(path: Path, data: YamlMapping) -> None:
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def read_snapshot_metadata(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    data = read_yaml(path)
    raw_snapshots = data.get("snapshots")
    if raw_snapshots is None:
        return {}
    if not isinstance(raw_snapshots, dict):
        raise ValueError(f"expected snapshots mapping in {path}")

    snapshots: dict[str, dict[str, str]] = {}
    for raw_slug, raw_snapshot in raw_snapshots.items():
        if not isinstance(raw_slug, str) or not isinstance(raw_snapshot, dict):
            raise ValueError(f"invalid snapshot metadata in {path}")
        snapshot = cast("YamlMapping", raw_snapshot)
        source_ref = snapshot.get("source-ref")
        version = snapshot.get("version")
        if not isinstance(source_ref, str) or not isinstance(version, str):
            raise ValueError(f"invalid snapshot metadata for {raw_slug} in {path}")
        snapshots[raw_slug] = {"source-ref": source_ref, "version": version}
    return snapshots


def write_snapshot_metadata(path: Path, snapshots: dict[str, dict[str, str]]) -> None:
    write_yaml(path, {"snapshots": snapshots})


def seed_mutable_snapshot_metadata(
    snapshots: dict[str, dict[str, str]], docs_yml: Path, slug: str
) -> None:
    if slug in snapshots:
        return
    data = read_yaml(docs_yml)
    for entry in parse_versions(data.get("versions")):
        if entry.slug != slug:
            continue
        match = DISPLAY_VERSION_RE.search(entry.display_name)
        if match is not None:
            snapshots[slug] = {
                "source-ref": "",
                "version": str(parse_release_version(match.group(1))),
            }
        return


def ensure_immutable_snapshot(
    snapshots: dict[str, dict[str, str]],
    target_fern: Path,
    slug: str,
    source_ref: str,
) -> None:
    existing = snapshots.get(slug)
    if existing is not None:
        if existing["source-ref"] != source_ref:
            raise ValueError(
                f"immutable snapshot {slug} already points to "
                f"{existing['source-ref']}, not {source_ref}"
            )
        return
    if (target_fern / f"pages-{slug}").exists():
        raise ValueError(
            f"immutable snapshot {slug} already exists without source metadata"
        )


def ensure_monotonic_snapshot(
    snapshots: dict[str, dict[str, str]],
    slug: str,
    source_ref: str,
    release_version: str,
    *,
    allow_rollback: bool,
) -> bool:
    existing = snapshots.get(slug)
    if existing is None:
        return True

    incoming_version = parse_release_version(release_version)
    existing_version = parse_release_version(existing["version"])
    if incoming_version < existing_version and not allow_rollback:
        return False
    if (
        incoming_version == existing_version
        and bool(existing["source-ref"])
        and existing["source-ref"] != source_ref
        and not allow_rollback
    ):
        raise ValueError(
            f"snapshot {slug} version {release_version} already points to "
            f"{existing['source-ref']}, not {source_ref}"
        )
    return True


def prefix_path(value: object, pages_dir: str) -> object:
    if not isinstance(value, str):
        return value
    if value.startswith(("../", "/", "http://", "https://")):
        return value
    return f"../{pages_dir}/{value}"


def prefix_navigation_paths(value: object, pages_dir: str) -> object:
    if isinstance(value, dict):
        mapping = cast("YamlMapping", value)
        for key in ("path", "folder"):
            if key in mapping:
                mapping[key] = prefix_path(mapping[key], pages_dir)
        for child in mapping.values():
            prefix_navigation_paths(child, pages_dir)
    elif isinstance(value, list):
        for child in cast("list[object]", value):
            prefix_navigation_paths(child, pages_dir)
    return value


def version_navigation(source_index: Path, pages_dir: str) -> YamlMapping:
    data = read_yaml(source_index)
    prefix_navigation_paths(data, pages_dir)
    return data


def parse_versions(raw_versions: object) -> list[VersionEntry]:
    if raw_versions is None:
        return []
    if not isinstance(raw_versions, list):
        raise ValueError("docs.yml versions must be a list")
    entries: list[VersionEntry] = []
    for raw in cast("list[object]", raw_versions):
        if not isinstance(raw, dict):
            continue
        entry = cast("YamlMapping", raw)
        slug = entry.get("slug")
        display_name = entry.get("display-name")
        path = entry.get("path")
        availability = entry.get("availability")
        if (
            isinstance(slug, str)
            and isinstance(display_name, str)
            and isinstance(path, str)
        ):
            entries.append(
                VersionEntry(
                    slug=slug,
                    display_name=display_name,
                    path=path,
                    availability=availability
                    if isinstance(availability, str)
                    else None,
                )
            )
    return entries


def ordered_entries(
    existing: list[VersionEntry], updated: VersionEntry
) -> list[VersionEntry]:
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
    rendered: list[dict[str, str]] = []
    for entry in entries:
        item = {
            "display-name": entry.display_name,
            "path": entry.path,
            "slug": entry.slug,
        }
        if entry.availability is not None:
            item["availability"] = entry.availability
        rendered.append(item)
    return rendered


def component_dirs(fern_dir: Path) -> list[str]:
    dirs: list[str] = []
    preferred = ["pages-latest", "pages-dev"]
    all_page_dirs = sorted(
        path.name for path in fern_dir.glob("pages-*") if path.is_dir()
    )
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


def write_snapshot(
    source_docs: Path,
    source_fern: Path,
    target_fern: Path,
    entry: VersionEntry,
    *,
    refresh_shared: bool,
) -> None:
    pages_dir = f"pages-{entry.slug}"
    reset_directory(
        source_docs,
        target_fern / pages_dir,
        preserve_components=not refresh_shared,
    )
    if refresh_shared:
        merge_directory(source_fern / "assets", target_fern / "assets", overwrite=True)
        merge_directory(
            source_fern / "components", target_fern / "components", overwrite=True
        )
        copy_if_exists(source_fern / "main.css", target_fern / "main.css")
        copy_if_exists(
            source_fern / "fern.config.json", target_fern / "fern.config.json"
        )

    versions_dir = target_fern / "versions"
    versions_dir.mkdir(parents=True, exist_ok=True)
    write_yaml(
        versions_dir / f"{entry.slug}.yml",
        version_navigation(source_docs / "index.yml", pages_dir),
    )
    update_docs_yml(target_fern / "docs.yml", entry, target_fern)


def remove_docs_yml_entry(docs_yml: Path, slug: str, fern_dir: Path) -> None:
    data = read_yaml(docs_yml)
    entries = [
        entry for entry in parse_versions(data.get("versions")) if entry.slug != slug
    ]
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
    release_version = clean_input(getattr(args, "release_version", ""))
    version_slug = clean_input(args.version_slug)
    display_override = clean_input(args.display_name)
    availability_override = clean_input(args.availability)
    if channel in {"dev", "latest", "stable"} and not release_version:
        raise ValueError(
            "--release-version is required for dev, latest, and stable channels"
        )
    slug = resolve_slug(channel, version_slug)
    display_name = resolve_display_name(channel, slug, source_ref, display_override)
    availability = resolve_availability(channel, availability_override)
    metadata_path = target_fern / SNAPSHOT_METADATA_FILE
    snapshots = read_snapshot_metadata(metadata_path)
    docs_yml = target_fern / "docs.yml"

    if channel == "stable":
        parsed_version = parse_release_version(release_version)
        expected_slug = f"v{parsed_version}"
        if slug != expected_slug:
            raise ValueError(f"stable version slug must be {expected_slug}, got {slug}")
        ensure_immutable_snapshot(snapshots, target_fern, slug, source_ref)
        stable_availability = availability or default_stable_availability(
            release_version
        )
        write_snapshot(
            source_docs,
            source_fern,
            target_fern,
            VersionEntry(
                slug=slug,
                display_name=slug,
                path=f"./versions/{slug}.yml",
                availability=stable_availability,
            ),
            refresh_shared=False,
        )
        snapshots[slug] = {
            "source-ref": source_ref,
            "version": str(parsed_version),
        }

        seed_mutable_snapshot_metadata(snapshots, docs_yml, "latest")
        if ensure_monotonic_snapshot(
            snapshots,
            "latest",
            source_ref,
            release_version,
            allow_rollback=bool(getattr(args, "allow_rollback", False)),
        ):
            write_snapshot(
                source_docs,
                source_fern,
                target_fern,
                VersionEntry(
                    slug="latest",
                    display_name=display_override or f"Latest ({slug})",
                    path="./versions/latest.yml",
                    availability=stable_availability,
                ),
                refresh_shared=False,
            )
            snapshots["latest"] = {
                "source-ref": source_ref,
                "version": str(parsed_version),
            }
        write_snapshot_metadata(metadata_path, snapshots)
        print(f"Synced immutable {slug} docs from {source_ref}")
        return

    if channel in {"dev", "latest"}:
        seed_mutable_snapshot_metadata(snapshots, docs_yml, slug)
        if not ensure_monotonic_snapshot(
            snapshots,
            slug,
            source_ref,
            release_version,
            allow_rollback=bool(getattr(args, "allow_rollback", False)),
        ):
            print(
                f"Skipped stale {slug} docs {release_version}; "
                f"current version is {snapshots[slug]['version']}"
            )
            return
    else:
        ensure_immutable_snapshot(snapshots, target_fern, slug, source_ref)
        release_version = release_version or slug.removeprefix("v")

    write_snapshot(
        source_docs,
        source_fern,
        target_fern,
        VersionEntry(
            slug=slug,
            display_name=display_name,
            path=f"./versions/{slug}.yml",
            availability=availability,
        ),
        refresh_shared=channel == "dev",
    )
    snapshots[slug] = {
        "source-ref": source_ref,
        "version": release_version,
    }
    write_snapshot_metadata(metadata_path, snapshots)

    print(f"Synced {channel} docs from {source_ref} to fern/pages-{slug}")


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
    metadata_path = target_fern / SNAPSHOT_METADATA_FILE
    snapshots = read_snapshot_metadata(metadata_path)
    if slug in snapshots:
        del snapshots[slug]
        write_snapshot_metadata(metadata_path, snapshots)

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
