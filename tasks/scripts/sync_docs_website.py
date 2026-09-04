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
    ref: str | None = None
    path: str | None = None
    availability: str | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Update the git-ref version manifest on the docs-website branch."
    )
    parser.add_argument("--operation", choices=["sync", "remove"], default="sync")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--docs-website-root", required=True, type=Path)
    parser.add_argument(
        "--channel", required=True, choices=["dev", "latest", "stable", "version"]
    )
    parser.add_argument("--source-ref", default="")
    parser.add_argument("--source-sha", default="")
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


def reset_directory(src: Path, dst: Path) -> None:
    ensure_existing(src, "source directory")
    if dst.exists():
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst)


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
        source_sha = snapshot.get("source-sha", "")
        version = snapshot.get("version")
        if (
            not isinstance(source_ref, str)
            or not isinstance(source_sha, str)
            or not isinstance(version, str)
        ):
            raise ValueError(f"invalid snapshot metadata for {raw_slug} in {path}")
        snapshots[raw_slug] = {
            "source-ref": source_ref,
            "source-sha": source_sha,
            "version": version,
        }
    return snapshots


def write_snapshot_metadata(path: Path, snapshots: dict[str, dict[str, str]]) -> None:
    write_yaml(path, {"snapshots": snapshots})


def parse_versions(raw_versions: object) -> list[VersionEntry]:
    if raw_versions is None:
        return []
    if not isinstance(raw_versions, list):
        raise ValueError("docs.yml versions must be a list")

    entries: list[VersionEntry] = []
    for raw in cast("list[object]", raw_versions):
        if not isinstance(raw, dict):
            raise ValueError("docs.yml version entries must be mappings")
        entry = cast("YamlMapping", raw)
        slug = entry.get("slug")
        display_name = entry.get("display-name")
        ref = entry.get("ref")
        path = entry.get("path")
        availability = entry.get("availability")
        if not isinstance(slug, str) or not isinstance(display_name, str):
            raise ValueError("docs.yml version entries require slug and display-name")
        if (ref is None) == (path is None):
            raise ValueError(
                f"docs.yml version {slug} must set exactly one of ref or path"
            )
        if ref is not None and not isinstance(ref, str):
            raise ValueError(f"docs.yml version {slug} ref must be a string")
        if path is not None and not isinstance(path, str):
            raise ValueError(f"docs.yml version {slug} path must be a string")
        if availability is not None and not isinstance(availability, str):
            raise ValueError(f"docs.yml version {slug} availability must be a string")
        entries.append(
            VersionEntry(
                slug=slug,
                display_name=display_name,
                ref=cast("str | None", ref),
                path=cast("str | None", path),
                availability=cast("str | None", availability),
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
        item = {"display-name": entry.display_name}
        if entry.ref is not None:
            item["ref"] = entry.ref
        elif entry.path is not None:
            item["path"] = entry.path
        else:
            raise ValueError(f"version {entry.slug} has no content source")
        item["slug"] = entry.slug
        if entry.availability is not None:
            item["availability"] = entry.availability
        rendered.append(item)
    return rendered


def infer_legacy_ref(entry: VersionEntry) -> str | None:
    if entry.ref is not None:
        return entry.ref
    if entry.slug == "latest":
        match = DISPLAY_VERSION_RE.search(entry.display_name)
        return f"v{match.group(1)}" if match is not None else None
    if entry.slug.startswith("v"):
        try:
            parse_release_version(entry.slug)
        except ValueError:
            return None
        return entry.slug
    return None


def remove_local_snapshot(target_fern: Path, slug: str) -> None:
    pages_dir = target_fern / f"pages-{slug}"
    if pages_dir.exists():
        shutil.rmtree(pages_dir)
    version_file = target_fern / "versions" / f"{slug}.yml"
    if version_file.exists():
        version_file.unlink()
    versions_dir = target_fern / "versions"
    if versions_dir.is_dir() and not any(versions_dir.iterdir()):
        versions_dir.rmdir()


def migrate_legacy_entries(
    entries: list[VersionEntry], target_fern: Path
) -> list[VersionEntry]:
    migrated: list[VersionEntry] = []
    for entry in entries:
        inferred_ref = infer_legacy_ref(entry)
        if entry.path is None or inferred_ref is None:
            migrated.append(entry)
            continue
        migrated.append(
            VersionEntry(
                slug=entry.slug,
                display_name=entry.display_name,
                ref=inferred_ref,
                availability=entry.availability,
            )
        )
        remove_local_snapshot(target_fern, entry.slug)
    return migrated


def seed_snapshot_metadata(
    snapshots: dict[str, dict[str, str]], entries: list[VersionEntry]
) -> None:
    for entry in entries:
        if entry.slug in snapshots:
            continue
        match = DISPLAY_VERSION_RE.search(entry.display_name)
        if match is None:
            continue
        snapshots[entry.slug] = {
            "source-ref": infer_legacy_ref(entry) or "",
            "source-sha": "",
            "version": str(parse_release_version(match.group(1))),
        }


def ensure_immutable_version(
    snapshots: dict[str, dict[str, str]],
    entries: list[VersionEntry],
    slug: str,
    source_ref: str,
    source_sha: str,
) -> None:
    existing = snapshots.get(slug)
    if existing is not None:
        existing_sha = existing["source-sha"]
        if existing_sha and existing_sha != source_sha:
            raise ValueError(
                f"immutable version {slug} already points to {existing_sha}, not {source_sha}"
            )
        existing_ref = existing["source-ref"]
        if existing_ref and existing_ref != source_ref:
            raise ValueError(
                f"immutable version {slug} already uses ref {existing_ref}, not {source_ref}"
            )

    existing_entry = next((entry for entry in entries if entry.slug == slug), None)
    if existing_entry is not None:
        existing_ref = infer_legacy_ref(existing_entry)
        if existing_ref != source_ref:
            raise ValueError(
                f"immutable version {slug} already uses ref {existing_ref}, not {source_ref}"
            )


def ensure_monotonic_snapshot(
    snapshots: dict[str, dict[str, str]],
    slug: str,
    source_sha: str,
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
        and bool(existing["source-sha"])
        and existing["source-sha"] != source_sha
        and not allow_rollback
    ):
        raise ValueError(
            f"version {slug} {release_version} already points to "
            f"{existing['source-sha']}, not {source_sha}"
        )
    return True


def normalize_manifest_components(data: YamlMapping) -> None:
    raw_experimental = data.get("experimental")
    experimental = (
        cast("YamlMapping", raw_experimental)
        if isinstance(raw_experimental, dict)
        else {}
    )
    experimental["mdx-components"] = ["../docs/_components", "./components"]
    data["experimental"] = experimental


def refresh_shared_fern(
    source_fern: Path, target_fern: Path, entries: list[VersionEntry]
) -> None:
    data = read_yaml(source_fern / "docs.yml")
    data["versions"] = render_versions(entries)
    normalize_manifest_components(data)
    write_yaml(target_fern / "docs.yml", data)

    for directory in ("assets", "components"):
        source_dir = source_fern / directory
        if source_dir.exists():
            reset_directory(source_dir, target_fern / directory)

    source_mdx_components = source_fern.parent / "docs" / "_components"
    target_mdx_components = target_fern.parent / "docs" / "_components"
    if source_mdx_components.exists():
        reset_directory(source_mdx_components, target_mdx_components)
    elif target_mdx_components.exists():
        shutil.rmtree(target_mdx_components)

    copy_if_exists(source_fern / "main.css", target_fern / "main.css")
    copy_if_exists(source_fern / "fern.config.json", target_fern / "fern.config.json")


def write_manifest(target_fern: Path, entries: list[VersionEntry]) -> None:
    docs_yml = target_fern / "docs.yml"
    data = read_yaml(docs_yml)
    data["versions"] = render_versions(entries)
    normalize_manifest_components(data)
    write_yaml(docs_yml, data)


def sync_docs(args: argparse.Namespace) -> None:
    if args.source_root is None:
        raise ValueError("--source-root is required when --operation=sync")
    source_root = args.source_root.resolve()
    docs_root = args.docs_website_root.resolve()
    source_fern = source_root / "fern"
    target_fern = docs_root / "fern"

    ensure_existing(source_fern / "docs.yml", "source Fern docs config")
    ensure_existing(target_fern / "docs.yml", "docs website Fern docs config")

    channel = clean_input(args.channel)
    source_ref = clean_input(args.source_ref)
    source_sha = clean_input(getattr(args, "source_sha", ""))
    release_version = clean_input(getattr(args, "release_version", ""))
    version_slug = clean_input(args.version_slug)
    display_override = clean_input(args.display_name)
    availability_override = clean_input(args.availability)
    allow_rollback = bool(getattr(args, "allow_rollback", False))

    if not source_ref:
        raise ValueError("--source-ref is required when --operation=sync")
    if not source_sha:
        raise ValueError("--source-sha is required when --operation=sync")
    if channel in {"dev", "latest", "stable"} and not release_version:
        raise ValueError(
            "--release-version is required for dev, latest, and stable channels"
        )

    slug = resolve_slug(channel, version_slug)
    display_name = resolve_display_name(channel, slug, source_ref, display_override)
    availability = resolve_availability(channel, availability_override)
    docs_yml = target_fern / "docs.yml"
    metadata_path = target_fern / SNAPSHOT_METADATA_FILE
    entries = parse_versions(read_yaml(docs_yml).get("versions"))
    snapshots = read_snapshot_metadata(metadata_path)
    seed_snapshot_metadata(snapshots, entries)

    if channel in {"dev", "latest"} and not ensure_monotonic_snapshot(
        snapshots,
        slug,
        source_sha,
        release_version,
        allow_rollback=allow_rollback,
    ):
        print(
            f"Skipped stale {slug} docs {release_version}; "
            f"current version is {snapshots[slug]['version']}"
        )
        return

    entries = migrate_legacy_entries(entries, target_fern)

    if channel == "stable":
        parsed_version = parse_release_version(release_version)
        expected_slug = f"v{parsed_version}"
        if slug != expected_slug:
            raise ValueError(f"stable version slug must be {expected_slug}, got {slug}")
        if source_ref != slug:
            raise ValueError(f"stable source ref must be tag {slug}, got {source_ref}")
        ensure_immutable_version(snapshots, entries, slug, source_ref, source_sha)
        stable_availability = availability or default_stable_availability(
            release_version
        )
        entries = ordered_entries(
            entries,
            VersionEntry(
                slug=slug,
                display_name=slug,
                ref=source_ref,
                availability=stable_availability,
            ),
        )
        snapshots[slug] = {
            "source-ref": source_ref,
            "source-sha": source_sha,
            "version": str(parsed_version),
        }
        remove_local_snapshot(target_fern, slug)

        if ensure_monotonic_snapshot(
            snapshots,
            "latest",
            source_sha,
            release_version,
            allow_rollback=allow_rollback,
        ):
            entries = ordered_entries(
                entries,
                VersionEntry(
                    slug="latest",
                    display_name=display_override or f"Latest ({slug})",
                    ref=source_ref,
                    availability=stable_availability,
                ),
            )
            snapshots["latest"] = {
                "source-ref": source_ref,
                "source-sha": source_sha,
                "version": str(parsed_version),
            }
            remove_local_snapshot(target_fern, "latest")
        write_manifest(target_fern, entries)
        write_snapshot_metadata(metadata_path, snapshots)
        print(f"Registered immutable {slug} docs from {source_ref}")
        return

    if channel == "version":
        ensure_immutable_version(snapshots, entries, slug, source_ref, source_sha)
        release_version = release_version or slug.removeprefix("v")

    content_ref = source_sha
    entries = ordered_entries(
        entries,
        VersionEntry(
            slug=slug,
            display_name=display_name,
            ref=content_ref,
            availability=availability,
        ),
    )
    snapshots[slug] = {
        "source-ref": source_ref,
        "source-sha": source_sha,
        "version": release_version,
    }
    remove_local_snapshot(target_fern, slug)

    if channel == "dev":
        refresh_shared_fern(source_fern, target_fern, entries)
    else:
        write_manifest(target_fern, entries)
    write_snapshot_metadata(metadata_path, snapshots)
    print(f"Registered {channel} docs from {content_ref}")


def remove_docs(args: argparse.Namespace) -> None:
    docs_root = args.docs_website_root.resolve()
    target_fern = docs_root / "fern"
    docs_yml = target_fern / "docs.yml"
    ensure_existing(docs_yml, "docs website Fern docs config")

    slug = resolve_slug(clean_input(args.channel), clean_input(args.version_slug))
    entries = migrate_legacy_entries(
        parse_versions(read_yaml(docs_yml).get("versions")), target_fern
    )
    entries = [entry for entry in entries if entry.slug != slug]
    remove_local_snapshot(target_fern, slug)
    write_manifest(target_fern, entries)

    metadata_path = target_fern / SNAPSHOT_METADATA_FILE
    snapshots = read_snapshot_metadata(metadata_path)
    snapshots.pop(slug, None)
    write_snapshot_metadata(metadata_path, snapshots)
    print(f"Removed {slug} docs from the version manifest")


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
