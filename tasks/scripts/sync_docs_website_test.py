# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for tasks/scripts/sync_docs_website.py.

Run via `mise run test:docs-website`, which provides pytest + PyYAML through
`uv run --with ...`. pytest puts this file's directory on sys.path, so the
sibling script imports directly as `sync_docs_website`.
"""

from __future__ import annotations

from argparse import Namespace
from typing import TYPE_CHECKING

import pytest
import sync_docs_website as sdw
import yaml

if TYPE_CHECKING:
    from pathlib import Path


def read_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_resolve_slug_channels() -> None:
    assert sdw.resolve_slug("dev", "") == "dev"
    assert sdw.resolve_slug("latest", "") == "latest"
    assert sdw.resolve_slug("version", "v0.0.36") == "v0.0.36"


def test_resolve_slug_version_requires_slug() -> None:
    with pytest.raises(ValueError):
        sdw.resolve_slug("version", "")


def test_resolve_slug_rejects_unsafe_characters() -> None:
    # Guards the slug that becomes a directory name (pages-<slug>).
    with pytest.raises(ValueError):
        sdw.resolve_slug("version", "../escape")
    with pytest.raises(ValueError):
        sdw.resolve_slug("version", "v1 0")


def test_resolve_display_name() -> None:
    assert sdw.resolve_display_name("dev", "dev", "main", "") == "dev"
    assert (
        sdw.resolve_display_name("latest", "latest", "v0.0.57", "")
        == "Latest (v0.0.57)"
    )
    assert sdw.resolve_display_name("latest", "latest", "abc123", "") == "Latest"
    assert sdw.resolve_display_name("version", "v0.0.36", "v0.0.36", "") == "v0.0.36"
    assert sdw.resolve_display_name("dev", "dev", "main", "Custom") == "Custom"


def test_ordered_entries_pins_latest_then_dev() -> None:
    existing = [
        sdw.VersionEntry("v0.0.36", "v0.0.36", "./versions/v0.0.36.yml"),
        sdw.VersionEntry("dev", "dev", "./versions/dev.yml"),
    ]
    updated = sdw.VersionEntry("latest", "Latest", "./versions/latest.yml")
    ordered = [entry.slug for entry in sdw.ordered_entries(existing, updated)]
    assert ordered == ["latest", "dev", "v0.0.36"]


def test_prefix_navigation_paths() -> None:
    nav = {
        "navigation": [
            {"page": "Intro", "path": "intro.mdx"},
            {
                "section": "Guide",
                "folder": "guide",
                "contents": [{"path": "guide/a.mdx"}],
            },
            {"page": "External", "path": "https://example.com"},
        ]
    }
    sdw.prefix_navigation_paths(nav, "pages-dev")
    assert nav["navigation"][0]["path"] == "../pages-dev/intro.mdx"
    assert nav["navigation"][1]["folder"] == "../pages-dev/guide"
    assert nav["navigation"][1]["contents"][0]["path"] == "../pages-dev/guide/a.mdx"
    # Absolute URLs are left untouched.
    assert nav["navigation"][2]["path"] == "https://example.com"


def _make_source_tree(root: Path) -> None:
    docs = root / "docs"
    docs.mkdir(parents=True)
    (docs / "intro.mdx").write_text("# Intro\n", encoding="utf-8")
    (docs / "index.yml").write_text(
        yaml.safe_dump({"navigation": [{"page": "Intro", "path": "intro.mdx"}]}),
        encoding="utf-8",
    )
    fern = root / "fern"
    (fern / "assets").mkdir(parents=True)
    (fern / "assets" / "logo.svg").write_text("<svg/>", encoding="utf-8")
    (fern / "components").mkdir(parents=True)
    (fern / "components" / "Card.tsx").write_text(
        "export const Card = 1;\n", encoding="utf-8"
    )
    (fern / "main.css").write_text("body{}\n", encoding="utf-8")
    (fern / "fern.config.json").write_text('{"version": "0.0.0"}\n', encoding="utf-8")


def _make_docs_website_tree(root: Path) -> None:
    fern = root / "fern"
    fern.mkdir(parents=True)
    (fern / "docs.yml").write_text(yaml.safe_dump({"versions": []}), encoding="utf-8")


def test_sync_docs_creates_snapshot(tmp_path: Path) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)

    sdw.sync_docs(
        Namespace(
            operation="sync",
            source_root=source,
            docs_website_root=website,
            channel="dev",
            source_ref="main",
            version_slug="",
            display_name="",
        )
    )

    fern = website / "fern"
    assert (fern / "pages-dev" / "intro.mdx").is_file()
    assert (fern / "assets" / "logo.svg").is_file()

    version_nav = read_yaml(fern / "versions" / "dev.yml")
    assert version_nav["navigation"][0]["path"] == "../pages-dev/intro.mdx"

    docs_yml = read_yaml(fern / "docs.yml")
    slugs = [entry["slug"] for entry in docs_yml["versions"]]
    assert slugs == ["dev"]
    assert docs_yml["versions"][0]["path"] == "./versions/dev.yml"
    assert "./components" in docs_yml["experimental"]["mdx-components"]


def test_remove_docs_drops_snapshot(tmp_path: Path) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)

    base = Namespace(
        operation="sync",
        source_root=source,
        docs_website_root=website,
        channel="version",
        source_ref="v0.0.36",
        version_slug="v0.0.36",
        display_name="",
    )
    sdw.sync_docs(base)

    fern = website / "fern"
    assert (fern / "pages-v0.0.36").is_dir()
    assert (fern / "versions" / "v0.0.36.yml").is_file()

    sdw.remove_docs(
        Namespace(
            operation="remove",
            source_root=None,
            docs_website_root=website,
            channel="version",
            source_ref="",
            version_slug="v0.0.36",
            display_name="",
        )
    )

    assert not (fern / "pages-v0.0.36").exists()
    assert not (fern / "versions" / "v0.0.36.yml").exists()
    docs_yml = read_yaml(fern / "docs.yml")
    assert [entry["slug"] for entry in docs_yml["versions"]] == []
