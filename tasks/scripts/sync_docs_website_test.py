# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for tasks/scripts/sync_docs_website.py.

Run via `mise run test:docs-website`, which provides pytest + PyYAML through
`uv run --with ...`. pytest puts this file's directory on sys.path, so the
sibling script imports directly as `sync_docs_website`.
"""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from typing import cast

import pytest
import sync_docs_website as sdw
import yaml


def read_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def read_workflow(name: str) -> dict:
    path = Path(__file__).resolve().parents[2] / ".github" / "workflows" / name
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_release_workflows_sync_and_publish_docs_once() -> None:
    dev = read_workflow("release-dev.yml")
    tag = read_workflow("release-tag.yml")
    dev_job = dev["jobs"]["publish-fern-docs"]
    tag_job = tag["jobs"]["publish-fern-docs"]

    assert dev_job["needs"] == [
        "compute-versions",
        "release-dev",
        "release-helm",
        "trigger-wheel-publish",
    ]
    assert dev_job["uses"] == "./.github/workflows/sync-docs.yml"
    assert dev_job["with"]["channel"] == "dev"
    assert (
        dev_job["with"]["release_version"]
        == "${{ needs.compute-versions.outputs.docs_version }}"
    )
    assert dev_job["with"]["publish"] == "true"
    assert (
        dev_job["with"]["display_name"]
        == "Dev (v${{ needs.compute-versions.outputs.docs_version }})"
    )

    assert tag_job["needs"] == [
        "compute-versions",
        "release",
        "publish-sdk-typescript",
        "release-helm",
        "trigger-wheel-publish",
    ]
    assert tag_job["uses"] == "./.github/workflows/sync-docs.yml"
    assert tag_job["with"]["channel"] == "stable"
    assert (
        tag_job["with"]["release_version"]
        == "${{ needs.compute-versions.outputs.semver }}"
    )
    assert (
        tag_job["with"]["version_slug"]
        == "v${{ needs.compute-versions.outputs.semver }}"
    )
    assert tag_job["with"]["publish"] == "true"
    assert "is_prerelease != 'true'" in tag_job["if"]

    for workflow_name in ("release-dev.yml", "release-tag.yml"):
        workflow_path = (
            Path(__file__).resolve().parents[2]
            / ".github"
            / "workflows"
            / workflow_name
        )
        workflow_text = workflow_path.read_text(encoding="utf-8")
        assert workflow_text.count("uses: ./.github/workflows/sync-docs.yml") == 1
        assert "fern generate --docs" not in workflow_text


def test_sync_workflow_serializes_sync_and_publish() -> None:
    workflow = read_workflow("sync-docs.yml")
    triggers = workflow["on"]
    publish_input = triggers["workflow_call"]["inputs"]["publish"]
    assert publish_input["type"] == "boolean"
    assert publish_input["default"] == "false"
    assert workflow["concurrency"]["group"] == "docs-website"
    assert workflow["concurrency"]["queue"] == "max"
    publish_workflow = read_workflow("publish-docs-website.yml")
    assert publish_workflow["concurrency"]["queue"] == "max"

    steps = workflow["jobs"]["sync"]["steps"]
    step_names = [step["name"] for step in steps]
    assert step_names.index("Commit docs website changes") < step_names.index(
        "Publish Fern docs"
    )
    publish_step = next(step for step in steps if step["name"] == "Publish Fern docs")
    assert publish_step["if"] == "${{ inputs.publish }}"
    assert publish_step["working-directory"] == "docs-website/fern"


def test_resolve_slug_channels() -> None:
    assert sdw.resolve_slug("dev", "") == "dev"
    assert sdw.resolve_slug("latest", "") == "latest"
    assert sdw.resolve_slug("stable", "v0.1.0") == "v0.1.0"
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


def test_resolve_availability() -> None:
    assert sdw.resolve_availability("dev", "") == "beta"
    assert sdw.resolve_availability("latest", "") is None
    assert sdw.resolve_availability("version", "") is None
    assert sdw.resolve_availability("version", "deprecated") == "deprecated"
    with pytest.raises(ValueError):
        sdw.resolve_availability("dev", "alpha")


def test_parse_and_render_versions_preserves_availability() -> None:
    raw_versions = [
        {
            "display-name": "v0.0.36",
            "path": "./versions/v0.0.36.yml",
            "slug": "v0.0.36",
            "availability": "deprecated",
        }
    ]

    entries = sdw.parse_versions(raw_versions)

    assert entries == [
        sdw.VersionEntry(
            "v0.0.36",
            "v0.0.36",
            "./versions/v0.0.36.yml",
            "deprecated",
        )
    ]
    assert sdw.render_versions(entries) == raw_versions


def test_ordered_entries_pins_latest_then_dev() -> None:
    existing = [
        sdw.VersionEntry("v0.0.36", "v0.0.36", "./versions/v0.0.36.yml"),
        sdw.VersionEntry("dev", "dev", "./versions/dev.yml"),
    ]
    updated = sdw.VersionEntry("latest", "Latest", "./versions/latest.yml")
    ordered = [entry.slug for entry in sdw.ordered_entries(existing, updated)]
    assert ordered == ["latest", "dev", "v0.0.36"]


def test_prefix_navigation_paths() -> None:
    nav: dict[str, object] = {
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
    navigation = cast("list[dict[str, object]]", nav["navigation"])
    guide = navigation[1]
    contents = cast("list[dict[str, object]]", guide["contents"])
    assert navigation[0]["path"] == "../pages-dev/intro.mdx"
    assert guide["folder"] == "../pages-dev/guide"
    assert contents[0]["path"] == "../pages-dev/guide/a.mdx"
    # Absolute URLs are left untouched.
    assert navigation[2]["path"] == "https://example.com"


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
            release_version="0.0.117.dev56",
            version_slug="",
            display_name="",
            availability="",
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
    assert docs_yml["versions"][0]["availability"] == "beta"
    assert "./components" in docs_yml["experimental"]["mdx-components"]


def test_sync_docs_preserves_other_version_availability(tmp_path: Path) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)
    docs_yml_path = website / "fern" / "docs.yml"
    docs_yml_path.write_text(
        yaml.safe_dump(
            {
                "versions": [
                    {
                        "display-name": "v0.0.36",
                        "path": "./versions/v0.0.36.yml",
                        "slug": "v0.0.36",
                        "availability": "deprecated",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    sdw.sync_docs(
        Namespace(
            operation="sync",
            source_root=source,
            docs_website_root=website,
            channel="dev",
            source_ref="main",
            release_version="0.0.117.dev56",
            version_slug="",
            display_name="Dev (v0.0.117.dev56)",
            availability="beta",
        )
    )

    versions = read_yaml(docs_yml_path)["versions"]
    assert versions == [
        {
            "display-name": "Dev (v0.0.117.dev56)",
            "path": "./versions/dev.yml",
            "slug": "dev",
            "availability": "beta",
        },
        {
            "display-name": "v0.0.36",
            "path": "./versions/v0.0.36.yml",
            "slug": "v0.0.36",
            "availability": "deprecated",
        },
    ]


def test_stable_sync_creates_immutable_version_and_promotes_latest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)

    sdw.sync_docs(
        Namespace(
            source_root=source,
            docs_website_root=website,
            channel="stable",
            source_ref="new-sha",
            release_version="0.2.0",
            version_slug="v0.2.0",
            display_name="",
            availability="",
            allow_rollback=False,
        )
    )

    fern = website / "fern"
    assert (fern / "pages-v0.2.0" / "intro.mdx").is_file()
    assert (fern / "pages-latest" / "intro.mdx").is_file()
    versions = read_yaml(fern / "docs.yml")["versions"]
    assert [entry["slug"] for entry in versions] == ["latest", "v0.2.0"]
    assert versions[0]["display-name"] == "Latest (v0.2.0)"
    assert versions[0]["availability"] == "stable"
    assert versions[1]["availability"] == "stable"
    snapshots = read_yaml(fern / sdw.SNAPSHOT_METADATA_FILE)["snapshots"]
    assert snapshots["latest"] == {"source-ref": "new-sha", "version": "0.2.0"}
    assert snapshots["v0.2.0"] == {
        "source-ref": "new-sha",
        "version": "0.2.0",
    }


def test_n_minus_one_sync_does_not_move_latest_backwards(tmp_path: Path) -> None:
    current = tmp_path / "current"
    maintenance = tmp_path / "maintenance"
    website = tmp_path / "docs-website"
    _make_source_tree(current)
    _make_source_tree(maintenance)
    (current / "docs" / "intro.mdx").write_text("# Current\n", encoding="utf-8")
    (maintenance / "docs" / "intro.mdx").write_text("# Maintenance\n", encoding="utf-8")
    _make_docs_website_tree(website)

    for source, source_ref, version in (
        (current, "current-sha", "0.3.1"),
        (maintenance, "maintenance-sha", "0.2.7"),
    ):
        sdw.sync_docs(
            Namespace(
                source_root=source,
                docs_website_root=website,
                channel="stable",
                source_ref=source_ref,
                release_version=version,
                version_slug=f"v{version}",
                display_name="",
                availability="",
                allow_rollback=False,
            )
        )

    fern = website / "fern"
    assert (fern / "pages-latest" / "intro.mdx").read_text(
        encoding="utf-8"
    ) == "# Current\n"
    assert (fern / "pages-v0.2.7" / "intro.mdx").read_text(
        encoding="utf-8"
    ) == "# Maintenance\n"
    snapshots = read_yaml(fern / sdw.SNAPSHOT_METADATA_FILE)["snapshots"]
    assert snapshots["latest"] == {
        "source-ref": "current-sha",
        "version": "0.3.1",
    }


def test_stable_sync_preserves_newer_legacy_latest_without_metadata(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)
    fern = website / "fern"
    (fern / "pages-latest").mkdir()
    (fern / "pages-latest" / "intro.mdx").write_text(
        "# Existing latest\n", encoding="utf-8"
    )
    (fern / "docs.yml").write_text(
        yaml.safe_dump(
            {
                "versions": [
                    {
                        "display-name": "Latest (v0.3.1)",
                        "path": "./versions/latest.yml",
                        "slug": "latest",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    sdw.sync_docs(
        Namespace(
            source_root=source,
            docs_website_root=website,
            channel="stable",
            source_ref="maintenance-sha",
            release_version="0.2.7",
            version_slug="v0.2.7",
            display_name="",
            availability="",
            allow_rollback=False,
        )
    )

    assert (fern / "pages-latest" / "intro.mdx").read_text(
        encoding="utf-8"
    ) == "# Existing latest\n"
    snapshots = read_yaml(fern / sdw.SNAPSHOT_METADATA_FILE)["snapshots"]
    assert snapshots["latest"] == {"source-ref": "", "version": "0.3.1"}


def test_dev_sync_rejects_stale_or_conflicting_updates(tmp_path: Path) -> None:
    current = tmp_path / "current"
    stale = tmp_path / "stale"
    website = tmp_path / "docs-website"
    _make_source_tree(current)
    _make_source_tree(stale)
    (current / "docs" / "intro.mdx").write_text("# Current\n", encoding="utf-8")
    (stale / "docs" / "intro.mdx").write_text("# Stale\n", encoding="utf-8")
    _make_docs_website_tree(website)

    def sync(source: Path, source_ref: str, version: str) -> None:
        sdw.sync_docs(
            Namespace(
                source_root=source,
                docs_website_root=website,
                channel="dev",
                source_ref=source_ref,
                release_version=version,
                version_slug="",
                display_name=f"Dev (v{version})",
                availability="beta",
                allow_rollback=False,
            )
        )

    sync(current, "current-sha", "0.3.2.dev10")
    sync(stale, "stale-sha", "0.3.2.dev9")
    intro = website / "fern" / "pages-dev" / "intro.mdx"
    assert intro.read_text(encoding="utf-8") == "# Current\n"

    with pytest.raises(ValueError, match="already points to current-sha"):
        sync(stale, "other-sha", "0.3.2.dev10")


def test_immutable_snapshot_cannot_change_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)
    args = Namespace(
        source_root=source,
        docs_website_root=website,
        channel="stable",
        source_ref="release-sha",
        release_version="0.2.0",
        version_slug="v0.2.0",
        display_name="",
        availability="",
        allow_rollback=False,
    )
    sdw.sync_docs(args)

    args.source_ref = "different-sha"
    with pytest.raises(ValueError, match=r"immutable snapshot v0\.2\.0"):
        sdw.sync_docs(args)


def test_only_dev_refreshes_shared_fern_files(tmp_path: Path) -> None:
    dev = tmp_path / "dev"
    release = tmp_path / "release"
    website = tmp_path / "docs-website"
    _make_source_tree(dev)
    _make_source_tree(release)
    (dev / "fern" / "components" / "Card.tsx").write_text(
        "export const Card = 'dev';\n", encoding="utf-8"
    )
    (release / "fern" / "components" / "Card.tsx").write_text(
        "export const Card = 'release';\n", encoding="utf-8"
    )
    _make_docs_website_tree(website)

    sdw.sync_docs(
        Namespace(
            source_root=dev,
            docs_website_root=website,
            channel="dev",
            source_ref="dev-sha",
            release_version="0.2.1.dev1",
            version_slug="",
            display_name="Dev (v0.2.1.dev1)",
            availability="beta",
            allow_rollback=False,
        )
    )
    sdw.sync_docs(
        Namespace(
            source_root=release,
            docs_website_root=website,
            channel="stable",
            source_ref="release-sha",
            release_version="0.2.0",
            version_slug="v0.2.0",
            display_name="",
            availability="",
            allow_rollback=False,
        )
    )

    card = website / "fern" / "components" / "Card.tsx"
    assert card.read_text(encoding="utf-8") == "export const Card = 'dev';\n"


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
        availability="deprecated",
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
            availability="",
        )
    )

    assert not (fern / "pages-v0.0.36").exists()
    assert not (fern / "versions" / "v0.0.36.yml").exists()
    docs_yml = read_yaml(fern / "docs.yml")
    assert [entry["slug"] for entry in docs_yml["versions"]] == []
