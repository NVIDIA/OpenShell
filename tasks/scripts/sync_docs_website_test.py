# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for tasks/scripts/sync_docs_website.py."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path

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
    assert dev_job["with"]["source_ref"] == "${{ github.sha }}"
    assert dev_job["with"]["publish"] == "true"

    assert tag_job["needs"] == [
        "compute-versions",
        "release",
        "publish-sdk-typescript",
        "release-helm",
        "trigger-wheel-publish",
    ]
    assert tag_job["uses"] == "./.github/workflows/sync-docs.yml"
    assert tag_job["with"]["channel"] == "stable"
    assert tag_job["with"]["source_ref"] == "${{ inputs.tag || github.ref_name }}"
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


def test_sync_workflow_serializes_manifest_update_and_publish() -> None:
    workflow = read_workflow("sync-docs.yml")
    triggers = workflow["on"]
    publish_input = triggers["workflow_call"]["inputs"]["publish"]
    dispatch_publish = triggers["workflow_dispatch"]["inputs"]["publish"]
    assert publish_input["type"] == "boolean"
    assert publish_input["default"] == "false"
    assert dispatch_publish["default"] == "false"
    assert workflow["concurrency"]["group"] == "docs-website"
    assert workflow["concurrency"]["queue"] == "max"

    steps = workflow["jobs"]["sync"]["steps"]
    step_names = [step["name"] for step in steps]
    assert step_names.index("Commit docs website changes") < step_names.index(
        "Publish Fern docs"
    )
    publish_step = next(step for step in steps if step["name"] == "Publish Fern docs")
    assert publish_step["if"] == "${{ inputs.publish }}"
    assert publish_step["working-directory"] == "docs-website/fern"
    source_checkout = next(
        step for step in steps if step["name"] == "Checkout source docs"
    )
    manifest_checkout = next(
        step for step in steps if step["name"] == "Checkout docs website branch"
    )
    assert source_checkout["with"]["fetch-depth"] == "0"
    assert manifest_checkout["with"]["fetch-depth"] == "0"


def test_manual_publish_workflow_defaults_to_preview() -> None:
    workflow = read_workflow("publish-docs-website.yml")
    mode = workflow["on"]["workflow_dispatch"]["inputs"]["mode"]
    assert mode["default"] == "preview"
    assert workflow["concurrency"]["queue"] == "max"


def test_branch_preview_stages_refs_without_updating_docs_website() -> None:
    workflow = read_workflow("branch-docs.yml")
    steps = workflow["jobs"]["preview"]["steps"]
    stage = next(
        step for step in steps if step["name"] == "Stage version manifest for preview"
    )
    assert "--docs-website-root docs-website" in stage["run"]
    assert '--source-sha "$SOURCE_SHA"' in stage["run"]
    assert "--allow-rollback" in stage["run"]

    generate = next(step for step in steps if step["name"] == "Generate preview URL")
    assert "fern generate --docs --preview" in generate["run"]
    workflow_text = (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "branch-docs.yml"
    ).read_text(encoding="utf-8")
    assert "git push" not in workflow_text


def test_resolve_slug_channels_and_validation() -> None:
    assert sdw.resolve_slug("dev", "") == "dev"
    assert sdw.resolve_slug("latest", "") == "latest"
    assert sdw.resolve_slug("stable", "v0.1.0") == "v0.1.0"
    assert sdw.resolve_slug("version", "v0.0.36") == "v0.0.36"
    with pytest.raises(ValueError):
        sdw.resolve_slug("version", "")
    with pytest.raises(ValueError):
        sdw.resolve_slug("version", "../escape")


def test_resolve_display_name_and_availability() -> None:
    assert sdw.resolve_display_name("dev", "dev", "main", "") == "dev"
    assert (
        sdw.resolve_display_name("latest", "latest", "v0.0.57", "")
        == "Latest (v0.0.57)"
    )
    assert sdw.resolve_display_name("dev", "dev", "main", "Custom") == "Custom"
    assert sdw.resolve_availability("dev", "") == "beta"
    assert sdw.resolve_availability("latest", "") is None
    assert sdw.resolve_availability("version", "deprecated") == "deprecated"
    with pytest.raises(ValueError):
        sdw.resolve_availability("dev", "alpha")


def test_parse_and_render_versions_support_ref_and_legacy_path() -> None:
    raw_versions = [
        {
            "display-name": "Latest (v0.2.0)",
            "ref": "v0.2.0",
            "slug": "latest",
            "availability": "stable",
        },
        {
            "display-name": "Dev",
            "path": "./versions/dev.yml",
            "slug": "dev",
        },
    ]
    entries = sdw.parse_versions(raw_versions)
    assert entries == [
        sdw.VersionEntry("latest", "Latest (v0.2.0)", "v0.2.0", None, "stable"),
        sdw.VersionEntry("dev", "Dev", None, "./versions/dev.yml", None),
    ]
    assert sdw.render_versions(entries) == raw_versions


def test_parse_versions_rejects_ref_and_path_together() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        sdw.parse_versions(
            [
                {
                    "display-name": "v1",
                    "ref": "v1",
                    "path": "./v1.yml",
                    "slug": "v1",
                }
            ]
        )


def test_ordered_entries_pins_latest_then_dev() -> None:
    existing = [
        sdw.VersionEntry("v0.0.36", "v0.0.36", "v0.0.36"),
        sdw.VersionEntry("dev", "dev", "dev-sha"),
    ]
    updated = sdw.VersionEntry("latest", "Latest", "v0.2.0")
    assert [entry.slug for entry in sdw.ordered_entries(existing, updated)] == [
        "latest",
        "dev",
        "v0.0.36",
    ]


def _make_source_tree(root: Path, *, marker: str = "source") -> None:
    docs = root / "docs"
    docs.mkdir(parents=True)
    (docs / "intro.mdx").write_text(f"# {marker}\n", encoding="utf-8")
    (docs / "index.yml").write_text(
        yaml.safe_dump({"navigation": [{"page": "Intro", "path": "intro.mdx"}]}),
        encoding="utf-8",
    )
    fern = root / "fern"
    (fern / "assets").mkdir(parents=True)
    (fern / "assets" / "logo.svg").write_text(f"<{marker}/>", encoding="utf-8")
    (fern / "components").mkdir(parents=True)
    (fern / "components" / "Card.tsx").write_text(
        f"export const Card = '{marker}';\n", encoding="utf-8"
    )
    (fern / "main.css").write_text(f"/* {marker} */\n", encoding="utf-8")
    (fern / "fern.config.json").write_text('{"version": "5.112.0"}\n', encoding="utf-8")
    (fern / "docs.yml").write_text(
        yaml.safe_dump(
            {
                "title": marker,
                "experimental": {
                    "mdx-components": ["../docs/_components", "./components"],
                    "basepath-aware": True,
                },
                "versions": [
                    {
                        "display-name": "Latest",
                        "path": "../docs/index.yml",
                        "slug": "latest",
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _make_docs_website_tree(root: Path) -> None:
    fern = root / "fern"
    fern.mkdir(parents=True)
    (fern / "docs.yml").write_text(
        yaml.safe_dump({"title": "manifest", "versions": []}), encoding="utf-8"
    )


def _sync_args(
    source: Path,
    website: Path,
    *,
    channel: str,
    source_ref: str,
    source_sha: str,
    release_version: str = "",
    version_slug: str = "",
    display_name: str = "",
    availability: str = "",
    allow_rollback: bool = False,
) -> Namespace:
    return Namespace(
        operation="sync",
        source_root=source,
        docs_website_root=website,
        channel=channel,
        source_ref=source_ref,
        source_sha=source_sha,
        release_version=release_version,
        version_slug=version_slug,
        display_name=display_name,
        availability=availability,
        allow_rollback=allow_rollback,
    )


def test_dev_sync_registers_exact_commit_without_copying_docs(tmp_path: Path) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source, marker="dev-shell")
    _make_docs_website_tree(website)

    sdw.sync_docs(
        _sync_args(
            source,
            website,
            channel="dev",
            source_ref="main",
            source_sha="dev-sha",
            release_version="0.2.1.dev4",
            display_name="Dev (v0.2.1.dev4)",
            availability="beta",
        )
    )

    fern = website / "fern"
    assert not (fern / "pages-dev").exists()
    assert not (fern / "versions").exists()
    config = read_yaml(fern / "docs.yml")
    assert config["title"] == "dev-shell"
    assert config["experimental"] == {
        "mdx-components": ["./components"],
        "basepath-aware": True,
    }
    assert config["versions"] == [
        {
            "display-name": "Dev (v0.2.1.dev4)",
            "ref": "dev-sha",
            "slug": "dev",
            "availability": "beta",
        }
    ]
    assert (fern / "assets" / "logo.svg").read_text() == "<dev-shell/>"
    assert (fern / "components" / "Card.tsx").is_file()


def test_stable_sync_creates_immutable_version_and_promotes_latest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)

    sdw.sync_docs(
        _sync_args(
            source,
            website,
            channel="stable",
            source_ref="v0.2.0",
            source_sha="new-sha",
            release_version="0.2.0",
            version_slug="v0.2.0",
        )
    )

    fern = website / "fern"
    assert not (fern / "pages-v0.2.0").exists()
    assert not (fern / "pages-latest").exists()
    assert not (fern / "versions").exists()
    versions = read_yaml(fern / "docs.yml")["versions"]
    assert versions == [
        {
            "display-name": "Latest (v0.2.0)",
            "ref": "v0.2.0",
            "slug": "latest",
            "availability": "stable",
        },
        {
            "display-name": "v0.2.0",
            "ref": "v0.2.0",
            "slug": "v0.2.0",
            "availability": "stable",
        },
    ]
    snapshots = read_yaml(fern / sdw.SNAPSHOT_METADATA_FILE)["snapshots"]
    assert snapshots["latest"]["source-sha"] == "new-sha"
    assert snapshots["v0.2.0"]["source-ref"] == "v0.2.0"


def test_stable_sync_requires_the_release_tag_as_source_ref(tmp_path: Path) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)
    with pytest.raises(ValueError, match="source ref must be tag"):
        sdw.sync_docs(
            _sync_args(
                source,
                website,
                channel="stable",
                source_ref="release-sha",
                source_sha="release-sha",
                release_version="0.2.0",
                version_slug="v0.2.0",
            )
        )


def test_n_minus_one_sync_registers_version_without_moving_latest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)

    for version, source_sha in (("0.3.1", "current-sha"), ("0.2.7", "old-sha")):
        sdw.sync_docs(
            _sync_args(
                source,
                website,
                channel="stable",
                source_ref=f"v{version}",
                source_sha=source_sha,
                release_version=version,
                version_slug=f"v{version}",
            )
        )

    versions = read_yaml(website / "fern" / "docs.yml")["versions"]
    by_slug = {entry["slug"]: entry for entry in versions}
    assert by_slug["latest"]["ref"] == "v0.3.1"
    assert by_slug["v0.2.7"]["ref"] == "v0.2.7"


def test_sync_migrates_legacy_copies_to_refs(tmp_path: Path) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)
    fern = website / "fern"
    (fern / "pages-latest").mkdir()
    (fern / "pages-latest" / "intro.mdx").write_text("old", encoding="utf-8")
    (fern / "pages-v0.0.36").mkdir()
    (fern / "pages-v0.0.36" / "intro.mdx").write_text("old", encoding="utf-8")
    (fern / "versions").mkdir()
    (fern / "versions" / "latest.yml").write_text("navigation: []\n")
    (fern / "versions" / "v0.0.36.yml").write_text("navigation: []\n")
    (fern / "docs.yml").write_text(
        yaml.safe_dump(
            {
                "versions": [
                    {
                        "display-name": "Latest (v0.3.1)",
                        "path": "./versions/latest.yml",
                        "slug": "latest",
                    },
                    {
                        "display-name": "v0.0.36",
                        "path": "./versions/v0.0.36.yml",
                        "slug": "v0.0.36",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    sdw.sync_docs(
        _sync_args(
            source,
            website,
            channel="stable",
            source_ref="v0.2.7",
            source_sha="maintenance-sha",
            release_version="0.2.7",
            version_slug="v0.2.7",
        )
    )

    assert not (fern / "pages-latest").exists()
    assert not (fern / "pages-v0.0.36").exists()
    assert not (fern / "versions").exists()
    versions = read_yaml(fern / "docs.yml")["versions"]
    by_slug = {entry["slug"]: entry for entry in versions}
    assert by_slug["latest"]["ref"] == "v0.3.1"
    assert by_slug["v0.0.36"]["ref"] == "v0.0.36"
    assert by_slug["v0.2.7"]["ref"] == "v0.2.7"


def test_dev_sync_rejects_stale_or_conflicting_updates(tmp_path: Path) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)

    def sync(source_sha: str, version: str, allow_rollback: bool = False) -> None:
        sdw.sync_docs(
            _sync_args(
                source,
                website,
                channel="dev",
                source_ref="main",
                source_sha=source_sha,
                release_version=version,
                display_name=f"Dev (v{version})",
                availability="beta",
                allow_rollback=allow_rollback,
            )
        )

    sync("current-sha", "0.3.2.dev10")
    sync("stale-sha", "0.3.2.dev9")
    versions = read_yaml(website / "fern" / "docs.yml")["versions"]
    assert versions[0]["ref"] == "current-sha"

    with pytest.raises(ValueError, match="already points to current-sha"):
        sync("other-sha", "0.3.2.dev10")

    sync("rollback-sha", "0.3.2.dev9", True)
    versions = read_yaml(website / "fern" / "docs.yml")["versions"]
    assert versions[0]["ref"] == "rollback-sha"


def test_stale_dev_sync_does_not_partially_migrate_legacy_manifest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)
    fern = website / "fern"
    pages = fern / "pages-latest"
    pages.mkdir()
    (pages / "intro.mdx").write_text("legacy", encoding="utf-8")
    versions_dir = fern / "versions"
    versions_dir.mkdir()
    (versions_dir / "latest.yml").write_text("navigation: []\n", encoding="utf-8")
    legacy_manifest = {
        "versions": [
            {
                "display-name": "Latest (v0.3.1)",
                "path": "./versions/latest.yml",
                "slug": "latest",
            }
        ]
    }
    (fern / "docs.yml").write_text(
        yaml.safe_dump(legacy_manifest, sort_keys=False), encoding="utf-8"
    )
    (fern / sdw.SNAPSHOT_METADATA_FILE).write_text(
        yaml.safe_dump(
            {
                "snapshots": {
                    "dev": {
                        "source-ref": "main",
                        "source-sha": "current-sha",
                        "version": "0.3.2.dev10",
                    }
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    sdw.sync_docs(
        _sync_args(
            source,
            website,
            channel="dev",
            source_ref="main",
            source_sha="stale-sha",
            release_version="0.3.2.dev9",
        )
    )

    assert read_yaml(fern / "docs.yml") == legacy_manifest
    assert (pages / "intro.mdx").read_text(encoding="utf-8") == "legacy"
    assert (versions_dir / "latest.yml").is_file()


def test_immutable_version_cannot_change_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)
    args = _sync_args(
        source,
        website,
        channel="stable",
        source_ref="v0.2.0",
        source_sha="release-sha",
        release_version="0.2.0",
        version_slug="v0.2.0",
    )
    sdw.sync_docs(args)
    args.source_sha = "different-sha"
    with pytest.raises(ValueError, match=r"immutable version v0\.2\.0"):
        sdw.sync_docs(args)


def test_only_dev_refreshes_shared_fern_files(tmp_path: Path) -> None:
    dev = tmp_path / "dev"
    release = tmp_path / "release"
    website = tmp_path / "docs-website"
    _make_source_tree(dev, marker="dev")
    _make_source_tree(release, marker="release")
    _make_docs_website_tree(website)

    sdw.sync_docs(
        _sync_args(
            dev,
            website,
            channel="dev",
            source_ref="main",
            source_sha="dev-sha",
            release_version="0.2.1.dev1",
        )
    )
    sdw.sync_docs(
        _sync_args(
            release,
            website,
            channel="stable",
            source_ref="v0.2.0",
            source_sha="release-sha",
            release_version="0.2.0",
            version_slug="v0.2.0",
        )
    )

    fern = website / "fern"
    assert read_yaml(fern / "docs.yml")["title"] == "dev"
    assert (fern / "components" / "Card.tsx").read_text() == (
        "export const Card = 'dev';\n"
    )


def test_remove_docs_drops_manifest_entry_and_legacy_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    website = tmp_path / "docs-website"
    _make_source_tree(source)
    _make_docs_website_tree(website)
    sdw.sync_docs(
        _sync_args(
            source,
            website,
            channel="version",
            source_ref="legacy-branch",
            source_sha="legacy-sha",
            version_slug="v0.0.36",
            availability="deprecated",
        )
    )
    assert read_yaml(website / "fern" / "docs.yml")["versions"][0]["ref"] == (
        "legacy-sha"
    )

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

    assert read_yaml(website / "fern" / "docs.yml")["versions"] == []
    assert read_yaml(website / "fern" / sdw.SNAPSHOT_METADATA_FILE)["snapshots"] == {}
