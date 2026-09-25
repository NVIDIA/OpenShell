# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

import check_docs_nav
import pytest

if TYPE_CHECKING:
    from pathlib import Path

FERN_CONFIG = """\
instances:
  - url: example.docs.buildwithfern.com/openshell
versions:
  - display-name: Dev
    path: ../docs/index.yml
    slug: dev
"""


def page(title: str, **extra: str) -> str:
    lines = (
        ["---", f'title: "{title}"']
        + [f'{k}: "{v}"' for k, v in extra.items()]
        + ["---", ""]
    )
    return "\n".join(lines)


def build(tmp_path: Path, nav: str, pages: dict[str, str], redirects: str = "") -> Path:
    docs = tmp_path / "docs"
    for rel, content in pages.items():
        (docs / rel).parent.mkdir(parents=True, exist_ok=True)
        (docs / rel).write_text(content)
    (docs / "index.yml").write_text(textwrap.dedent(nav))
    (tmp_path / "fern").mkdir()
    (tmp_path / "fern" / "docs.yml").write_text(
        FERN_CONFIG + textwrap.dedent(redirects)
    )
    return tmp_path


def test_fern_slug_splits_camel_case() -> None:
    assert check_docs_nav.fern_slug("TypeScript") == "type-script"
    assert check_docs_nav.fern_slug("Why OpenShell") == "why-open-shell"
    assert check_docs_nav.fern_slug("API Errors") == "api-errors"
    assert check_docs_nav.fern_slug("0.1.0") == "0-1-0"


def test_matching_nav_passes(tmp_path: Path) -> None:
    root = build(
        tmp_path,
        """
        navigation:
        - section: "Guides"
          slug: guides
          path: guides/index.mdx
          contents:
          - page: "Setup"
            path: guides/setup.mdx
          - page: "Policy Prover"
            path: guides/prover.mdx
            slug: prover
        """,
        {
            "guides/index.mdx": page("Guides"),
            "guides/setup.mdx": page("Set Up", **{"sidebar-title": "Setup"}),
            "guides/prover.mdx": page("Policy Prover"),
        },
    )
    assert check_docs_nav.run(root) == []


def test_label_url_that_differs_from_file_path_fails(tmp_path: Path) -> None:
    root = build(
        tmp_path,
        """
        navigation:
        - section: "SDK"
          slug: sdk
          contents:
          - page: "TypeScript"
            path: sdk/typescript.mdx
        """,
        {"sdk/typescript.mdx": page("TypeScript")},
    )
    issues = check_docs_nav.run(root)
    assert len(issues) == 1
    assert "URL /sdk/type-script" in issues[0]
    assert "relative slug in docs/index.yml" in issues[0]


def test_frontmatter_slug_can_pin_the_url_to_the_file_path(tmp_path: Path) -> None:
    root = build(
        tmp_path,
        """
        navigation:
        - section: "SDK"
          slug: sdk
          contents:
          - page: "TypeScript"
            path: sdk/typescript.mdx
        """,
        {"sdk/typescript.mdx": page("TypeScript", slug="sdk/typescript")},
    )
    assert check_docs_nav.run(root) == []


def test_sidebar_name_must_match_nav_label(tmp_path: Path) -> None:
    root = build(
        tmp_path,
        """
        navigation:
        - section: "About"
          slug: about
          contents:
          - page: "Overview"
            path: about/overview.mdx
        """,
        {"about/overview.mdx": page("Overview of the Product")},
    )
    issues = check_docs_nav.run(root)
    assert issues == [
        "about/overview.mdx: title 'Overview of the Product' does not match nav label 'Overview'"
    ]


@pytest.mark.parametrize(
    ("nav", "rel"),
    [
        (
            """
            navigation:
            - section: Guides
              slug: ignored
              skip-slug: true
              contents:
              - page: Setup
                path: setup.mdx
            """,
            "setup.mdx",
        ),
        (
            """
            navigation:
            - section: Guides
              contents:
              - page: Setup
                slug: ignored
                skip-slug: true
                path: guides/index.mdx
            """,
            "guides/index.mdx",
        ),
        (
            """
            navigation:
            - section: Guides
              contents:
              - folder: guides
                slug: ignored
                skip-slug: true
            """,
            "guides/setup.mdx",
        ),
    ],
)
def test_skip_slug_omits_navigation_level(tmp_path: Path, nav: str, rel: str) -> None:
    root = build(tmp_path, nav, {rel: page("Setup")})
    assert check_docs_nav.run(root) == []


def test_skip_slug_detects_url_that_differs_from_file_path(tmp_path: Path) -> None:
    root = build(
        tmp_path,
        """
        navigation:
        - section: Guides
          skip-slug: true
          contents:
          - page: Setup
            path: guides/setup.mdx
        """,
        {"guides/setup.mdx": page("Setup")},
    )
    issues = check_docs_nav.run(root)
    assert len(issues) == 1
    assert "URL /setup" in issues[0]
    assert "does not match its file path /guides/setup" in issues[0]


def test_folder_pages_use_file_names_and_orphans_fail(tmp_path: Path) -> None:
    root = build(
        tmp_path,
        """
        navigation:
        - folder: kubernetes
          title: "Kubernetes"
        """,
        {
            "kubernetes/openshift.mdx": page("OpenShift"),
            "stray.mdx": page("Stray"),
        },
    )
    assert check_docs_nav.run(root) == ["stray.mdx: not reachable from docs/index.yml"]


@pytest.mark.parametrize(
    ("redirect", "expected"),
    [
        (
            '  - source: "/openshell/dev/old"\n    destination: "/openshell/dev/missing"\n',
            "destination does not exist",
        ),
        (
            '  - source: "/openshell/dev/guides/setup"\n    destination: "/openshell/dev/guides/setup"\n',
            "is still a live page",
        ),
    ],
)
def test_dev_redirects_must_point_to_live_pages(
    tmp_path: Path, redirect: str, expected: str
) -> None:
    root = build(
        tmp_path,
        """
        navigation:
        - section: "Guides"
          slug: guides
          contents:
          - page: "Setup"
            path: guides/setup.mdx
        """,
        {"guides/setup.mdx": page("Setup")},
        "redirects:\n" + redirect,
    )
    issues = check_docs_nav.run(root)
    assert len(issues) == 1 and expected in issues[0]
