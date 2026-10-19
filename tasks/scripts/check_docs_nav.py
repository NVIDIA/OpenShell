#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "PyYAML==6.0.2",
# ]
# ///

"""Check that the published docs navigation mirrors the docs folder structure.

Fern does not build page URLs from file paths. It uses, in order, the page's
frontmatter `slug`, the nav entry's `slug`, or the nav label, and it splits
camel case in labels, so "TypeScript" becomes `type-script`. Pages in a
`folder:` section use their file names. A URL can therefore drift away from
where its file lives without any link breaking.

This check fails when:

- a page's URL differs from its file path under docs/, without `.mdx`, and
  without `/index` for a section's own page;
- a nav page's sidebar name, its `sidebar-title` or else its `title`, differs
  from its nav label. Fern shows the sidebar name but builds the URL from the
  label, so the two must agree;
- a docs page is not reachable from the navigation; or
- a redirect for this docs version points to a URL that does not exist, or its
  source is still a live page.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Files under docs/ that are intentionally not published as pages.
UNPUBLISHED = {"CONTRIBUTING.mdx"}


def fern_slug(label: str) -> str:
    """Slugify a nav label the way Fern does, including camel-case splits."""
    split = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", label)
    return re.sub(r"[^a-z0-9]+", "-", split.lower()).strip("-")


def path_url(rel_path: str) -> str:
    """Return the URL that a docs file path implies."""
    url = "/" + re.sub(r"\.mdx$", "", rel_path)
    return re.sub(r"/index$", "", url)


def frontmatter(path: Path) -> dict:
    match = re.match(r"---\n(.*?)\n---", path.read_text(encoding="utf-8"), re.S)
    if not match:
        return {}
    return yaml.safe_load(match.group(1)) or {}


@dataclass
class NavCheck:
    docs_root: Path
    urls: dict[str, str] = field(default_factory=dict)  # URL -> docs-relative path
    reachable: set[str] = field(default_factory=set)
    issues: list[str] = field(default_factory=list)

    def page_url(self, rel_path: str, default_url: str) -> str:
        slug = frontmatter(self.docs_root / rel_path).get("slug")
        return "/" + str(slug).strip("/") if slug else default_url

    def record(self, rel_path: str, url: str, how: str) -> None:
        self.reachable.add(rel_path)
        if url in self.urls and self.urls[url] != rel_path:
            self.issues.append(
                f"{rel_path}: URL {url} is also used by {self.urls[url]}"
            )
        self.urls[url] = rel_path
        expected = path_url(rel_path)
        if url != expected:
            self.issues.append(
                f"{rel_path}: URL {url} ({how}) does not match its file path "
                f"{expected}. Rename the file, change the nav label, or set a "
                "relative slug in docs/index.yml. For folder-discovered pages, "
                f'use frontmatter slug: "{expected.lstrip("/")}".'
            )

    def walk(self, items: list, prefix: str) -> None:
        for item in items or []:
            if "section" in item:
                url = prefix + "/" + item.get("slug", fern_slug(item["section"]))
                if item.get("skip-slug"):
                    url = prefix
                if "path" in item:
                    rel = item["path"]
                    self.record(rel, self.page_url(rel, url), "section page")
                self.walk(item.get("contents", []), url)
            elif "page" in item:
                rel, label = item["path"], item["page"]
                if not (self.docs_root / rel).exists():
                    self.issues.append(
                        f"docs/index.yml: nav page {label!r} points to missing {rel}"
                    )
                    continue
                if item.get("skip-slug"):
                    default, how = prefix, "skip-slug"
                elif "slug" in item:
                    default, how = prefix + "/" + item["slug"], "nav slug"
                else:
                    default, how = (
                        prefix + "/" + fern_slug(label),
                        f"nav label {label!r}",
                    )
                meta = frontmatter(self.docs_root / rel)
                how = "frontmatter slug" if meta.get("slug") else how
                self.record(rel, self.page_url(rel, default), how)
                shown_key = "sidebar-title" if "sidebar-title" in meta else "title"
                shown = meta.get(shown_key)
                if shown != label:
                    self.issues.append(
                        f"{rel}: {shown_key} {shown!r} does not match nav label {label!r}"
                    )
            elif "folder" in item:
                folder = item["folder"].strip("./").rstrip("/")
                url = (
                    prefix
                    + "/"
                    + item.get("slug", fern_slug(item.get("title", folder)))
                )
                if item.get("skip-slug"):
                    url = prefix
                for page in sorted((self.docs_root / folder).rglob("*.mdx")):
                    rel = page.relative_to(self.docs_root).as_posix()
                    stem = (
                        page.relative_to(self.docs_root / folder)
                        .with_suffix("")
                        .as_posix()
                    )
                    default = re.sub(r"/index$", "", url + "/" + stem)
                    how = (
                        "frontmatter slug"
                        if frontmatter(page).get("slug")
                        else "folder file name"
                    )
                    self.record(rel, self.page_url(rel, default), how)

    def check_orphans(self) -> None:
        for page in sorted(self.docs_root.rglob("*.mdx")):
            rel = page.relative_to(self.docs_root).as_posix()
            if rel in UNPUBLISHED or rel in self.reachable or rel.startswith("_"):
                continue
            self.issues.append(f"{rel}: not reachable from docs/index.yml")

    def check_redirects(self, redirects: list, prefix: str) -> None:
        live = set(self.urls) | {""}
        for redirect in redirects or []:
            source, dest = redirect.get("source", ""), redirect.get("destination", "")
            if dest.startswith(prefix + "/") or dest == prefix:
                target = dest[len(prefix) :].split("#", 1)[0].rstrip("/")
                if ":" not in target and target not in live:
                    self.issues.append(
                        f"fern/docs.yml: redirect {source} -> {dest}: destination does not exist"
                    )
            if source.startswith(prefix + "/") and ":" not in source:
                origin = source[len(prefix) :].rstrip("/")
                if origin in live:
                    self.issues.append(
                        f"fern/docs.yml: redirect source {source} is still a live page"
                    )


def redirect_prefix(fern_config: dict, nav_file: Path, config_dir: Path) -> str | None:
    """Return the URL prefix, such as /openshell/dev, for the checked docs version."""
    instances = fern_config.get("instances") or []
    url = instances[0].get("url", "") if instances else ""
    base = "/" + url.split("/", 1)[1].strip("/") if "/" in url else ""
    for version in fern_config.get("versions") or []:
        if (config_dir / version.get("path", "")).resolve() == nav_file.resolve():
            return f"{base}/{version['slug']}".replace("//", "/")
    return None


def run(repo_root: Path) -> list[str]:
    docs_root = repo_root / "docs"
    nav_file = docs_root / "index.yml"
    nav = yaml.safe_load(nav_file.read_text(encoding="utf-8"))
    check = NavCheck(docs_root)
    landing = (nav.get("landing-page") or {}).get("path")
    if landing:
        check.reachable.add(landing)
    check.walk(nav.get("navigation", []), "")
    check.check_orphans()
    fern_file = repo_root / "fern" / "docs.yml"
    if fern_file.exists():
        fern_config = yaml.safe_load(fern_file.read_text(encoding="utf-8"))
        prefix = redirect_prefix(fern_config, nav_file, fern_file.parent)
        if prefix:
            check.check_redirects(fern_config.get("redirects"), prefix)
    return check.issues


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check that the published docs navigation mirrors the docs folder structure."
    )
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    args = parser.parse_args()
    issues = run(args.repo_root)
    for issue in issues:
        print(f"docs nav: {issue}", file=sys.stderr)
    if issues:
        print(f"docs nav: {len(issues)} problem(s) found", file=sys.stderr)
        return 1
    print("docs nav: every page URL matches its file path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
