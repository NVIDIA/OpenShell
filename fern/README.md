# Fern documentation site

OpenShell uses [Fern](https://buildwithfern.com/) to validate, preview, and publish the documentation at [docs.nvidia.com/openshell](https://docs.nvidia.com/openshell/). This directory contains the site configuration and presentation files. The documentation content lives in `docs/`.

## Repository layout

| Path | Purpose |
|---|---|
| `docs/` | MDX pages, navigation in `docs/index.yml`, and page-specific components. |
| `fern/docs.yml` | Site, theme, version, redirect, and navigation configuration. |
| `fern/fern.config.json` | Fern organization and pinned CLI version. |
| `fern/components/` | Shared site components. |
| `fern/assets/` | Logos and other shared assets. |
| `fern/main.css` | Site-wide styles. |

In a normal source checkout, `fern/docs.yml` points the `latest` version at `docs/index.yml`. Release automation builds the multi-version configuration on the generated `docs-website` branch.

## Local development

Start a local Fern server from the repository root:

```shell
mise run docs:serve
```

Validate the configuration, navigation, and links without starting a server:

```shell
mise run docs
```

The tasks read the Fern CLI version from `fern/fern.config.json`, so local checks and GitHub Actions use the same version. See [docs/CONTRIBUTING.mdx](../docs/CONTRIBUTING.mdx) for the authoring and style guide.

## Pull request previews

`.github/workflows/branch-docs.yml` validates pull requests that change documentation or Fern configuration. When the workflow can access `FERN_TOKEN`, it publishes a Fern preview from the pull request checkout and adds the preview URL to the pull request. This path does not use or update the `docs-website` branch.

## Versioned production site

The generated `docs-website` branch contains the complete production input for Fern. Each version has an exact copy of its source commit's `docs/` tree under `fern/pages-<slug>/` and a navigation file under `fern/versions/`. `fern/.docs-snapshots.yml` records the original source ref, resolved source commit, and release version for each managed snapshot.

The site uses these version types:

| Version | Source | Update policy | Fern status |
|---|---|---|---|
| `dev` | The most recent successful Release Dev run from `main`. | Mutable. Automation rejects an older version or the same version from a different commit unless a maintainer explicitly allows a rollback. | Beta. |
| `latest` | The newest stable release. | Mutable. A maintenance release older than the current stable release cannot move it backward unless a maintainer explicitly allows a rollback. | Stable starting with v0.1.0. |
| `vX.Y.Z` | The matching stable release tag. | Immutable. Repeating the sync is allowed only when the tag resolves to the same commit. | Stable starting with v0.1.0. |

Release Dev waits for the development artifacts and Helm chart, then calls `.github/workflows/sync-docs.yml` once. The reusable workflow updates `dev`, validates the generated site, commits and pushes the branch when needed, and publishes the production site once.

Release Tag follows the same sequence for a non-prerelease tag after the release artifacts, SDK package, Helm chart, and wheel publication complete. It creates the immutable `vX.Y.Z` snapshot and updates `latest` when the release is not older than the current version. One call to `.github/workflows/sync-docs.yml` performs both changes and publishes the production site once.

The sync and publish workflows share the `docs-website` concurrency group. This serializes writes and publication. Queued runs remain pending instead of replacing one another.

The `dev` snapshot also owns the shared Fern configuration, components, assets, and CSS on `docs-website`. Stable snapshots copy their documentation and navigation but do not replace those shared files. This keeps the site configuration aligned with `main` while preserving the content captured for each release.

## Manual maintenance and publishing

Maintainers can run `.github/workflows/sync-docs.yml` manually to add, refresh, or remove a snapshot. The workflow preserves snapshots that were not selected. Production publishing is disabled by default for a manual sync.

`.github/workflows/publish-docs-website.yml` validates and publishes the existing `docs-website` branch without syncing content. Its default mode creates a preview. Selecting production mode publishes the live site, so use it only for an intentional production republish.

Run the automated sync tests after changing the version model or either publishing workflow:

```shell
mise run test:docs-website
```
