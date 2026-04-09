# Docs Site Layout

## Overview

Published documentation content lives under `docs/`. The `fern/` directory stores Fern site configuration, React components, theme assets, and publish settings.

## Repository Layout

| Path | Role |
|---|---|
| `docs/` | Source of truth for published documentation pages and assets |
| `docs/index.yml` | Navigation definition for the published docs site |
| `fern/docs.yml` | Fern site configuration, including version wiring and publish settings |
| `fern/components/` | Custom Fern React components |
| `fern/assets/` | Site logos and other Fern-managed assets |
| `fern/main.css` | Site theme overrides |
| `fern/fern.config.json` | Fern CLI version and organization config |

The navigation source is `docs/index.yml`. `fern/docs.yml` points its `versions[].path` field at `../docs/index.yml`, so Fern reads page structure from `docs/` during validation, preview, and publish.

## Local Workflow

`tasks/docs.toml` defines the local docs tasks:

- `mise run docs` runs strict validation.
  - Resolves the Fern CLI version from `fern/fern.config.json`
  - Runs `fern check`
- `mise run docs:serve` starts a local Fern preview server with `fern docs dev`

Both tasks execute from `fern/`, but they validate and render the content defined in `docs/`.

## CI and Release Workflow

### Pull requests

`.github/workflows/branch-docs.yml` is the PR docs workflow.

- It triggers on changes under `docs/**`, `fern/**`, and the workflow file itself.
- It validates the site with `fern check`.
- When `FERN_TOKEN` is available, it runs `fern generate --docs --preview --id pr-<number>` and posts or updates a preview URL on the pull request.

### Releases

`.github/workflows/release-tag.yml` publishes production docs in the `publish-fern-docs` job.

- The job runs after the release job completes.
- It installs the Fern CLI, changes into `./fern`, and runs `fern generate --docs`.

## Operational Rules

- Add or edit published pages in `docs/`.
- Change sidebar structure in `docs/index.yml`.
- Change site chrome, theme, Fern behavior, or publish settings in `fern/`.
