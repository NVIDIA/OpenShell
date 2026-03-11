---
name: sbom
description: Generate and manage Software Bill of Materials (SBOMs) for the OpenShell project. Covers SBOM generation with Syft, license resolution via public registries, and CSV export for compliance review. Trigger keywords - SBOM, sbom, bill of materials, license audit, license resolution, generate sbom, sbom csv, dependency license, supply chain, license scan.
---

# SBOM Generation and License Resolution

Generate CycloneDX SBOMs, resolve missing licenses, and export to CSV for compliance review.

## Overview

The OpenShell SBOM tooling produces CycloneDX JSON SBOMs using Syft, resolves missing or hash-based licenses by querying public registries (crates.io, npm, PyPI), and exports the results to CSV for stakeholder review.

SBOMs are **release artifacts only** -- they are generated on demand and not committed to the repository. Output lands in `deploy/sbom/output/` (gitignored).

## Prerequisites

- `mise install` has been run (installs Syft and other tools)
- The repository is checked out at the root

## Workflow 1: Full SBOM Generation (One Command)

```bash
mise run sbom
```

This single command chains three stages:

1. **Generate** (`sbom:generate`): Syft scans the workspace source tree and produces a CycloneDX JSON SBOM
2. **Resolve** (`sbom:resolve`): Public registry APIs fill in missing or hash-based licenses in the JSON
3. **CSV** (`sbom:csv`): JSON SBOMs are converted to CSV for review

Output directory: `deploy/sbom/output/`

After running, the user can find:
- `deploy/sbom/output/*.cdx.json` -- full CycloneDX SBOMs
- `deploy/sbom/output/*.csv` -- CSV exports ready for spreadsheet review

## Workflow 2: Individual Stages

Run stages independently when debugging or iterating:

```bash
mise run sbom:generate   # Generate JSON SBOMs only (requires Syft)
mise run sbom:resolve    # Resolve licenses in existing JSONs (queries APIs)
mise run sbom:csv        # Convert existing JSONs to CSV
```

## Workflow 3: License Check (CI Advisory)

```bash
mise run sbom:check
```

Reports unresolved licenses without failing. Intended for PR CI as a non-blocking advisory check. Requires that SBOMs have already been generated (`mise run sbom:generate`).

## Workflow 4: Processing External SBOMs

The Python scripts accept explicit file paths, so they can process SBOMs from any source (e.g., NVIDIA nSpect pipeline output):

```bash
uv run python deploy/sbom/resolve_licenses.py /path/to/external-sbom.json
uv run python deploy/sbom/sbom_to_csv.py /path/to/external-sbom.json
```

## License Resolution Details

The resolver queries these public registries:

| Registry | Package URL prefix | Method |
|----------|-------------------|--------|
| crates.io | `pkg:cargo/*` | REST API |
| npm | `pkg:npm/*` | Registry API |
| PyPI | `pkg:pypi/*` | JSON API |
| Go modules | `pkg:golang/*` | Known license map (no API) |
| Debian/Ubuntu | `pkg:deb/*` | Known license map |

Components from private registries (e.g., `@openclaw/*` npm packages) are not resolved and will appear in the "unresolved" report.

## Output Files

| Pattern | Description |
|---------|-------------|
| `deploy/sbom/output/openshell-source-{version}.cdx.json` | CycloneDX JSON SBOM |
| `deploy/sbom/output/openshell-source-{version}.csv` | CSV export (name, version, type, purl, licenses, bom-ref) |

## Key Files

| File | Purpose |
|------|---------|
| `deploy/sbom/resolve_licenses.py` | License resolution script |
| `deploy/sbom/sbom_to_csv.py` | JSON-to-CSV converter |
| `tasks/sbom.toml` | Mise task definitions |
| `mise.toml` | Syft tool definition (under `[tools]`) |

## Quick Reference

| Task | Command |
|------|---------|
| Full pipeline | `mise run sbom` |
| Generate only | `mise run sbom:generate` |
| Resolve licenses | `mise run sbom:resolve` |
| Export CSV | `mise run sbom:csv` |
| CI license check | `mise run sbom:check` |
| Process external SBOM | `uv run python deploy/sbom/resolve_licenses.py <file>` |
