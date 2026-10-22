---
name: release-openshell
description: Pick the latest qualified OpenShell prerelease and tag its commit as stable. Create and qualify a prerelease first when none exists.
metadata:
  internal: true
---

# Release OpenShell

For the intended release version and branch, inspect the latest passing
prerelease and changes since the previous stable release. Present the candidate
to the maintainer. Once approved, dispatch Release from that branch:

```shell
gh workflow run release.yml --ref main -f tag=vX.Y.Z
```

Use the support branch instead of `main` for a previous minor version. Release
selects the highest-numbered `vX.Y.Z-pre.N` reachable from that branch with a
successful Pre-release run triggered by that tag or dispatched on the same branch,
and matching passing `release-tag-v1` qualification evidence. Missing or expired evidence blocks
promotion. Inspect the selected candidate in the promotion job summary.
The entire Pre-release run must succeed, including publication. If qualification
passed but publication failed, rerun the failed jobs before promoting the candidate.

Release creates `vX.Y.Z` at that exact commit, then rebuilds and publishes all
stable artifacts without rerunning qualification. Embedded versions change, so
stable artifacts are not byte-identical to the qualified prerelease. An existing
stable tag may be retried only if it already points to the selected commit.
Stable images are saved as OCI archives during the build and pushed under the
stable version tags during publication. Their SBOMs are verified before updating
`latest`; the qualified prerelease's commit-SHA image tags remain unchanged.

If no prerelease exists, agree on the version and source commit, then create and
push `vX.Y.Z-pre.1`. Prerelease tag pushes start Pre-release. If the tag was
created using `GITHUB_TOKEN`, dispatch Pre-release explicitly on the intended branch:

```shell
gh workflow run release-prerelease.yml --ref main -f tag=vX.Y.Z-pre.1
```

Wait for the entire Pre-release run to pass before promoting it. Stable tag pushes do not
start Release. Release Auto-Tag creates and dispatches prereleases on `main`.

Stable releases serialize across branches. A release older than the highest
stable Git tag publishes versioned artifacts without moving GHCR `latest`, the
GitHub latest release, npm `latest`, or snap `latest/stable`. Its npm package
uses `release-X.Y`; snap files remain available in its GitHub Release rather than
updating a Snap Store support track. Docs retain an
immutable version and advance latest only for a newer version.

Watch the stable release run and report its result.
