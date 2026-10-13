---
name: release-openshell
description: Pick the latest qualified OpenShell prerelease and tag its commit as stable. Create and qualify a prerelease first when none exists.
metadata:
  internal: true
---

# Release OpenShell

For the intended release version, pick the latest prerelease whose Release
Qualification job passed. Confirm that its qualification summary matches the
tag and commit. Present the candidate and changes since the previous stable
release to the maintainer; once approved, tag that exact commit as `vX.Y.Z`.

If no prerelease exists, agree on the version and source commit, then create and
push `vX.Y.Z-pre.1`. Wait for qualification to pass before promoting it.

Both prerelease and stable tag pushes start Release Tag. Release Auto-Tag uses
an explicit dispatch because its `GITHUB_TOKEN` pushes do not trigger workflows.
Watch the stable release run and report its result.
