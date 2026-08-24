# RFC 0014 Supplement - Release Version Selection

This supplement defines how OpenShell selects the next pre-release version
after a stable release during the `0.x` series.

## Algorithm

1. Find the latest stable tag and collect commits after it on the target branch.
2. Classify commits using Conventional Commits:
   - `feat:` requests a minor release.
   - A commit marked with `!` or a `BREAKING CHANGE` footer requests a minor
     release during `0.x`.
   - `fix:` and `deps:` request a patch release.
   - Other commit types do not request a release by default.
3. Select the highest requested bump. Minor takes precedence over patch. If no
   commit requests a release, do not create a pre-release.
4. Increment the stable version to obtain the pre-release base version. From
   `0.2.0`, a patch becomes `0.2.1` and a minor becomes `0.3.0`.
5. Create a `-pre.1` Git tag before building and qualifying a new base version.
   If that base already has a pre-release, increment the pre-release number.
6. Treat that base version as fixed for the weekly train. If a patch train has
   started, stage any later breaking change that requires a minor release for
   the following week's train.
7. Fail the branch check if the pre-release base version is not greater than the
   latest stable version.

| Latest stable | Commits since stable | Next pre-release |
| --- | --- | --- |
| `0.2.0` | `fix:` | `0.2.1-pre.1` |
| `0.2.0` | `feat:` | `0.3.0-pre.1` |
| `0.2.0` | `feat!:` | `0.3.0-pre.1` |
| `0.2.0` | Only `docs:` or `chore:` | No pre-release |

Git tags are the version source of truth; release versions are never committed
to source. If a commit has multiple tags, select stable over pre-release, then
use Semantic Version order; use the commit SHA when neither exists. After
tagging the selected commit with its stable version, delete its `-pre.N` tags.
Stored pre-release artifacts retain their provenance metadata.

## Release Please

[Release Please](https://github.com/googleapis/release-please-action) can
implement the commit classification and base-version calculation. During
`0.x`, its manifest configuration should include:

```json
{
  "bump-minor-pre-major": true,
  "bump-patch-for-minor-pre-major": false
}
```

The release workflow owns the `-pre.N` suffix and stable publication. An explicit
`Release-As: x.y.z` footer may override the calculation with maintainer
approval.
