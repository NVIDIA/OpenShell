# RFC 0014 Supplement - Release Version Selection

This supplement defines how OpenShell selects the next release candidate
version after a stable release during the `0.x` series.

## Algorithm

1. Find the latest stable tag and collect commits after it on the target branch.
2. Classify commits using Conventional Commits:
   - `feat:` requests a minor release.
   - A commit marked with `!` or a `BREAKING CHANGE` footer requests a minor
     release during `0.x`.
   - `fix:` and `deps:` request a patch release.
   - Other commit types do not request a release by default.
3. Select the highest requested bump. Minor takes precedence over patch. If no
   commit requests a release, do not create a release candidate.
4. Increment the stable version to obtain the candidate base version. From
   `0.2.0`, a patch becomes `0.2.1` and a minor becomes `0.3.0`.
5. Publish `-rc.1` for a new base version. If that base already has a release
   candidate, increment the RC number instead.
6. Fail the branch check if the candidate base version is not greater than the
   latest stable version.

| Latest stable | Commits since stable | Next candidate |
| --- | --- | --- |
| `0.2.0` | `fix:` | `0.2.1-rc.1` |
| `0.2.0` | `feat:` | `0.3.0-rc.1` |
| `0.2.0` | `feat!:` | `0.3.0-rc.1` |
| `0.2.0` | Only `docs:` or `chore:` | No candidate |

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

The release workflow owns the `-rc.N` suffix and stable promotion. An explicit
`Release-As: x.y.z` footer may override the calculation with maintainer
approval.
