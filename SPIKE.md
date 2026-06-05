# Docs Website Branch Spike

This orphan branch proves a generated Fern docs branch layout for
[NVIDIA/OpenShell#1296](https://github.com/NVIDIA/OpenShell/issues/1296).

## Source Snapshots

| Version | Source ref | Source commit |
| --- | --- | --- |
| `dev` | `origin/main` | `c3964a6513ca000b85f1016973c90a08eafb1dc3` |
| `latest` | `v0.0.57` | `97986d9059da8092455ec63648ef6de6b231a291` |
| `v0.0.36` | `v0.0.36` | `4483c860e0f2567880fa6dc8d0f90e0bcd7a5140` |

## Layout

```text
fern/
├── docs.yml
├── versions/
│   ├── dev.yml
│   ├── latest.yml
│   └── v0.0.36.yml
├── pages-dev/
├── pages-latest/
└── pages-v0.0.36/
```

`latest` is configured in `fern/docs.yml` as the current release snapshot,
generated from `v0.0.57`. This first-pass spike does not publish a dedicated
`v0.0.57` route.

Expected routes:

- `/openshell/latest/...` renders the `v0.0.57` snapshot.
- `/openshell/dev/...` renders the `origin/main` docs snapshot.
- `/openshell/v0.0.36/...` renders the `v0.0.36` snapshot.

## Validation

Run Fern validation:

```shell
mise run docs
```

Run a local Fern preview:

```shell
mise run docs:serve
```

If `FERN_TOKEN` is available, run a non-production hosted preview:

```shell
npx --yes fern-api@5.40.0 generate --docs --preview --id openshell-docs-website-spike-1296
```

## Notes

- This branch intentionally contains generated docs-site artifacts rather than
  OpenShell application source.
- `mise.toml` and `tasks/docs.toml` are included only so the normal docs
  validation and serve commands work in the orphan worktree.
- No production publish workflow is included. Promotion to a long-lived
  `docs-website` branch should add CI-managed generation and a carefully scoped
  publish workflow after the layout is accepted.
- PR preview behavior remains unchanged because this spike does not modify
  `.github/workflows/branch-docs.yml`.
