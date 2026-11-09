# Temporary SQLx SQLite security backport

This is the published `sqlx-sqlite` 0.9.0 crate with its SQLite dependency
constraint changed to `>=0.39.0, <0.40.0`. The minimum excludes versions affected
by [RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html).
The upper bound follows the upstream changes
[94aafe3](https://github.com/transact-rs/sqlx/commit/94aafe3a68884d923b0798a767c8d7f6cfda89d2)
and [10462fa](https://github.com/transact-rs/sqlx/commit/10462fa4414c6c7f1ed1d39bb31678e3b726878c),
which have not yet been published in a SQLx release.

The Rust sources are unchanged. The archive's license-path placeholders are
replaced with the complete license texts from the published source commit.
Its unused lockfile, workspace manifest template, and Cargo cache metadata are
omitted. A targeted Git whitespace attribute preserves upstream rustdoc hard
line breaks in `src/connection/deserialize.rs`.

- Source: <https://crates.io/crates/sqlx-sqlite/0.9.0>
- Published source commit: `003b698e99e024f3621b8043a2426fde5b741171`
- Archive SHA-256: `488e99c397a62007e4229aec669a179816339afc6d2620ca6fa420dbee2e982c`
- Licenses: [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE)

OpenShell's Cargo workspaces patch this crate by path so the build continues to
use registry dependencies without a Git-source exception. Their lockfiles select
`libsqlite3-sys` 0.39.1, which bundles SQLite 3.54.1. SQLite features and the
SQLx 0.9 API remain unchanged.

Remove this directory, the workspace patches, the root workspace exclusion,
the Git attributes, and the license-header exclusion once a published SQLx
release accepts a patched `libsqlite3-sys`. Update the affected lockfiles and
rerun the persistence and dependency-policy checks when removing the backport.
