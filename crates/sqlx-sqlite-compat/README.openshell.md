# SQLx SQLite compatibility copy

This is the crates.io sqlx-sqlite 0.9.0 source, archive SHA-256
`488e99c397a62007e4229aec669a179816339afc6d2620ca6fa420dbee2e982c`. Its Rust source is unchanged. Full MIT/Apache license notices are copied
from the upstream sqlx 0.9.0 archive, SHA-256
`378620ccc25c62c89d8be1c819e76a88d59bdcc3304733330788948e619bfd71`.
The normalized manifest selects libsqlite3-sys 0.39.1 with column metadata
and disables publication. SQLite 3.54.1 fixes RUSTSEC-2026-0459.

SQLx 0.9.0 caps libsqlite3-sys below the patched version. Upstream's bound
has been relaxed, but a patch release is still requested in
[SQLx #4516](https://github.com/transact-rs/sqlx/issues/4516). Remove this copy and the
workspace patch when a compatible SQLx release accepts the patched binding.
