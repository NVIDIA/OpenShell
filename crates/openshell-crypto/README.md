# openshell-crypto

Single point of cryptographic backend selection for the workspace. Every TLS,
PKI, JWT, AEAD, and RNG operation routes through this crate, along with hashing
that serves a cryptographic purpose, so a FIPS build is one Cargo feature rather
than an audit of every call site. Content and revision hashing is deliberately
out of scope — see [Boundaries](#boundaries).

**No other crate may name a crypto backend directly.** The workspace `rustls`,
`tokio-rustls`, and `rcgen` entries deliberately declare no backend feature;
adding one back links `ring` unconditionally and silently defeats the FIPS build.

## Build modes

| Feature | Backend | Algorithms |
|---|---|---|
| *(none)* — default | `ring` | rustls/russh defaults, including ChaCha20-Poly1305 and X25519 |
| `fips` | AWS-LC in FIPS mode | FIPS-approved only |

```shell
cargo build -p openshell-server                   # default
cargo build -p openshell-server \
  --no-default-features --features fips,telemetry  # FIPS (needs CMake + Go)
```

There is deliberately no opposite `backend-ring` feature. Cargo features are
additive, so two mutually exclusive backend features can always both end up
enabled — and a dependency resolving that toward `ring` (sqlx does exactly this)
would produce a non-FIPS build that still looked like one. `ring` is an
unconditional dependency and `fips` is a one-way switch.

`--no-default-features` is required for the gateway because sqlx's backend comes
from *its* features rather than the process default; a `compile_error!` in
`openshell-server` enforces it.

FIPS mode is compile-time only. rustls derives `require_ems` from its own `fips`
feature at compile time, so one binary cannot serve both modes.

## Usage

Install the provider once per process, at the entry point, before any TLS:

```rust
openshell_crypto::install_default_provider();
openshell_crypto::verify_fips_posture()?;
```

Every `ClientConfig::builder()` and `ServerConfig::builder()` call then inherits
the FIPS suite and group restrictions — no provider threading required.

`verify_fips_posture()` is the runtime half of the compile-time guarantee. It
catches a build where `fips` reached this crate but not `rustls`, which would
otherwise produce a non-approved provider with no visible symptom.

For anything that needs a backend explicitly:

```rust
let key = openshell_crypto::generate_pki_keypair()?;        // ECDSA P-256
let sealed = openshell_crypto::aead::seal(&key, aad, pt)?;  // AES-256-GCM
let digest = openshell_crypto::sha256(bytes);
let alg = openshell_crypto::jwt_algorithm();                // EdDSA or ES256
let prefs = openshell_crypto::ssh::preferred();             // russh algorithm sets
```

## Boundaries

Algorithm restriction comes from `rustls::crypto::default_fips_provider()`, not
a hand-maintained suite list, so the approved set tracks rustls's view of the
module's validated boundary.

Three things this crate cannot fix, each documented at its definition:

- **SSH implementations.** `ssh::preferred()` restricts negotiation, but russh
  implements those algorithms with `ed25519-dalek`, `p256`, and RustCrypto AES —
  no validated module. Accepted because the SSH transport sits inside the mTLS
  boundary and performs no authentication of its own.
- **`sqlx`.** Selects a provider from its own Cargo features rather than the
  process default, and prefers `ring` when both are enabled, so
  `openshell-server` forwards the backend choice separately and a
  `compile_error!` rejects the ambiguous combination.
- **Content and revision hashing.** Policy revisions, profile catalogs, and
  image digests still use RustCrypto `sha2`. Those are content-addressing rather
  than security functions; key and credential-identifier hashing is routed here.
- **`aws-smithy-http-client`.** Constructs its own provider, so AWS SDK calls use
  `ring` regardless of this crate.

`mise run fips:audit` reports the residual `ring` surface in a FIPS build.
See `docs/security/fips.mdx` for the operator-facing view and
`architecture/build.md` for how this fits the workspace feature scheme.
