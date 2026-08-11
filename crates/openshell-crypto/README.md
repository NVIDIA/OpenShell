# openshell-crypto

Single point of cryptographic backend selection for the workspace. Every TLS,
PKI, JWT, AEAD, hashing, and RNG operation routes through this crate so a FIPS
build is one Cargo feature rather than an audit of every call site.

**No other crate may name a crypto backend directly.** The workspace `rustls`,
`tokio-rustls`, and `rcgen` entries deliberately declare no backend feature;
adding one back links `ring` unconditionally and silently defeats the FIPS build.

## Build modes

| Feature | Backend | Algorithms |
|---|---|---|
| `backend-ring` (default) | `ring` | rustls/russh defaults, including ChaCha20-Poly1305 and X25519 |
| `fips` | AWS-LC in FIPS mode | FIPS-approved only |

```shell
cargo build -p openshell-server                  # default
cargo build -p openshell-server --features fips   # FIPS (needs CMake + Go)
```

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
  process default, so `openshell-server` forwards the backend choice separately.
- **`aws-smithy-http-client`.** Constructs its own provider, so AWS SDK calls use
  `ring` regardless of this crate.

`mise run fips:audit` reports the residual `ring` surface in a FIPS build.
See `docs/security/fips.mdx` for the operator-facing view and
`architecture/build.md` for how this fits the workspace feature scheme.
