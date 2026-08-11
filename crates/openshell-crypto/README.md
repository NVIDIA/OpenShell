# openshell-crypto

Backend selection for everything that uses the process-default cryptographic
provider: OpenShell's own TLS, PKI, JWT, AEAD, RNG, and hashing that serves a
cryptographic purpose. For those, a FIPS build is one Cargo feature rather than an
audit of every call site.

`sqlx` and the AWS SDK construct their own provider and so are explicit
exceptions, selected by `openshell-server` and enforced separately. Content and
revision hashing is also out of scope. See [Boundaries](#boundaries).

**Name a crypto backend directly only where a dependency leaves no choice**, and
keep those exceptions in `openshell-server` where they are enumerated and
separately enforced. The workspace `rustls`, `tokio-rustls`, and `rcgen` entries
deliberately declare no backend feature; adding one back links `ring`
unconditionally and silently defeats the FIPS build.

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

FIPS mode is selected at build time, not at runtime. That is a choice rather than
a technical necessity — `ring` is already linked in a FIPS build, so one artifact
could dispatch at runtime. Build-time selection keeps *which module is in use* a
property of the artifact rather than of a code path.

`verify_fips_posture()` covers only what uses the process-default provider. It
reads `CryptoProvider::get_default()` and therefore cannot see `sqlx`'s or the AWS
SDK's provider, each of which selects its own; those are enforced separately by a
`compile_error!` and by a unit test in `openshell-server`. See
`architecture/build.md` for the full table.

On rustls 0.23 `require_ems` is additionally derived from the `fips` feature, but
that mechanism is going away in 0.24 — see the migration note in
`architecture/build.md`. The conclusion does not change.

## Usage

Install the provider once per process, at the entry point, before any TLS:

```rust
openshell_crypto::install_default_provider();
openshell_crypto::verify_fips_posture()?;
```

Every `ClientConfig::builder()` and `ServerConfig::builder()` call then inherits
the FIPS suite and group restrictions — no provider threading required.

`verify_fips_posture()` is the runtime half of the compile-time guarantee *for the
process-default provider*. It inspects the installed provider, so it catches both
a build where `fips` reached this crate but not `rustls`, and a process default
installed by something that won the race. Either would otherwise produce a
non-approved provider with no visible symptom. It says nothing about `sqlx` or the
AWS SDK — see above.

Library code that builds a TLS client without a binary entry point having run
first should call `ensure_default_provider()` instead — it fills in a missing
provider and never replaces one, so it is safe from a library.

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

What this crate does not cover, each documented at its definition:

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
- **`aws-smithy-http-client`.** Constructs its own provider, so
  `openshell-server` selects the AWS SDK's TLS backend explicitly
  (`provider_refresh::aws_crypto_mode`) rather than inheriting the process
  default.
- **`aws-sigv4`.** Depends on RustCrypto `hmac` and `sha2` unconditionally with
  no backend feature, so SigV4 request signing runs outside the validated module
  in every build mode — this one is not fixable by configuration at any layer.

`mise run fips:audit` reports the residual `ring` surface in a FIPS build.
See `docs/security/fips.mdx` for the operator-facing view and
`architecture/build.md` for how this fits the workspace feature scheme.
