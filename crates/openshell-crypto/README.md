# OpenShell crypto backend

`openshell-crypto` owns first-party crypto backend selection. AWS-LC is the only
production implementation. This change preserves TLS algorithms, Ed25519 gateway
JWTs, P-256 certificate keys, native trust roots, and credential envelope formats.
It does not introduce OpenSSL or a FIPS build mode.

## Boundaries

`CryptoBackend` defines randomness, incremental SHA-256, and AES-256-GCM without
crypto-library types. `ProtocolBackend` adds Rustls, rcgen, and jsonwebtoken
adapters. These adapters retain their protocol libraries' validation and encoding;
they do not expose AWS-LC types. A later native OpenSSL TLS integration may need
an additional transport adapter; this interface does not claim to provide one.

Callers use `aead`, `pki`, `tls`, and `jwt`, or an explicit `CryptoContext`.
Certificate policy and JWT claim validation remain at their existing callers.
The rcgen adapter returns key pairs that own their signing implementation; a
future backend must supply its own implementation (for example, rcgen remote
keys) rather than silently using rcgen's compiled default. Raw signing and
verification currently use the protocol adapters, not a new general signature API.

Shared manifests do not select a provider. Consumers of dependencies that select
their own providers enable `tls-tonic`, `tls-hyper`, `tls-kube`, or `tls-sqlx` on
this crate. Those features retain the current dependency selections and do not
make the dependencies use `CryptoContext` at runtime. Adding another backend
requires adapting these integrations as well as implementing the traits.

## Lifecycle and posture

`default_context()` lazily selects AWS-LC. An embedder can call
`install_default_context(context)` before first use. Reinstalling a clone of the
same context succeeds; installing a different context fails even if names match.
There is no live backend switching. Independent contexts can be used without
changing process state, including in contract tests.

`tls::provider()` constructs an explicit provider from the selected context.
`tls::ensure_default_provider()` preserves an embedder's existing process default
and returns the actual installed provider. This preserves existing SDK behavior.
It must not be used as evidence that the process default belongs to the context.

JWT initialization likewise preserves an existing process provider.
`install_jwt_provider()` reports whether this call installed it; jsonwebtoken 10
has no public getter for verifying a previously installed provider. JWT adapters
retain that library's algorithm/key binding and claim-validation checks. Select a
custom context before initializing either protocol library, including indirect
initialization by dependencies. Neither global provider can be replaced safely.

`CryptoContext::verify_posture(false)` reports the context's capabilities, not
ownership of process globals. A strict request is always rejected in this stage.
The module version is explicitly unknown because the backend wrapper does not
provide that information through the API used here. Backend identity, enabled
algorithms, and a successful operation are not deployment FIPS evidence.

## Compatibility and exclusions

AEAD stores a random 12-byte nonce and appends a 16-byte tag to ciphertext.
AAD construction, envelope version, key IDs, and encoding remain in the credential
driver. Random nonces do not guarantee uniqueness; existing key-volume and
rotation constraints still apply. Authentication failures expose no plaintext or
distinction between wrong keys, AAD, nonce, ciphertext, or tags.

Coverage excludes dependency-owned SSH/russh primitives, AWS SigV4 signing,
SPIFFE RustCrypto verification, and non-Rust client runtimes. AWS SDK HTTPS also
retains its dependency-owned selection. Non-security content hashes and ordinary
scheduling randomness are not migrated. No SSH or PQC capability is asserted by
the primitive capability report. OpenSSL, strict policy, module version discovery,
and deployment qualification belong in follow-up work.

## Extending and checking

Implement both traits without importing application crates. Retain provider/key
resources for the full operation lifetime, propagate entropy and authentication
failures, and never fall back after a failure. Document unsupported algorithms
and avoid secret-bearing diagnostics. Add protocol adapters rather than moving
certificate or authorization policy into primitive implementations.

Run `cargo test -p openshell-crypto` for known-answer crypto, tampering, JWT
validation, context substitution, and isolated global-provider tests. Existing
bootstrap, credential-store, gateway TLS/OIDC, and proxy tests exercise the
migrated consumers. `mise run crypto:check` rejects direct backend imports and
feature selections outside this crate. The existing cargo-deny Ring ban remains
in force. A source scan cannot attest the behavior of transitive dependencies.
