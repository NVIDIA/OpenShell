# OpenShell crypto backend

See [Cryptography and FIPS](CRYPTO.md) for the architecture,
contributor rules, and production OpenSSL/FIPS follow-up requirements.

`openshell-crypto` owns first-party crypto backend selection. AWS-LC remains the
application default; an optional system-OpenSSL backend supports explicit context
selection by embedders. The facade preserves TLS algorithms, Ed25519 gateway
JWTs, P-256 certificate keys, native trust roots, and credential envelope formats.
The OpenSSL implementation builds on the standalone proof of concept following
[the generic backend refactor](https://github.com/NVIDIA/OpenShell/pull/3351).
Application-wide OpenSSL selection and downstream FIPS qualification remain
separate work; enabling this backend is not a FIPS build or compliance claim.

## Boundaries

`CryptoBackend` defines randomness, incremental SHA-256, and AES-256-GCM without
crypto-library types. `ProtocolBackend` adds Rustls, rcgen, and jsonwebtoken
adapters. These adapters retain their protocol libraries' validation and encoding;
they do not expose AWS-LC types. A later native OpenSSL TLS integration may need
an additional transport adapter; this interface does not claim to provide one.

Digest creation, updates, and finalization return `Result` so backends can report
provider and operation failures. Callers discard a digest after an update error;
the one-shot SHA-256 helper propagates the first failure without fallback.

Callers use `aead`, `pki`, `tls`, and `jwt`, or an explicit `CryptoContext`.
Certificate policy and JWT claim validation remain at their existing callers.
`pki::KeyPair` owns a backend `SigningKey` and implements rcgen 0.14's
`PublicKeyData` and `SigningKey` traits directly.
The backend generates/imports keys, signs messages, and exports PKCS#8 DER.
PEM wrapping and certificate encoding remain in the facade. Public keys expose
algorithm-specific bytes and SPKI; private exports are fallible, including for
non-exportable keys. Certificate encoding never requires private-key export.
`pki::Certificate` retains public issuance parameters separately from the encoded
certificate, allowing generated certificates to be used as issuers without
retaining private keys. Persisted proxy CAs use `pki::issuer_from_der` and keep
their original certificate bytes in issued chains.
Persisted CA keys are imported through the selected backend. Provider resources
must remain alive for the full key lifetime.
Default certificate serial numbers and key identifiers are derived through the
selected digest backend, preserving the existing SHA-256 derivation without
depending on rcgen's compiled crypto implementation.

## Build selection

The crate's default `aws-lc` feature selects the current implementation. The root
workspace declares that choice once in its `openshell-crypto` dependency;
application crates inherit it rather than choosing a backend independently.
Standalone examples select their own default through their path dependency.
Disabling crate defaults removes its AWS-LC implementation and requires an
explicit context before use; use without initialization fails closed with an
initialization panic. This mode is for embedders and backend contract tests, not
an independently runnable OpenShell product configuration.

Integration features (`tls-tonic`, `tls-kube`, `tls-sqlx`) activate
dependencies. The `aws-lc` feature supplies their AWS-LC choices conditionally.
These libraries still own their crypto selection internally; they do not consult
`CryptoContext`. Cargo feature unification does not prevent direct library use.
A second backend must adapt these integrations and the application startup path.
Disabling this crate's feature alone does not remove dependency-owned crypto
from the entire product graph.

### Selecting system OpenSSL

An embedder enables `openssl` and disables crate defaults:

```toml
openshell-crypto = { path = "crates/openshell-crypto", default-features = false, features = ["openssl"] }
```

Install the context before facade use or JWT initialization:

```rust,ignore
use openshell_crypto::{CryptoContext, OpenSsl, install_default_context};

install_default_context(CryptoContext::new(Box::new(OpenSsl)))?;
```

The feature makes `OpenSsl` available without selecting it automatically. When
both backends are enabled, `CryptoContext::default()` still chooses AWS-LC. With
AWS-LC disabled, use before installation fails closed. Inspect Cargo's resolved
graph for other dependencies that re-enable AWS-LC. This feature adds no gateway
flag, image, or supported OpenSSL-only whole-application build.

Use OpenSSL 3 development libraries, a C compiler, and pkg-config. The Nix shell
supplies these; Homebrew OpenSSL works on macOS. Set `OPENSSL_NO_VENDOR=1` and
`OPENSSL_STATIC=0` for shared-library builds, then inspect `otool -L` (macOS) or
`ldd` (Linux). No vendoring feature is enabled. Runtime libraries, provider
packages and configuration must be supplied and verified by the deployment.

The backend uses OpenSSL's default library context and configuration without
loading modules or overriding property queries. Configure the process before
startup; do not unload providers or change policy during operations. Keys retain
OpenSSL resources for their lifetime. Capabilities describe implemented operations,
not runtime algorithm availability. `provider_version` stays unknown because the
library version does not identify the module that performed an operation.

Certificate keys support P-256, P-384, Ed25519 and RSA, with PEM/PKCS#8 import and
PKCS#8 export. Encrypted PEM keys, including those with an empty passphrase, are
rejected without prompting for a password. RSA generation uses 2048 bits. P-521 certificate keys are rejected:
rcgen 0.14 exposes that descriptor only with AWS-LC enabled. Existing P-521 users
must retain AWS-LC until this limitation is resolved. This backend uses exportable
software keys and does not add HSM or PKCS#11 loading.

TLS uses `rustls-openssl` 0.4.1 with TLS 1.2/1.3, without its `fips`, vendored or
prefer-post-quantum features. The jsonwebtoken 10 adapter includes compatibility
guards for malformed HMAC signatures, EC key consistency and algorithm/curve
binding, RSA public-component bounds, JOSE RSA-PSS salt lengths and fixed-width
EC JWK coordinates. Certificate key import also checks EC key consistency and
requires RSA keys in the 2048–8192-bit range, matching AWS-LC.
RSA certificate imports and JWT signing also validate private-key consistency,
including the private exponent, primes, and CRT parameters, before using the key.
RSA signing/verification, EC signing, and EC JWK extraction reuse the validated
OpenSSL key instead of parsing it again through the upstream adapter. Claim
validation stays in jsonwebtoken. AEAD setup errors remain distinct from authentication errors;
tentative plaintext is cleared on failure and returned only after authentication.

At AEAD finalization, all OpenSSL errors map to `CryptoError::Authentication`.
The [EVP AEAD interface](https://docs.openssl.org/3.0/man3/EVP_EncryptInit/#aead-interface)
reports unsuccessful authentication through the finalization result; it does not
provide a portable error-stack discriminator between a bad tag and a late provider
failure across providers. A provider failure at this stage therefore shares that
classification. Setup and update failures remain `CryptoError::Operation`.
No failure releases tentative plaintext or triggers a backend fallback.

The optional `tls-tonic`, `tls-kube`, and `tls-sqlx` features can each compile with
`--no-default-features --features openssl,<feature>`; CI checks those combinations
individually. These features expose integration dependencies, not OpenSSL transport
adapters for them. Compilation does not establish that dependency-owned clients
use OpenSSL at runtime or make an OpenSSL-only whole-application build supported.

Linux CI checks that the OpenSSL-only TLS test executable dynamically resolves
both `libssl` and `libcrypto`. The Nix devshell supplies those libraries; this is
a linkage regression check, not validation against a distro's OpenSSL packages,
provider configuration, or FIPS operating mode. Distro qualification remains
downstream work.
The test explicitly creates a native OpenSSL TLS context to retain `libssl` for
this assertion; the backend itself uses Rustls for TLS protocol handling.

Both protocol adapters are external community-maintained dependencies:
[`rustls-openssl`](https://github.com/tofay/rustls-openssl) and
[`jsonwebtoken-openssl`](https://github.com/arckoor/jsonwebtoken-providers).
As of 2026-10-23, upstream rustls-openssl has released 0.4.2, while the JWT adapter's
repository remains unarchived with recent activity. This is not a support or
security-maintenance commitment from OpenShell or those projects. The exact
`rustls-openssl =0.4.1` pin preserves the reviewed provider behavior until a
deliberate upgrade is validated. `jsonwebtoken-openssl =1.0.0` matches our
jsonwebtoken 10 provider API; version 2 targets jsonwebtoken 11. Dependency
updates must rerun interoperability, rejection, provider-failure, and linkage
checks. Distro packagers need both Rust adapter crates as well as system OpenSSL;
packaging Rust sources does not permit vendoring the native OpenSSL library.

Protocol limitations remain: Rustls hash/HKDF callbacks and JWT JWK thumbprint
hashing cannot return backend errors; adapter helpers can panic on provider
failure. The TLS adapter also uses direct OpenSSL SHA operations and low-level
EC key generation that do not establish provider-module ownership. First-party
TLS setup uses `tls::try_client_builder()` / `tls::try_server_builder()` and their
`_with_protocol_versions` variants. These return configuration errors when the
selected provider has no usable ciphers or compatible key-exchange groups, without
switching providers or relaxing the requested protocol versions. The older
infallible builders remain for API compatibility and panic on configuration errors;
runtime consumers should use the fallible variants. This backend does not
promise panic-free protocol operation or a provider-qualified TLS path. These
limitations require disposition during downstream integration and qualification.

The pinned `rustls-openssl` 0.4.1 verifier prints OpenSSL error stacks directly to
stderr through `std::dbg!`, including in release builds, when verification returns
an OpenSSL error. Peer-controlled malformed signatures can trigger this path;
the output bypasses application logging controls and can create repeated
diagnostic noise. Verification still fails. Upstream
[0.4.2 removes this output](https://github.com/tofay/rustls-openssl/blob/0.4.2/src/verify.rs#L347).
Upgrade and validate the dependency before deploying this TLS path; that release
also changes provider routing and FIPS reporting, so the upgrade requires more
than removing the diagnostic call.

## Lifecycle and posture

`default_context()` lazily selects AWS-LC when that feature is enabled. An embedder can call
`install_default_context(context)` before first use. Reinstalling a clone of the
same context succeeds; installing a different context fails even if names match.
There is no live backend switching. Independent contexts can be used without
changing process state, including in contract tests.

`tls::provider()` constructs the selected context's provider.
`tls::ensure_default_provider()` retains an existing Rustls process default and
returns it; it does not attest ownership. Directly constructed OpenShell TLS
configurations use the facade provider, including the CLI health-check connector.
The dependency-owned clients listed below retain their own selection paths.
If a context was explicitly selected before facade use, these configurations use
that context even if another library already initialized Rustls. Otherwise they
preserve an embedder's installed provider. Key loading, custom verification
algorithms, and the gateway client-certificate verifier use the same
configuration-provider policy.
Explicit protocol-version constraints remain unchanged. A provider incompatible
with the requested versions fails during construction rather than falling back.
This rule controls first-party configs; it cannot override dependency-owned TLS.

JWT initialization likewise preserves an existing process provider.
`install_jwt_provider()` reports whether this call installed it; jsonwebtoken 10
has no public getter for verifying a previously installed provider. JWT adapters
retain that library's algorithm/key binding and claim-validation checks. Select a
custom context before JWT initialization, including indirect initialization by
dependencies. Neither global provider can be replaced safely.

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
SPIFFE JWT verification, and non-Rust client runtimes. SPIFFE uses its AWS-LC
backend directly, outside the facade. AWS SDK HTTPS also
retains its dependency-owned selection. Non-security content hashes and ordinary
scheduling randomness are not migrated. No SSH or PQC capability is asserted by
the primitive capability report. Application-wide OpenSSL integration, strict
policy, module version discovery, and deployment qualification remain follow-ups.

Migrated paths for operator certificate fingerprints, runtime refresh replay hashes and derived token
IDs, bearer-cache fingerprints, Sandbox Protocol request digests and request-ID
entropy, Kubernetes/VM runtime
fence entropy, VM socket-directory entropy, and rootfs staging-token entropy use
the selected backend. The [dependency exception inventory](CRYPTO.md#existing-direct-first-party-exceptions)
records remaining direct implementations, including other bearer-cache and
session-identity paths.
These operations retain SHA-256, UUID v4 encoding where applicable, and existing
hex encodings. Backend failures propagate; callers must not substitute another
implementation or continue with a placeholder identity.

The remaining first-party uses require explicit classification; the facade is
not a whole-application crypto coverage claim:

| Remaining use | Current scope and follow-up |
| --- | --- |
| Reqwest clients (OIDC/JWKS, token exchange, provider refresh, Vault, token grants, telemetry) | These use Rustls's process-default provider after ensuring one exists; they do not necessarily honor an explicitly selected `CryptoContext`. The OpenSSL follow-up must supply compatible preconfigured TLS or another supported transport integration and test actual provider use. |
| Kubernetes client TLS (`kube-client` 0.99) | The AWS-LC-enabled client attempts to install AWS-LC as the Rustls process default. It does not consult `CryptoContext`; the OpenSSL follow-up must adapt this transport before claiming selected-backend coverage. |
| Outer-fence evidence digest (`openshell-isolation-interface::contract`) | The digest binds generation and native enforcement evidence using `sha2` through `Sha256Digest::compute`. This security-relevant hash remains outside facade dispatch and must be migrated with failure propagation before claiming exclusive backend ownership. |
| VM image/archive digest verification and cached supervisor validation (`openshell-driver-vm`) | Security-relevant artifact integrity remains outside this runtime credential migration. Moving it requires covering the streaming readers, embedded-artifact cache, and build-time digest generation together; it must be addressed before claiming exclusive backend ownership. |
| UUID generation outside Sandbox Protocol request envelopes | Includes runtime identities, authentication nonces, and session identifiers as well as ordinary correlation IDs. These still use the UUID library's entropy source. They are not attested by context posture; a follow-up must classify each use and propagate entropy failure through currently infallible constructors. |
| DNS policy contract fingerprints (`openshell-supervisor-network::policy_dns`) | These bind cached DNS state to policy and are security-relevant. They remain outside this migration; migrating the cache identity API and its failure handling is required for exclusive backend ownership. |
| Credential-storage names (`credentials`, Kubernetes Secrets, Vault) | Deterministic namespace derivation, not encryption or proof of authorization. These retain their current hashing implementation and stored names; backend coverage is not asserted for them. |
| Provider-refresh advisory-lock keys | Deterministic database lock selection for coordinating refreshes, not authentication or encryption. These remain outside the selected-backend contract. |
| Service-routing hostname labels (`openshell-core::app_listener`) | Deterministic public DNS naming, not authentication or proof of authorization. The existing truncated SHA-256/base32 encoding remains unchanged and uses `sha2`; gateway and application paths share the implementation. |
| Endpoint IDs and pagination fingerprints | Deterministic identification/request matching, not authentication. These remain outside the selected-backend contract. |
| Debug token fingerprints | Diagnostic display only; direct hashing remains outside the contract even though the input is a credential. |
| Destination-trust generation labels (`openshell-server` network trust, Podman operator staging, Kubernetes ConfigMap naming, VM staged-snapshot checks) | Deterministic identity derivation for naming and generation equality, not encryption or proof of authorization. Trust decisions use the gateway's normalization, immutable staging, exact-byte validation, and TLS verification rather than these digests. These retain `sha2` directly. |
| Schema compatibility tests, content-cache identities, retry jitter, test fixtures | Non-authentication uses remain unchanged. |

The [cargo-deny dependency guardrail](CRYPTO.md#dependency-guardrail) rejects
unapproved direct dependencies on the catalogued crypto implementations. It
preserves explicitly classified exceptions, including security-sensitive uses
awaiting migration. Review operations inside those crates against that scope;
the dependency check does not inspect source-level usage.

Durable proxy CA loading uses backend key import and `pki::issuer_from_der`.
The helper uses `x509-parser` without verification features to read the subject,
key usage, and subject key identifier. Missing identifiers use the selected
backend's SHA-256 over SPKI, truncated to 20 bytes. It rejects trailing bytes,
malformed metadata, and subject names that rcgen cannot represent without loss
(including repeated attribute OIDs and multi-valued RDNs).
Parsing does not establish trust or verify signatures; the proxy separately
checks certificate/key matching through the selected TLS backend.
rcgen's `x509-parser` feature stays disabled: in 0.14.10 it also compiles CSR
verification that requires AWS-LC or Ring. No fork or fallback backend is needed
for CA import, and the parser's former Ring exception is removed from `deny.toml`.
The standalone facade also excludes AWS-LC when default features are disabled.
The build-time Z3 archive downloader retains the narrowly allowed Rustls/Ring
wrappers in `deny.toml`; context capabilities do not attest build tools.

## Extending and checking

Implement both traits without importing application crates. Retain provider/key
resources for the full operation lifetime, propagate entropy and authentication
failures, and never fall back after a failure. Document unsupported algorithms
and avoid secret-bearing diagnostics. Add protocol adapters rather than moving
certificate or authorization policy into primitive implementations.

Run `cargo test -p openshell-crypto` for known-answer crypto, tampering, JWT
validation, key import/export, encryption compatibility, context substitution,
and an actual TLS handshake after process-default preemption.
`cargo test -p openshell-crypto --no-default-features --test independent_backend`
exercises independent test-only key and AEAD implementations without AWS-LC or
Ring. Inspect that boundary with
`cargo tree -p openshell-crypto --no-default-features --edges normal,build,dev`.
Branch Checks runs this test separately from workspace tests and rejects Ring or
AWS-LC in the dependency tree, including build and test dependencies.
It also runs OpenSSL-only and dual-backend tests and Clippy, and rejects Ring,
AWS-LC and vendored OpenSSL from the OpenSSL-only crate graph. Run locally with
system OpenSSL available:

```shell
OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=0 cargo test --locked -p openshell-crypto --no-default-features --features openssl
OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=0 cargo test --locked -p openshell-crypto --features openssl
OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=0 cargo clippy --locked -p openshell-crypto --no-default-features --features openssl --all-targets -- -D warnings
OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=0 cargo clippy --locked -p openshell-crypto --features openssl --all-targets -- -D warnings
cargo tree --locked -p openshell-crypto --no-default-features --features openssl --edges normal,build,dev
```

For Nix, run these commands from `nix develop .#crypto`, entered outside the
default development shell. CI uses this native toolchain for both OpenSSL-only
and dual-backend checks. The default shell's release toolchains supply an
unprefixed system AWS-LC whose `libcrypto`/`libssl` names and symbols collide with
OpenSSL. The crypto shell selects Nix OpenSSL explicitly and lets Cargo build
symbol-prefixed AWS-LC for the dual-backend tests.

Tests cover known answers, tampering, chunked AEAD, PKI/CA import, JWT algorithms
and claims, TLS 1.2/1.3 mutual authentication and rejected peers, and AWS-LC/OpenSSL
interoperability. A subprocess uses an unsatisfiable property query to test
unavailable algorithms without modifying its parent process. Its ignored child
test is invoked by the parent automatically. These are backend contract tests,
not target RHEL qualification or product E2E tests.

Existing bootstrap, credential-store, gateway TLS/OIDC, and proxy tests exercise the
migrated consumers. The cargo-deny Ring restrictions and their explicit wrapper
exceptions remain in force.
