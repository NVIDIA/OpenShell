# OpenShell crypto backend

`openshell-crypto` owns first-party crypto backend selection. AWS-LC is the only
production implementation. This change preserves TLS algorithms, Ed25519 gateway
JWTs, P-256 certificate keys, native trust roots, and credential envelope formats.
The interface is intended to support a system-OpenSSL backend for regulated
deployments, related to [#900](https://github.com/NVIDIA/OpenShell/issues/900).
This stage implements AWS-LC only. An OpenSSL proof of concept will validate the
provider integration separately; this is not a FIPS build or compliance claim.

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

Integration features (`tls-tonic`, `tls-hyper`, `tls-kube`, `tls-sqlx`) activate
dependencies. The `aws-lc` feature supplies their AWS-LC choices conditionally.
These libraries still own their crypto selection internally; they do not consult
`CryptoContext`. Cargo feature unification does not prevent direct library use.
A second backend must adapt these integrations and the application startup path.
Disabling this crate's feature alone does not remove dependency-owned crypto
from the entire product graph.

The later OpenSSL build must use system shared libraries without vendoring,
respect system provider configuration, and verify the resulting linked artifacts.
Linking and module qualification are build/deployment concerns, separate from the
Rust key and primitive contracts. The proof of concept will test those concerns
and the Rustls provider integration before a production OpenSSL backend is added.

## Lifecycle and posture

`default_context()` lazily selects AWS-LC when that feature is enabled. An embedder can call
`install_default_context(context)` before first use. Reinstalling a clone of the
same context succeeds; installing a different context fails even if names match.
There is no live backend switching. Independent contexts can be used without
changing process state, including in contract tests.

`tls::provider()` constructs the selected context's provider.
`tls::ensure_default_provider()` retains an existing Rustls process default and
returns it; it does not attest ownership. OpenShell configurations use facade
client/server builders instead of Rustls's implicit builders. If a context was
explicitly selected before facade use, these builders use that context even if
another library already initialized Rustls. Otherwise they preserve an embedder's
installed provider. Key loading, custom verification algorithms, and the gateway
client-certificate verifier use the same configuration-provider policy.
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
SPIFFE RustCrypto verification, and non-Rust client runtimes. AWS SDK HTTPS also
retains its dependency-owned selection. Non-security content hashes and ordinary
scheduling randomness are not migrated. No SSH or PQC capability is asserted by
the primitive capability report. OpenSSL, strict policy, module version discovery,
and deployment qualification belong in follow-up work.

Runtime refresh replay hashes and derived token IDs, bearer-cache fingerprints,
Sandbox Protocol request digests and request-ID entropy, Kubernetes/VM runtime
fence entropy, VM socket-directory entropy, and rootfs staging-token entropy use
the selected backend.
These operations retain SHA-256, UUID v4 encoding where applicable, and existing
hex encodings. Backend failures propagate; callers must not substitute another
implementation or continue with a placeholder identity.

The remaining first-party uses require explicit classification; the facade is
not a whole-application crypto coverage claim:

| Remaining use | Current scope and follow-up |
| --- | --- |
| VM image/archive digest verification and cached supervisor validation (`openshell-driver-vm`) | Security-relevant artifact integrity remains outside this runtime credential migration. Moving it requires covering the streaming readers, embedded-artifact cache, and build-time digest generation together; it must be addressed before claiming exclusive backend ownership. |
| UUID generation outside Sandbox Protocol request envelopes | Includes runtime identities, authentication nonces, and session identifiers as well as ordinary correlation IDs. These still use the UUID library's entropy source. They are not attested by context posture; a follow-up must classify each use and propagate entropy failure through currently infallible constructors. |
| DNS policy contract fingerprints (`openshell-supervisor-network::policy_dns`) | These bind cached DNS state to policy and are security-relevant. They remain outside this migration; migrating the cache identity API and its failure handling is required for exclusive backend ownership. |
| Credential-storage names (`credentials`, Kubernetes Secrets, Vault) | Deterministic namespace derivation, not encryption or proof of authorization. These retain their current hashing implementation and stored names; backend coverage is not asserted for them. |
| Endpoint IDs and pagination fingerprints | Deterministic identification/request matching, not authentication. These remain outside the selected-backend contract. |
| Debug token fingerprints | Diagnostic display only; direct hashing remains outside the contract even though the input is a credential. |
| Schema compatibility tests, content-cache identities, retry jitter, test fixtures | Non-authentication uses remain unchanged. |

Cargo feature selection does not prevent a crate from adding another crypto
dependency. Review first-party security-sensitive operations against this scope;
no source-scanning boundary lint is installed.

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
`cargo tree -p openshell-crypto --no-default-features --edges normal,build`.
Existing bootstrap, credential-store, gateway TLS/OIDC, and proxy tests exercise the
migrated consumers. The cargo-deny Ring restrictions and their explicit wrapper
exceptions remain in force.
