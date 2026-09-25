# Cryptography and FIPS

OpenShell routes first-party security-sensitive cryptography through
`openshell-crypto`. The workspace selects AWS-LC as the production backend.
The interface supports a future system-OpenSSL backend; the current production
implementation does not assert FIPS compliance, and strict posture requests fail
closed.

## Backend boundary

Application code owns protocol choices, authorization policy, and persisted
formats. The backend owns cryptographic implementations and key resources.
`CryptoBackend` provides randomness, incremental SHA-256, and AES-256-GCM;
`ProtocolBackend` adapts Rustls, certificate signing, key import/generation, and
JWT operations. Backend neutrality preserves explicit algorithm choices required
by existing protocols and stored data.

Signing keys retain backend ownership and may refuse private-key export.
rcgen encodes certificates using those keys. Persisted CA metadata is parsed
without a cryptographic verification backend; parsing does not establish trust.
The proxy checks certificate/key matching through the selected TLS provider and
retains the original CA certificate in issued chains.

Backend failures propagate to callers without selecting another implementation.
Authentication failures must not expose plaintext or secret-bearing diagnostics.
Existing ciphertext layouts, digest inputs, JWT algorithms, and protocol versions
remain compatibility constraints when adding or changing a backend.

## Selection and initialization

Consumer crates inherit the workspace's backend choice and enable integration
features on the facade. A build without the default backend must install a
context before facade use. Select the context before constructing clients,
listeners, or dependencies that initialize process-wide crypto providers.

Explicit context selection controls first-party TLS builders even when a
dependency initialized Rustls first. Without explicit selection, those builders
preserve an embedder's installed provider. JWT adapters retain jsonwebtoken's
process-global provider constraints; that provider cannot be replaced safely.
Neither behavior redirects dependency-owned cryptography automatically.

## Contributor rules and coverage

Route new first-party security-sensitive hashing, randomness, encryption,
signing, verification, and TLS/PKI/JWT operations through `openshell-crypto`.
If an operation is missing, extend the facade and backend implementation rather
than calling an external cryptographic implementation from an application crate.
Test backend dispatch, failure handling, and any affected compatibility contract.

Protocol and parsing types may remain in application code. Non-security uses
and dependency-owned operations require explicit classification; do not claim
that the selected backend covers them or silently expand an existing exception.
The [crate README](../crates/openshell-crypto/README.md#compatibility-and-exclusions)
records current coverage, including remaining artifact-integrity hashes, policy
cache fingerprints, UUID entropy, SSH, and other dependency-owned operations.
Review changes against that scope. Cargo features and contributor instructions
alone do not prove exclusive backend ownership.

## OpenSSL and FIPS follow-up

Backend capability reporting describes that backend's operations. A backend name,
successful operation, dynamic link, or clean dependency scan alone does not
establish deployment compliance. A production OpenSSL/FIPS profile requires:

- A defined supported feature set and disposition for every security-sensitive
  crypto path, including dependencies and all shipped processes.
- Dynamic linking to the intended system OpenSSL and provider packages in the
  supported runtime image, with recorded versions and provenance.
- Separate evidence for provider ownership, effective provider policy, host
  operating mode, and actual TLS configurations. A strict requirement must
  reject missing evidence or unsupported operations without fallback.
- TLS policy validation for clients, listeners, and reload paths, including the
  TLS 1.2 Extended Master Secret requirement for the intended FIPS profile.
- Checks of the selected build graph and shipped artifacts, including dynamic
  dependencies, bundled crypto, and an accurate dependency manifest. Required
  evidence must fail validation when unavailable.
- Tests in the qualified target environment covering TLS/mTLS, JWT, persisted CA
  loading, credential encryption, and negative startup/algorithm cases.

These are follow-up requirements, not guarantees of the current backend.
Implementation details and extension APIs live in the
[crypto crate README](../crates/openshell-crypto/README.md).
