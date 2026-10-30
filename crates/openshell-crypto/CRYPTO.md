# Cryptography and FIPS

OpenShell routes first-party security-sensitive cryptography through
`openshell-crypto`. Executable packages select AWS-LC as the production backend.
The opt-in `openssl` feature supplies a system-OpenSSL backend for explicit
context selection. Neither backend asserts deployment FIPS compliance, and strict
posture requests fail closed. Application startup, dependency-owned transports,
and downstream packaging/qualification remain separate OpenSSL integration work.

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

Reusable libraries inherit a backend-neutral workspace dependency and enable
integration features on the facade. Executable packages select AWS-LC explicitly;
standalone library tests select it through development dependencies. An embedder
must select a backend and install its context before facade use. Select the
context before constructing clients,
listeners, or dependencies that initialize process-wide crypto providers.

Explicit context selection controls first-party TLS builders even when a
dependency initialized Rustls first. Without explicit selection, those builders
preserve an embedder's installed provider. JWT adapters retain jsonwebtoken's
process-global provider constraints; that provider cannot be replaced safely.
Neither behavior redirects dependency-owned cryptography automatically. Enabling
OpenSSL does not replace the AWS-LC default; an embedder must install its context
explicitly. System libraries and provider configuration belong to the deployment;
the backend does not modify provider policy.

Runtime TLS configuration uses the facade's `try_client_builder` and
`try_server_builder` APIs (including explicit protocol-version variants). A
provider with no usable cipher suites or compatible key-exchange groups produces
a configuration error without panic or fallback. The older infallible builders
are compatibility helpers, not the runtime error-handling contract.

## Contributor rules and coverage

Route new first-party security-sensitive hashing, randomness, encryption,
signing, verification, and TLS/PKI/JWT operations through `openshell-crypto`.
If an operation is missing, extend the facade and backend implementation rather
than calling an external cryptographic implementation from an application crate.
Test backend dispatch, failure handling, and any affected compatibility contract.

Protocol and parsing types may remain in application code. Non-security uses
and dependency-owned operations require explicit classification; do not claim
that the selected backend covers them or silently expand an existing exception.
The [crate README](README.md#compatibility-and-exclusions)
records current coverage, including remaining artifact-integrity hashes, policy
cache fingerprints, UUID entropy, SSH, and other dependency-owned operations.
Review changes against that scope. Cargo features and contributor instructions
alone do not prove exclusive backend ownership.

## Dependency guardrail

The root `deny.toml` uses cargo-deny's `bans.deny` and `wrappers` rules to reject
unapproved direct dependencies on named crypto implementations. AWS-LC and OpenSSL
are accessible through `openshell-crypto` and the explicitly listed libraries
that own their own crypto operations. Native `*-sys` crates and the OpenSSL
protocol adapters have separate rules to prevent bypassing the provider boundary.
`openssl-src` is banned without wrapper exceptions: OpenSSL must come from the
system, including when enabled transitively through another dependency.
The catalog also covers RustCrypto hashes, MACs, ciphers, and signature libraries.
Protocol/parsing types remain usable in application crates.

Cargo Deny in Branch Checks enforces the policy with all workspace features and
no target filter, including build and development dependencies. Renaming a
dependency in `Cargo.toml` does not bypass a package-name ban. An allowed wrapper
on one path does not excuse another unapproved direct parent of the same package.
Run the policy and its offline regression fixtures with:

```shell
mise run rust:deny:policy
```

Run just the regression fixtures with `mise run rust:deny:crypto-test`. They use
the cargo-deny version pinned in `mise.toml`, as does the Branch Checks job; the
fixtures reject a mismatched tool version before checking dependency graphs. They use
local stub packages to exercise cargo-deny without compiling cryptography or
downloading dependencies. They test allowed provider paths, shared-dependency
bypasses, aliases, build/dev/target dependencies, and unapproved intermediary
wrappers. The normal policy check separately validates the real dependency graph.

### Existing direct first-party exceptions

These are package-level allowances, not permission to add new security-sensitive
operations outside the facade. Migration must preserve protocols and stored
identities and propagate backend failures. Remove an allowance when its last use
is migrated or deleted.

| Dependency | Allowed application crates | Classification |
| --- | --- | --- |
| `sha2` | `openshell-core` | Endpoint identities and canonical policy hashes; policy binding still requires migration. |
| `sha2` | `openshell-driver-docker`, `openshell-driver-kubernetes-secrets`, `openshell-driver-vault` | Deterministic volume and credential-storage names, not authentication. |
| `sha2` | `openshell-driver-kubernetes`, `openshell-driver-podman` | Destination-trust ConfigMap names and operator-bundle generation labels, not authenticity proofs. Trust relies on immutable staging, exact-byte validation, and TLS verification; see the README's destination-trust classification. |
| `sha2` | `openshell-driver-vm`, `openshell-isolation-interface`, `openshell-supervisor-network` | Artifact integrity, outer-fence evidence, and DNS policy binding; security-sensitive migration remains required. |
| `sha2` | `openshell-gateway-interceptors` | Provider-profile snapshot revision hashes; content identity outside backend dispatch. |
| `sha2` | `openshell-supervisor-process` | Diagnostic debug-token fingerprints. |
| `sha2`, `hmac` | `openshell-server` | Naming, coordination, request matching, and tests, plus security-sensitive bearer-cache keys, launch-session derivation, policy/review bindings, credential handles, and protected mutation fingerprints. The security-sensitive uses must migrate; the HMAC exception is for `grpc::mutation_replay`'s protection against offline guessing. |
| `rsa` | `openshell-server` | Development dependency for OIDC test keys. Cargo-deny cannot restrict a wrapper exception to development dependencies. |
| `sha1` | `openshell-supervisor-network` | WebSocket accept-handshake hashing, a protocol requirement rather than cryptographic authentication. |

The other wrappers in `deny.toml` cover dependency-owned operations: SSH,
TLS/X.509/JWT, AWS SigV4, OAuth PKCE, database protocols, archive handling,
artifact/content hashing, and implementation-to-implementation dependencies.
The existing Rustls/Ring exceptions support the Z3 downloader; wrapper rules
constrain direct parents, not an entire ancestry exclusively to Z3. Dependency
upgrades that introduce a new parent must receive review instead of automatically
adding that parent to the allowlist.

This is an enumerated dependency guardrail, not a source scanner or a FIPS
attestation. It does not automatically recognize a new cryptographic crate,
detect hand-written cryptography, inspect calls through re-exports, or prevent
new uses inside an already allowed package. Generic entropy sources such as
`rand`, `getrandom`, and `uuid` remain outside this catalog because ordinary
scheduling and dependency-owned entropy coexist with the outstanding
security-sensitive UUID uses. Standalone Cargo workspaces require their own
policy invocation. Review source changes as well as manifests, extend the catalog
when introducing a crypto library, and document every new exception here with
its scope and migration requirement. Do not weaken the policy merely to pass CI.

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

These are follow-up requirements, not guarantees of the current backends. The
OpenSSL protocol adapters also have infallible callbacks and provider-ownership
limitations documented in the crate README; backend tests do not resolve those
deployment requirements.
Implementation details and extension APIs live in the
[crypto crate README](README.md).
