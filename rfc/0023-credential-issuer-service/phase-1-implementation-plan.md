# Phase 1: embedded credential issuer extraction

## Scope and outcome

Implement phase 1 of [RFC 0023 at the requested revision](https://github.com/mrunalp/OpenShell/blob/b416373d6ac84bd67bb3802861d343a50703accc/rfc/0023-credential-issuer-service/README.md) as a behavior-preserving Rust library extraction. This plan was checked against local source revision `dbc0517a3103a1361194262a70800cf30c8fc939`.

Move credential backend orchestration out of `openshell-server` into `openshell-credential-issuer`. The gateway continues to embed that library in its existing process. Existing credential-driver crates remain the concrete backends; do not copy their implementations into the issuer.

Users keep the same commands, configuration, APIs, credentials, and deployment. There is no issuer executable, listener, image, Helm option, generated protocol, or additional shipped build artifact. Cargo will naturally compile the new library as an ordinary dependency of the existing gateway. No new e2e tests, fixtures, or lanes are required.

Phase 1 establishes the storage boundary and typed owners. It does **not** move the refresh engine or implement the RFC's final remote-service architecture.

## Decisions

### Reuse the existing credential persistence port

Use `DbCredstoreObjectStore` from `openshell-driver-db-credstore` as the embedded issuer's database persistence port. It already supplies the get, conditional put, and conditional delete operations that credential storage needs. Inject its implementation into the issuer rather than injecting `Arc<openshell_server::persistence::Store>`.

Keep a small gateway adapter implementing that port against the existing `Store`. The adapter may translate records, write conditions, and persistence errors, but it must not select drivers, construct credential envelopes, manage encryption keys, or resolve plaintext. The issuer owns credential persistence behavior; the gateway supplies access to its already-open database connection pools.

This chooses a narrow credential storage layer, not a wholesale extraction of `openshell-server::persistence`. The latter currently includes policy storage, sandbox image transactions, gateway-member checks, private protobuf descriptors, metrics, and lock ordering. Moving all of that is unnecessary to extract credential storage and would greatly expand a transparent phase 1 refactor. Do not duplicate the SQLite/Postgres implementation or create a second connection pool either.

The phase 1 extraction is the credential persistence **interface and orchestration**, not the general-purpose SQL implementation. Refresh-state persistence, advisory locks, and the refresh engine remain in the server for phase 2. The future standalone issuer will need its own adapter and refresh-state persistence; phase 1 does not claim that it can already run independently.

### Add one library crate, not a new service stack

Use this dependency direction:

```text
openshell-gateway
  -> openshell-server
       -> openshell-credential-issuer
            -> openshell-core / openshell-crypto as needed
            -> openshell-driver-db-credstore
            -> openshell-driver-kubernetes-secrets
            -> openshell-driver-vault
       -> gateway Store adapter implementing issuer's persistence port
```

The issuer must never depend on `openshell-server`, `ServerState`, gateway RPC modules, or gateway-private storage protobufs. Re-export the existing database port and its record/write types through the issuer's persistence module so gateway glue need not depend on concrete driver implementations. Do not add a separate interface crate unless an actual additional consumer requires it.

Reuse the existing async, TOML, tonic, and driver dependencies. Do not introduce another secret-management framework. Vault, Kubernetes Secrets, the encrypted database driver, and the existing UDS extension mechanism already provide the necessary storage implementations.

### Separate issuer storage from gateway provider semantics

Introduce an object-safe Rust `CredentialIssuer` trait implemented by `EmbeddedCredentialIssuer`. Its phase 1 surface is batch store, batch delete, batch resolve, handle validation/storage ownership, and negotiated extension metadata. Keep the existing backend-level `CredentialDriver` trait private to the issuer implementation where practical.

The trait uses issuer-owned requests carrying explicit owner identity, logical keys, opaque `CredentialHandle`s, existing handles, and optional per-write object identity. Batch resolution returns values and backend expiration metadata keyed to the requested logical keys. Retain `tonic::Status` internally to preserve the existing error mapping rather than introducing an unrelated error redesign.

Keep `openshell-server/src/credentials.rs` as a thin gateway facade during the migration. It owns an `Arc<dyn CredentialIssuer>` and preserves convenient provider-facing entry points while callers migrate. It may translate `Provider` metadata, combine provider/backend expiration, and translate durable deletion records; it must not contain the old registry, transport, backend, or key-derivation implementations. Every secret store/delete/resolve operation goes through the issuer trait, including requests originating in refresh code.

Do not make the issuer understand provider profiles, attachments, workspace authorization, provider CAS writes, mutation replay, placeholder identity, or supervisor delivery. Those remain gateway responsibilities.

### Introduce typed owners without changing stored identity

Define a Rust owner model with workspace plus an explicit kind:

- `Provider`: provider UUID and current provider name.
- `Sandbox`: sandbox UUID, for SSH host identity.
- `SupervisorInstance`: the existing assignment's sandbox UUID, for launch material.

Each secret request also carries its logical credential/material key. An optional per-write `object_id` identifies a staged object, not its owner or authorization epoch.

The issuer alone translates these kinds into the **unchanged** legacy `CredentialDriver` request fields:

| Internal owner | Legacy `provider` | Legacy `provider_id` | Workspace |
| --- | --- | --- | --- |
| Provider | Existing provider name | Provider UUID | Provider workspace |
| Sandbox | `sandbox-ssh-<sandbox UUID>` | Sandbox UUID | Sandbox workspace |
| SupervisorInstance | `sandbox-instance-<sandbox UUID>` | Sandbox UUID | Assignment workspace |

Current launch-material ownership is per sandbox assignment, not the shared supervisor route or host. Preserve that identity even though the RFC calls the owner kind `supervisor_instance`.

Remove synthetic `Provider` construction from `ssh_identity.rs`, `supervisor_pool.rs`, and refresh-material resolution. Legacy synthetic names remain only inside the issuer's compatibility adapter. Do not change backend paths, encrypted envelope ownership fields, handle bytes/metadata, logical keys, or candidate UUID generation as a side effect of adding owner types.

These are real kinds at the Rust boundary, not a new durable owner schema or new authorization enforcement in old external drivers. Persisted kind-aware ownership and authenticated gateway binding belong to later contracts. Do not advertise stronger cross-kind isolation than the unchanged backend protocol provides.

## Source migration map

| Current source | Phase 1 destination or responsibility |
| --- | --- |
| `openshell-server/src/credentials.rs`: registry, driver selection, config table parsing, built-in construction, extension negotiation | Issuer `config.rs`, `registry.rs`, and `embedded.rs` |
| Same file: backend `CredentialDriver` implementations, `RemoteCredentialDriver`, UDS connection/readiness, managed subprocess lifetime | Issuer `drivers.rs` and `transport/uds.rs`; preserve platform guards |
| Same file: storage batching, handle dispatch, partial-store cleanup, batch-response validation | Issuer storage implementation behind `CredentialIssuer` |
| Same file: `refresh_material_storage_key` and material-name/key translation | Issuer `refresh_material.rs`, preserving the exact domain-separated hash and backend keys |
| Same file: `ServerDbCredstoreObjectStore` and persistence-error mapping | Small server `credential_store.rs` adapter, injected into issuer construction |
| Same file: provider wrapper, `ResolvedProviderCredentials`, effective provider/backend expiration | Thin server facade; provider expiration remains gateway semantics |
| Same file: `StoredRefreshMaterialDeletion` input | Server converts to issuer-owned deletion inputs; generated storage type does not cross the boundary |
| Same file: static fake, failure injection, store/resolve gates | Issuer test support, with server forwarding helpers for existing tests |
| `openshell-server/src/lib.rs` | Project existing configuration into issuer options and construct the embedded implementation once |
| `grpc/provider.rs`, `grpc/provider_credentials.rs`, `provider_refresh.rs` | Keep orchestration; route their storage calls through the facade/issuer trait |
| `ssh_identity.rs`, `supervisor_pool.rs` | Pass typed owners rather than fake providers; keep lifecycle, CAS, cancellation, and cleanup logic |
| `compute/mod.rs`, `config_delivery/mod.rs`, `grpc/mod.rs` | Check constructor plumbing, delivery helpers, and extension reporting still use the same runtime |

Suggested layout:

```text
crates/openshell-credential-issuer/
  Cargo.toml
  README.md
  src/
    lib.rs                 # Rust trait and request/result types
    owner.rs               # Typed owner -> legacy driver scope
    config.rs              # Credential-specific settings and existing validation
    embedded.rs            # Embedded implementation, store/delete/resolve
    registry.rs            # Driver ownership and handle dispatch
    drivers.rs             # Existing backend adapters
    persistence.rs         # Re-exports of the existing DB object-store port
    refresh_material.rs    # Existing deterministic material-key translation
    transport/
      mod.rs
      uds.rs               # Existing external-driver transport, not issuer RPC
    test_support.rs        # Feature-gated fake driver and concurrency hooks
```

This is a decomposition of existing code, not a requirement to create an abstraction per file. The important boundary is the dependency graph, not the exact module count.

## Implementation sequence

Each step should compile and pass the relevant existing tests before the next. They can be reviewed as commits in one scoped PR; no intermediate commit changes storage formats.

### 1. Establish the library and inject database/config dependencies

1. Add the library crate with workspace package/lint settings and no binary target or build script. The root workspace already discovers `crates/*`.
2. Move the existing credential backend trait, registry, backend construction, legacy UDS transport, and resource-lifetime ownership into the library. Use the current driver protocol unchanged.
3. Move `ServerDbCredstoreObjectStore` into dedicated server glue and pass it as `Arc<dyn DbCredstoreObjectStore>`; preserve all error-code mappings and CAS conditions.
4. Replace the issuer's dependency on server `ConfigFile` with credential-specific options containing enabled/default driver names, the existing default storage table, and existing per-driver tables. The server still loads the configuration file; the issuer still performs the same credential-specific validation and backend parsing.
5. Preserve synchronous test constructors, asynchronous production construction, absent/unconnected-store behavior, database fallback rules, and optional UDS child ownership. The issuer must retain managed child handles across clones exactly as the runtime does today.
6. Wire the server facade to `EmbeddedCredentialIssuer` through the Rust trait. Preserve negotiated extension metadata returned by `GetGateway`.
7. Update Cargo dependencies and affected tracked lockfiles using existing tooling. Move direct Kubernetes Secrets/Vault runtime dependencies out of the server if no callers remain; route the database adapter's types through the issuer persistence re-exports.

Gate: the issuer compiles without any server dependency, and the gateway constructs the same drivers from unchanged configuration.

### 2. Move storage operations behind the issuer boundary

1. Move store/delete/resolve batching, driver lookup, handle normalization and validation, and partial-success cleanup into the issuer. Preserve existing concurrency, response correlation checks, missing/duplicate response handling, timeouts, and error precedence.
2. Add the typed owner/request model and the legacy driver-scope conversion inside the issuer. Pass provider metadata explicitly from the server facade.
3. Move refresh-material key derivation and material-name translation. Replace the synthetic provider used to resolve material with a typed storage request.
4. Convert gateway-private `StoredRefreshMaterialDeletion` records into issuer deletion requests in the server. Keep malformed-record checks, pending-deletion persistence, and retry orchestration unchanged.
5. Leave the facade's provider/backend expiration combination and `expired_keys` behavior intact. Raw issuer resolution must not accidentally impose the expired injectable credential's lifetime on refresh inputs or internal launch material; preserve the current handling of backend expiration and the existing `now_ms = 0` internal resolution paths.

Gate: the server's credential module contains only construction/adaptation and provider-specific behavior, not a second storage implementation.

### 3. Migrate every gateway consumer, including internal owners

1. Audit the current call sites rather than treating the RFC's approximate count as a checklist. Include provider create/update/delete, on-read inline-credential migration, credential export, refresh configuration/rotation/cleanup, SSH identity, and supervisor launch material.
2. Route each through the same trait-backed runtime. Keep provider authorization, validation against attached sandboxes, profile defaults, replay, mutation guards, and provider persistence in their current order.
3. Replace `SshIdentityStore::owner` and `supervisor_pool::material_owner` with typed owner construction. Preserve `SSH_HOST_PRIVATE_KEY`, the existing launch-material key, and all durable identity/assignment/candidate records.
4. Keep fresh per-write candidate/object IDs on SSH, launch, and refresh paths. Never substitute owner ID for staging ID: a losing writer must not overwrite or delete a winner's secret.
5. Check compute initialization, snapshot construction, push/poll delivery, and gateway extension reporting. They need no new protocol, revision calculation, or delivery mechanism.

Gate: there are no direct concrete backend calls outside the issuer and no synthetic provider owners outside its legacy compatibility adapter. The only remaining server database glue is the object-store adapter, not secret logic.

### 4. Relocate tests without losing test-only behavior

1. Move registry/config/transport/material-key/storage tests with the extracted implementation. Keep database-adapter tests in the server where the real `Store` is available.
2. Keep existing provider, credential-export, refresh, SSH identity, supervisor pool, and configuration-delivery tests in the server. They must exercise the extracted implementation through the same facade as production.
3. Expose the existing fake driver, store/resolve gates, counters, and failure injection under issuer `test-support`. A dependency does not inherit its caller's `cfg(test)`: gate these helpers with `cfg(any(test, feature = "test-support"))`, enable the issuer feature in the server's dev-dependency, and forward the server's existing `test-support` feature where needed. Do not add a release-default test backend.
4. Add only focused unit/in-process regression cases for the new boundary: exact owner-to-legacy field mapping, unchanged material-key derivation, existing persisted-handle resolution, staging identity propagation, and facade expiration behavior. Extend existing fixtures instead of introducing a new harness.
5. Use existing database fixtures to exercise persisted handles across reconstruction of the issuer runtime; an in-memory fake that only survives by cloning is not sufficient evidence of restart compatibility.

Gate: tests moved rather than silently dropped; cancellation/race/error-path coverage still runs across the new crate boundary.

### 5. Document the internal boundary and remove obsolete coupling

1. Add the issuer crate README describing embedding, the persistence port, typed owners, legacy compatibility, and what remains in the gateway.
2. Update the architecture table in `AGENTS.md` with the new library and review related contributor guidance using the existing skill-maintenance map. Do not expand public operating skills for an unchanged workflow.
3. Remove obsolete backend/transport code and imports from the server; keep only useful compatibility facades, not duplicate implementations.
4. Do not change published configuration docs, SDKs, CLI commands, deployment files, release workflows, or e2e definitions. There is no new user workflow to document.

Gate: the final diff is an internal extraction with targeted regression tests and implementation documentation only.

## Compatibility invariants

- No changes to public provider/refresh RPC shapes or `proto/credential_driver.proto`, including external UDS driver capability negotiation.
- No changes to configuration field names, defaults, accepted/rejected combinations, environment variables, key-encryption-key file location, or key selection. Issuer options are an internal projection, not a new user configuration section.
- Existing opaque handles, driver names, metadata, backend object paths, encrypted envelopes/AAD, and persisted rows keep their current meaning. No schema/data migration or startup rewrite is introduced for typed owners.
- Existing inline-provider migration remains where it runs today and uses the extracted store path. Do not add a new migration mode or remove existing compatibility handling.
- Provider/backend expiration takes the same earliest applicable value; expired credentials remain withheld with the same failure behavior. Keep export selection/redaction, partial-failure cleanup, and public status mapping unchanged.
- Refresh scheduling, concurrency limits, Postgres advisory lock keys, workspace lock ordering, authorization epochs, staged writes, uncertain-mint recovery, and provider CAS behavior remain unchanged. Phase 1 redirects secret access, not the refresh state machine.
- SSH host fingerprints remain stable across restart/upgrade; launch material remains resolvable; cancellation, failed cleanup, deletion retry, and candidate-race semantics remain unchanged.
- No new caching, value logging, secret-bearing `Debug` output, or value hashing for snapshot revisions. Continue routing cryptographic operations through the existing `openshell-crypto` boundary and preserve documented exceptions.
- No rollout flag, backend switch, secret export/import, extra process, or operator action. With unchanged durable formats, reverting the refactor needs no reverse data migration.

## Validation

Use the repository's existing test infrastructure. New unit cases are appropriate for an internal API boundary; new e2e tests and build artifacts are not.

During implementation, run focused tests after each extraction step, then these final checks in the normal development environment:

```shell
mise x -- cargo fmt --all -- --check
mise x -- cargo check -p openshell-credential-issuer -p openshell-server -p openshell-gateway --all-targets
mise x -- cargo clippy -p openshell-credential-issuer -p openshell-server -p openshell-gateway --all-targets -- -D warnings
mise x -- cargo test -p openshell-credential-issuer
mise x -- cargo test -p openshell-server --features test-support
mise x -- cargo test -p openshell-driver-db-credstore -p openshell-driver-kubernetes-secrets -p openshell-driver-vault
mise run rust:lockfiles:check
mise run rust:deny:policy
```

The server check/test environment needs the existing Z3 dependency as documented in `CONTRIBUTING.md`. Use the established Nix/system setup or existing `vendored-z3` feature, not a new build artifact or packaging path. Review crypto dependency-policy changes if moved hashing imports require a narrowly scoped existing-exception update; do not broaden exceptions to accommodate the new crate indiscriminately.

Run `mise run test:rust:postgres` against the existing disposable database setup to retain confidence in the real-store adapter and existing refresh-lock/CAS behavior. This is the existing backend integration lane, not a new e2e suite. Ordinary repository CI and any already-required e2e checks continue unchanged; this plan adds no new e2e coverage, service fixture, or test image.

Inspect `cargo tree -p openshell-credential-issuer` for the dependency boundary and Cargo metadata for a library-only target. Check that release-default dependency features do not enable issuer test support. Review the diff for accidental changes to public/driver protobufs, SQL migrations, deployment/release files, snapshot revisions, or refresh algorithms.

## Explicitly deferred

- Stable credential references, versions, grant records, handle-to-reference migration, and version-aware environment revisions.
- Moving refresh-state records, scheduling, advisory locks, minting, and recovery into the issuer; minter traits/registry and `strategy_name`.
- `CredentialStore`, `CredentialRefresh`, or `TokenMinter` service protobufs and RPC handlers.
- Remote issuer configuration, mTLS/SPIFFE identity, gateway/workspace binding, watches, caches, and subject-token cache reordering.
- A standalone binary, container, Helm deployment, additional release artifacts, or remote-service e2e coverage.

These are RFC phases 2–5. Keeping them out is what makes phase 1 independently reviewable and transparent to users.

## Definition of done

- The existing gateway uses one embedded issuer implementation through a Rust trait for every secret storage operation.
- Credential driver orchestration, transport, storage dispatch, and material-key translation no longer live in `openshell-server`; concrete existing driver crates are reused.
- Gateway-internal consumers use typed owners and no longer manufacture provider resources for storage access.
- The issuer has no server/private-proto dependency, and persistence remains on the existing database through the narrow injected port.
- Existing durable data and external driver contracts work without migration or reconfiguration.
- Moved tests and existing gateway/backend tests pass, including concurrency and cleanup cases; new testing is limited to unit/in-process boundary coverage.
- No new user-visible behavior, e2e tests, deployment requirements, or shipped artifacts are introduced.
