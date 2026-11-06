# Embedded credential issuer

`openshell-credential-issuer` owns credential backend selection, secret storage and resolution, refresh-material storage-key translation, built-in token minting, refresh scheduling/recovery, and the existing external-driver UDS transport. The gateway embeds this library in its existing process. This crate has no executable, listener, generated service contract, or deployment configuration.

## Boundary

The gateway uses the object-safe `CredentialIssuer` trait. `EmbeddedCredentialIssuer` implements it using the existing encrypted database, Kubernetes Secrets, or Vault drivers. Driver capability negotiation, timeout behavior, batching, staged object IDs, and opaque handles retain the existing credential-driver contract.

Choose embedded or external issuer deployment at initial setup; conversion in either direction is unsupported. This change implements only the embedded issuer. Its legacy-record adoption upgrades the same embedded deployment and selected backend, not deployment mode. An external storage driver over UDS is still a backend of the embedded issuer, not an external issuer service.

The gateway still owns provider records and profiles, workspace authorization, attachment validation, provider expiration, public credential export, and supervisor delivery. The gateway's thin `credentials` facade adapts those concerns to this library. The issuer does not depend on `openshell-server` or gateway-private protobufs.

`IssuerConfig` projects the existing backend settings. The gateway separately owns the default-off `enable_versioned_credentials` maintenance-window activation; see [gateway configuration](../../docs/how-it-works/gateways/configuration.mdx). Enabling it is an operator attestation that incompatible writers have been drained, not a fence against an old binary.

## Persistence

The `persistence` module re-exports the existing `DbCredstoreObjectStore` port and its conditional-write types from `openshell-driver-db-credstore`. The gateway supplies a small adapter over its already-open SQLite/Postgres `Store`; the issuer does not open a second pool or duplicate the SQL implementation. The adapter only translates encrypted object records, write conditions, and errors. Envelope encryption and key management remain in the database driver.

`CredentialRefresh` is separate from storage-only consumers. Its shared `RefreshRuntime` owns the existing cancellation-safe state machine, process-wide admission/execution limits and weak keyed mutex registry, retries, uncertainty markers, rotated-material retention, staging/cleanup, and sequential worker sweep. The immutable `TokenMinter` registry contains only the four existing built-ins. Resolved mint requests and outputs have no value-bearing debug or serialization implementation.

Before activation, `RefreshStateStore` uses the existing field-preserving V1/V2 adapter and temporary `GatewayRefreshCommit` provider-CAS path. Activated mode instead uses issuer-owned grant encoding in `refresh::persistence` and owner-qualified references in `references`. Frozen readers remain upgrade-compatible, but startup retires verified legacy refresh rows after the corresponding issuer recovery state is durable. Exact source-version retirement intents and atomic source-deletion/completion prevent a failed cleanup from discarding material or silently accepting a changed source. Already-active compatible upgrades run this retirement too, without reimporting revoked grants. Both modes retain owned data-pool PostgreSQL refresh leases and the existing process-local coordination.

A reference preserves its original driver and opaque identity; explicit metadata binds it to the durable issuer namespace, workspace, typed owner, logical key, epoch, and output manifest. The backend candidate stays private to that manifest. Adoption starts at version 1 without moving backend objects. New secret activations increment checked, durable versions; bookkeeping and retries do not. One owner-record CAS exposes all outputs of a grant and its terminal refresh journal together, so multi-output credentials cannot be mixed across activations. Backend I/O is staged outside the transaction, with non-secret recovery evidence for uncertain writes. Tombstones and reclamation claims prevent resurrection and deletion racing a new live link.

Successful refresh history does not accumulate full terminal grant states in the hot owner row. The runtime retains the current activation there and archives superseded exact-intent digests and original receipts as compact immutable conditional-store sidecars. Successfully deleted candidates similarly leave durable denial evidence outside the owner row; failed reclamation and uncertain backend-write recovery stay intact. Arbitrary operation IDs/epochs are not safe pruning watermarks, so minimal receipts and anti-resurrection evidence are retained indefinitely. Static provider-update markers and protected-write recovery remain replayable. See [successful-history retention](REFERENCE_TRANSITIONS.md#successful-history-retention) for crash ordering and enumeration limitations.

Protected static-write retries revalidate the durable journal before reconstructing candidates. If another exact retry completed while a newer write reclaimed the old candidates, the retry returns its original references without backend writes or version changes. A completion receipt does not revive revoked references, and an unfinished abandoned journal remains rejected.

`RefreshRuntime::with_references` has no gateway provider observation or commit callback. The gateway validates configuration and publishes the initial binding; subsequent refreshes change only issuer manifests and grants. Snapshot builders capture resolved values, versions, and expiration once and hash those versions, never values. The existing subject-token cache is scoped by the captured reference/epoch/version while retaining resolution-before-cache ordering. `RefreshCommitSink` carries non-secret committed reference/version hints with immutable provider/grant IDs, effective epoch and validated embedded namespace at the existing worker/manual publication points. Names remain fanout hints, never authorization; malformed or legacy snapshots do not invent version evidence. Export and caller cancellation do not gain unconditional publication.

The optional public `strategy_name` supports the four canonical built-ins with explicit enum compatibility. Unknown names and enum integers on new inputs fail rather than falling back. Custom minters, RPCs, remote watches/caching, and service packaging remain later phases. See [reference transitions](REFERENCE_TRANSITIONS.md) for the embedded commit and migration contract.

## Owners and compatibility

`SecretOwner` scopes each operation to a workspace and one of three kinds:

- `Provider`: the existing provider UUID and name.
- `Sandbox`: the sandbox UUID for its SSH host identity.
- `SupervisorInstance`: the sandbox UUID owning a launch-material assignment, not the shared supervisor route or host.

Only the issuer's owner adapter translates internal kinds into legacy provider-shaped driver requests. SSH keys keep `sandbox-ssh-<sandbox UUID>` and launch material keeps `sandbox-instance-<sandbox UUID>`. Existing workspace fields, backend paths, envelope ownership, keys, and opaque handles are unchanged. Activated reference metadata enforces these typed bindings in the issuer; it does not imply that an unchanged external driver gained its own new authorization protocol.

`StoreSecrets::object_id` identifies a particular staged write, not its owner. Distinct candidate IDs remain essential: a losing candidate must not overwrite or delete another writer's committed secret. Refresh-material keys retain the same domain-separated SHA-256 bytes, computed through `openshell-crypto` with failures propagated.

Raw resolution returns backend expiration metadata without applying provider policy. The gateway combines provider and backend expiration and withholds expired values. Refresh material has no provider expiration and retains its existing zero-time backend-expiration cutoff.

## Backend write recovery

Call `references::backend_recovery::validate_activation` with the effective `IssuerConfig` and negotiated extensions before any inline credential/material conversion or irreversible activation marker. An external UDS driver's name does not establish recovery support: it must advertise `openshell.credentials.recoverable-immutable-write`. Missing support fails activation before conversion; ordinary legacy-mode connections remain available. The Kubernetes driver service advertises this capability; the existing Vault UDS service does not.

Explicit staged object IDs must be unique per immutable attempt and different from the owner-default ID. The database driver derives a durable, owner/key/attempt-qualified opaque ID through `openshell-crypto`; retry decrypts and verifies an existing candidate without rewriting its ciphertext. Kubernetes retries a conflicting attempt-owned Secret only after verifying its managed ownership, logical key, and actual value in memory. A different value is a conflict, not an overwrite. Existing handles/paths and legacy owner-default allocation behavior are preserved.

The in-tree Vault adapter reuses the deterministic attempt path for a retry of the same protected intent. A retry may create another backend KV version; this is not exactly-once physical I/O. Its legacy contract does not provide generic immutable-write recovery guarantees for arbitrary UDS plugins. New execution IDs and durable recovery evidence prevent uncertain output writes from replacing live candidates, but an unknown write without a returned handle is not automatically enumerable or safe to delete. Retain that evidence for backend-specific recovery rather than claiming every orphan was reclaimed.

## Tests

Issuer tests cover built-in token exchanges/error classification, refresh commit uncertainty and cleanup, cross-runtime cancellation/coalescing, registry/configuration/transport behavior, owner translation, storage batching, response correlation, and material-key compatibility. The existing server tests continue to cover provider orchestration, refresh races/recovery, credential export, SSH identity, launch material, and delivery through the extracted implementation.

The `test-support` feature exposes the existing static backend and deterministic failure/concurrency hooks on `EmbeddedCredentialIssuer` to server tests. The hooks are not part of `CredentialIssuer`, so other implementations need only implement the storage contract even when this feature is enabled. The server's test helpers retain the same concrete issuer allocation used by its trait object. The feature is enabled by the server's dev-dependency and explicit test-support feature, not by release defaults. A dependency does not inherit its caller's `cfg(test)`.

```shell
cargo test -p openshell-credential-issuer
cargo test -p openshell-server --features test-support
```

Reference tests cover monotonic versions, atomic bundles, idempotent intent, grant lifecycle, shared-candidate reclamation, and concurrent resolution. Local protocol fixtures additionally exercise the real Vault/Kubernetes adapters and existing UDS transport for handle-preserving adoption, unique staging, backend outages/missing objects, and uncertain-write recovery. These fixtures do not replace live-cluster/backend qualification. Server migration tests exercise real encrypted SQLite records, inline/handle adoption, exact-identity restart recovery, internal secret ownership, and activation/downgrade gates. Remote RPCs, authentication, watches/caching, and service packaging remain later RFC 0023 work; embedded activation creates no new runtime artifact.
