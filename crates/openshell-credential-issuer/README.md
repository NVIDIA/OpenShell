# Embedded credential issuer

`openshell-credential-issuer` owns credential backend selection, secret storage and resolution, refresh-material storage-key translation, and the existing external-driver UDS transport. The gateway embeds this library in its existing process. This crate has no executable, listener, generated service contract, or deployment configuration.

## Boundary

The gateway uses the object-safe `CredentialIssuer` trait. `EmbeddedCredentialIssuer` implements it using the existing encrypted database, Kubernetes Secrets, or Vault drivers. Driver capability negotiation, timeout behavior, batching, staged object IDs, and opaque handles retain the existing credential-driver contract.

The gateway still owns provider records and profiles, workspace authorization, attachment validation, provider expiration, public credential export, refresh scheduling/minting/recovery, and supervisor delivery. The gateway's thin `credentials` facade adapts those concerns to this library. The issuer does not depend on `openshell-server` or gateway-private protobufs.

`IssuerConfig` is an internal projection of the existing credential settings. The embedding process loads configuration and passes credential-specific settings to the issuer. This does not add or change any operator-facing configuration fields.

## Persistence

The `persistence` module re-exports the existing `DbCredstoreObjectStore` port and its conditional-write types from `openshell-driver-db-credstore`. The gateway supplies a small adapter over its already-open SQLite/Postgres `Store`; the issuer does not open a second pool or duplicate the SQL implementation. The adapter only translates encrypted object records, write conditions, and errors. Envelope encryption and key management remain in the database driver.

Refresh-state persistence and advisory locks are not extracted in this phase. A future standalone issuer will need its own database adapter and refresh-state store; this library is not yet a standalone service.

## Owners and compatibility

`SecretOwner` scopes each operation to a workspace and one of three kinds:

- `Provider`: the existing provider UUID and name.
- `Sandbox`: the sandbox UUID for its SSH host identity.
- `SupervisorInstance`: the sandbox UUID owning a launch-material assignment, not the shared supervisor route or host.

Only the issuer's owner adapter translates internal kinds into legacy provider-shaped driver requests. SSH keys keep `sandbox-ssh-<sandbox UUID>` and launch material keeps `sandbox-instance-<sandbox UUID>`. Existing workspace fields, backend paths, envelope ownership, keys, and opaque handles are unchanged. Typed kinds do not introduce new durable ownership metadata or stronger authorization into old external drivers.

`StoreSecrets::object_id` identifies a particular staged write, not its owner. Distinct candidate IDs remain essential: a losing candidate must not overwrite or delete another writer's committed secret. Refresh-material keys retain the same domain-separated SHA-256 bytes, computed through `openshell-crypto` with failures propagated.

Raw resolution returns backend expiration metadata without applying provider policy. The gateway combines provider and backend expiration and withholds expired values. Refresh material has no provider expiration and retains its existing zero-time backend-expiration cutoff.

## Tests

Issuer tests cover registry/configuration/transport behavior, owner translation, storage batching, response correlation, and material-key compatibility. The existing server tests continue to cover provider orchestration, refresh races/recovery, credential export, SSH identity, launch material, and delivery through the extracted implementation.

The `test-support` feature exposes the existing static backend and deterministic failure/concurrency hooks on `EmbeddedCredentialIssuer` to server tests. The hooks are not part of `CredentialIssuer`, so other implementations need only implement the storage contract even when this feature is enabled. The server's test helpers retain the same concrete issuer allocation used by its trait object. The feature is enabled by the server's dev-dependency and explicit test-support feature, not by release defaults. A dependency does not inherit its caller's `cfg(test)`.

```shell
cargo test -p openshell-credential-issuer
cargo test -p openshell-server --features test-support
```

No new e2e suite or runtime artifact is needed. Versioned references, refresh-engine extraction, remote RPCs, authentication, watches/caching, and service packaging remain later RFC 0023 phases.
