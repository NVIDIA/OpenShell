# Phase 2 completion and staged embedded rollout

This implementation addendum records the scope of Phase 2 in [the pinned RFC 0023](https://github.com/mrunalp/OpenShell/blob/b416373d6ac84bd67bb3802861d343a50703accc/rfc/0023-credential-issuer-service/README.md). The [Phase 2 extraction plan](phase-2-implementation-plan.md) and [Phase 2.1 reference plan](phase-2.1-implementation-plan.md) remain design history. They are not evidence that every deployment or backend has been qualified.

## Completion scope

The activated embedded path implements stable owner-qualified references, durable monotonic versions, adoption of existing handles at version 1, coherent version-aware environment revisions, issuer-owned grant/output activation, the four built-in minters behind a registry, and additive `strategy_name` compatibility. Gateway provider/profile policy, authorization, configuration replay, export and delivery remain gateway-owned. A refresh activates its fixed output bundle and terminal journal without a Provider write or gateway commit callback.

New value activations, including intentional same-byte writes, advance checked versions. Failed attempts, bookkeeping and exact retries do not. A capture keeps each value with its committed version and effective expiration; snapshots never hash secret values. Authorization epochs and workload placeholders do not change merely because a reference version advances.

## Deployment mode boundary

Choose embedded or external issuer mode at initial deployment. No conversion, secret transfer, or grant transfer between those modes is supported in either direction. This decision replaces any assumption that a later migration tool will convert an embedded deployment to an external issuer. External issuer implementation remains later-phase work.

The adoption and retirement below upgrade legacy records within the same embedded issuer and selected storage backend. They do not change deployment mode or copy state to another issuer. An external credential driver over UDS is a storage backend of the embedded issuer, not an external issuer service.

## Staged rollout decision

This implementation deliberately refines the original RFC's automatic first-start migration into maintenance-window opt-in activation. `enable_versioned_credentials` stays false by default. A compatible binary alone does not migrate a deployment. Enabling the option attests that all incompatible writers and outstanding backend operations are drained, coordinated backups exist, and old binaries cannot return.

The durable activation marker coordinates compatible replicas and rejects compatible legacy startup after the irreversible boundary. It does not fence old binaries. Do not replace this exclusion requirement with an expiring membership check or change the default without a separately reviewed rollout policy.

Legacy mode remains supported while unactivated, including `GatewayRefreshCommit`, `RefreshAttempt`, frozen V1/V2 journals and per-refresh Provider writes. These are not dependencies of the activated runtime. Their whole-product removal is deferred until legacy-mode support is deliberately retired; the Phase 2.1 plan's bridge-removal gate applies to the activated path, not deletion of all upgrade compatibility code. Phase 2 functional completion therefore means the supported activated embedded path, not automatic conversion of every existing deployment.

The in-tree encrypted database, Kubernetes Secrets and Vault adapters support activation. A UDS driver must negotiate `openshell.credentials.recoverable-immutable-write`. The current Vault UDS service does not; startup rejects activation before conversion. This explicit support boundary remains in place rather than emulating recovery unsafely. See [gateway activation guidance](../../docs/how-it-works/gateways/configuration.mdx#versioned-credential-activation) for key, backup and rollback requirements.

## Legacy source retirement

Before any import or recovery work, startup binds each original legacy refresh source generation in a non-secret retirement journal, including its immutable owner/grant/key/epoch identity and authoritative source version. After issuer grants and their handle-backed recovery state are durable, one existing SQLite or PostgreSQL transaction removes the exact source and records completion; a failed transaction preserves the original row and pending intent. Retirement does not acquire a nested credential lease or modify issuer state. Activation holds its unchanged advisory key through the existing lock pool, leaving room for credential-scoped binding recovery and database work in the supported two-connection PostgreSQL data pool. Ordinary refresh leases still use the data pool and progress independently of mutation-pool capacity.

Restart resumes retirement without reminting, rebinding or rewriting backend material. An incomplete conversion with an existing grant but no pre-import retirement ticket fails closed. Already-active compatible upgrades also retire sources retained by an earlier implementation, using only existing matching grants. Such releases never recorded an imported source version: their one-time ticket bootstrap relies on the operator's maintenance-window attestation that retained sources stayed frozen. It cannot retrospectively prove their original version or material equality after issuer rotation. Missing, prepared or mismatched grants cannot authorize removal. A changed source or a source recreated after completed retirement fails closed rather than being silently discarded. Retirement does not revive revoked grants or delete the backend candidates and replacement-material generations retained by issuer recovery.

Frozen V1/V2 decoders remain available for upgrades. Their secret-bearing source rows do not remain a redundant plaintext archive after successful retirement. Logical row removal does not erase old backups, database journals or historical storage pages; their retention remains an operator responsibility.

## Embedded invalidation contract

Committed refresh hints contain workspace, immutable Provider ID, immutable grant ID, effective authorization epoch, validated embedded issuer namespace, and committed reference/version pairs. Provider names remain for the existing fanout. Legacy or malformed hints do not invent an epoch or advertise unproven versions. Namespace identifies durable embedded state, not an authenticated remote gateway.

The sink remains an invalidation hint, not authorization or a durable per-grant event stream. Builders reauthorize and resolve current state. Worker, manual, export and caller-cancellation publication ownership is unchanged. Polling and idle push reconciliation recover missed hints. Remote watch contracts must not assume these hints already provide remote authentication, replay or delivery guarantees.

## Qualification boundaries

The source tests cover activated export and subject exchange through actual handlers, version-scoped cache behavior, reference-only revocation, idle reconciliation and placeholder lifecycle, actual supervisor application, and concurrent compatible PostgreSQL activation/restart. Fault-injected retirement tests verify atomic source/completion rollback and exact restart behavior. The test reports must distinguish these executable paths from any separately modeled bridge between gateway and supervisor fixtures.

Real encrypted SQLite migration, the existing disposable PostgreSQL lane and real driver implementations against local HTTP/UDS protocol fixtures remain the automated backend evidence. They are not a live Vault/Kubernetes deployment, a deployed multi-replica upgrade/restore exercise, or exhaustive interleaving verification. Release qualification must run the relevant existing backend and deployment checks for its selected configuration; do not infer those results from unit totals.

A failed credential update can still revoke static material while an unchanged supervisor retains its previous policy and dynamic grants. That inherited boundary is documented, not resolved by delivering a narrower snapshot. This increment does not change the supervisor protocol or move dynamic grants into the issuer.

## Phase 3 handoff

Service protobufs, remote mTLS/SPIFFE identity binding, `ListStrategies`, custom minter transport, remote watches, version-keyed secret caching and reordering the subject-token cache lookup remain Phase 3. Standalone binary/image/Helm packaging is Phase 4; remote-service and separate-cluster qualification is Phase 5. Their absence is not an incomplete embedded Phase 2 implementation, and embedded completion does not certify remote readiness.
