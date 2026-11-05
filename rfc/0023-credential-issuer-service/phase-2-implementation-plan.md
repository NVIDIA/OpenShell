# Phase 2: embedded refresh boundary refactoring

## Scope and outcome

Continue [RFC 0023 at the requested revision](https://github.com/mrunalp/OpenShell/blob/b416373d6ac84bd67bb3802861d343a50703accc/rfc/0023-credential-issuer-service/README.md) from the [phase 1 extraction](phase-1-implementation-plan.md). This plan was checked against source revision `b8a0255a856ce7193bfa428cecd47bf382e121db`, the phase 1 implementation in [PR #5266](https://github.com/NVIDIA/OpenShell/pull/5266). That PR is the dependency, not an assumption that its changes have already merged. Reconcile with its final merge revision before implementation.

Move refresh execution, built-in minting, retry/recovery decisions, and refresh scheduling into the existing `openshell-credential-issuer` library. Inject narrow refresh persistence and gateway integration ports so the issuer no longer needs `openshell-server`, its private storage protobufs, `ServerState`, or `ComputeRuntime`. The gateway continues to own provider policy, authorization, mutations, public API adaptation, and delivery.

This is a plan only. Implement it as a separate follow-up to phase 1, not as an unsolicited update to the open phase 1 PR.

The implementation must be transparent to users:

- Keep the same CLI, SDK, provider/profile definitions, RPC shapes, configuration, defaults, refresh strategies, and status/error behavior.
- Keep the same opaque handles, stored refresh records, backend objects, database connection pools, refresh locks, and provider commit semantics. No new SQL or durable-data migration.
- Keep a single embedded gateway process. No new binary, service listener, image, Helm option, generated service bindings, or shipped artifact. Ordinary recompilation of the existing libraries is expected.
- Add only focused unit and in-process integration coverage using existing fixtures. No new e2e tests, lanes, images, or service fixtures; existing required CI remains in force.

## Relationship to the RFC's phase 2

The RFC groups several changes under phase 2. Separate the behavior-preserving extraction from activating a new durable credential model:

| RFC phase 2 item | This internal-refactoring increment |
| --- | --- |
| Refresh engine behind a minter, refresh-state store, and commit-notification sink | Implement in the existing issuer library. Preserve provider writes through an explicit temporary gateway commit port. |
| Replace strategy execution `match` with a registry | Implement a built-in-only registry with canonical internal string names and enum compatibility. |
| Add `strategy_name` | Introduce an internal strategy identifier, not a public protobuf/profile field or a custom strategy configuration surface. |
| Stable references, monotonically increasing secret versions, and handle migration | Defer durable activation to a separately reviewed embedded increment before remote mode. Do not rename current handles and claim those semantics already exist. |
| Include resolved secret versions in environment revisions | Defer with durable versioning. Preserve today's revision inputs and publication paths in this increment. |

**This increment does not complete every item in the RFC's original phase 2.** It prepares the internal interfaces without mixing a state-machine extraction with handle migration, revision changes, and new public inputs. Full references/versioning remains a prerequisite for externalizing refresh, not optional work that can be skipped when adding transport.

A provider `resource_version`, refresh-row `resource_version`, completed-mint UUID, authorization epoch, and future secret version have different meanings. Do not substitute one for another. The current completed-mint marker coalesces waiters; it is not a monotonic secret version.

## Current code and remaining coupling

Phase 1 already supplies `CredentialIssuer`, `EmbeddedCredentialIssuer`, typed secret owners, the existing backend implementations, and a narrow database object-store adapter. Reuse them rather than introducing another secret store, plugin framework, or service stack.

The remaining refresh implementation lives in `openshell-server/src/provider_refresh.rs`:

- `create_refresh_state`, `persist_refresh_state_if_current`, get/list/delete helpers, and coordinated cleanup use `Store` and `StoredProviderCredentialRefreshStateV2` directly.
- `refresh_from_snapshot_with_trigger` owns admission, cancellation-safe task spawning, local serialization, distributed locking, and post-lock generation checks.
- `refresh_provider_credential_locked` owns the uncertainty markers, minting, rotated-material staging, CAS transitions, failure schedules, and cleanup.
- `mint_credential` dispatches four built-in strategies. OAuth response handling and error classification, Google JWT signing, and AWS STS calls share that file.
- `apply_minted_credential` mixes issuer storage with gateway provider semantics: workspace preparation, attachment validation, a short workspace mutation guard, provider CAS, and cleanup of replaced handles.
- `spawn_refresh_worker`, `run_refresh_worker_tick`, and `refresh_states` schedule work and publish changed providers through gateway configuration delivery.

Other callers must remain part of the migration audit:

| Source | Responsibility to preserve |
| --- | --- |
| `grpc/provider.rs` | Refresh configuration/default resolution, output collision checks, create/reconfigure/delete, status/rotate RPCs, provider lifecycle, and authorization-epoch placeholder identity. |
| `grpc/provider_credentials.rs` | Operator export, minimum remaining lifetime, automatic refresh coalescing, and post-refresh identity/epoch revalidation. |
| `grpc/mutation_replay/ordinary.rs` | Mutation receipts, replay identity, and mapping durable refresh status to responses. |
| `grpc/policy.rs` | Immutable snapshot inputs, refresh-state revision hashing, placeholder/delivery behavior, and failure handling. |
| `config_delivery/` | Existing push publication and poll snapshot behavior. |
| `persistence/mod.rs` and `persistence/refresh_lock_tests.rs` | Real SQLite/Postgres records, conditional updates/deletes, authoritative row versions, and session-owned advisory locks. |
| `lib.rs` and `credentials.rs` | Construct one shared issuer/refresh runtime and inject adapters; preserve existing storage consumers. |

## Boundary decisions

### 1. Use issuer-owned Rust refresh types

Add an internal refresh API alongside the existing storage trait. Keep `CredentialIssuer` as the secret-storage boundary; do not force SSH or supervisor launch-material consumers to implement refresh operations.

Define an object-safe `CredentialRefresh` interface for read/create/replace/delete of refresh state, explicit rotation, automatic refresh against an observed generation, and worker sweeps. Exact method names may follow existing call sites. Use owned requests for work detached from RPC cancellation. This is not a frozen external protocol.

Issuer-owned types must represent the existing state without information loss:

- Workspace, provider ID/name, credential key, refresh object ID/name, authoritative row version, metadata/annotations, and deletion marker.
- Authorization epoch, including the legacy fallback to the existing object ID.
- Canonical built-in strategy identity and preserved legacy enum value, including unsupported/unknown values needed for existing status/error behavior.
- Resolved token URL, scopes, refresh-before/max-lifetime durations, pinned semantic-output mappings, and current expiration-presence semantics.
- Secret-material handles, legacy inline material, all pending deletion generations, scheduling timestamps, status, completed-mint marker, and structured failure/recovery details.

Do not pass the gateway's private generated refresh record across the crate boundary, regenerate it in the issuer, or move the whole gateway storage schema. Keep a server adapter for field-preserving conversion, `ObjectType` registration, legacy-time decoding, public status mapping, and wire-compatible persistence. Preserve unrelated metadata and unknown strategy values on read-modify-write; do not reconstruct records from only the fields a mint happens to use.

Transient resolved material and mint outputs must not implement value-bearing `Debug`, be serialized into durable state, or appear in tracing/errors. Legacy inline refresh material must remain readable without introducing an automatic rewrite or implying all old records are already handle-only.

### 2. Inject a narrow refresh-state store and owned lock lease

Add `RefreshStateStore` in the issuer with operations matching the current algorithm:

- Fetch by workspace/provider/key and exact refresh identity; list by provider and across workspaces with hydrated authoritative row versions.
- Create-if-absent, replace-if-current returning the new row version, and delete-if-current. Distinguish contention/deletion from infrastructure errors; an update must never silently become an upsert.
- Acquire the existing per-provider/key distributed refresh lease as an owned, `Send` RAII token whose lifetime spans the entire mint/commit attempt.

Implement it in a small server `refresh_store.rs` adapter over the already-open `Store`. Preserve object type/name/scope, V2 encoding, legacy readers, unique-violation handling, error mappings, and all conditional-write semantics. No duplicate SQL implementation, second pool, raw SQL/protobuf closures crossing into the issuer, or general persistence-crate extraction.

Keep advisory-lock derivation and acquisition in the existing persistence layer. The issuer holds an opaque lease, not a database connection. PostgreSQL must retain the session-owned lock from the **data pool**, not the mutation-lock pool; SQLite retains the current no-op distributed lease plus process-local serialization. A lease must not be released when only the initiating RPC is canceled.

Process-local coordination must remain shared across all refresh entry points and runtime clones, including more than one runtime constructed in a process. Preserve the weak mutex registry keyed by the existing provider/key identity, the process-wide admission/execution budgets, lock ordering, and lifetime behavior. A per-request or per-clone semaphore would silently weaken existing limits.

### 3. Extract stateless built-in minters and a registry

Add a `TokenMinter` Rust trait and immutable built-in registry. A mint request contains the resolved strategy configuration, transient secret material, pinned output mapping, and timing/lifetime inputs it needs; it does not contain `Store`, `Provider`, private protobufs, profiles, or gateway state. The engine owns persistence, material resolution, retries, and staging; a minter only performs the upstream exchange and returns outputs, expiration, and replacement secret material.

Register exactly these existing implementations:

- `oauth2_refresh_token`
- `oauth2_client_credentials`
- `google_service_account_jwt`
- `aws_sts_assume_role`

Preserve the existing primary/additional-output mapping and failure precedence before considering a generic output model. In particular, AWS STS's semantic outputs must still use the configure-time pinned credential keys, not guessed AWS environment names. Preserve rotated OAuth refresh-token handling.

Move the central execution `match` into registry lookup. A single compatibility mapping may still match the public enum to internal names; avoiding every enum `match` is not the goal. `static`, `external`, unspecified, and unknown values remain non-mintable with the same public behavior. Do not accidentally register `EXTERNAL` as a built-in minter.

Keep profile parsing/defaults/validation in `openshell-providers` and the gateway. At the request and worker boundaries, use the registry to decide executable availability. Add a parity test between built-in registrations, existing profile descriptors/output requirements, and `is_gateway_mintable_strategy` rather than creating an issuer-to-profile-catalog dependency or a providers-to-issuer dependency cycle.

Reuse the current HTTP/AWS libraries and crypto facade. Move dependencies only where the implementations actually move; retain server dependencies still used by dynamic token grants or other features. Google signing must initialize the existing `openshell-crypto` JWT backend without calling a server helper. Preserve token endpoint validation, bounded OAuth error-body reads, recognized error codes/subtypes, timeout behavior, expiry rounding/caps, and explicit-vs-ambient AWS identity selection. Test-only STS endpoint overrides must stay unavailable in release-default builds.

No operator registration, custom minter service, minter configuration, `ListStrategies` RPC, public `strategy_name`, or new retry/idempotency guarantee is added. Existing upstream calls do not become idempotent merely because the internal interface can later carry an attempt identifier.

### 4. Keep fallible provider commit separate from notifications

A minter plus refresh-state store plus notification sink is **not sufficient** while provider records still hold replaceable backend handles. The current refresh must commit those handles into the provider and may fail attachment validation, workspace locking, or provider persistence. A fire-and-forget sink cannot safely perform that work.

Introduce a temporary `GatewayRefreshCommit` port, implemented in a server `refresh_commit.rs` adapter. Its job is limited to gateway provider integration:

1. Observe/validate the provider identity before minting at the same points as today, retaining the provider snapshot needed by the current commit algorithm. Preserve name-replacement and deletion checks. Use an opaque attempt context if necessary; do not send `Provider` records into minters or re-resolve by name during commit and target a replacement.
2. Preserve workspace preparation before output staging when the current storage path requires it.
3. Accept issuer-staged output handles plus expiration metadata and the observed owner/attempt context. Keep the existing inline-output fallback available for the internal/test construction paths that currently exercise it; do not make it a new production mode.
4. Acquire the short workspace mutation guard only after upstream I/O and staging. Validate the proposed provider against attached sandboxes and perform the existing provider CAS/rebase behavior, preserving unrelated keys.
5. Return success/failure and exactly the old handles replaced in the winning CAS. The issuer cleans up staged losers on failure and superseded handles on success using its existing storage boundary, with the same fatal/nonfatal cleanup rules.

The adapter must neither mint nor select backends, resolve refresh material, implement retry/recovery schedules, or call back into the refresh engine. Specify its result so a completed provider write is not mistaken for an uncommitted candidate merely because later best-effort cleanup/publication failed. If the provider CAS succeeds but the final refresh-state CAS fails, the outputs are already live: do not delete them as losing candidates or automatically mint again. Preserve the current error and uncertain-commit recovery behavior; this refactor does not make the two records atomic. Avoid ownership cycles: adapters capture only the needed store/compute components, not `Arc<ServerState>` or the refresh runtime itself.

This port is an explicit embedded-compatibility dependency, **not** a callback allowed in the eventual remote issuer protocol. Stable issuer-owned references must eliminate per-refresh provider writes and this port before refresh can run independently of gateway persistence.

Add a separate non-secret `RefreshCommitSink` for change notification. It reports owner/credential identity and the actual committed generation when one exists; do not invent a future secret version. Notify only after provider handles and the final successful refresh state are committed. Status/deletion changes that currently trigger publication must retain their existing delivery path as well.

Preserve current publication timing and call-site ownership: worker sweeps return/coalesce changed providers, and explicit RPC mutations retain their existing publication behavior. In particular, `grpc/provider_credentials.rs` currently performs export-triggered refresh without publishing, while manual rotation publishes in `grpc/provider.rs` after awaiting the cancellation-safe engine task. Moving publication unconditionally inside that detached task would change export and caller-cancellation behavior. Keep those asymmetries in this increment and cover them with focused tests; changing them requires a separate behavioral decision. Route existing signals through a shared sink adapter at their current orchestration points, not through an unconditional new event on every engine completion or CAS/cleanup write. Notifications are invalidation hints, contain no values, and must not roll back or repeat a mint. Snapshot polling remains the existing read/reconciliation path; this increment introduces neither watches nor a durable notification outbox.

### 5. Move scheduling without changing execution semantics

The issuer owns the existing sweep eligibility, tombstone finalization, pending-deletion cleanup, rotation-request handling, per-grant locking, retry/backoff decisions, and execution state machine. The gateway owns task startup and delivery wiring: construct the runtime once and start it at the same point with the same one-minute interval, initial tick behavior, and delayed missed-tick policy.

Do not use this extraction to parallelize the currently sequential sweep, change concurrency limits, redesign shutdown, or add new retries. Keep the existing tracing span names/fields and safe logs where practical. Do not add a new OCSF event or metrics surface as incidental refactoring.

## Implementation sequence

Implement in compiling, reviewable steps on top of phase 1. Each gate uses existing tests plus focused boundary cases; no step requires a new service deployment.

### 1. Characterize state and define the internal ports

- Record the existing refresh tests and classify engine/minter, real-store adapter, and gateway orchestration coverage so moved tests cannot disappear silently.
- Introduce issuer-owned state/request/failure/strategy types and `CredentialRefresh`, `RefreshStateStore`, lease, gateway commit, and notification interfaces. Keep names provisional until the first callers compile.
- Implement field-preserving server conversions and the real-store adapter without changing the durable schema. Exercise create/replace/delete conflicts and authoritative row-version hydration against existing SQLite fixtures.
- Retain a thin server `provider_refresh.rs` facade to preserve gateway entry points and public status/epoch helpers during the move; no second state machine.

Gate: issuer code compiles without any server dependency; existing records round-trip with unchanged identity, material, durations, metadata, and recovery state. The implementation has no extra library/binary target or generated protocol.

### 2. Move minters before moving orchestration

- Move OAuth/JWT/STS implementation, safe error classification, timing helpers, and related tests behind the minter trait.
- Install the four built-ins in one registry and adapt the old dispatch function to call it. Preserve output/error behavior before restructuring callers.
- Move only necessary Cargo dependencies, reuse `openshell-crypto`, and update affected tracked lockfiles with existing tooling. Forward `test-support` deliberately where mock endpoints/hooks must cross the crate boundary.
- Add registry/enum/profile parity coverage, unsupported-strategy coverage, and tests ensuring production constructors cannot enable test endpoints.

Gate: existing mock HTTP/STS tests and gateway refresh tests exercise the extracted minters; there is no duplicate mint implementation or new user-selectable strategy.

### 3. Split staging, gateway commit, and cleanup

- Extract `apply_minted_credential` into issuer output staging/cleanup plus the small gateway commit adapter, maintaining the exact ordering of workspace preparation, staging, validation, CAS, and cleanup.
- Keep observed provider identity/context bound to the attempt. Preserve multi-output collisions, partial failure, sibling-handle preservation, and the existing CAS behavior rather than imposing an unrelated stricter provider-version check.
- Keep legacy inline/test construction paths explicit. Do not resolve issuer-stored output handles back into plaintext merely to give the gateway a uniform commit interface.
- Add in-process adapter cases for failed guard/validation/CAS, same-name provider replacement, successful provider commit followed by final refresh-state CAS failure, and successful commit followed by cleanup failure.

Gate: only the gateway adapter knows attachment validation, `MutationScope::Workspace`, and provider persistence. Only the issuer chooses storage operations and owns secret staging/cleanup.

### 4. Move the state machine and refresh-state lifecycle

- Move rotate/automatic-refresh execution, secret material resolution, uncertainty transitions, recovery/backoff, rotated-material staging, and pending-deletion/tombstone processing into the issuer.
- Replace direct `Store`/private-proto calls with the refresh-state port and retain owned lock leases across the detached attempt.
- Preserve create/reconfigure/delete coordination through the gateway facade and adapters; keep authorization, profile resolution, replay receipts, and attachment rules in the gateway. Do not reimplement replay in the issuer.
- Ensure manual rotate, automatic sweeps, and export freshness all call the same engine. Export still revalidates provider identity and authorization epoch after refresh and before returning values.

Gate: existing cancellation, stale-generation, deleted/reconfigured-grant, uncertain-mint, rotated-token, and cleanup tests run through the new engine. No gateway wrapper retains a second retry/scheduling implementation.

### 5. Move worker sweeps and wire existing publication

- Move `run_refresh_worker_tick`, due/rotation/tombstone selection, and sweep processing; leave startup composition and provider publication in server glue.
- Share one runtime and coordination domain across clones/callers. Adapt worker changed-provider results and existing RPC/export publication paths without adding unconditional publishes.
- Preserve immutable snapshot construction and current revision hashing. No values, raw handles, or completed-mint UUIDs become new revision inputs under the pretense of versioning.
- Audit all callers in the source map, including deletion, mutation replay, environment-key/placeholder helpers, and extension reporting. Storage-only SSH and launch-material callers keep using phase 1's interface unchanged.

Gate: both push and poll behavior remain covered by the existing configuration-delivery/snapshot tests; status, export, replay, and credential placeholders retain their current contracts.

### 6. Remove coupling and document the handoff

- Remove obsolete minter/engine/worker implementations from the server and keep only API/domain adaptation, persistence/commit adapters, and startup/publication glue.
- Update the issuer README and crate-specific server documentation, and review related contributor skills with the existing maintenance map. Update the architecture table only if its description needs adjustment.
- Leave published operating/configuration docs, public proto/SDK files, CLI, Helm/deployment/release files, SQL migrations, and e2e definitions untouched because this increment changes none of their contracts.
- Record remaining stable-reference/versioning work and the temporary gateway commit dependency prominently; do not describe the issuer as remote-ready.

Gate: the diff is an internal extraction, targeted in-process tests, dependency relocation, and implementation documentation only.

## Compatibility and failure invariants

1. Acquire admission before detached work; spawn before externally observable mint effects. Dropping the caller's future must not cancel an upstream exchange or release its local/distributed guards.
2. Preserve local lock, execution permit, distributed lease, and post-lock identity/epoch reload ordering, including existing 40-second waits, four execution slots, and 32 admissions. Cleanup uses the same serialization domain as minting; the sweep must reload after acquiring it.
3. Distinguish a changed row version from a completed mint. Only the existing committed-mint evidence may satisfy coalesced waiters; cleanup/bookkeeping alone must not do so.
4. Persist `refresh_in_progress` and the parked schedule before contacting an upstream. Keep `refresh_committing` across the output-commit window. A restart or uncertain result must not silently reuse a potentially consumed grant.
5. Claim the refresh generation by update-only CAS before provider writes. Deleted/reconfigured refresh state must not be resurrected or overwritten. Preserve the current behavior of races at every transition rather than claiming cross-record atomicity the current system does not provide.
6. Retain rotated refresh material when persistence outcome is uncertain; do not delete the only upstream-valid replacement. Preserve failed-store reauthorization, pending deletions for multiple generations, and tombstone retry behavior.
7. Keep unique per-write staging IDs separate from owner and authorization epoch. Losing writes must not overwrite or delete winning credentials; successful replacement cleans only handles actually replaced by that CAS.
8. Preserve provider/backend expiration combination, explicit Unix epoch versus absent expiration, fractional duration handling, status/error/recovery mapping, and automatic-backoff versus explicit-rotation behavior.
9. Keep authorization epochs and placeholder identity unchanged across automatic/manual refresh; explicit reconfiguration still revokes the old epoch. Preserve same-name replacement protection and export's post-refresh revalidation.
10. Preserve immutable record snapshots, revision hashes, supervisor protocol, push publication triggers, polling, and failure/withholding behavior. No new secret cache, value hashing, value-bearing notifications, or extra plaintext persistence.
11. Keep storage driver negotiation, UDS transport, encrypted-envelope/AAD/path identity, key management, SSH host fingerprints, and supervisor launch-material identity unchanged.
12. Preserve crypto-facade routing and propagate backend failures without fallback. No application-local signing implementation or widened dependency-policy exception to make the move compile.

## Validation

For the implementation, relocate tests with their responsibility rather than moving the entire refresh test module mechanically:

| Test layer | Required evidence |
| --- | --- |
| Issuer unit/in-process tests | Built-in registry parity, token requests/error classification, expiration math, engine transitions, retries/parking, cancellation, coalescing, rotated-material retention, staging cleanup, and notification ordering. Use fake ports plus the existing mock HTTP/STS patterns. |
| Gateway adapter tests with real `Store` | Full V2 state conversion, hydrated row versions, unique-create and update/delete CAS conflicts, legacy epoch/expiration/inline-material handling, multiple pending deletions, and reconstruction from persisted state. |
| Existing gateway integration tests | Configure/rotate/delete/status, profile defaults, attachment/output collisions, mutation guard failures, provider CAS/sibling preservation, replay, export freshness/revocation, placeholders, immutable snapshots, and push/poll delivery. |
| Existing Postgres lane | Independent replica sessions serialize on the same refresh key, unrelated keys progress, and refresh still progresses with the mutation-lock pool exhausted. Keep the current data-pool lease behavior. |
| Production feature/dependency inspection | Issuer has no server/private-proto dependency, test endpoint/hooks are not release-default, and target/shipped-artifact inventory is unchanged. |

A dependency does not inherit its caller's `cfg(test)`. Put portable mocks/gates behind the existing issuer `test-support` feature, enabled only by dev-dependencies or explicit forwarding. Keep real-store/provider assertions in server tests and compare the before/after test inventory. Do not count fake-only store tests as proof of Postgres lock/session behavior or restart compatibility.

Use the existing repository commands during implementation:

```shell
mise x -- cargo fmt --all -- --check
mise x -- cargo check -p openshell-credential-issuer -p openshell-server -p openshell-gateway --all-targets
mise x -- cargo clippy -p openshell-credential-issuer -p openshell-server -p openshell-gateway --all-targets -- -D warnings
mise x -- cargo test -p openshell-credential-issuer
mise x -- cargo test -p openshell-server --features test-support
mise x -- cargo test -p openshell-providers
mise run test:rust:postgres
mise run rust:lockfiles:check
mise run rust:deny:policy
mise x -- cargo tree -p openshell-credential-issuer
mise x -- cargo metadata --no-deps --format-version 1
```

Use the established Z3 and disposable Postgres setup documented in `CONTRIBUTING.md`, not a new image, test harness, or packaging path. Check normal production features separately from all-target/dev-feature unification. Rerun existing driver tests if changes extend beyond caller/dependency relocation. Inspect the final diff for public/private schema, SQL migration, configuration, deployment, release, e2e, or revision-algorithm drift. Run the existing Markdown checks on implementation documentation.

These are future implementation gates, not a claim that this planning-only change ran Rust tests. Validate this document with scoped Markdown lint, local-link/source-path checks, and `git diff --check`; a plan alone does not require rebuilding the workspace.

## Alternatives and deferred work

- **Extract all persistence:** reject for this increment. The phase 1 database port plus a refresh-specific adapter reuses existing pools, authoritative versions, and lock behavior without moving unrelated policy/image/sandbox transactions.
- **Keep the engine in the server and move only HTTP clients:** insufficient. It leaves scheduling, recovery, and secret staging coupled to gateway code instead of preparing an issuer-owned engine.
- **Hide provider CAS in a notification sink:** reject. Commit is fallible correctness work; notification follows committed state and is not a transaction coordinator.
- **Activate stable references in this refactor:** defer. It is valuable but changes the durable commit/revocation model and snapshot consistency, not just code placement. Keep it independently reviewable and testable in embedded mode first.
- **Add custom strategies or a public `strategy_name` now:** defer. Internal canonical names/registry remove execution coupling without changing accepted user configuration or generated APIs.

Before moving to remote refresh, complete a separate embedded reference/version increment that:

1. Defines issuer-owned reference/grant records, persistent monotonic per-reference versions, authorization-epoch binding, conditional/idempotent updates, and race-safe migration from every supported legacy handle/backend without copying secret values into gateway records.
2. Defines crash-safe multi-output activation, replacement-material retention, deletion, and upgrade/rollback/mixed-version behavior. Startup adoption must be retryable and must not resurrect revoked epochs or rewrite handles before corresponding issuer state is durable.
3. Makes outputs resolve through one reference path and removes per-refresh provider CAS, attachment revalidation, and the temporary gateway commit port only after configure-time output validation plus reference-epoch checks replace their safety role.
4. Includes committed reference versions in the exact snapshot whose values are delivered, without reading a version and later resolving different-generation values. Updates both push invalidation and poll revision calculation; never hashes secret values.
5. Adds public strategy-name compatibility only with its own API/profile design and validation; preserves existing enums/requests. This is not implied by the internal registry.

Remote RPCs, mTLS/SPIFFE identity, gateway/workspace binding, watches, version-keyed caches, subject-token cache reordering, standalone service packaging, operator migration tooling, and remote-service e2e coverage remain subsequent RFC work. This plan adds none of those runtime surfaces.

## Definition of done

- The existing embedded issuer owns all built-in refresh execution, scheduling decisions, material staging/cleanup, retries, and uncertain-mint recovery through one engine.
- Gateway code owns authorization, provider/profile semantics, public RPC/status/replay adaptation, delivery, and the explicitly temporary provider commit adapter; it no longer implements minting or the refresh state machine.
- Issuer code depends only on issuer-owned Rust ports/types and existing shared libraries, never on the server's private schema, compute runtime, or `ServerState`.
- Durable refresh records, credential handles, lock identities/pools, provider write ordering, snapshots, placeholders, and public behavior remain compatible without migration or user action.
- Existing tests are retained at the appropriate layers and pass, including real SQLite/Postgres coordination and gateway delivery/export/replay coverage. Additional tests are limited to unit/in-process boundaries.
- No new e2e requirements, public API/configuration, process, generated service contract, deployment option, or shipped artifact is introduced.
- Remaining reference/version migration and gateway commit coupling are documented as prerequisites, not misrepresented as completed externalization.
