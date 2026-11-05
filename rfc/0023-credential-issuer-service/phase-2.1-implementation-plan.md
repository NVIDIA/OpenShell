# Phase 2.1: embedded references, versions, and grants

## Scope and baseline

Complete the deferred parts of phase 2 in [RFC 0023 at the requested revision](https://github.com/mrunalp/OpenShell/blob/b416373d6ac84bd67bb3802861d343a50703accc/rfc/0023-credential-issuer-service/README.md), before starting its phase 3 transport work. This is an implementation plan supporting that RFC, not a new RFC or authorization to implement it.

Checked against `22349a7b3a52a4e6a4068c26e37cd3c6c8412f30`, the current head of [phase 2 PR #5283](https://github.com/NVIDIA/OpenShell/pull/5283). The PR is still open; reconcile this plan with its final merge revision before implementation. The [phase 2 plan](phase-2-implementation-plan.md) explicitly limited that increment to behavior-preserving internal extraction and recorded the remaining work. Its deferrals are not newly discovered regressions in the extraction.

Phase 2.1 remains embedded: one existing gateway process, existing credential backends, and no issuer listener, remote client, image, or Helm service. Unlike the extraction, it intentionally changes durable credential representation and revision calculation, and adds an optional strategy-name input. Those changes need schema, migration, and compatibility review; they must not be described as another migration-free refactor.

## Remaining phase 2 gaps

| Gap | Current evidence | Phase 2.1 outcome |
| --- | --- | --- |
| Stable credential references | `CredentialIssuer` stores and resolves replaceable `CredentialHandle` maps; provider refresh commits replacement handles into `Provider`. | Provider keys bind to issuer-owned references stable within an authorization epoch; backend handles become issuer implementation details. |
| Monotonic secret versions | `ResolvedSecret` has a value and expiration but no version. Completed-mint UUIDs and database row versions have other meanings. | Every active reference has a durable `uint64` version; resolve returns the value, version, and expiration from the same committed generation. |
| Legacy migration | Typed owner adaptation preserves existing backend paths, and legacy inline provider/refresh material is still readable. There is no reference-adoption migration. | Retryable adoption of existing handles at version 1, encrypted storage of inline secrets, and explicit activation/rollback rules without moving between backends. |
| Version-aware delivery | `policy.rs` computes the environment revision before credential resolution, using provider/refresh metadata rather than resolved secret versions. | Push and poll use committed reference versions from the exact resolution result used to build their snapshot; values are never hashed. |
| Autonomous grant/output commit | `RefreshRuntime` still needs `GatewayRefreshCommit` and server-private refresh-state adaptation; publication reports a completed-mint marker, not a version. | Issuer-owned grants atomically activate output generations without provider writes or gateway callbacks; version-bearing invalidation follows activation. |
| Public strategy-name compatibility | The four built-ins have internal canonical names, but profiles and configure/status protobufs remain enum-based. | Optional `strategy_name` in the relevant API/profile projections, with explicit enum compatibility and registry-based availability checks. No custom minter transport yet. |

The extracted engine, narrow persistence ports, owned leases, built-in registry, typed owners, cancellation safety, and current backend adapters already exist. Keep them; do not repeat the extraction or build a second credential framework. Existing database conditional-write/transaction facilities and driver contracts are the starting point, not a new general persistence service or paid dependency.

## Boundaries and non-goals

- Gateway: provider/profile semantics, workspace authorization, attachment/output-collision validation, public mutations and their replay, policy, placeholders, operator export, and supervisor delivery.
- Issuer: reference ownership, versions, grants, secret material, mint attempts, output activation, retry/uncertainty state, and backend cleanup. Embedded adapters may reuse the existing database pools without making gateway provider records part of refresh commit.
- Preserve the four built-in strategies and `STATIC`/`EXTERNAL` behavior. Dynamic subject-token exchange and supervisor client-credentials grants remain gateway delivery concerns.
- Do not add service protobufs, mTLS/SPIFFE, remote configuration, watches, a version-keyed secret cache, custom minter services, or subject-token cache reordering. These belong to phase 3. Standalone packaging, cross-cluster migration, and remote e2e coverage remain phases 4/5.
- Do not change backend selection, copy secrets between Vault/Kubernetes/database backends, or redesign scheduling, process-wide limits, lock pools, crypto, or the supervisor protocol.
- The earlier restriction against public/schema changes applied to phase 2's extraction, not this proposed increment. Make only the changes necessary for the six gaps and obtain review before implementation/activation.

## Data and commit model

### 1. References, bindings, and versions

Define issuer-owned Rust domain types and a versioned durable representation, separate from the gateway's frozen V1/V2 refresh messages. Reuse `SecretOwner` kinds, extending the stored binding with the logical secret key and authorization epoch where applicable. A provider display name is audit metadata, never identity. Embedded replicas must use one durable local issuer namespace, not a per-process or replica identifier; authenticated gateway namespaces are a later transport concern.

A reference record contains non-secret identity/binding information and a link to its activation manifest. The manifest selects immutable backend candidates and stores their committed secret versions and expiration metadata. Keep raw backend handles internal to the issuer after migration. A gateway reference is not a user-authored Vault path or a way to select another backend.

Reference identity stays stable across automatic/manual refresh and ordinary same-epoch value updates. Explicit refresh reconfiguration creates a new grant, epoch, and output references. Provider replacement, credential removal, or authorization revocation must not let an old reference resolve through a name or key reused by a replacement.

Adopt the existing opaque handle as the migrated reference identity, as the RFC specifies. Preserve its bytes and record its driver/metadata separately. Old handles need not be globally unique: qualify lookup by the durable issuer namespace, workspace, owner kind/immutable ID, logical key, and driver identity. Never resolve by the bare handle alone. Introduce an explicit internal reference projection rather than pretending the old `driver` field now denotes a remote issuer. Keep existing handle fields readable during preparation; never accept authored references in public provider mutations.

Start adopted committed values at version 1. A new reference with no output yet is pending and cannot return a value/version; its first activated output is version 1. Advance versions only on successful value activation, including an intentional write of identical bytes. Status changes, bookkeeping, cleanup, and failed or retried attempts do not advance versions. Use checked increments; overflow fails closed. Versions survive restarts and never reset or get reused within a reference, including after a tombstone. An epoch, reference version, row resource version, attempt ID, and completed-mint marker remain distinct.

Resolution returns a transient, non-serializable, redacted result containing reference identity, secret version, activation generation, value, and effective issuer/backend expiration. No plaintext goes into reference/grant metadata, logs, mutation receipts, notification records, or gateway durable state.

### 2. Issuer-owned grants and atomic activation

A grant pins the strategy/configuration, owner/epoch, output-to-credential-key/reference mapping, refresh-material handles, schedule/status/recovery details, and current mint attempt. Preserve all existing semantics, including unknown legacy enum integers, fractional durations, expiration presence, completed-mint coalescing, parked uncertainty, and multiple pending deletion generations.

Use one issuer-owned activation manifest per grant output bundle. Its update-only CAS is the visibility/linearization point for all outputs of a mint, with each reference's next version included in that manifest. Independent static secrets use the same model with a single-output manifest. Readers of one grant bundle load one manifest and never combine old AWS access keys with new secret/session keys. Do not imply unrelated providers are globally transactional.

Extend a narrow issuer persistence port only with the operations this model needs: create-if-absent, versioned reads, conditional manifest/grant transition, exact-identity tombstone, migration progress, and owned lease acquisition. A manifest may embed the state needed for a one-record activation; if a transition spans records, its adapter must perform one real database transaction. Merely sequencing independent `put_if` calls is not atomic. Reuse current SQLite/Postgres facilities and pools; do not extract unrelated persistence or duplicate SQL in the issuer.

Mint/commit order:

1. Acquire the existing admission, local/execution guards, distributed lease, and reload/epoch checks in their current order. Durably park uncertainty before upstream I/O.
2. Persist attempt identity and recovery intent. Mint outside database transactions; upstream OAuth calls are not made idempotent by assigning an attempt ID.
3. Preserve rotated refresh material with the current uncertainty guarantees. Stage immutable backend output candidates under unique per-attempt/write IDs, never by overwriting the live backend object. External backend operations are not part of the database transaction.
4. Record the candidate handles/recovery state durably before activation. CAS the expected active grant/epoch and manifest, activating the entire output bundle and versions together. A stale, deleted, or reconfigured grant cannot publish outputs.
5. After activation, return committed references/versions and make non-secret invalidation eligible. Retain recoverable cleanup debt for replaced material/output handles; cleanup failure must not roll back activation or cause another mint.

Record enough intent before backend writes for orphan recovery. Where existing drivers cannot enumerate or atomically report a write whose outcome is unknown, retain deterministic attempt/write identity and recovery state; never claim exactly-once physical writes or safe deletion without evidence. Test each supported driver's retry/lookup limits before freezing the persistence contract.

Once activation succeeds, its outputs are live even if response delivery, status follow-up, cleanup, or publication fails. A repeated activation with the same operation ID returns the same result, not another version. Bind operation IDs to the immutable owner/grant, expected generation, and protected request intent; reuse for a different intent is a conflict. Reuse existing mutation-replay protections for secret-bearing intent rather than persisting plaintext or bare hashes vulnerable to offline guessing.

### 3. Gateway configuration and revocation

At configure time, the gateway resolves profile defaults, validates all primary/additional output keys against attachments, and asks the issuer to prepare an inactive grant/reference set. Commit the provider binding with the existing provider mutation/replay rules, then activate the prepared grant through a recoverable operation. A failed provider CAS must leave no active losing grant. A crash between the two stores must be recoverable using the exact operation/provider identity, without minting or reauthorizing an abandoned candidate.

The gateway owns this configuration saga; it is not an issuer callback into the gateway database. Persist preparation/activation intent and retain the previous working binding until the new binding is safely committed. Resolution of an unactivated new binding fails closed. Define the provider-binding switch and old-epoch revocation as an explicit recoverable transition so the old grant cannot continue serving after the new authorization takes effect. If the chosen embedded adapter can perform the binding switch/revocation transactionally, use that narrow capability; do not assume a future remote transaction.

Refresh then updates only issuer state. Remove per-refresh provider CAS, workspace preparation, and attachment revalidation only after fixed-output validation plus grant/reference/epoch checks cover their safety role. Handle profile edits, direct `UpdateProvider` writes, additional-output collisions, provider replacement, and deletion through the same binding rules; they must not silently redirect an existing grant. A direct write to a refresh-owned key must preserve today's accept/reject and ownership behavior, not create a second writer that bypasses the manifest.

Distinguish disabling refresh from deleting a provider secret. Existing refresh deletion retains the last credential values and clears only refresh-owned expiration metadata where appropriate. Preserve that behavior by deliberately transferring retained values into a static binding while revoking the old grant/epoch; do not accidentally delete the final credential. Old and new references can temporarily share a legacy backend candidate during adoption/rebinding: cleanup must check durable live reachability or transfer ownership before deleting it, not blindly delete every handle on a revoked reference. Coordinate the last-link check and durable reclamation claim atomically with all new-link/ownership-transfer operations; once reclamation is claimed, reject new links to that candidate. A reachability query followed by an unguarded backend delete is not sufficient. Retain the claim through uncertain deletion and recovery so another replica cannot adopt a candidate being reclaimed.

Separate provider-authored expiration policy from the expiration previously copied into provider records by refresh. The active grant/manifest becomes authoritative for refresh-owned output expiry; migration must remove or stop enforcing the stale copied expiry using existing ownership rules, without dropping an independently authored limit. Otherwise the first post-migration refresh could remain withheld by the old provider timestamp. Status, export, and public provider projections that expose expiration must read the corresponding committed metadata rather than restoring per-refresh provider writes.

Storage-only SSH host keys and supervisor launch material also use the reference resolver; their fingerprints, owner IDs, backend paths, registration contents, and lifecycle remain unchanged. Their versions do not become provider environment hash inputs.

### 4. Coherent snapshots and invalidation

Refactor snapshot construction into policy/selection validation, batched reference resolution, and final snapshot/revision assembly. Derive versions, values, expiration, and omission/readiness evidence from one captured resolution result. Apply provider expiration and endpoint/attachment policy using the same captured provider/profile/policy inputs. A metadata-only revision probe must not be paired with later values from a different generation.

Extend the deterministic revision input with the ordered reference identities and committed versions for the credentials that affect the environment, alongside existing policy/provider inputs that remain meaningful. Keep order/encoding canonical and domain-separated through the existing crypto boundary. Never hash values, transient backend handles, raw refresh tokens, or completed-mint UUIDs as a substitute for versions. Poll must detect a successful refresh with no provider-row update; push must rebuild on the same committed version.

If configuration/revocation changes during resolution, revalidate the captured provider binding/epoch or retry a bounded build; do not label a new value with an old version or return a revoked owner. Handle cleanup racing a backend read by pinning the candidate for the read or detecting the changed manifest and retrying, never by substituting another generation under the captured version. Preserve export's minimum-lifetime checks and post-resolution authorization revalidation. Missing/expired/revoked references fail closed with existing withholding/readiness behavior; a lookup error cannot publish an apparently complete successful revision.

Audit other consumers that currently rely on provider resource-version changes. In particular, `exchange_provider_subject_token_inner` keys its intermediate-token cache by provider resource version, but that version will no longer advance on refresh. Keep its current authorization/identity validation and resolution-before-cache order in phase 2.1; include the resolved subject reference/epoch/version in the cache key (or provide equivalent version-scoped invalidation) and bound cached-token lifetime by the captured subject expiration. A subject rotation must not reuse a cache entry from the old secret version merely because the provider row is unchanged. Moving the cache check before issuer resolution remains phase 3 work.

Replace the completed-mint-only notification payload with non-secret committed reference/version and owner/grant identity. Local delivery remains a hint; snapshot polling and periodic reconciliation recover missed invalidations. Publish only committed activations, not staged candidates or cleanup writes. Keep current worker/manual/export/caller-cancellation publication ownership unless a separate reviewed decision explicitly changes it. No unconditional event from the detached mint task is required for embedded phase 2.1; durable remote watches belong to phase 3.

Stable placeholders continue to identify authorization epochs, not each new secret version. Supervisor wire messages stay unchanged; only the gateway's revision and resolved snapshot contents change.

### 5. Public strategy-name compatibility

Add optional `strategy_name` to refresh profile/configure/status projections where needed, including their Rust/YAML and generated client representations. Allocate new protobuf tags after inspecting the final schema; preserve existing numbers, enums, presence semantics, and old enum-only requests. Store the canonical selected name in the new grant representation, without rewriting frozen V1/V2 messages.

Use one resolution rule:

- Name absent: preserve existing enum/profile-default behavior exactly.
- Name present: resolve the exact canonical registry name; if an explicit non-default enum also names a strategy, require agreement rather than silently choosing one.
- An unknown name is an explicit unsupported/configuration error, not fallback to another strategy. Reject an unknown nonzero enum on a new configure/profile input even when it accompanies a valid name; only the default/unspecified enum permits name-only selection. Preserve unknown integers when reading/migrating legacy stored state without making that state mintable. Name-only built-ins must work end to end.
- `static` and `external` retain their existing non-minting behavior. The `custom:` namespace is reserved but unavailable until registered custom minters exist in phase 3; adding a field does not add a plugin implementation.

Validate execution availability through an injected descriptor/registry view, without creating an issuer-to-profiles or providers-to-issuer dependency cycle. Keep offline structural profile validation separate from gateway availability validation. Update configure fingerprinting/replay so different strategy names cannot replay the same request intent. Preserve all existing output/material validation and built-in descriptor parity.

## Migration and rollout

This is a correctness gate, not incidental startup cleanup. Do not activate reference writes while phase 2 or older processes can still mutate the same records/backends.

1. **Prepare compatible readers.** Add the versioned issuer schema, migrations/decoders, read support, reference/grant persistence port, and migration journal without switching active writes. Freeze old decoders and reviewed schema fingerprints. Inspect existing gateway activation patterns, but do not mistake expiring membership records for a fence against unknown old writers.
2. **Establish exclusion.** For the first activation, recommend an operator-controlled maintenance window: drain incompatible gateways and all refresh/configuration writers, take a coordinated database/backend backup, and start only compatible replicas under an exclusive migration lease. Reuse supported SQLite single-gateway and Postgres locking behavior. If all-at-once automatic startup migration cannot establish exclusion, require explicit activation rather than trusting a new marker an old binary does not understand. A new activation option, if necessary, requires matching configuration docs; no Helm service or remote mode is introduced.
3. **Inventory all state.** Enumerate provider static/refresh outputs, existing grants, legacy inline provider/refresh material, typed internal secrets, tombstones, parked/in-progress attempts, and pending deletions. Classify by database, Kubernetes Secrets, Vault, and configured UDS driver capabilities. Persist progress by immutable owner/key/source identity, not a pagination offset or provider name. Missing sources or unsupported driver guarantees block that owner rather than silently skipping it.
4. **Adopt existing handles.** Under the appropriate lease, record reference bindings/version 1 pointing at the current backend candidates without rewriting paths, ciphertext/AAD, key IDs, or handle bytes. Preserve effective legacy epoch, expiration presence, all metadata and recovery state. Adoption itself does not mint, rotate, or establish that an uncertain attempt succeeded. Missing output values remain pending/withheld, not fabricated version-1 credentials.
5. **Prepare inline migration.** Store inline values through the same selected encrypted backend with unique, retryable staging identities, and durably prepare the corresponding issuer binding. Keep the original active inline fields intact throughout preparation. At the binding switch in step 6, remove those fields in the same conditional gateway-record update that installs the validated replacement binding; do not clear a value in one step and attach its replacement in another. Destructive inline removal is itself an irreversible old-binary compatibility boundary, even if no new mint has occurred. On uncertainty keep a recoverable candidate/intent; never delete the only valid rotated refresh token. The journal contains only protected/non-secret intent and handles, never plaintext values. No additional durable plaintext copy is introduced.
6. **Switch bindings and activate.** Conditionally update provider/internal-secret bindings and active grants only after their adopted state is durable and validated. Resume incomplete transitions on restart without reverting newer state, resurrecting deleted epochs, or creating another reference/version for the same migration intent. Finish a scoped consistency scan before resuming that owner's refresh/delivery. Fail startup/readiness clearly if the deployment-wide activation cannot finish safely.
7. **Retire compatibility writes.** After activation, write only the new representation and keep legacy decoding for recovery/upgrade tests. Remove the temporary `GatewayRefreshCommit`, `RefreshAttempt`, and provider-write path after every active refresh path uses manifests. Retain any server adapter still needed to read old records; its existence is not a second engine.

Before any binding switch or destructive inline removal, rollback can use the old active records because new records are only prepared. Old-binary rollback eligibility ends at the first such incompatible mutation, not merely at the first mint or the final deployment-wide activation marker. Once legacy fields have been removed or versioned writes become authoritative, an old binary cannot safely run: values may no longer be reachable by its readers, stale legacy handles would miss rotations, and old writers could corrupt new state. Require a compatible rollback build or a reviewed coordinated database/backend restore. Do not promise a lossless downgrade by flipping a flag or dual-writing rotated handles forever. An upstream-rotated refresh token may also make a backup restore insufficient; retain replacement-material recovery and document when reauthorization is required.

Backend migration to another store and embedded-to-remote data transfer remain out of scope. Do not delete legacy physical candidates merely because their former gateway fields have been removed; only unreachable candidates with a durable cleanup record are eligible.

## Implementation sequence and gates

Implement as separately reviewable changes on the final phase 2 base. Keep preparation and activation separable; do not expose a half-migrated release as remote-ready.

| Step | Work | Required gate |
| --- | --- | --- |
| 1. Freeze contracts and characterize behavior | Specify reference identity, version/manifest linearization, grant lifecycle, configuration saga, delete-to-static behavior, migration exclusion, and strategy precedence. Record current tests and durable fixtures. | Review agrees on data model and rollout; no ambiguity about epoch vs version or old-writer exclusion. |
| 2. Add issuer persistence and versioned storage | Add reference/grant/manifest/journal types and narrow adapter operations. Reuse existing pools and backend drivers; add immutable staging, conditional/idempotent activation, and exact tombstones. | Real SQLite/Postgres tests prove atomic bundle visibility, monotonicity, conflicts, restart recovery, and no resurrection. |
| 3. Prepare migration and resolver | Add legacy readers/adoption, inline migration, internal-secret bindings, and versioned batch resolution behind inactive activation. Keep frozen old formats. | All supported backend/legacy fixtures resume safely after failure at every transition; preparation alone leaves old behavior usable. |
| 4. Bind grants at configuration time | Prepare/commit/activate grants through existing authorization, output validation, provider CAS, replay, deletion, and export paths. Introduce references without per-refresh provider mutation. | Same-name replacement, direct writes, reconfigure/delete races, static retention, and replay cannot leak/revive old epochs or activate losing grants. |
| 5. Activate outputs inside issuer | Adapt the existing engine to manifest commits and version-bearing results; preserve rotated-material/uncertainty handling, leases, limits, and cleanup. | Mint succeeds with no provider writes or gateway commit callback; multi-output and final-response/status failures do not repeat activation or delete live outputs. |
| 6. Wire coherent revisions and publication | Resolve once per build, hash those versions, adapt push/poll/export and local invalidation payloads, and keep placeholder identity stable within an epoch. | A refresh with unchanged provider resource version changes delivery revision; raced resolution never pairs mismatched values/versions; existing failure and publication contracts pass. |
| 7. Add strategy-name compatibility | Add protobuf/profile/CLI/SDK projections and compatibility/replay validation; use registry descriptors without dependency cycles. | Enum-only, name-only, matching/conflicting dual inputs, defaults, unknown values, output mapping, and YAML/API round-trips have coverage. |
| 8. Activate, remove bridges, document | Exercise maintenance-window upgrade/restart/rollback gates, remove `GatewayRefreshCommit` and obsolete live V2 writers, document user-visible compatibility changes. | Final migration/backend/SQLite/Postgres/delivery matrix passes; no callback, duplicate engine, remote feature, or unsupported downgrade claim remains. |

## Source map

Paths are relative to the repository root. Exact new module names are implementation choices, not requirements to scatter the model across more crates.

| Area | Existing integration points |
| --- | --- |
| Issuer storage and owner APIs | `crates/openshell-credential-issuer/src/lib.rs`, `embedded.rs`, `owner.rs`, `refresh_material.rs` |
| Refresh engine/registry/ports | `crates/openshell-credential-issuer/src/refresh/{mod,engine,minter,tests}.rs` |
| Existing persistence/backend integration | `crates/openshell-server/src/{credential_store,refresh_store,refresh_commit,storage_proto}.rs`, `crates/openshell-server/src/persistence/`, `crates/openshell-server/proto/storage.proto`, `crates/openshell-driver-db-credstore/`, `crates/openshell-driver-vault/`, `crates/openshell-driver-kubernetes-secrets/` |
| Gateway composition and grants | `crates/openshell-server/src/{lib,credentials,provider_refresh}.rs`, `grpc/provider.rs`, `grpc/provider_credentials.rs`, `grpc/mutation_replay/ordinary.rs` |
| Snapshot/revision/delivery and intermediate-token cache | `crates/openshell-server/src/grpc/policy.rs`, `grpc/policy/config_inputs.rs`, `grpc/provider.rs`, `config_delivery/` |
| Internal secrets | `crates/openshell-server/src/ssh_identity.rs`, `crates/openshell-server/src/supervisor_pool.rs` |
| Strategy schema/profile/client mapping | `proto/{datamodel,openshell}.proto`, `crates/openshell-providers/src/profiles.rs`, `crates/openshell-cli/`, `crates/openshell-core/build.rs`, Python and TypeScript codegen consumers |

## Validation matrix

| Boundary | Required evidence |
| --- | --- |
| Versions and activation | Adoption starts at 1; successful same-byte writes increment; failed/stale/idempotent retries do not; overflow fails closed; reload preserves versions; cleanup/status writes do not satisfy mint coalescing. |
| Multi-output consistency | Readers see one committed AWS output bundle; faults before/after each staging/journal/CAS step never publish a mixed bundle; expired/missing outputs fail closed. |
| Identity and revocation | Workspace/owner/key/driver mismatches denied; same-name provider replacement denied; reconfiguration revokes the old epoch; stale mint/delete/replay cannot overwrite or resurrect a replacement; delete-to-static preserves intended last values. |
| Configuration saga | Provider CAS failure, lost activation response, crash before/after binding switch, abandoned prepared grant, and replay with a different intent have deterministic recovery; only the winning grant can mint. |
| Real backends | Database encryption/AAD and handle/path compatibility, Vault/Kubernetes/UDS staging and uncertain-write behavior, missing objects, outage/retry, and cleanup of candidates shared by old/new bindings, including concurrent last-link reclamation versus adoption/ownership transfer. Use existing fixtures/lanes; do not treat an in-memory fake as backend migration evidence. |
| Migration/rollout | V1/V2 refresh records, legacy inline material, absent/explicit-epoch/fractional times, parked/committing attempts, multiple deletion generations, typed internal owners, restart mid-migration, concurrent compatible replicas, rejected old-writer activation, atomic inline removal/binding switch, and rollback eligibility before/after the first incompatible mutation. |
| Locking and cancellation | Preserve data-pool Postgres advisory leases, local serialization, 32 admissions/four executors, unrelated-key progress, mutation-pool exhaustion behavior, cancellation-safe attempts, and bounded sequential sweeps. |
| Delivery and export | Version/value/expiration come from one capture; poll and push see rotations without provider writes; stable placeholders do not rotate with versions; revocation/profile edits or cleanup during resolve fail/retry; export lifetime and no-partial-value rules remain; stale copied refresh expiries do not cap new outputs, while independent provider limits still apply. |
| Existing token cache | Subject rotation with an unchanged provider row misses the prior version's intermediate-token entry; authorization/identity checks and subject-expiration bounds remain; resolution still precedes cache lookup in this increment. |
| Publication | No publish before activation, losing CAS, or cleanup; existing worker/manual/export/cancellation asymmetries retained; lost local invalidations recovered by existing poll/reconciliation. |
| Public/API compatibility | Enum/name precedence, profile defaults, canonical name parity, unknown/custom rejection, request replay fingerprints, additive protobuf evolution, frozen durable fingerprints, public descriptor/reflection boundaries, and generated-client round-trips. |
| Internal secrets | Existing SSH fingerprints and supervisor launch-material identity survive adoption/restart; deleted owners cannot resolve; no provider-version hash dependency introduced. |

Preserve and extend the existing unit/in-process integration and Postgres lanes. Add upgrade fixtures and focused existing-lane backend coverage where durable behavior changes. Do not introduce remote-service e2e requirements in this phase; retain the repository's ordinary required CI and existing relevant backend e2e checks.

Use the established tasks and toolchains during implementation:

```shell
mise x -- cargo fmt --all -- --check
mise x -- cargo check --locked -p openshell-credential-issuer -p openshell-server -p openshell-gateway
mise x -- cargo check --locked -p openshell-cli --tests
mise x -- cargo clippy --locked -p openshell-credential-issuer -p openshell-server -p openshell-gateway --all-targets -- -D warnings
mise x -- cargo test --locked -p openshell-credential-issuer
mise x -- cargo test --locked -p openshell-server --features test-support
mise x -- cargo test --locked -p openshell-providers
mise run test:rust:postgres
mise run proto:lint
mise run python:proto
mise run sdk:ts:ci
mise run rust:lockfiles:check
mise run rust:deny:policy
mise run pre-commit
```

Run affected driver and schema-compatibility tests, existing relevant Python/CLI tests, and normal production feature/dependency checks. Rust generation follows the existing build script. Do not commit generated TypeScript outputs or modify frozen `sdk/go/`; coordinate any needed Go SDK changes in its maintained repository. Public `strategy_name` and durable schema changes require their actual compatibility tests, not merely proto lint or manually updated fingerprints. Use existing Z3/Postgres setup; no new image or test runner is implied.

Update the issuer/server READMEs, relevant provider-refresh/profile/API docs, and upgrade/rollback guidance. Review related contributor skills with `sync-agent-infra`; update configuration docs and `debug-openshell-cluster` only if an activation option or operating procedure changes. Do not edit published remote-mode instructions before that feature exists.

For this planning-only artifact, run scoped Markdown lint, source/link checks, and `git diff --check`; Rust/runtime validation above is an implementation requirement, not a claim of tests run for this document.

## Review decisions before implementation

1. **Approve the activation model:** one manifest/CAS per output bundle and a recoverable prepare/bind/activate/revoke configuration protocol. Write its state-transition table, including exact old-epoch revocation and output-retention points, before changing persistence.
2. **Approve rollout policy:** recommend explicit maintenance-window activation and no old-binary downgrade after activation. If rolling mixed-version activation is required, it needs a real old-writer fencing design and additional scope; membership snapshots alone are insufficient.
3. **Confirm driver recovery requirements:** document which existing backends can safely stage/recover uncertain writes. A capability gap must produce an explicit unsupported activation path or reviewed adapter improvement, not unsafe emulation.
4. **Approve the additive public field scope:** canonical built-in names now, `custom:` reserved but unavailable, and explicit conflicts with enums rejected. `ListStrategies` and custom minter transport remain phase 3.

These are design/rollout approvals for future implementation, not blockers to writing this plan. They must not be silently decided by implementation convenience.

## Definition of done and phase 3 handoff

- All six gaps have implementation and test evidence: stable references, persistent secret versions, retryable legacy migration, coherent version-aware revisions, issuer-owned grant/output activation, and compatible public strategy names.
- Refresh preserves provider identity, epoch/recovery semantics, locks, backend compatibility, and fixed output mappings without mutating provider rows or invoking `GatewayRefreshCommit`.
- Provider/profile/authorization/delivery policy remains gateway-owned. Secrets remain only in issuer-selected backends; gateway records and migration/replay/notification metadata contain no new plaintext.
- Existing handles migrate as reference identities at version 1; mixed-version exclusion, incomplete migrations, cleanup debt, and downgrade limitations are enforced and documented rather than implied away.
- One snapshot hashes the versions of the values it actually delivers. Poll detects issuer-only changes; push remains a recoverable invalidation path; supervisor protocol and same-epoch placeholders remain stable.
- Embedded mode remains the only runtime mode. The issuer has no server-private format dependency in its active domain model and no provider-commit callback. It may still use embedding-supplied persistence adapters; this does not claim a standalone issuer database/binary already exists.
- Phase 3 can then design service contracts, authenticated identity binding, watches/caching, remote minters, and subject-token cache ordering against real reference/grant/version semantics, not raw-handle emulation.
