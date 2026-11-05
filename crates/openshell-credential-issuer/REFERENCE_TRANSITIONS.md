# Embedded reference activation transitions

This is the implementation contract for RFC 0023 phase 2.1. No network service or remote transaction is implied.

## Identity and visibility

- A qualified reference binds issuer namespace, workspace, immutable typed owner, logical key, and original driver/reference identity. Names are audit-only.
- A grant pins its epoch and output keys. Refresh never changes the provider binding, grant epoch, or reference identity.
- A per-owner CAS record contains reference manifests and grant journals. Grant journal resource versions are independent counters; unrelated grants can retry an owner-record CAS without invalidating their own expected grant generation.
- A successful activation CAS makes all output candidates, versions, expiration, and terminal grant state visible together. Failed/uncertain upstream attempts never count as completed mints.
- The row resource version, grant journal version, reference version, authorization epoch, and attempt ID are distinct quantities.

## Configuration and migration

| State | Durable evidence | Allowed next action | Read/mint behavior |
| --- | --- | --- | --- |
| Legacy | Existing provider/refresh/internal-secret records only | Prepare compatible readers, drain old writers, obtain migration lease | Existing behavior |
| Prepared | Handle-backed candidates and inactive reference/grant bindings; old fields retained | Conditional binding switch or abandon preparation | Old binding works; inactive candidates cannot mint |
| Binding switched | Provider CAS installs prepared references and removes inline fields together; exact immutable identity recorded | Activate matching prepared grant, or recovery of that exact switch | Unactivated new binding fails closed; no fallback to old epoch |
| Active | Matching binding/epoch and manifest/journal activation committed | Resolve; mint under existing guards; prepare replacement | Resolve only committed versions; no gateway provider commit during refresh |
| Reconfigured | New binding and epoch win; old epoch revoked | Reclaim unreachable old candidates | Old reference and in-flight old mint fail; no name-based rebinding |
| Refresh disabled | Last active outputs transferred into an authorized static binding; grant revoked | Resolve static outputs or explicitly replace/remove them | Last values retained according to existing expiration rules; old grant cannot mint |
| Owner deleted | Exact owner/reference tombstone committed | Reclaim unreachable candidates | No resolution or resurrection |

Ordinary static provider updates stage separate immutable candidates, then commit a non-secret provider transition marker while retaining the existing destination references. Until the exact issuer activation receipt exists, resolution fails closed. One owner-record CAS advances destination versions and retires staged aliases; restart replays that exact marker without incrementing twice. A definite provider CAS loser may reclaim its preparation; an ambiguous database outcome must retain it until exact binding reconciliation proves what committed.

Disabling refresh captures and transfers the entire output bundle in one owner-record CAS, creating independent static manifests without mixing source generations. Public provider expiration projections read committed manifest metadata without secret I/O and retain any shorter independently authored limit; a committing grant journal is not expiration authority.

The first incompatible binding switch or removal of inline fields ends old-binary rollback eligibility. A final migration marker is not that boundary. All old writers must be retired before switching; replica membership expiration is not an old-writer fence. A compatible rollback build or coordinated database/backend recovery is required afterward; upstream-rotated grants may require reauthorization.

## Mint and reclamation

| Transition | Required condition | Failure/recovery |
| --- | --- | --- |
| Claim attempt | Current grant version/epoch, not deleted; existing admission/lock/lease held | Stale attempt aborts without upstream I/O |
| Park uncertainty | Durable in-progress marker before upstream I/O | Restart parks rather than reuses a potentially consumed grant |
| Stage replacement material | Unique immutable backend write identity | Preserve potentially upstream-valid replacement on uncertain persistence |
| Stage outputs | Durable attempt intent; fixed declared output mapping | No output is visible before activation |
| Activate bundle | Expected grant version/epoch and all output candidates; one CAS | Winner advances versions exactly once; loser cannot delete winner |
| Finish/notify | Activation already durable | Lost response/notification or cleanup failure cannot roll back, bump again, or remint |
| Claim reclamation | Last-link check and reclamation claim atomic with new links/ownership transfer | New links rejected once claimed; uncertain deletion retains claim/debt |
| Resolve during cleanup | One captured manifest; pinned candidate or generation recheck | Retry/fail closed, never substitute another generation under an old version |

No step claims atomicity across external backend writes and database activation, exactly-once OAuth effects, or snapshot consistency across unrelated providers. Idempotency applies to the issuer activation decision with the same bound operation intent, not an arbitrary repeated upstream call.

## Successful-history retention

The runtime bounds the hot owner row for a fixed refresh binding to the current
activation journal, current grant state and candidate links, plus unfinished
operation/reclamation debt. Before an owner CAS removes a superseded successful
activation, it durably writes a create-only sidecar containing a domain-separated
`openshell-crypto` SHA-256 digest of the exact non-secret operation intent and the
original activation receipt. The full historical terminal grant state, handles,
and staging journal are not copied into the receipt. An exact retry returns that
receipt without changing authorization, versions, backend objects, or current
terminal grant state; changed intent under the same ID is rejected.

After successful backend deletion, compact create-only candidate-denial evidence
replaces the hot `Deleted` candidate. The reclamation claim remains in the owner
row until this evidence is durable. A new link checks both the hot claim and
sidecar evidence; the owner CAS arbitrates a concurrent claim/link. Recreating an
old opaque backend object cannot make its identity adoptable again. Failed or
uncertain deletes retain their full claim and backend ownership information.

Sidecars reuse the existing conditional store in a separate cold object type,
`credential.issuer-reference-retention.v1`, with disjoint, owner-qualified IDs.
The narrow `get_retention`/create-only `put_retention` port keeps this collection
out of owner enumeration, including ordinary grant lookup and refresh sweeping.
Archive writes precede owner-row pruning: a crash/conflict can leave duplicate
evidence, never an owner row pruned without evidence. Only previously committed,
superseded activation decisions are archived; staging a new activation never
creates a success receipt for it. Grant enumeration never fetches sidecars.

Operation IDs and authorization epochs are arbitrary strings, not monotonic
watermarks. Manifest generations and grant resource versions fence stale writes,
but do not prove that an old operation ID was never bound to different intent.
Consequently the runtime does not TTL-prune receipts or candidate-denial evidence.
Total durable minimal evidence still grows with distinct historical operations
and physical candidates; ordinary resolution and owner-row mutation no longer
reload/rewrite those historical records. Grant enumeration likewise reads only
hot owner records, not historical sidecars. Static protected-write recovery
journals, exact provider-update markers, binding/epoch tombstones, and unfinished
recovery debt are deliberately retained, not treated as refresh-history garbage.

A protected static-write retry reloads and revalidates its durable exact intent
and abandonment state before reconstructing candidates. A concurrent retry may
already have completed the journal while a newer write and reclamation removed
its former candidates. In that case the durable completion receipt returns the
original references without backend I/O or another version increment. Historical
success does not authorize a revoked binding; unfinished abandoned writes fail
closed instead of using a stale local journal.
