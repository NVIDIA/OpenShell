<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# OpenShell gateway server

The server owns control-plane RPCs, authentication, provider credential delivery,
and sandbox lifecycle orchestration. The `openshell-gateway` crate composes the
server with selected compute drivers.

## Sandbox launch identity

A new start, including an automatic restart, commits a fresh runtime generation
and an incremented authorization epoch before invoking the compute driver.
The launch session ID is derived from the durable sandbox ID and generation.
Retries reuse that generation and session, including after gateway restart.
Credential renewal retains both; credentials for an older launch cannot
authorize the new one.

## Operator credential export

`GetProviderCredentials` exports selected profile-declared runtime environment
keys from one provider in an explicitly named workspace. It requires the distinct
`Principal::Operator`, established only from a verified TLS leaf certificate with
`OU=operator` when `mtls_auth.operator_enabled` is enabled. The TLS listener supplies
its certificate fingerprint separately from user identity; the ordinary
identity-only serving path cannot establish an operator.

Operators explicitly inherit user/platform-admin permissions, but not sandbox or
peer identities. Descriptor authorization and a handler guard both protect the
export RPC. Operator mutation admission uses a separate caller namespace from
ordinary mTLS users with the same certificate subject. Credential responses never
enter durable mutation replay or generic interceptor routing.

The export resolver validates the entire selection before minting, resolves only
selected credential handles, and fences provider revisions, refresh epochs, and
profile declarations before delivery. Driver expiration and provider expiration
combine using the earlier timestamp. OAuth minting inputs, broker-only keys, and
supervisor-bound dynamic grants are not exportable. A failed response can still
have committed refresh effects. Missing refresh-owned stored outputs trigger
refresh-on-read; missing static outputs and other credential-backend errors fail
closed without falling back to inline values.

## Refresh coordination

Explicit rotation, background refresh, and operator refresh-on-read share the
same refresh coordination:

- A process-local weak keyed mutex coalesces waiters without retaining deleted
  providers indefinitely.
- A bounded admission queue and executor pool limit detached refresh work.
- PostgreSQL deployments also take a dedicated per-provider/per-credential
  advisory lock; SQLite uses the local mutex. Worker secret cleanup takes the
  same locks and reloads state before changing its resource version.
- A durable `refresh_in_progress` marker precedes upstream minting. A
  `refresh_committing` marker protects the interval between grant persistence
  and provider-handle persistence. Only a completed provider commit publishes
  `refreshed` state, with a unique completed-mint identity in metadata
  annotations. Waiters coalesce against that identity, not bookkeeping changes
  to the resource version.
- Automatic callers recheck live recovery and retry deadlines under both locks.
  A failed mint blocks queued automatic exchanges without disabling scheduled
  worker retries or a separately requested manual rotation.
- Detached refresh tasks complete despite request cancellation, preserving
  replacement refresh tokens returned by the issuer.
- Existing generation/CAS fencing remains active for deletion and
  reconfiguration. An ambiguous rotating-token exchange is parked for recovery
  rather than automatically consuming the grant again.

A crash or lost database-lock session can leave a parked marker. Reconfigure or
reauthorize the refresh grant after investigating its issuer state. Changing a
marker directly is not a supported recovery workflow.

## Focused verification

```shell
cargo test -p openshell-server --features test-support,prebuilt-z3
cargo clippy -p openshell-server --all-targets --features test-support,prebuilt-z3 -- -D warnings
```

The ignored `postgres_refresh_locks_coordinate_independent_replica_sessions` test
runs under `mise run test:rust:postgres` (see `TESTING.md`) and still accepts
`OPENSHELL_REFRESH_TEST_DATABASE_URL` pointing to a disposable PostgreSQL database.
It exercises independent sessions without the local mutex. Do not point this
fixture at an existing deployment database.

## Sandbox identity broker

`openshell.gateway.spiffe_delegation` enables gateway-owned SPIRE
acquisition for the Kubernetes shared supervisor. The private admin
socket is mounted only in the gateway. `GetSandboxProviderAccessToken` accepts an
endpoint-bound configured credential key; sandbox identity comes from the
verified, currently authorized session JWT. The key must equal one of the
gateway's configured keys, including its endpoint owner, once the supervisor's
revision and installation are removed. Provider attachment and profile
configuration determine the endpoint, audience, and scopes. The gateway performs
RFC 7523 or both RFC 8693 exchanges and returns only the final access token.
Its bounded cache is isolated by sandbox generation, credential epoch, provider
revision, the matched configured key and grant, and the subject token, which is
resolved before every lookup so its revocation or rotation also applies to
cached tokens. Concurrent misses for one cache key wait for a single
acquisition, then use its cached token. A token is served until the usual skew
before the earliest of its `expires_in`, its JWT `exp`, and the session, SVID,
and subject expiries, and no longer than the default cache lifetime; a
configured cache TTL can only shorten that. The response reports the remaining
lifetime. The session is authorized again around each SPIRE and
token-service call. A cache hit and a fresh token then pass the same final
check: the grant configuration still matches and the session is still
authorized. A fresh token is cached only after that check. Startup validates
the delegation settings, and gateway state construction parses them once and
returns a configuration error when they are invalid; each cache miss fetches
a new SVID and the agent's current JWT bundle. SPIRE still trusts the gateway as a
delegate for its agent's available registration scope.

`openshell_core::token_grant_failure` defines the time limits: SPIRE and
Workload API calls, token-service requests, the gateway's deadline for one
request (including waiting for a concurrent acquisition), and the longer
supervisor deadline that covers connecting to the gateway.

Deployments must admit the admin socket mount: the chart uses a hostPath
volume, which Pod Security Baseline and Restricted forbid, so the namespace
needs a policy exception or custom admission policy, and OpenShift must admit
`admin_socket_group`. The gateway never changes its own groups; outside the
chart, run it with that group. The SPIRE agent must create the socket directory
before the gateway Pod starts. Sandbox registrations must cover every agent
that may run a gateway Pod, for example through a node alias; a gateway on a
node whose agent lacks them fails every grant.
