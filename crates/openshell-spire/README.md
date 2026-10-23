# openshell-spire

SPIRE adapter for gateway-owned sandbox identities. The gateway uses it to
obtain JWT-SVIDs for sandboxes under shared supervision. In this flow, only
the gateway reaches the SPIRE agent.

## Interface

`SpireDelegatedIdentity` implements
`openshell_spiffe::SandboxIdentityProvider` with
`openshell_core::token_grant_failure::TokenGrantFailure` as its error type.
The gateway builds it once
at startup from `[openshell.gateway.spiffe_delegation]` and keeps it as a
trait object, so the provider-token broker does not depend on SPIRE. The
broker authorizes the sandbox session and provider credential first, then asks
for an identity with the gateway ID, sandbox ID, and token-service audience.
It retains provider configuration, token exchange, caching, and the
authorization checks around each call.

The result is a `SandboxJwtSvid` holding the stable SPIFFE ID, the token, and
its verified expiry. Its `Debug` output omits the token.

## Issuance

The stable identity is
`<spiffe_id_prefix>/gateway/<gateway-id>/sandbox/<sandbox-id>`, built by
`openshell_spiffe::SandboxSpiffeIdPrefix`, which configuration
validation also uses. Gateway and sandbox IDs must already be SPIFFE path
segments; anything else fails as a configuration error before the agent is
contacted.

For each request the adapter:

1. Connects to the agent's admin socket. Only an absolute Unix socket path is
   accepted, because the agent authorizes the delegate by attesting the
   connecting process. The underlying `spiffe` connector rejects Unix sockets
   on other platforms.
2. Calls `FetchJWTSVIDs` with the single selector
   `openshell:sandbox:<gateway-id>:<sandbox-id>` and the audience.
3. Requires exactly one SVID whose reported ID is the stable identity, so a
   missing, misregistered, or ambiguous registration is refused.
4. Reads the agent's current JWT bundle for the prefix's trust domain from
   `SubscribeToJWTBundles`, then verifies the token signature, audience, and
   expiry through the `spiffe` crate with the JWT provider installed by
   `openshell-crypto`, and checks the verified subject again.

Nothing is cached; every request fetches a new SVID and bundle.

## Errors and limits

Failures are `openshell_core::token_grant_failure::TokenGrantFailure` values,
which carry only an allowlisted classification. Agent status messages,
tokens, and bundles are never retained or logged. Agent status codes map to
`WorkloadIdentityRejected`, `Timeout`, `Unavailable`, `Configuration`, or
`Unclassified`. Connecting and each agent call are bounded by
`WORKLOAD_IDENTITY_CALL_TIMEOUT`.

## Wire messages

`src/wire.rs` transcribes the Delegated Identity API messages for
`FetchJWTSVIDs` and `SubscribeToJWTBundles` from `spire-api-sdk` `v1.15.3`,
with field numbers and types unchanged, instead of generating the full API.

## Tests

Unit tests cover identity and socket checks that fail before contacting an
agent. The ignored live test runs against a real SPIRE server and agent:

```shell
mise run test:spire-delegation
```

The task downloads a pinned, checksum-verified SPIRE release, registers
correct, missing, misregistered, and ambiguous sandbox entries, and requires
Linux.
