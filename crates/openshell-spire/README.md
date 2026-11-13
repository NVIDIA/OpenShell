# openshell-spire

SPIFFE Broker API adapter for gateway-owned sandbox identities. Only the
gateway obtains sandbox JWT-SVIDs; supervisors receive final provider tokens.

`SpireSandboxIdentity` implements `SandboxIdentityProvider` using
`openshell_core::token_grant_failure::TokenGrantFailure` as its error type.
Startup selects it from `[openshell.gateway.spiffe_broker]`. The provider-token
broker owns session authorization, provider configuration, exchange, and caching.

For each acquisition the adapter:

1. Extracts the Sandbox CR UID from the gateway's persisted Kubernetes runtime
   identity. Supervisors cannot supply a reference or selectors.
2. Fetches current gateway X.509-SVID credentials and trust bundles through the
   local CSI Workload API socket.
3. Connects to the Broker endpoint over mTLS, verifying the agent certificate
   chain and exact configured SPIFFE URI through `openshell-crypto`.
4. Requests a JWT-SVID for a `KubernetesObjectReference` containing the Sandbox
   resource type and UID. SPIRE resolves and attests the object and enforces the
   gateway's Kubernetes authorization.
5. Fetches the JWT bundle and verifies the signature, audience, expiry, and
   exact expected subject `<prefix>/gateway/<gateway-id>/sandbox/<sandbox-id>`.

Every RPC includes `broker.spiffe.io: true`. Acquisitions fetch fresh credentials
and bundles so Workload API rotation does not require a gateway restart. The
whole operation is bounded by `WORKLOAD_IDENTITY_CALL_TIMEOUT`. Errors retain
only bounded classifications; credentials and upstream diagnostics are not logged.

The operator enables SPIRE's experimental Broker endpoint, authorizes the
gateway SPIFFE ID and `KubernetesObjectReference` over TCP, and configures
`access_policy = "enforced"`. The agent needs Sandbox lookup and
SubjectAccessReview permissions; the gateway SPIFFE ID needs
`impersonate-via-spire` only for its permitted Sandbox resources. Registrations
match attested Sandbox UIDs and must reach each selected agent. The configured
server SPIFFE ID must match the endpoint's agent certificate.

## Verification

```shell
mise run e2e:kubernetes:shared-supervisor-spiffe
```

The test installs pinned SPIRE charts, exercises the full provider exchange,
checks supervisor takeover and stale-session fencing, and forces acquisition
after the fixture's 30-second workload X.509-SVID expires. It also checks that
the gateway Pod passes Restricted Pod Security admission.

The [`broker_probe` experiment](../../e2e/kubernetes/spiffe-broker/README.md)
provides independent positive and negative protocol checks.
