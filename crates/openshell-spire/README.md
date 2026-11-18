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
3. Connects to the selected Broker endpoint over mTLS, verifying the agent certificate
   chain and configured exact or cluster-scoped SPIFFE URI policy through `openshell-crypto`.
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
SubjectAccessReview permissions. UID-only references require cluster-wide
`get`/`list` access to Sandbox resources for the SPIRE agents; metadata-only
responses do not narrow Kubernetes RBAC permissions. The gateway SPIFFE ID needs
`impersonate-via-spire` only for its permitted Sandbox resources. Registrations
match attested Sandbox UIDs and must reach each selected agent. The configured
peer policy must authorize the endpoint's agent certificate. Configure exactly
one of `server_spiffe_id` (exact identity) and `server_spiffe_id_prefix`
(descendants of one cluster-scoped SPIFFE path). Use a node alias as the parent
of registrations served by multiple agents; the alias does not replace their
concrete certificate identities.

Set `node_local_port` to connect directly to the gateway's node-local agent.
The gateway resolves `OPENSHELL_NODE_IP` from the Pod's Downward API at startup;
missing or invalid addresses fail startup. IPv4 and IPv6 addresses are supported.
The Broker listener must be reachable on that node address. Alternatively, set
an explicit HTTPS `endpoint`. These settings are mutually exclusive. Node-local
mode uses no Broker Service; gateway movement requires registrations on every
eligible agent, even when the sandbox and supervisor remain on other nodes.

## Verification

```shell
mise run e2e:kubernetes:shared-supervisor-spiffe
mise run e2e:kubernetes:shared-supervisor-spiffe-node-local
```

The test installs pinned SPIRE charts, exercises the full provider exchange,
forces acquisition through each agent on a three-node cluster and a replacement
agent without re-registering sandboxes, checks supervisor
takeover and stale-session fencing, and forces acquisition
after the fixture's 30-second workload X.509-SVID expires. It also checks that
the gateway Pod passes Restricted Pod Security admission.
The node-local variant uses external PostgreSQL to move the gateway across
nodes, restricts Broker egress to its current node, and verifies fresh acquisition
without a Broker Service, including after its local agent is replaced.
