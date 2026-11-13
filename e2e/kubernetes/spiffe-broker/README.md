# SPIFFE Broker API experiment

This local spike checks whether SPIRE's Broker API can issue the stable sandbox
JWT-SVID over mTLS using an attested Kubernetes object reference. It runs
against the existing Helm dev cluster in the checkout's `kubeconfig`, with the
SPIRE 1.15.3 / hardened chart 0.30.3 fixture already installed in `spire`.
The gateway integration is covered by the separate end-to-end task below.

Run from the repository root:

```shell
mise exec -- cargo build -p openshell-spire --example broker_probe
mise exec -- uv run --no-project python e2e/kubernetes/spiffe-broker/experiment.py setup
mise exec -- uv run --no-project python e2e/kubernetes/spiffe-broker/experiment.py test
```

`setup` backs up the agent ConfigMap under ignored `.cache/spiffe-broker/`,
enables the experimental TCP Broker endpoint on port 8443, adds agent permissions
to resolve Sandbox objects and perform SubjectAccessReviews, and restarts the
agent. Use a dedicated development cluster without concurrent SPIRE configuration
changes. The script expects the fixture's resource names and `openshell.local`
trust domain.

The two client pods run in `openshell-broker-probe`, where Restricted Pod Security
is enforced. Their only identity socket is the CSI Workload API mount. An init
container obtains a short-lived X.509-SVID; the script copies the test credentials
to ignored files with mode 0600 for the native Rust probe. This export is a test
shortcut. A gateway integration must obtain and rotate its own credentials through
the Workload API without exporting them to the operator's machine.

`test` owns a temporary port-forward from localhost:18443 to the agent. The Rust
client verifies the agent's certificate chain and exact SPIFFE URI SAN using
`openshell-crypto`. It sends the required `broker.spiffe.io: true` header,
requests a JWT-SVID, retrieves the JWT bundle, then verifies the signature,
audience, expiry, and expected sandbox subject. Tokens and private keys are not
printed.

The target is a suspended Sandbox CR referenced by resource type, namespace,
name, and UID. Its SPIRE registration matches `k8s:resource` and `k8s:uid`,
using properties attested by SPIRE. The client's SPIFFE
identity has the custom `impersonate-via-spire` permission for only the allowed
Sandbox. A second Sandbox exists to check authorization denial.

## Observed results

Against the local k3d Helm dev cluster on November 13, 2026:

| Check | Result |
| --- | --- |
| Allowed Sandbox reference | JWT-SVID issued and verified |
| UID-only Sandbox reference | JWT-SVID issued and verified |
| Missing Broker metadata header | `InvalidArgument` |
| Existing Sandbox outside the client's object grant | `PermissionDenied` |
| Correct name with a stale UID | `NotFound` |
| Valid X.509-SVID absent from the broker allowlist | Request refused; native client observes `Unknown` |
| Agent certificate with an empty trust store | Client rejects the certificate chain |
| Unexpected agent SPIFFE identity | Client rejects the TLS certificate |

This establishes transport and identity issuance against real SPIRE with enforced
Kubernetes authorization. It does not establish OpenShift operator support,
credential rotation, multi-agent routing, or the full gateway provider-token and
supervisor-failover path.

## Gateway verification

The branch's gateway adapter uses the SPIFFE Broker API with the persisted
Sandbox CR UID. Run the complete provider-token and failover path with:

```shell
mise run e2e:kubernetes:shared-supervisor-spiffe
```

That task creates a separate test cluster and pinned SPIRE installation. It
also tests Restricted gateway admission and acquisition after X.509 credential
rotation. The independent probe above targets the existing dev cluster.

Restore the agent's original configuration and remove the probe objects and
exported credentials:

```shell
mise exec -- uv run --no-project python e2e/kubernetes/spiffe-broker/experiment.py cleanup
```

Upstream contracts:

- [SPIRE 1.15.3 Broker API](https://github.com/spiffe/spire/blob/v1.15.3/doc/spire_agent.md#spiffe-broker-api)
- [SPIRE 1.15.3 Kubernetes reference attestation](https://github.com/spiffe/spire/blob/v1.15.3/doc/plugin_agent_workloadattestor_k8s.md)
- [Broker API protobuf](https://github.com/spiffe/spiffe/blob/main/standards/brokerapi.proto)
