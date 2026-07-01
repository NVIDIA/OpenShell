# Governance Interceptor Example

This standalone example implements the
`openshell.gateway_interceptor.v1.GatewayInterceptor` service. It demonstrates
how an interceptor can vend provider profiles and make them the gateway's
authoritative profile source.

- provider profile YAML lives in `profiles/*.yaml`
- `provider list-profiles` shows only the profiles vended by this interceptor
- providers can only be created with a `type` that matches one of those vended
  profile IDs
- every vended provider profile gets governance annotations for its hash,
  signature, and signing key ID
- every new sandbox receives `policy.yaml` during `CreateSandbox`
- requested sandbox providers must match one of the vended profile IDs
- every new sandbox gets an `openshell.nvidia.com/policy-signature` metadata
  annotation that is used to verify the policy
- sandbox creation evaluations add a `correlation_id` log annotation for gateway
  audit logs, plus non-secret policy hash/signing key metadata
- users cannot replace or merge sandbox policy after sandbox creation
- users cannot import or update provider profiles outside the vended set
- provider profile deletion is blocked by the interceptor

Run the interceptor:

```shell
cargo run -- \
  --listen 127.0.0.1:18081 \
  --policy policy.yaml \
  --profiles profiles \
  --gateway-endpoint http://127.0.0.1:8080
```

At startup the example parses `policy.yaml`, converts it to the protobuf JSON
shape used by sandbox creation, computes a canonical SHA-256 digest, and signs
that digest as an EdDSA JWT. The interceptor adds that JWT to each governed
sandbox under `metadata.annotations["openshell.nvidia.com/policy-signature"]`
and verifies the JWT against the sandbox policy during the `CreateSandbox`
validate phase. The signing key is generated in memory on each interceptor
start. This keeps the example self-contained. Production governance services
should load managed signing keys, publish verifier keys, and define a rotation
process.

The interceptor polls the policy file every second by default. When `policy.yaml`
changes and parses successfully, the interceptor re-signs it immediately. New
sandboxes receive the updated signed policy through `CreateSandbox`. If
`--gateway-endpoint` is set, the example also lists running sandboxes and calls
`UpdateConfig` for ready or provisioning sandboxes so dynamic policy changes
propagate through the normal sandbox config polling path. Static baseline
changes that the gateway rejects for existing sandboxes are logged and still
apply to newly created sandboxes.

Provider profile YAML files are loaded by the interceptor from `--profiles`
(default: this example's `profiles/` directory). The interceptor names each
profile from its filename without the extension: `profiles/github.yaml` becomes
profile ID `github`, and `profiles/slack.yaml` becomes profile ID `slack`. The
YAML files do not need an `id` field; if one is present, the filename still wins.

The interceptor advertises `provider_profiles = true` in its manifest and vends
the current profile set through `SnapshotProviderProfiles`. While the
interceptor is attached, the gateway uses that snapshot as the profile source:
`provider list-profiles` shows only `github` and `slack`, and built-in/user
sources are omitted. The example signs each profile's canonical protobuf
payload and exposes the JWT under
`annotations["openshell.nvidia.com/profile-signature"]`; the signed hash and key
ID are exposed beside it. Valid edits to files under `profiles/` change the
profile signature and snapshot revision, so running sandboxes that use the
edited provider profile reload their effective provider-derived policy through
the normal gateway config polling path. Invalid edits keep the last valid
snapshot active.

Gateway TOML snippet:

```toml
[[openshell.gateway.interceptors]]
name               = "provider-governance"
grpc_endpoint      = "http://127.0.0.1:18081"
order              = 10
failure_policy     = "fail_closed"
timeout            = "500ms"
max_response_bytes = 1048576
max_patches        = 32
```

Run the launcher script to start a local gateway with the interceptor attached.
The script prints the gateway endpoint and log paths, then keeps the gateway and
interceptor running until you press Ctrl-C:

```shell
./smoke.sh
```

To run the governance smoke test suite and stop the gateway when it completes:

```shell
./smoke.sh --test-suite
```
