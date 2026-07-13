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
- sandbox policy synchronization must carry the current signed governance
  policy; unsigned, stale, or modified policies are denied for every caller
- sandbox policy analysis may report telemetry, but sandbox-authored policy
  proposals are denied before they reach the gateway handler
- `proposal_approval_mode=auto` is blocked at both sandbox and global scope
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

The example owns this digest contract independently of the gateway. It uses a
local reflected protobuf codec, recursively sorts ProtoJSON object keys, and
preserves repeated-field order. Policy and profile hashes use the
`sha256:v2:<hex>` format, and their JWTs require
`hash_algorithm=openshell-governance-protojson-sha256-v2`. The gateway's policy
hash is a separate operational revision identifier and is not expected to
match the signed governance hash.

The interceptor polls the policy file every second by default. When `policy.yaml`
changes and parses successfully, the interceptor re-signs it immediately. New
sandboxes receive the updated signed policy through `CreateSandbox`. If
`--gateway-endpoint` is set, the example also lists running sandboxes and calls
`UpdateConfig` for ready or provisioning sandboxes so dynamic policy changes
propagate through the normal sandbox config polling path. Static baseline
changes that the gateway rejects for existing sandboxes are logged and still
apply to newly created sandboxes.

The example also validates `SubmitPolicyAnalysis`. Requests without proposed
policy chunks remain available for denial and network-activity telemetry.
Requests containing proposed chunks are denied, so a sandbox cannot use the
gateway's optional auto-approval path to widen its governed policy. This rule
belongs to the example: gateways without this binding retain the standard
proposal workflow.

Provider profile YAML files are loaded by the interceptor from `--profiles`
(default: this example's `profiles/` directory). The interceptor names each
profile from its filename without the extension: `profiles/github.yaml` becomes
profile ID `github`, and `profiles/slack.yaml` becomes profile ID `slack`. The
YAML files do not need an `id` field; if one is present, the filename still wins.

The interceptor advertises `provider_profiles = true` in its manifest and vends
the current profile set through `SnapshotProviderProfiles`. The gateway config
selects the interceptor as its only provider profile source, so
`provider list-profiles` shows only `github` and `slack`; built-in and user
sources are omitted. The example signs each profile's canonical protobuf payload
and exposes the JWT under
`annotations["openshell.nvidia.com/profile-signature"]`; the signed hash and key
ID are exposed beside it. These annotations demonstrate logic an interceptor
can own; the gateway treats them as opaque metadata and does not verify them.
Valid edits to files under `profiles/` change the profile signature and snapshot
revision, so running sandboxes that use the edited provider profile reload their
effective provider-derived policy through the normal gateway config polling
path. Invalid edits keep the last valid snapshot active.

Gateway TOML snippet:

```toml
[openshell.gateway]
provider_profile_sources = [
  { type = "interceptor", name = "provider-governance" },
]

[[openshell.gateway.interceptors]]
name               = "provider-governance"
grpc_endpoint      = "http://127.0.0.1:18081"
order              = 10
failure_policy     = "fail_closed"
binding_policy     = "allowlist"
timeout            = "500ms"
max_response_bytes = 1048576
max_patches        = 32

[[openshell.gateway.interceptors.bindings]]
rpc    = "openshell.v1.OpenShell/CreateSandbox"
phases = ["modify_operation", "validate"]

[[openshell.gateway.interceptors.bindings]]
rpc    = "openshell.v1.OpenShell/CreateProvider"
phases = ["validate"]

[[openshell.gateway.interceptors.bindings]]
rpc    = "openshell.v1.OpenShell/UpdateConfig"
phases = ["validate"]

[[openshell.gateway.interceptors.bindings]]
rpc    = "openshell.v1.OpenShell/SubmitPolicyAnalysis"
phases = ["validate"]

[[openshell.gateway.interceptors.bindings]]
rpc    = "openshell.v1.OpenShell/ImportProviderProfiles"
phases = ["validate"]

[[openshell.gateway.interceptors.bindings]]
rpc    = "openshell.v1.OpenShell/UpdateProviderProfiles"
phases = ["validate"]

[[openshell.gateway.interceptors.bindings]]
rpc    = "openshell.v1.OpenShell/DeleteProviderProfile"
phases = ["validate"]
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

The suite uses a gateway-signed JWT for the created sandbox identity to attempt
an unsigned policy widening and a policy proposal. It verifies that both are
denied, telemetry is accepted, and the active policy version and hash remain
unchanged.
