# Governance Interceptor Example

This standalone example implements the
`openshell.gateway_interceptor.v1.GatewayInterceptor` service. It demonstrates how to
extend OpenShell to provide advanced governance over sandbox policies.

- every new sandbox receives `policy.yaml` sourced from this examples folder
- every new sandbox is attached to exactly `github` and `slack`
- `github` must use the `github` provider profile
- `slack` must use the custom `slack` provider profile
- governed provider network policy lives in `profiles/*.yaml`, not in the
  signed baseline sandbox policy
- every new sandbox gets an `openshell.nvidia.com/policy-signature` metadata annotation
  that is used to verify the policy
- every sandbox creation evaluation adds a `correlation_id` log annotation so the
  gateway log can be correlated with interceptor-side decisions
- users cannot attach or detach other providers after sandbox creation
- users cannot replace or merge sandbox policy after sandbox creation
- users cannot create provider records other than `github` and `slack`
- users cannot update or delete the governed `github` or `slack` provider records
- users cannot import or update provider profiles other than `github` and
  `slack`
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
sandbox under `metadata.annotations["openshell.nvidia.com/policy-signature"]` and
verifies the JWT against the sandbox policy during the `CreateSandbox` validate
phase.

Provider profile YAML files are loaded by the interceptor from `--profiles`
(default: this example's `profiles/` directory). The interceptor names each
profile from its filename without the extension: `profiles/github.yaml` becomes
profile ID `github`, and `profiles/slack.yaml` becomes profile ID `slack`. The
YAML files do not need an `id` field; if one is present, the filename still wins.

When `--gateway-endpoint` is set, the interceptor reconciles the loaded profiles
through the gateway's normal provider profile APIs. GitHub is already a built-in
read-only profile, so the interceptor accepts the exported built-in `github`
profile as present; the gateway still rejects importing or updating that
built-in ID. Slack is a custom profile: the interceptor uses
`ImportProviderProfiles` for first-time vending and `UpdateProviderProfiles` for
ongoing changes. It exports the current profile to read `resource_version`,
injects that version into the loaded YAML payload, and submits
`UpdateProviderProfiles`. It never deletes governed profiles.

The signing key is generated in memory on each interceptor start. This keeps the
example self-contained. Production governance services should load managed
signing keys, publish verifier keys, and define a rotation process.

Interceptors can also attach non-secret operational metadata to
`InterceptorResult.log_annotations`. The gateway logs that map as structured
interceptor metadata for each successful evaluation. This example adds
`correlation_id = "governance:create-sandbox:<sandbox-name>"` during
`CreateSandbox` modification alongside the policy hash and signing key ID. Do
not put secrets, tokens, or policy signatures in log annotations.

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

Run the smoke test script to automatically start the gateway, interceptor, and test the
governance controls

```shell
./smoke.sh
```
