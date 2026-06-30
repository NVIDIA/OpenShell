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
- users cannot import or update provider profiles outside the governed set
- provider profile deletion is blocked by the interceptor

Run the interceptor:

```shell
cargo run -- \
  --listen 127.0.0.1:18081 \
  --policy policy.yaml \
  --profiles profiles
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

The interceptor vends the loaded profiles through
`InterceptorManifest.provider_profile_catalog` with authoritative mode. While
the interceptor is attached, the gateway treats that catalog as the profile
source of truth: `provider list-profiles` shows only `github` and `slack`, and
the built-in/user profile catalog is hidden. The normal import, update, and
delete profile APIs remain available for gateways without an authoritative
catalog, but profiles managed by this interceptor cannot be changed through
those APIs.

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
