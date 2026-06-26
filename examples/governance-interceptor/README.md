# Governance Interceptor Example

This standalone example implements the
`openshell.gateway_interceptor.v1.GatewayInterceptor` service. It demonstrates how to
extend OpenShell to provide advanced governance over sandbox policies.

- every new sandbox receives `policy.yaml` sourced from this examples folder
- every new sandbox is attached to exactly `github` and `gitlab`
- every new sandbox gets an `openshell.nvidia.com/policy-signature` metadata annotation
  that is used to verify the policy
- every sandbox creation evaluation adds a `correlation_id` log annotation so the
  gateway log can be correlated with interceptor-side decisions
- users cannot attach or detach other providers after sandbox creation
- users cannot replace or merge sandbox policy after sandbox creation
- users cannot create provider records other than `github` and `gitlab`
- users cannot update or delete the governed `github` or `gitlab` provider records

Run the interceptor:

```shell
cargo run -- \
  --listen 127.0.0.1:18081 \
  --policy policy.yaml
```

At startup the example parses `policy.yaml`, converts it to the protobuf JSON
shape used by sandbox creation, computes a canonical SHA-256 digest, and signs
that digest as an EdDSA JWT. The interceptor adds that JWT to each governed
sandbox under `metadata.annotations["openshell.nvidia.com/policy-signature"]` and
verifies the JWT against the sandbox policy during the `CreateSandbox` validate
phase.

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
name               = "source-control-governance"
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
