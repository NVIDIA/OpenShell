# Governance Interceptor Example

This standalone example implements the `openshell.gateway_interceptor.v1.GatewayInterceptor` service. It enforces a source-control governance baseline:

- every new sandbox receives `policy.yaml`
- every new sandbox is attached to exactly `github` and `gitlab`
- every new sandbox gets an `openshell.nvidia.com/policy-signature` metadata annotation
- users cannot attach or detach other providers after sandbox creation
- users cannot replace or merge sandbox policy after sandbox creation
- users cannot create provider records other than `github` and `gitlab`
- users cannot update or delete the governed `github` or `gitlab` provider records

Run these commands from `examples/governance-interceptor`.

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

Run the smoke test against a local gateway and compute driver:

```shell
./smoke.sh
```

The smoke test prints one `PASS` or `FAIL` line per case. Gateway, interceptor, build, and CLI logs are written to a temporary log directory and shown only if a case fails. Set `OPENSHELL_GOVERNANCE_KEEP_LOGS=1` or `OPENSHELL_GOVERNANCE_LOG_DIR=/path/to/logs` to keep logs after a successful run.
