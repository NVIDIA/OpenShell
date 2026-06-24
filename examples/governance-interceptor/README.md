# Governance Interceptor Example

This standalone example implements the `openshell.gateway_interceptor.v1.GatewayInterceptor` service. It enforces a source-control governance baseline:

- every new sandbox receives `policy.yaml`
- every new sandbox is attached to exactly `github` and `gitlab`
- every new sandbox gets an `openshell.nvidia.com/policy-signature` label
- users cannot attach or detach other providers after sandbox creation
- users cannot replace or merge sandbox policy after sandbox creation
- users cannot create provider records other than `github` and `gitlab`
- users cannot update or delete the governed `github` or `gitlab` provider records

Run the interceptor:

```shell
cargo run --manifest-path examples/governance-interceptor/Cargo.toml -- \
  --listen 127.0.0.1:18081 \
  --policy examples/governance-interceptor/policy.yaml
```

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
examples/governance-interceptor/smoke.sh
```

The smoke test prints one `PASS` or `FAIL` line per case. Gateway, interceptor, build, and CLI logs are written to a temporary log directory and shown only if a case fails. Set `OPENSHELL_GOVERNANCE_KEEP_LOGS=1` or `OPENSHELL_GOVERNANCE_LOG_DIR=/path/to/logs` to keep logs after a successful run.

Set `OPENSHELL_GOVERNANCE_SMOKE_DRIVER=docker|podman|vm|kubernetes` to force a driver. Without it, the gateway uses its existing local driver detection.

On macOS the smoke script uses `clang`/`clang++` for native dependencies, because Apple SDK headers require Clang block syntax. It also disables `RUSTC_WRAPPER` by default so local `sccache` configuration does not affect the smoke run.

The workspace build requires Z3. The smoke script uses `pkg-config`, `brew --prefix z3`, `/opt/homebrew/opt/z3`, or `/usr/local/opt/z3` when those locations contain `include/z3.h` and a `lib` directory. If no usable local Z3 install exists, install it first:

```shell
brew install z3
```

Build overrides:

```shell
OPENSHELL_GOVERNANCE_CC=/path/to/clang \
OPENSHELL_GOVERNANCE_CXX=/path/to/clang++ \
OPENSHELL_GOVERNANCE_RUSTC_WRAPPER=sccache \
Z3_SYS_Z3_HEADER=/path/to/include/z3.h \
Z3_LIBRARY_PATH_OVERRIDE=/path/to/lib \
examples/governance-interceptor/smoke.sh
```

Set `OPENSHELL_GOVERNANCE_KEEP_CC=1` or `OPENSHELL_GOVERNANCE_KEEP_RUSTC_WRAPPER=1` to preserve the caller environment.
Set `OPENSHELL_GOVERNANCE_ALLOW_BUNDLED_Z3=1` to opt into the bundled Z3 build, which downloads source metadata from GitHub and can fail in offline or rate-limited environments.
