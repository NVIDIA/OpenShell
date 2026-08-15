# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

## Commands

This project uses [mise](https://mise.jdx.dev/) as the task runner. Task definitions live in `tasks/*.toml` (run `mise tasks` to list them all). Run `mise trust` once after cloning.

### Build

```bash
cargo build --workspace                 # build all Rust crates
mise run build                          # full build: Rust workspace + docker + python wheel
openshell --help                        # local CLI shortcut (scripts/bin/openshell), builds openshell-cli on demand
```

### Test

```bash
mise run test                           # full test suite: Rust + Python + SBOM + install.sh + docs-website
cargo test --workspace --exclude openshell-server   # Rust tests except the gateway crate
cargo test -p openshell-server --features test-support  # gateway tests (needs test-support feature)
cargo test -p <crate-name> <test_name>  # single Rust test
uv run pytest python/                   # Python SDK tests
uv run pytest python/path/to/test.py::test_name  # single Python test
```

`test:rust` sets `OPENSHELL_TELEMETRY_ENABLED=false`; match that when running gateway tests manually if telemetry-off behavior matters.

### End-to-end tests

`mise run e2e` runs the default e2e lane (Rust + Python + MCP conformance). E2E tests spin up a real gateway (Docker, Podman, Kubernetes, or VM backed) — see `tasks/test.toml` for the full list of `e2e:*` tasks (`e2e:docker`, `e2e:podman`, `e2e:kubernetes`, `e2e:vm`, `e2e:oidc-pkce`, GPU variants, etc.). Sandbox/infrastructure changes should exercise the relevant e2e path per AGENTS.md.

### Lint / format / typecheck

```bash
mise run lint                           # license headers, rustfmt check, clippy, python/helm/markdown lint
mise run fmt                            # cargo fmt + python format + markdown format
mise run check                          # cargo check --workspace + python typecheck
mise run pre-commit                     # fmt + lint — run before every commit
mise run ci                             # full local CI: lint + check + test + go:ci
```

### Go SDK (`sdk/go/`)

```bash
mise run go:ci                          # full Go SDK CI: format check, lint, build, test, proto-check, docs-check
mise run go:test                        # go test with race + coverage
mise run go:proto:gen                   # regenerate proto bindings from proto/
```

### Other useful tasks

```bash
mise run gateway                        # run a standalone gateway for local development
mise run sandbox                        # create or reconnect to the dev sandbox
mise run docs:serve                     # preview Fern docs locally
mise run docs                           # non-interactive docs validation
mise run helm:docs                      # regenerate the Helm chart README
mise run clean                          # cargo clean
```

Bazel targets exist experimentally (`bazel build //...`, `bazel test //...`) but Cargo/mise remain the primary build system — see CONTRIBUTING.md.

## Architecture

OpenShell has three stable runtime components: **CLI/SDK/TUI** (user-facing), the **Gateway** (authenticated control plane), and the **Supervisor** (runs inside every sandbox as the local security boundary). Full crate-to-purpose mapping is in AGENTS.md; the paragraphs below describe how the pieces interact at runtime — see `architecture/` for the canonical, longer-form docs (`architecture/gateway.md`, `architecture/sandbox.md`, `architecture/security-policy.md`, `architecture/compute-runtimes.md`).

### Control plane vs. data plane split

The gateway (`openshell-server`) owns durable state and authorization: sandbox lifecycle, policy revisions, settings, provider/credential records, inference configuration, and session records. It talks to pluggable **drivers** (`openshell-driver-docker`, `openshell-driver-podman`, `openshell-driver-kubernetes`, `openshell-driver-vm`, `openshell-driver-vault`, `openshell-driver-kubernetes-secrets`) over gRPC/UDS for compute, credentials, and identity — the gateway itself never talks to Docker/K8s/Vault directly. The gateway does **not** enforce agent network policy at request time; it only delivers policy/settings/credentials to sandboxes.

Each sandbox runs the supervisor (`openshell-supervisor-process`, `openshell-supervisor-network`, `openshell-supervisor-middleware*`), which is the actual security boundary: it launches the agent as a restricted child process, fetches config from the gateway, injects credentials, and enforces filesystem/network/process policy locally where process identity is visible. The relationship is supervisor-initiated — each sandbox connects outbound to the gateway and keeps a live session open for control traffic, policy/settings refresh, log push, and relayed operations (connect, exec, file sync, service forwarding). If that session drops, the sandbox may keep running but live operations become unreachable until it reconnects.

### Egress / policy enforcement path

All ordinary agent egress is forced through a local policy proxy inside the sandbox (`openshell-supervisor-network`), which evaluates each request against the policy engine (`openshell-policy`, OPA-based) for destination, binary identity, SSRF, and TLS/L7 rules before allowing, denying, or rerouting it. Requests to `https://inference.local` are intercepted and forwarded by the inference router (`openshell-router`) to a configured model backend instead of leaving the sandbox directly — this is how the privacy-aware LLM routing / credential-stripping described in the README is implemented. Policies are declarative YAML: filesystem and process sections are locked at sandbox creation; network and inference sections are hot-reloadable via `openshell policy set` without restarting the sandbox.

### Gateway interceptors and RPC authorization

Gateway RPC authorization is compile-time-checked via `openshell-server-macros`; each RPC is classified (`rpc_auth`) as user-only, sandbox-callable, or dual, and that classification also determines which negotiated Docker/Podman listeners can reach it. `openshell-gateway-interceptors` runs configured interceptors in one middleware layer after authentication and before handler dispatch, against an explicit allowlist of interceptable unary RPCs built from the compiled protobuf descriptor set — new RPCs are non-interceptable until deliberately added to that allowlist.

### Observability

Sandbox-observable security/lifecycle events (network decisions, HTTP/L7 enforcement, SSH auth, process lifecycle, policy/config changes) are logged via OCSF builders in `openshell-ocsf`, not plain `tracing` — see the "Sandbox Logging (OCSF)" section in AGENTS.md for the builder-per-event-class table and severity conventions before adding or changing a log emission in `openshell-sandbox`. Distributed tracing goes through `openshell-otel`.

### Proto and multi-language SDKs

`proto/` is the source of truth for the gRPC contract, consumed by the Rust `openshell-sdk` (used by CLI/TUI), the Python SDK (`python/openshell/`), and the Go SDK (`sdk/go/`, module `github.com/NVIDIA/OpenShell/sdk/go`). Go domain types under `sdk/go/openshell/v1/types/` must not import proto packages directly; converters in `sdk/go/openshell/v1/internal/converter/` deep-copy at the proto/domain boundary. Regenerate Go bindings with `mise run go:proto:gen` after changing `.proto` files.
