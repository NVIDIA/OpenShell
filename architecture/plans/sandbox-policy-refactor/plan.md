# Sandbox Policy Refactor: Single YAML + Typed Proto + Baked Rules

**Status:** Implemented
**Date:** 2026-02-11

## Goal

Consolidate sandbox policy into a single YAML file parsed by the CLI, transmitted as a fully-typed proto, and consumed by the sandbox with baked-in OPA rules. Eliminate the separate rego data file as a user-facing artifact.

## Design Summary

### Single YAML policy file

The user maintains one file (`dev-sandbox-policy.yaml`) containing everything:

```yaml
version: 1
inference:
  allowed_routing_hints:
    - local
filesystem:
  include_workdir: true
  read_only: ["/usr", "/lib"]
  read_write: ["/sandbox", "/tmp"]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  claude_code:
    endpoints:
      - { host: api.anthropic.com, port: 443 }
      - { host: statsig.anthropic.com, port: 443 }
      - { host: sentry.io, port: 443 }
      - { host: raw.githubusercontent.com, port: 443 }
      - { host: platform.claude.com, port: 443 }
    binaries:
      - { path: /usr/local/bin/claude }
  gitlab:
    endpoints:
      - { host: gitlab.com, port: 443 }
      - { host: gitlab.mycorp.com, port: 443 }
    binaries:
      - { path: /usr/bin/glab }
```

This file is **baked into the CLI** as the default (via `include_str!`). Users can override with `--sandbox-policy <path>` or `NAVIGATOR_SANDBOX_POLICY` env var.

### Proto (`sandbox.proto`)

Fully typed, reusing tags 2-5 (no backward-compat constraint):

```protobuf
message SandboxPolicy {
  uint32 version = 1;
  FilesystemPolicy filesystem = 2;
  LandlockPolicy landlock = 3;
  ProcessPolicy process = 4;
  map<string, NetworkPolicyRule> network_policies = 5;
  InferencePolicy inference = 6;
}
```

New messages for network policies: `NetworkPolicyRule`, `NetworkEndpoint`, `NetworkBinary`.
`LandlockPolicy.compatibility` changes from enum to string.
Old `NetworkPolicy`/`NetworkMode`/`ProxyPolicy` removed from proto (sandbox-internal concern).

### Data flow

```
YAML ──[CLI]──> Proto (typed) ──[server stores]──> Proto ──[sandbox fetches via gRPC]──> OPA engine
```

1. **CLI**: Parses YAML, populates typed `SandboxPolicy` proto, sends to server at sandbox creation.
2. **Server**: Stores proto as-is. Reads `inference` field directly for routing authorization. Returns full proto on `GetSandboxPolicy`.
3. **Sandbox**: Fetches proto via gRPC. Converts typed proto fields to JSON, wraps under `{"sandbox": {...}}` key, feeds to `engine.add_data_json()`. Uses baked-in rego rules (via `include_str!`). Rego rules are unchanged — they still reference `data.sandbox.*`.

### Baked-in rego rules

The rego rules file (`dev-sandbox-policy.rego`) is baked into the **sandbox binary** via `include_str!`. The OPA engine is constructed from baked rules + JSON data derived from the proto. The `--rego-policy`/`--rego-data` CLI args on the sandbox binary are kept as dev-only overrides.

### TODO (future)

- Drop rego passthrough rules for filesystem/landlock/process — deserialize directly from proto with serde instead of querying OPA for static config.
- Remove the `--rego-policy`/`--rego-data` sandbox args once the gRPC path is fully proven.
- Delete `dev-sandbox-policy-data.rego` once all tests are migrated to use `from_proto` or inline rego data.

### Questions for review

1. **`dev-sandbox-policy-data.rego` kept for now** — it's still used by the existing `from_strings` OPA tests and the `--rego-policy`/`--rego-data` dev override path. Should we migrate the `from_strings` tests to `from_proto` and remove the file?
2. **`NetworkMode`/`ProxyPolicy` still internal to sandbox** — the sandbox derives `NetworkMode::Proxy` when `network_policies` is non-empty in the proto. The proxy's bind address is still hardcoded/auto-detected. Is this the right default, or should there be an explicit way to set proxy config?
3. **`name` field in `NetworkPolicyRule`** — the proto has both the map key and a `name` field inside the message. The CLI defaults `name` to the map key if not set. Should we remove the `name` field from the proto and just use the map key?

## Implementation Steps

### Step 1: Update `sandbox.proto`

- Rewrite `SandboxPolicy` with typed fields on tags 1-6
- Add new messages: `NetworkPolicyRule`, `NetworkEndpoint`, `NetworkBinary`
- Change `LandlockPolicy.compatibility` from enum to string
- Remove old `NetworkPolicy`, `NetworkMode`, `ProxyPolicy`, `ProxyConfig` messages from proto
- Keep `InferencePolicy`, `GetSandboxPolicyRequest`, `GetSandboxPolicyResponse` as-is
- Keep `LandlockCompatibility` enum removed (replaced by string field)

### Step 2: Regenerate proto code

- Run `mise run build` (or `cargo build -p navigator-core`) to trigger `tonic_build` codegen
- The generated `navigator.sandbox.v1.rs` will reflect the new proto shape

### Step 3: Update `dev-sandbox-policy.yaml`

- Expand to include all policy fields (filesystem, landlock, process, network_policies)
- This becomes the single source of truth

### Step 4: Update CLI (`navigator-cli`)

- Bake `dev-sandbox-policy.yaml` via `include_str!` in `run.rs`
- Rewrite `DevSandboxPolicyFile` struct and `load_dev_sandbox_policy()` to match new YAML shape
- Convert parsed YAML → typed `SandboxPolicy` proto (using new proto messages)
- Support `--sandbox-policy <path>` flag / `NAVIGATOR_SANDBOX_POLICY` env var to override
- Update `print_sandbox_policy()` and `policy_to_yaml()` for the new proto shape
- Remove old `DevFilesystemPolicy`, `DevNetworkPolicy`, `DevProxyPolicy`, `DevLandlockPolicy`, `DevProcessPolicy` structs (replace with new ones matching the flat YAML)

### Step 5: Update sandbox (`navigator-sandbox`)

**`policy.rs`:**
- Update `SandboxPolicy` (internal) and `TryFrom<ProtoSandboxPolicy>` conversion
- `NetworkMode` / `NetworkPolicy` / `ProxyPolicy` remain as internal types but are no longer derived from proto — instead, the sandbox sets `NetworkMode::Proxy` when `network_policies` is non-empty, `NetworkMode::Block` otherwise
- Update `FilesystemPolicy`, `LandlockPolicy`, `ProcessPolicy` conversions for new proto shape

**`opa.rs`:**
- Bake `dev-sandbox-policy.rego` via `include_str!` as `const BAKED_POLICY_RULES: &str`
- Add a new constructor: `OpaEngine::from_policy_proto(proto: &ProtoSandboxPolicy) -> Result<Self>` that:
  1. Loads baked rules via `engine.add_policy()`
  2. Converts proto `network_policies` (and filesystem/landlock/process for rego passthrough compatibility) to JSON matching the `data.sandbox.*` shape the rego rules expect
  3. Loads the JSON via `engine.add_data_json()`
- Keep `from_files()` and `from_strings()` for dev/testing

**`lib.rs` (`load_policy`):**
- In gRPC mode: after fetching proto, construct `OpaEngine` from proto (using new constructor) instead of returning `None`
- In rego file mode: keep as-is (dev override)

### Step 6: Update server (`navigator-server`)

**`inference.rs`:**
- The `InferencePolicy` extraction path stays the same (it reads `sandbox.spec.policy.inference`)
- No changes needed — the server is a passthrough for the policy proto

**`grpc.rs`:**
- `GetSandboxPolicy` handler stays the same — returns stored proto

### Step 7: Fix compilation across crates

- `navigator-sandbox/src/process.rs` — update references to `policy.network.mode`
- `navigator-sandbox/src/sandbox/linux/seccomp.rs` — same
- `navigator-sandbox/src/proxy.rs` — update `ProxyPolicy` usage
- `navigator-sandbox/src/ssh.rs` — update `SandboxPolicy` usage
- Test files in `navigator-cli/tests/` and `navigator-server/tests/` — update mock `SandboxPolicy` construction
- `navigator-core/src/proto/mod.rs` — update re-exports if needed

### Step 8: Delete obsolete files

- `dev-sandbox-policy-data.rego` — replaced by YAML → proto → JSON flow
- The rego rules file (`dev-sandbox-policy.rego`) stays in the repo but is now baked into the sandbox binary

### Step 9: Tests

- Update existing OPA engine tests to work with proto-based constructor
- Update CLI policy loading tests
- Update server integration test mocks for new proto shape
- Verify `mise run test:rust` passes

### Step 10: Pre-commit and build verification

- `mise run pre-commit`
- `mise run build`
- `mise run test`
