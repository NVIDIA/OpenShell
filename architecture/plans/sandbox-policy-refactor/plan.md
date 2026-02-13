# Sandbox Policy Refactor: Single YAML + Typed Proto + Baked Rules

**Status:** Implemented
**Date:** 2026-02-11 (updated 2026-02-12)

## Goal

Consolidate sandbox policy into a single YAML file parsed by the CLI, transmitted as a fully-typed proto, and consumed by the sandbox with baked-in OPA rules. Eliminate the separate rego data file (`dev-sandbox-policy-data.rego`) as a user-facing artifact.

## Design Summary

### Single YAML policy file

The user maintains one file (`dev-sandbox-policy.yaml`) containing everything:

```yaml
version: 1

filesystem_policy:
  include_workdir: true
  read_only: ["/usr", "/lib"]
  read_write: ["/sandbox", "/tmp"]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
inference:
  allowed_routing_hints:
    - local
network_policies:
  claude_code:
    name: claude_code
    endpoints:
      - { host: api.anthropic.com, port: 443 }
      - { host: statsig.anthropic.com, port: 443 }
      - { host: sentry.io, port: 443 }
      - { host: raw.githubusercontent.com, port: 443 }
      - { host: platform.claude.com, port: 443 }
    binaries:
      - { path: /usr/local/bin/claude }
  gitlab:
    name: gitlab
    endpoints:
      - { host: gitlab.com, port: 443 }
      - { host: gitlab.mycorp.com, port: 443 }
    binaries:
      - { path: /usr/bin/glab }
```

This file is **baked into the CLI** as the default (via `include_str!`). Users can override with `--sandbox-policy <path>` or `NAVIGATOR_SANDBOX_POLICY` env var.

This same file can also be loaded directly by the sandbox binary via `--policy-rules` + `--policy-data` for local development. Regorus reads the YAML natively (via its `yaml` feature).

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
3. **Sandbox**: Fetches proto via gRPC. Converts typed proto fields to JSON data at the root level, feeds to `engine.add_data_json()`. Uses baked-in rego rules (via `include_str!`). Rego rules reference `data.filesystem_policy`, `data.network_policies`, etc.

### Local dev override

For local development (`mise run sandbox`), the sandbox binary can load policy directly from files via `--policy-rules` + `--policy-data` (or `NAVIGATOR_POLICY_RULES` / `NAVIGATOR_POLICY_DATA` env vars). The rego rules file is loaded as the policy, and the YAML data file is loaded natively by regorus (via its `yaml` feature).

### Baked-in rego rules

The rego rules file (`dev-sandbox-policy.rego`) is baked into the **sandbox binary** via `include_str!`. The OPA engine is constructed from baked rules + data (either JSON from proto conversion, or YAML from the data file).

### TODO (future)

- Drop rego passthrough rules for filesystem/landlock/process — deserialize directly from proto with serde instead of querying OPA for static config.

### Open questions

1. **`NetworkMode`/`ProxyPolicy` still internal to sandbox** — the sandbox derives `NetworkMode::Proxy` when `network_policies` is non-empty in the proto. The proxy's bind address is still hardcoded/auto-detected. Is this the right default, or should there be an explicit way to set proxy config?
2. **`name` field in `NetworkPolicyRule`** — the proto has both the map key and a `name` field inside the message. The CLI defaults `name` to the map key if not set. Should we remove the `name` field from the proto and just use the map key?

## What was done

### Phase 1 (2026-02-11): Typed proto + baked rules

- Rewrote `sandbox.proto` with typed fields (tags 1-6)
- Added `NetworkPolicyRule`, `NetworkEndpoint`, `NetworkBinary` messages
- CLI parses YAML → typed `SandboxPolicy` proto via `DevSandboxPolicyFile` structs
- Sandbox bakes `dev-sandbox-policy.rego` via `include_str!`
- Added `OpaEngine::from_proto()` — converts proto fields to JSON data for regorus
- gRPC mode: sandbox fetches proto, constructs OPA engine from baked rules + proto-derived data
- File mode: sandbox loads rego rules + data file directly

### Phase 2 (2026-02-12): Delete rego data file, consolidate on YAML

- Deleted `dev-sandbox-policy-data.rego` — YAML is now the single source of truth for policy data
- Flattened `dev-sandbox-policy.yaml` — top-level keys (`filesystem_policy`, `landlock`, `process`, `inference`, `network_policies`), no nesting wrapper
- Renamed `filesystem` → `filesystem_policy` in YAML to match rego convention
- Updated rego rules: `data.sandbox.*` → `data.*` (dropped `sandbox.` prefix from data paths)
- Enabled regorus `yaml` feature — `from_files()` loads YAML data natively via `Value::from_yaml_file()`
- Updated `from_strings()` and `reload()` to accept YAML data (via `Value::from_yaml_str()`) instead of rego policies
- Removed `"sandbox"` wrapper from `proto_to_opa_data_json()` — JSON data emitted at root level
- Renamed sandbox CLI args: `--rego-policy`/`--rego-data` → `--policy-rules`/`--policy-data`
- Renamed env vars: `NAVIGATOR_REGO_POLICY`/`NAVIGATOR_REGO_DATA` → `NAVIGATOR_POLICY_RULES`/`NAVIGATOR_POLICY_DATA`
- Converted all inline test data from rego/JSON to YAML
