# Gateway Settings Channel

## Overview

The settings channel provides a two-tier key-value configuration system that the gateway delivers to sandboxes alongside policy. Settings are runtime-mutable name-value pairs (e.g., `log_level`, feature flags) that flow from the gateway to sandboxes through the existing `GetSandboxSettings` poll loop. The system supports two scopes -- sandbox-level and global -- with a deterministic merge strategy and per-key mutual exclusion to prevent conflicting ownership.

## Architecture

```mermaid
graph TD
    CLI["CLI / TUI"]
    GW["Gateway<br/>(openshell-server)"]
    DB["Store<br/>(objects table)"]
    SB["Sandbox<br/>(poll loop)"]

    CLI -- "UpdateSandboxPolicy<br/>(setting_key + value)" --> GW
    CLI -- "GetSandboxSettings<br/>GetGatewaySettings" --> GW
    GW -- "load/save<br/>gateway_settings<br/>sandbox_settings" --> DB
    GW -- "GetSandboxSettingsResponse<br/>(policy + settings + config_revision)" --> SB
    SB -- "diff settings<br/>reload OPA on policy change" --> SB
```

## Settings Registry

**File:** `crates/openshell-core/src/settings.rs`

The `REGISTERED_SETTINGS` static array defines the allowed setting keys and their value types. The registry is the source of truth for both client-side validation (CLI, TUI) and server-side enforcement.

```rust
pub const REGISTERED_SETTINGS: &[RegisteredSetting] = &[
    RegisteredSetting { key: "log_level", kind: SettingValueKind::String },
    RegisteredSetting { key: "dummy_int", kind: SettingValueKind::Int },
    RegisteredSetting { key: "dummy_bool", kind: SettingValueKind::Bool },
];
```

| Type | Proto variant | Description |
|------|---------------|-------------|
| `String` | `SettingValue.string_value` | Arbitrary UTF-8 string |
| `Int` | `SettingValue.int_value` | 64-bit signed integer |
| `Bool` | `SettingValue.bool_value` | Boolean; CLI accepts `true/false/yes/no/1/0/on/off` via `parse_bool_like()` |

The reserved key `policy` is excluded from the registry. It is handled by dedicated policy commands and stored as a hex-encoded protobuf `SandboxPolicy` in the global settings' `Bytes` variant. Attempts to set or delete the `policy` key through settings commands are rejected.

Helper functions:
- `setting_for_key(key)` -- look up a `RegisteredSetting` by name, returns `None` for unknown keys
- `registered_keys_csv()` -- comma-separated list of valid keys for error messages
- `parse_bool_like(raw)` -- flexible bool parsing from CLI string input

## Proto Layer

**File:** `proto/sandbox.proto`

### New Message Types

| Message | Fields | Purpose |
|---------|--------|---------|
| `SettingValue` | `oneof value { string_value, bool_value, int_value, bytes_value }` | Type-aware setting value |
| `EffectiveSetting` | `SettingValue value`, `SettingScope scope` | A resolved setting with its controlling scope |
| `SettingScope` enum | `UNSPECIFIED`, `SANDBOX`, `GLOBAL` | Which tier controls the current value |
| `PolicySource` enum | `UNSPECIFIED`, `SANDBOX`, `GLOBAL` | Origin of the policy in a settings response |

### New RPCs

**File:** `proto/openshell.proto`

| RPC | Request | Response | Called by |
|-----|---------|----------|-----------|
| `GetSandboxSettings` | `GetSandboxSettingsRequest { sandbox_id }` | `GetSandboxSettingsResponse { policy, version, policy_hash, settings, config_revision, policy_source }` | Sandbox poll loop, CLI `settings get` |
| `GetGatewaySettings` | `GetGatewaySettingsRequest {}` | `GetGatewaySettingsResponse { settings, settings_revision }` | CLI `settings get --global`, TUI dashboard |

### Extended `UpdateSandboxPolicyRequest`

The existing `UpdateSandboxPolicy` RPC now multiplexes policy and setting mutations through additional fields:

| Field | Type | Description |
|-------|------|-------------|
| `setting_key` | `string` | Key to mutate (mutually exclusive with `policy` payload) |
| `setting_value` | `SettingValue` | Value to set (for upsert operations) |
| `delete_setting` | `bool` | Delete the key from the specified scope |
| `global` | `bool` | Target gateway-global scope instead of sandbox scope |

Validation rules:
- `policy` and `setting_key` cannot both be present
- At least one of `policy` or `setting_key` must be present
- `delete_setting` cannot be combined with a `policy` payload
- The reserved `policy` key requires the `policy` field (not `setting_key`) for set operations
- `name` is required for sandbox-scoped updates but not for global updates

## Server Implementation

**File:** `crates/openshell-server/src/grpc.rs`

### Storage Model

Settings are persisted using the existing generic `objects` table with two new object types:

| Object type string | Record ID | Record name | Purpose |
|--------------------|-----------|-------------|---------|
| `gateway_settings` | `"global"` | `"global"` | Singleton global settings |
| `sandbox_settings` | `"settings:{sandbox_uuid}"` | sandbox name | Per-sandbox settings |

The sandbox settings ID is prefixed with `settings:` to avoid a primary key collision with the sandbox's own record in the `objects` table. The `sandbox_settings_id()` function computes this key.

The payload is a JSON-encoded `StoredSettings` struct:

```rust
struct StoredSettings {
    revision: u64,                                   // Monotonically increasing
    settings: BTreeMap<String, StoredSettingValue>,   // Sorted for determinism
}

enum StoredSettingValue {
    String(String),
    Bool(bool),
    Int(i64),
    Bytes(String),  // Hex-encoded binary (used for global policy)
}
```

### Two-Tier Resolution (`merge_effective_settings`)

The `GetSandboxSettings` handler resolves the effective settings map by merging sandbox and global tiers:

1. **Seed registered keys**: All keys from `REGISTERED_SETTINGS` are inserted with `scope: UNSPECIFIED` and `value: None`. This ensures registered keys always appear in the response even when unset.
2. **Apply sandbox values**: Sandbox-scoped settings overlay the registered defaults. Scope becomes `SANDBOX`.
3. **Apply global values**: Global settings override sandbox values. Scope becomes `GLOBAL`.
4. **Exclude reserved keys**: The `policy` key is excluded from the merged settings map (it is delivered as the top-level `policy` field in the response).

```mermaid
flowchart LR
    REG["REGISTERED_SETTINGS<br/>(seed: scope=UNSPECIFIED)"]
    SB["Sandbox settings<br/>(scope=SANDBOX)"]
    GL["Global settings<br/>(scope=GLOBAL)"]
    OUT["Effective settings map"]

    REG --> OUT
    SB -->|"overlay"| OUT
    GL -->|"override"| OUT
```

### Global Policy as a Setting

The reserved `policy` key in global settings stores a protobuf-encoded `SandboxPolicy`. When present, `GetSandboxSettings` uses the global policy instead of the sandbox's own policy:

1. `decode_policy_from_global_settings()` checks for the `policy` key in global settings
2. If present, the global policy replaces the sandbox policy in the response
3. `policy_source` is set to `GLOBAL`
4. The sandbox policy version counter is preserved for status APIs

This allows operators to push a single policy that applies to all sandboxes via `openshell policy set --global --policy FILE`.

### Config Revision (`compute_config_revision`)

The `config_revision` field is a 64-bit fingerprint that changes whenever the effective configuration changes. The sandbox poll loop compares this value to detect changes without re-parsing the full response.

Computation:
1. Hash `policy_source` as 4 little-endian bytes
2. Hash the deterministic policy hash (if policy present)
3. Sort settings entries by key
4. For each entry: hash key bytes, scope as 4 LE bytes, then a type tag byte + value bytes
5. Truncate the SHA-256 digest to 8 bytes and interpret as `u64` (little-endian)

### Per-Key Mutual Exclusion

Global and sandbox scopes cannot both control the same key simultaneously:

| Operation | Global key exists | Behavior |
|-----------|-------------------|----------|
| Sandbox set | Yes | `FailedPrecondition`: "setting '{key}' is managed globally; delete the global setting before sandbox update" |
| Sandbox delete | Yes | `FailedPrecondition`: "setting '{key}' is managed globally; delete the global setting first" |
| Sandbox set | No | Allowed |
| Sandbox delete | No | Allowed |
| Global set | (any) | Always allowed (global overrides) |
| Global delete | (any) | Allowed; unlocks sandbox control for the key |

This prevents conflicting values at different scopes. An operator must delete a global key before a sandbox-level value can be set for the same key.

### Sandbox-Scoped Policy Update Interaction

When a global policy is set, sandbox-scoped policy updates via `UpdateSandboxPolicy` are rejected with `FailedPrecondition`:

```
policy is managed globally; delete global policy before sandbox policy update
```

Deleting the global policy (`openshell policy delete --global`) removes the `policy` key from global settings and restores sandbox-level policy control.

## Sandbox Implementation

### Poll Loop Changes

**File:** `crates/openshell-sandbox/src/lib.rs` (`run_policy_poll_loop`)

The poll loop uses `GetSandboxSettings` (not a policy-specific RPC) and tracks `config_revision` as the change-detection signal:

1. **Fetch initial state**: Call `poll_settings(sandbox_id)` to establish baseline `current_config_revision`, `current_policy_hash`, and `current_settings`.
2. **On each tick**: Compare `result.config_revision` against `current_config_revision`. If unchanged, skip.
3. **Determine what changed**:
   - Compare `result.policy_hash` against `current_policy_hash` to detect policy changes
   - Call `log_setting_changes()` to diff the settings map and log individual changes
4. **Conditional OPA reload**: Only call `opa_engine.reload_from_proto()` when `policy_hash` changes. Settings-only changes update the tracked state without touching the OPA engine.
5. **Status reporting**: Report policy load status only for sandbox-scoped revisions (`policy_source == SANDBOX` and `version > 0`). Global policy overrides trigger a reload but do not write per-sandbox policy status history.

```mermaid
sequenceDiagram
    participant PL as Poll Loop
    participant GW as Gateway
    participant OPA as OPA Engine

    PL->>GW: GetSandboxSettings(sandbox_id)
    GW-->>PL: policy + settings + config_revision

    loop Every interval (default 10s)
        PL->>GW: GetSandboxSettings(sandbox_id)
        GW-->>PL: response

        alt config_revision unchanged
            PL->>PL: Skip
        else config_revision changed
            PL->>PL: log_setting_changes(old, new)
            alt policy_hash changed
                PL->>OPA: reload_from_proto(policy)
                PL->>GW: ReportPolicyStatus (if sandbox-scoped)
            else settings-only change
                PL->>PL: Update tracked state (no OPA reload)
            end
        end
    end
```

### Per-Setting Diff Logging

**File:** `crates/openshell-sandbox/src/lib.rs` (`log_setting_changes`)

When `config_revision` changes, the sandbox logs each individual setting change:

- **Changed**: `info!(key, old, new, "Setting changed")` -- logs old and new values
- **Added**: `info!(key, value, "Setting added")` -- new key not in previous snapshot
- **Removed**: `info!(key, "Setting removed")` -- key in previous snapshot but not in new

Values are formatted by `format_setting_value()`: strings as-is, bools and ints as their string representation, bytes as `<bytes>`, unset as `<unset>`.

### `SettingsPollResult`

**File:** `crates/openshell-sandbox/src/grpc_client.rs`

```rust
pub struct SettingsPollResult {
    pub policy: Option<ProtoSandboxPolicy>,
    pub version: u32,
    pub policy_hash: String,
    pub config_revision: u64,
    pub policy_source: PolicySource,
    pub settings: HashMap<String, EffectiveSetting>,
}
```

The `poll_settings()` method maps the full `GetSandboxSettingsResponse` into this struct. The `settings` field carries the effective settings map for diff logging.

## CLI Commands

**File:** `crates/openshell-cli/src/main.rs` (`SettingsCommands`), `crates/openshell-cli/src/run.rs`

### `settings get [name] [--global]`

Display effective settings for a sandbox or the gateway-global scope.

```bash
# Sandbox-scoped effective settings
openshell settings get my-sandbox

# Gateway-global settings
openshell settings get --global
```

Sandbox output includes: sandbox name, config revision, policy source (sandbox/global), policy hash, and a table of settings with key, value, and scope (sandbox/global/unset).

Global output includes: scope label, settings revision, and a table of settings with key and value. Registered keys without a configured value display as `<unset>`.

### `settings set [name] --key K --value V [--global] [--yes]`

Set a single setting key at sandbox or global scope.

```bash
# Sandbox-scoped
openshell settings set my-sandbox --key log_level --value debug

# Global (requires confirmation)
openshell settings set --global --key log_level --value warn
openshell settings set --global --key dummy_bool --value yes
openshell settings set --global --key dummy_int --value 42

# Skip confirmation
openshell settings set --global --key log_level --value info --yes
```

Value parsing is type-aware: bool keys accept `true/false/yes/no/1/0/on/off` via `parse_bool_like()`. Int keys parse as base-10 `i64`. String keys accept any value.

### `settings delete [name] --key K [--global] [--yes]`

Delete a setting key from the specified scope.

```bash
# Global delete (unlocks sandbox control)
openshell settings delete --global --key log_level --yes
```

### `policy set --global --policy FILE [--yes]`

Set a gateway-global policy that overrides all sandbox policies.

```bash
openshell policy set --global --policy policy.yaml --yes
```

The `--wait` flag is not supported for global policy updates.

### `policy delete --global [--yes]`

Delete the gateway-global policy, restoring sandbox-level policy control.

```bash
openshell policy delete --global --yes
```

### HITL Confirmation

All `--global` mutations require human-in-the-loop confirmation via an interactive prompt. The `--yes` flag bypasses the prompt for scripted/CI usage. In non-interactive mode (no TTY), `--yes` is required -- otherwise the command fails with an error.

The confirmation message varies:
- **Global setting set**: warns that this will override sandbox-level values for the key
- **Global setting delete**: warns that this re-enables sandbox-level management
- **Global policy set**: warns that this overrides all sandbox policies
- **Global policy delete**: warns that this restores sandbox-level control

## TUI Integration

**File:** `crates/openshell-tui/src/`

### Dashboard: Global Settings Tab

The dashboard's middle pane has a tabbed interface: **Providers** | **Global Settings**. Press `Tab` to switch.

The Global Settings tab displays registered keys with their current values, fetched via `GetGatewaySettings`. Features:

- **Navigate**: `j`/`k` or arrow keys to select a setting
- **Edit** (`Enter`): Opens a type-aware editor:
  - Bool keys: toggle between true/false
  - String/Int keys: text input field
- **Delete** (`d`): Remove the selected key's value
- **Confirmation modals**: Both edit and delete operations show a confirmation dialog before applying
- **Scope indicators**: Each key shows its current value or `<unset>`

### Sandbox Screen: Settings Tab

The sandbox detail view's bottom pane has a tabbed interface: **Policy** | **Settings**. Press `l` to switch tabs.

The Settings tab shows effective settings for the selected sandbox, fetched as part of the `GetSandboxSettings` response. Features:

- Same navigation and editing as the global settings tab
- **Scope indicators**: Each key shows `(sandbox)`, `(global)`, or `(unset)` to indicate the controlling tier
- Sandbox-scoped edits are blocked for globally-managed keys (server returns `FailedPrecondition`)

### Data Refresh

Settings are refreshed on each 2-second polling tick alongside the sandbox list and health status. The global settings revision is tracked to detect changes. Sandbox settings are refreshed when viewing a specific sandbox.

## Data Flow: Setting a Global Key

End-to-end trace for `openshell settings set --global --key log_level --value debug --yes`:

1. **CLI** (`crates/openshell-cli/src/run.rs` -- `gateway_setting_set()`):
   - `parse_cli_setting_value("log_level", "debug")` -- looks up `SettingValueKind::String` in the registry, wraps as `SettingValue { string_value: "debug" }`
   - `confirm_global_setting_takeover()` -- skipped because `--yes`
   - Sends `UpdateSandboxPolicyRequest { setting_key: "log_level", setting_value: Some(...), global: true }`

2. **Gateway** (`crates/openshell-server/src/grpc.rs` -- `update_sandbox_policy()`):
   - Detects `global=true`, `has_setting=true`
   - `validate_registered_setting_key("log_level")` -- passes (key is in registry)
   - `load_global_settings()` -- reads `gateway_settings` record from store
   - `proto_setting_to_stored()` -- converts proto value to `StoredSettingValue::String("debug")`
   - `upsert_setting_value()` -- inserts into `BTreeMap`, returns `true` (changed)
   - Increments `revision`, calls `save_global_settings()`
   - Returns `UpdateSandboxPolicyResponse { settings_revision: N }`

3. **Sandbox** (next poll tick in `run_policy_poll_loop()`):
   - `poll_settings(sandbox_id)` returns new `config_revision`
   - `log_setting_changes()` logs: `Setting changed key="log_level" old="<unset>" new="debug"`
   - `policy_hash` unchanged -- no OPA reload
   - Updates tracked `current_config_revision` and `current_settings`

## Cross-References

- [Gateway Architecture](gateway.md) -- Persistence layer, gRPC service, object types
- [Sandbox Architecture](sandbox.md) -- Poll loop, `CachedOpenShellClient`, OPA reload lifecycle
- [Policy Language](security-policy.md) -- Live policy updates, global policy CLI commands
- [TUI](tui.md) -- Settings tabs in dashboard and sandbox views
