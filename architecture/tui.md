# OpenShell TUI

The OpenShell TUI is a terminal user interface for OpenShell, inspired by [k9s](https://k9scli.io/). Instead of typing individual CLI commands to check cluster health, list sandboxes, and manage resources, the TUI gives you a real-time, keyboard-driven dashboard — everything updates automatically and you navigate with a few keystrokes.

## Launching the TUI

The TUI is a subcommand of the OpenShell CLI, so it inherits all your existing configuration — cluster selection, TLS settings, and verbosity flags all work the same way.

```bash
openshell term                   # launch against the active gateway
nav term                         # dev alias (builds from source)
nav term --gateway prod          # target a specific gateway
OPENSHELL_GATEWAY=prod nav term  # same thing, via environment variable
```

Gateway resolution follows the same priority as the rest of the CLI:

1. `--gateway` flag (if provided)
2. `OPENSHELL_GATEWAY` environment variable
3. Active gateway from `~/.config/openshell/active_gateway`

No separate configuration files or authentication are needed.

## Screen Layout

The TUI divides the terminal into four horizontal regions:

```
┌─────────────────────────────────────────────────────────────────┐
│  OpenShell ─ my-cluster ─ Dashboard  ● Healthy                   │  ← title bar
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  (view content — Dashboard or Sandboxes)                        │  ← main area
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  [1] Dashboard  [2] Sandboxes  │  [?] Help  [q] Quit           │  ← nav bar
├─────────────────────────────────────────────────────────────────┤
│  :                                                              │  ← command bar
└─────────────────────────────────────────────────────────────────┘
```

- **Title bar** — shows the OpenShell logo, cluster name, current view, and live cluster health status.
- **Main area** — the active view (Dashboard or Sandboxes).
- **Navigation bar** — lists available views with their shortcut keys, plus Help and Quit.
- **Command bar** — appears when you press `:` to type a command (like vim).

## Views

### Dashboard (press `1`)

The Dashboard is the home screen. It shows your cluster at a glance.

The dashboard is divided into a top info pane and a middle pane with two tabs:

- **Top pane**: Cluster name, gateway endpoint, health status, sandbox count.
- **Middle pane**: Tabbed view toggled with `Tab`:
  - **Providers** — provider configurations attached to the cluster.
  - **Global Settings** — gateway-global runtime settings (fetched via `GetGatewaySettings`).

**Health status** indicators:
  - `●` **Healthy** (green) — everything is running normally.
  - `◐` **Degraded** (yellow) — the cluster is up but something needs attention.
  - `○` **Unhealthy** (red) — the cluster is not operating correctly.
  - `…` — still connecting or status unknown.

**Global policy indicator**: When a global policy is active, the gateway row shows `Global Policy Active (vN)` in yellow (the `status_warn` style). The TUI detects this by polling `ListSandboxPolicies` with `global: true, limit: 1` on each tick and checking if the latest revision has `PolicyStatus::Loaded`. See `crates/openshell-tui/src/ui/dashboard.rs`.

#### Global Settings Tab

The Global Settings tab shows all registered setting keys with their current values. Keys without a configured value display as `<unset>`.

| Key | Action |
|-----|--------|
| `j` / `↓` | Move selection down |
| `k` / `↑` | Move selection up |
| `Enter` | Edit the selected setting (type-aware: bool toggle, string/int text input) |
| `d` | Delete the selected setting's value |

Both edit and delete operations display a confirmation modal before applying. Changes are sent to the gateway via the `UpdateSandboxPolicy` RPC with `global: true`.

### Sandboxes (press `2`)

The Sandboxes view shows a table of all sandboxes in the cluster:

| Column | Description |
|--------|-------------|
| NAME | Sandbox name |
| STATUS | Current phase, color-coded (see below) |
| AGE | Time since creation (e.g., `45s`, `12m`, `3h 20m`, `2d 5h`) |
| IMAGE | Container image the sandbox is running |
| PROVIDERS | Provider names attached to the sandbox |
| NOTES | General-purpose metadata (e.g., `fwd:8080,3000` for forwarded ports) |

Status colors tell you the sandbox state at a glance:

- **Green** — Ready (sandbox is running and accessible)
- **Yellow** — Provisioning (sandbox is starting up)
- **Red** — Error (something went wrong)
- **Dim** — Deleting or Unknown

Use `j`/`k` or the arrow keys to move through the list. The selected row is highlighted in green.

When there are no sandboxes, the view displays: *"No sandboxes found."*

When viewing a specific sandbox (by pressing `Enter` on a selected row), the bottom pane shows a tabbed view toggled with `l`:

- **Policy** — the sandbox's current active policy, auto-refreshed on version change.
- **Settings** — effective runtime settings for the sandbox (fetched via `GetSandboxSettings`).

**Global policy indicator on sandbox detail**: When the sandbox's policy is managed globally (`policy_source == GLOBAL` in the `GetSandboxSettings` response), the metadata pane shows `Policy: managed globally (vN)` in yellow. Draft chunks in the **Network Rules** pane are greyed out and a yellow warning reads `"Cannot approve rules while global policy is active"`. Approve (`a`), reject/revoke (`x`), and approve-all actions are blocked client-side with status messages. See `crates/openshell-tui/src/ui/sandbox_detail.rs` and `crates/openshell-tui/src/ui/sandbox_draft.rs`.

#### Sandbox Settings Tab

The Settings tab shows all registered setting keys with their effective values and scope indicators:

- **(sandbox)** — value is set at sandbox scope
- **(global)** — value is set at gateway-global scope (overrides sandbox)
- **(unset)** — no value configured at any scope

Navigation and editing use the same keys as the Global Settings tab (`j`/`k`, `Enter` to edit, `d` to delete). Sandbox-scoped edits to globally-managed keys are rejected by the server with a `FailedPrecondition` error.

## Keyboard Controls

The TUI has two input modes: **Normal** (default) and **Command** (activated by pressing `:`).

### Normal Mode

| Key | Action |
|-----|--------|
| `1` | Switch to Dashboard view |
| `2` | Switch to Sandboxes view |
| `j` or `↓` | Move selection down |
| `k` or `↑` | Move selection up |
| `:` | Enter command mode |
| `q` | Quit |
| `Ctrl+C` | Force quit |

### Command Mode

Press `:` to open the command bar at the bottom of the screen. Type a command and press `Enter` to execute it.

| Command | Action |
|---------|--------|
| `quit` or `q` | Quit |
| `dashboard` or `1` | Switch to Dashboard view |
| `sandboxes` or `2` | Switch to Sandboxes view |

Press `Esc` to cancel and return to Normal mode. `Backspace` deletes characters as you type.

## Data Refresh

The TUI automatically polls the cluster every **2 seconds**. Cluster health, the sandbox list, and global settings all update on each tick, so the display stays current without manual refreshing. This uses the same gRPC calls as the CLI — no additional server-side setup is required.

When viewing a sandbox, the policy pane auto-refreshes when a new policy version is detected. The sandbox list response includes `current_policy_version` for each sandbox; on every tick the TUI compares this against the currently displayed policy version and re-fetches the full policy only when they differ. This avoids extra RPCs during normal operation while ensuring policy updates appear within the polling interval. The user's scroll position is preserved across auto-refreshes.

Global settings are refreshed via `GetGatewaySettings` and tracked by `settings_revision` to detect changes. Sandbox settings are fetched as part of the `GetSandboxSettings` response when viewing a specific sandbox.

## Theme

The TUI uses a dark terminal theme based on the NVIDIA brand palette:

- **Background**: Black — the standard terminal background.
- **Text**: White for primary content, dimmed white for labels and secondary information.
- **Accent**: NVIDIA Green (`#76b900`) — used for the selected row, active tab indicator, and healthy/ready status.
- **Borders**: Everglade (`#123123`) — subtle dark green for structural separators.
- **Status**: Green for healthy/ready, yellow for pending/provisioning, red for error/unhealthy.

The title bar uses white text on an Everglade background to visually anchor the top of the screen.

## Port Forwarding

The TUI supports creating sandboxes with port forwarding directly from the create modal. When creating a sandbox, you can specify ports to forward in the **Ports** field (comma-separated, e.g., `8080,3000`). After the sandbox reaches `Ready` state, the TUI automatically spawns background SSH tunnels (`ssh -N -f -L <port>:127.0.0.1:<port>`) for each specified port.

Forwarded ports are displayed in the **NOTES** column of the sandbox table as `fwd:8080,3000` and in the **Forwards** row of the sandbox detail view.

Port forwarding lifecycle:
- **On create**: The TUI polls for sandbox readiness (up to 30 attempts at 2-second intervals), then spawns SSH tunnels.
- **On delete**: Any active forwards for the sandbox are automatically stopped before deletion.
- **PID tracking**: Forward PIDs are stored in `~/.config/openshell/forwards/<name>-<port>.pid`, shared with the CLI.

The forwarding implementation lives in `openshell-core::forward`, shared between the CLI and TUI.

## What is Not Yet Available

The TUI is in active development. The following features are planned but not yet implemented:

- **Inference views** — browsing inference routes and configuration.
- **Help overlay** — the `?` key is shown in the nav bar but does not open a help screen yet.
- **Command bar autocomplete** — the command bar accepts text but does not offer suggestions.
- **Filtering and search** — no `/` search within views yet.

## Crate Structure

The TUI lives in `crates/openshell-tui/`, a separate workspace crate. The CLI crate (`crates/openshell-cli/`) depends on it and launches it via the `Term` command variant in the `Commands` enum. This keeps TUI-specific dependencies (ratatui, crossterm) out of the CLI when not in use.

The `openshell-tui` crate depends on `openshell-core` for protobuf types, the gRPC client, and shared utilities (e.g., `openshell_core::forward` for port forwarding PID management) — it communicates with the gateway over the same gRPC channel the CLI uses.
