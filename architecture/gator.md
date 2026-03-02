# Gator: Navigator TUI

Gator is a terminal user interface for Navigator, inspired by [k9s](https://k9scli.io/). Instead of typing individual CLI commands to check cluster health, list sandboxes, and manage resources, Gator gives you a real-time, keyboard-driven dashboard — everything updates automatically and you navigate with a few keystrokes.

## Launching Gator

Gator is a subcommand of the Navigator CLI, so it inherits all your existing configuration — cluster selection, TLS settings, and verbosity flags all work the same way.

```bash
navigator gator                   # launch against the active cluster
nav gator                         # dev alias (builds from source)
nav gator --cluster prod          # target a specific cluster
NAVIGATOR_CLUSTER=prod nav gator  # same thing, via environment variable
```

Cluster resolution follows the same priority as the rest of the CLI:

1. `--cluster` flag (if provided)
2. `NAVIGATOR_CLUSTER` environment variable
3. Active cluster from `~/.config/navigator/active_cluster`

No separate configuration files or authentication are needed.

## Screen Layout

Gator divides the terminal into four horizontal regions:

```
┌─────────────────────────────────────────────────────────────────┐
│  gator ─ my-cluster ─ Dashboard  ● Healthy                     │  ← title bar
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

- **Title bar** — shows the Gator logo, cluster name, current view, and live cluster health status.
- **Main area** — the active view (Dashboard or Sandboxes).
- **Navigation bar** — lists available views with their shortcut keys, plus Help and Quit.
- **Command bar** — appears when you press `:` to type a command (like vim).

## Views

### Dashboard (press `1`)

The Dashboard is the home screen. It shows your cluster at a glance:

- **Cluster name** and **gateway endpoint** — which cluster you are connected to and how to reach it.
- **Health status** — a live indicator that polls the cluster every 2 seconds:
  - `●` **Healthy** (green) — everything is running normally.
  - `◐` **Degraded** (yellow) — the cluster is up but something needs attention.
  - `○` **Unhealthy** (red) — the cluster is not operating correctly.
  - `…` — still connecting or status unknown.
- **Sandbox count** — how many sandboxes exist in the cluster.

### Sandboxes (press `2`)

The Sandboxes view shows a table of all sandboxes in the cluster:

| Column | Description |
|--------|-------------|
| NAME | Sandbox name |
| STATUS | Current phase, color-coded (see below) |
| AGE | Time since creation (e.g., `45s`, `12m`, `3h 20m`, `2d 5h`) |
| IMAGE | Container image the sandbox is running |

Status colors tell you the sandbox state at a glance:

- **Green** — Ready (sandbox is running and accessible)
- **Yellow** — Provisioning (sandbox is starting up)
- **Red** — Error (something went wrong)
- **Dim** — Deleting or Unknown

Use `j`/`k` or the arrow keys to move through the list. The selected row is highlighted in green.

When there are no sandboxes, the view displays: *"No sandboxes found."*

## Keyboard Controls

Gator has two input modes: **Normal** (default) and **Command** (activated by pressing `:`).

### Normal Mode

| Key | Action |
|-----|--------|
| `1` | Switch to Dashboard view |
| `2` | Switch to Sandboxes view |
| `j` or `↓` | Move selection down |
| `k` or `↑` | Move selection up |
| `:` | Enter command mode |
| `q` | Quit Gator |
| `Ctrl+C` | Force quit |

### Command Mode

Press `:` to open the command bar at the bottom of the screen. Type a command and press `Enter` to execute it.

| Command | Action |
|---------|--------|
| `quit` or `q` | Quit Gator |
| `dashboard` or `1` | Switch to Dashboard view |
| `sandboxes` or `2` | Switch to Sandboxes view |

Press `Esc` to cancel and return to Normal mode. `Backspace` deletes characters as you type.

## Data Refresh

Gator automatically polls the cluster every **2 seconds**. Both cluster health and the sandbox list update on each tick, so the display stays current without manual refreshing. This uses the same gRPC calls as the CLI — no additional server-side setup is required.

## Theme

Gator uses a dark terminal theme based on the NVIDIA brand palette:

- **Background**: Black — the standard terminal background.
- **Text**: White for primary content, dimmed white for labels and secondary information.
- **Accent**: NVIDIA Green (`#76b900`) — used for the selected row, active tab indicator, and healthy/ready status.
- **Borders**: Everglade (`#123123`) — subtle dark green for structural separators.
- **Status**: Green for healthy/ready, yellow for pending/provisioning, red for error/unhealthy.

The title bar uses white text on an Everglade background to visually anchor the top of the screen.

## What is Not Yet Available

Gator is in its initial phase. The following features are planned but not yet implemented:

- **Sandbox operations** — creating, connecting to (SSH), deleting, and viewing logs for sandboxes.
- **Inference and provider views** — browsing inference routes and provider configurations.
- **Help overlay** — the `?` key is shown in the nav bar but does not open a help screen yet.
- **Command bar autocomplete** — the command bar accepts text but does not offer suggestions.
- **Filtering and search** — no `/` search within views yet.

See the [Gator design plan](plans/gator-tui.md) for the full roadmap, including mockups and future phases.

## Crate Structure

The TUI lives in `crates/navigator-tui/`, a separate workspace crate. The CLI crate (`crates/navigator-cli/`) depends on it and launches it via the `Gator` command variant in the `Commands` enum. This keeps TUI-specific dependencies (ratatui, crossterm) out of the CLI when not in use.

The `navigator-tui` crate depends on `navigator-core` for protobuf types and the gRPC client — it communicates with the gateway over the same gRPC channel the CLI uses.
