<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Cluster and Sandbox Health

NemoClaw provides two ways to monitor health: the CLI for quick checks and the Gator TUI for a live dashboard.

## CLI

Check cluster health:

```console
$ nemoclaw cluster status
```

Shows gateway connectivity and version.

Check sandbox status:

```console
$ nemoclaw sandbox list
$ nemoclaw sandbox get <name>
```

`sandbox list` shows all sandboxes with their current phase. `sandbox get` returns detailed information for a single sandbox, including status, image, attached providers, and policy revision.

## Gator TUI

Gator is a terminal user interface for NemoClaw, inspired by [k9s](https://k9scli.io/). Instead of typing individual CLI commands to check cluster health, list sandboxes, and manage resources, Gator gives you a real-time, keyboard-driven dashboard.

### Launching Gator

```console
$ nemoclaw gator
$ nemoclaw gator --cluster prod
$ NEMOCLAW_CLUSTER=prod nemoclaw gator
```

Gator inherits all CLI configuration --- cluster selection, TLS settings, and verbosity flags work the same way. No separate configuration is needed.

### Screen Layout

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

- **Title bar** --- Gator logo, cluster name, current view, and live health status.
- **Main area** --- the active view.
- **Navigation bar** --- available views with shortcut keys.
- **Command bar** --- appears when you press `:` (vim-style).

### Views

#### Dashboard (press `1`)

Shows your cluster at a glance:

- **Cluster name** and **gateway endpoint**.
- **Health status** --- polls every 2 seconds:
  - `●` **Healthy** (green) --- everything is running normally.
  - `◐` **Degraded** (yellow) --- the cluster is up but something needs attention.
  - `○` **Unhealthy** (red) --- the cluster is not operating correctly.
- **Sandbox count**.

#### Sandboxes (press `2`)

A live table of all sandboxes:

| Column | Description |
|--------|-------------|
| NAME | Sandbox name. |
| STATUS | Current phase, color-coded (green = Ready, yellow = Provisioning, red = Error). |
| AGE | Time since creation. |
| IMAGE | Container image. |
| PROVIDERS | Attached provider names. |
| NOTES | Metadata like forwarded ports (`fwd:8080,3000`). |

Navigate with `j`/`k` or arrow keys.

### Keyboard Controls

#### Normal Mode

| Key | Action |
|-----|--------|
| `1` | Switch to Dashboard. |
| `2` | Switch to Sandboxes. |
| `j` / `↓` | Move selection down. |
| `k` / `↑` | Move selection up. |
| `:` | Enter command mode. |
| `q` | Quit Gator. |
| `Ctrl+C` | Force quit. |

#### Command Mode

Press `:` to open the command bar. Type a command and press `Enter`.

| Command | Action |
|---------|--------|
| `quit` / `q` | Quit Gator. |
| `dashboard` / `1` | Switch to Dashboard. |
| `sandboxes` / `2` | Switch to Sandboxes. |

Press `Esc` to cancel.

### Port Forwarding

When creating a sandbox in Gator, specify ports in the **Ports** field (comma-separated, e.g., `8080,3000`). After the sandbox reaches `Ready` state, Gator automatically spawns background SSH tunnels. Forwarded ports appear in the **NOTES** column and in the sandbox detail view.

### Data Refresh

Gator polls the cluster every 2 seconds. Both cluster health and the sandbox list update automatically --- no manual refresh needed.

### Theme

Gator uses a dark terminal theme based on the NVIDIA brand palette:

- **Background**: Terminal black.
- **Text**: White for primary, dimmed for secondary.
- **Accent**: NVIDIA Green (`#76b900`) for selected rows, active tabs, and healthy status.
- **Borders**: Everglade (`#123123`) for structural separators.
- **Status**: Green = Ready/Healthy, Yellow = Provisioning/Degraded, Red = Error/Unhealthy.
