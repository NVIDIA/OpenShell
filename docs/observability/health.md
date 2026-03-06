<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Cluster and Sandbox Health

NemoClaw provides two ways to monitor health: the CLI for quick checks and the NemoClaw Terminal for a live dashboard.

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

## NemoClaw Terminal

The NemoClaw Terminal is a terminal user interface inspired by [k9s](https://k9scli.io/). Instead of typing individual CLI commands to check cluster health, list sandboxes, and manage resources, it gives you a real-time, keyboard-driven dashboard.

### Launching the Terminal

```console
$ nemoclaw term
$ nemoclaw term --cluster prod
$ NEMOCLAW_CLUSTER=prod nemoclaw term
```

The terminal inherits all CLI configuration: cluster selection, TLS settings, and verbosity flags work the same way. No separate configuration is needed.

### Screen Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  NemoClaw ─ my-cluster ─ Dashboard  ● Healthy                   │  ← title bar
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

- **Title bar**: NemoClaw logo, cluster name, current view, and live health status.
- **Main area**: The active view.
- **Navigation bar**: Available views with shortcut keys.
- **Command bar**: Appears when you press `:` (vim-style).

### Views

#### Dashboard

Shows your cluster at a glance:

- **Cluster name** and **gateway endpoint**.
- **Health status**: Polls every two seconds:
  - `●` **Healthy** (green): Everything is running normally.
  - `◐` **Degraded** (yellow): The cluster is up but something needs attention.
  - `○` **Unhealthy** (red): The cluster is not operating correctly.
- **Sandbox count**.

#### Sandboxes

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
| `q` | Quit the terminal. |
| `Ctrl+C` | Force quit. |

#### Command Mode

Press `:` to open the command bar. Type a command and press `Enter`.

| Command | Action |
|---------|--------|
| `quit` / `q` | Quit the terminal. |
| `dashboard` / `1` | Switch to Dashboard. |
| `sandboxes` / `2` | Switch to Sandboxes. |

Press `Esc` to cancel.

### Port Forwarding

When creating a sandbox in the terminal, specify ports in the **Ports** field (comma-separated, for example, `8080,3000`). After the sandbox reaches `Ready` state, the terminal automatically spawns background SSH tunnels. Forwarded ports appear in the **NOTES** column and in the sandbox detail view.

### Data Refresh

The terminal polls the cluster every two seconds. Both cluster health and the sandbox list update automatically. No manual refresh needed.

### Theme

The NemoClaw Terminal uses a dark terminal theme based on the NVIDIA brand palette:

- **Background**: Terminal black.
- **Text**: White for primary, dimmed for secondary.
- **Accent**: NVIDIA Green (`#76b900`) for selected rows, active tabs, and healthy status.
- **Borders**: Everglade (`#123123`) for structural separators.
- **Status**: Green = Ready/Healthy, Yellow = Provisioning/Degraded, Red = Error/Unhealthy.
