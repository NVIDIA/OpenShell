---
name: tui-development
description: Guide for developing the NemoClaw TUI — a ratatui-based terminal UI for the NemoClaw platform. Covers architecture, navigation, data fetching, theming, UX conventions, and development workflow. Trigger keywords - term, TUI, terminal UI, ratatui, navigator-tui, tui development, tui feature, tui bug.
---

# NemoClaw TUI Development Guide

Comprehensive reference for any agent working on the NemoClaw TUI.

## 1. Overview

The NemoClaw TUI is a ratatui-based terminal UI for the NemoClaw platform. It provides a keyboard-driven interface for managing gateways, sandboxes, and logs — the same operations available via the `nemoclaw` CLI, but with a live, interactive dashboard.

- **Launched via:** `nemoclaw term` or `mise run term`
- **Crate:** `crates/navigator-tui/`
- **Key dependencies:**
  - `ratatui` (workspace version) — uses `frame.size()` (not `frame.area()`)
  - `crossterm` (workspace version) — terminal backend and event polling
  - `tonic` with TLS — gRPC client for the NemoClaw gateway
  - `tokio` — async runtime for event loop, spawned tasks, and mpsc channels
  - `navigator-core` — proto-generated types (`NavigatorClient`, request/response structs)
  - `navigator-bootstrap` — cluster discovery (`list_clusters()`)
- **Theme:** NVIDIA-branded green on dark terminal background

## 2. Domain Object Hierarchy

The data model follows a strict hierarchy: **Cluster > Sandboxes > Logs**.

```
Cluster (discovered via navigator_bootstrap::list_clusters())
  └── Sandboxes (fetched via gRPC ListSandboxes)
        └── Logs (fetched via GetSandboxLogs + streamed via WatchSandbox)
```

- **Clusters** are discovered from on-disk config via `navigator_bootstrap::list_clusters()`. Each cluster has a name, gateway endpoint, and local/remote flag.
- **Sandboxes** belong to the active cluster. Fetched via `ListSandboxes` gRPC call with a periodic tick refresh. Each sandbox has: `id`, `name`, `phase`, `created_at_ms`, and `spec.template.image`.
- **Logs** belong to a single sandbox. Initial batch fetched via `GetSandboxLogs` (500 lines), then live-tailed via `WatchSandbox` with `follow_logs: true`.

The **title bar** always reflects this hierarchy, reading left-to-right from general to specific:

```
 NemoClaw │ Current Cluster: <name> (<status>) │ <screen/context>
```

## 3. Navigation & Screen Architecture

### Screens (`Screen` enum)

Top-level layouts that own the full content area. Each has its own nav bar hints.

| Screen | Description | Module |
| --- | --- | --- |
| `Dashboard` | Cluster list (top) + sandbox table (bottom) | `ui/dashboard.rs` |
| `Sandbox` | Single-sandbox view — detail or logs depending on `Focus` | `ui/sandbox_detail.rs`, `ui/sandbox_logs.rs` |

### Focus (`Focus` enum)

Tracks which panel currently receives keyboard input.

| Focus | Screen | Description |
| --- | --- | --- |
| `Clusters` | Dashboard | Cluster list panel has input focus |
| `Sandboxes` | Dashboard | Sandbox table panel has input focus |
| `SandboxDetail` | Sandbox | Sandbox detail view (name, status, image, age) |
| `SandboxLogs` | Sandbox | Log viewer with structured rendering |

### Screen dispatch

The top-level `ui::draw()` function (`ui/mod.rs`) handles the chrome (title bar, nav bar, command bar) and dispatches to the correct screen module:

```rust
match app.screen {
    Screen::Dashboard => dashboard::draw(frame, app, chunks[1]),
    Screen::Sandbox => draw_sandbox_screen(frame, app, chunks[1]),
}
```

Within the `Sandbox` screen, focus determines which sub-view renders:

```rust
match app.focus {
    Focus::SandboxLogs => sandbox_logs::draw(frame, app, area),
    _ => sandbox_detail::draw(frame, app, area),
}
```

### Layout structure

Every frame renders four vertical regions:

```
┌─────────────────────────────────────────────┐
│ Title bar (1 row) — brand + cluster + context│
├─────────────────────────────────────────────┤
│                                             │
│ Main content (flexible)                     │
│                                             │
├─────────────────────────────────────────────┤
│ Nav bar (1 row) — context-sensitive key hints│
├─────────────────────────────────────────────┤
│ Command bar (1 row) — `:` command input      │
└─────────────────────────────────────────────┘
```

### Title bar examples

- Dashboard: ` NemoClaw │ Current Cluster: nemoclaw (Healthy) │ Dashboard`
- Sandbox detail: ` NemoClaw │ Current Cluster: nemoclaw (Healthy) │ Sandbox: my-sandbox`

### Adding a new screen

1. Add a variant to `Screen` in `app.rs`.
2. Create a new module under `src/ui/` with a `pub fn draw(frame, app, area)`.
3. Add the module declaration in `ui/mod.rs`.
4. Add a match arm in `ui::draw()` to dispatch to the new module.
5. Add relevant `Focus` variants if the screen has multiple panels.
6. Add key handling methods in `App` for the new focus states.
7. Add nav bar hints in `draw_nav_bar()` for the new screen/focus combinations.

## 4. Data Fetching Pattern

### Initial fetch first, then stream

Always grab a batch of initial data so the UI has content immediately, then attach streaming for live updates.

**Logs example** (`spawn_log_stream` in `lib.rs`):

```
Phase 1: GetSandboxLogs  →  500 initial lines  →  send via Event::LogLines
Phase 2: WatchSandbox(follow_logs: true)  →  live tail  →  send via Event::LogLines
```

**Sandboxes**: Currently fetched via `ListSandboxes` on a 2-second tick. Could be enhanced with a watch mechanism.

### Never block the event loop

All network calls must be spawned as async tasks via `tokio::spawn`. The event loop in `lib.rs` must remain responsive to keyboard input and rendering at all times.

**Pattern:**

```rust
// Background task sends data back via mpsc channel
let handle = tokio::spawn(async move {
    let result = client.some_rpc(request).await;
    let _ = tx.send(Event::SomeData(result));
});
```

### Loading states

Show `"Loading..."` while async data is in flight (see `sandbox_logs.rs` — renders a loading message when `filtered` is empty and `sandbox_log_lines` is also empty).

### Event channel

Background tasks communicate with the event loop via `mpsc::UnboundedSender<Event>`. The `EventHandler` provides a `sender()` method to clone the transmit handle:

```rust
// In lib.rs
spawn_log_stream(&mut app, events.sender());

// In the spawned task
let _ = tx.send(Event::LogLines(lines));
```

### gRPC timeouts

All gRPC calls use a 5-second timeout via `tokio::time::timeout`:

```rust
tokio::time::timeout(Duration::from_secs(5), client.health(req)).await
```

## 5. Style Guide & Colors

### NVIDIA Green Theme (`theme.rs`)

All colors and styles are defined in `crates/navigator-tui/src/theme.rs`.

#### Colors (`theme::colors`)

| Constant | Value | Usage |
| --- | --- | --- |
| `NVIDIA_GREEN` | `Color::Rgb(118, 185, 0)` | Primary accent — selections, active items, key hints |
| `EVERGLADE` | `Color::Rgb(18, 49, 35)` | Dark green — borders (unfocused), title bar background |
| `BG` | `Color::Black` | Terminal background |
| `FG` | `Color::White` | Default foreground text |

#### Styles (`theme::styles`)

| Constant | Definition | Usage |
| --- | --- | --- |
| `TEXT` | White foreground | Default body text |
| `MUTED` | White + DIM modifier | Secondary info, separators (`│`), unfocused items |
| `HEADING` | White + BOLD | Panel titles, sandbox/cluster names when active |
| `ACCENT` | NVIDIA_GREEN foreground | Selected row marker (`▌`), sandbox source labels |
| `ACCENT_BOLD` | NVIDIA_GREEN + BOLD | "NemoClaw" brand text, command prompt `:` |
| `SELECTED` | BOLD modifier only | Selected row text emphasis |
| `BORDER` | EVERGLADE foreground | Unfocused panel borders |
| `BORDER_FOCUSED` | NVIDIA_GREEN foreground | Focused panel borders |
| `STATUS_OK` | NVIDIA_GREEN foreground | Healthy status, INFO log level, Ready phase |
| `STATUS_WARN` | Yellow foreground | Degraded status, WARN log level, Provisioning phase |
| `STATUS_ERR` | Red foreground | Unhealthy status, ERROR log level, Error phase |
| `KEY_HINT` | NVIDIA_GREEN foreground | Keyboard shortcut labels in nav bar (e.g., `[Tab]`) |
| `TITLE_BAR` | White on EVERGLADE + BOLD | Title bar background strip |

#### Visual conventions

- **Selected row**: Green `▌` left-border marker on the selected row. Active cluster also gets a green `●` dot.
- **Focused panel**: Border changes from `EVERGLADE` to `NVIDIA_GREEN`.
- **Status indicators**: Green for healthy/ready/info, yellow for degraded/provisioning/warn, red for unhealthy/error.
- **Separators**: Muted `│` characters between title bar segments and nav bar sections.
- **Log source labels**: `"sandbox"` source renders in `ACCENT` (green), `"gateway"` in `MUTED`.

## 6. UX Conventions

### Destructive actions require confirmation

Always show a y/n confirm dialog before delete, stop, or other irreversible operations.

```
Delete sandbox 'my-sandbox'? [y] Confirm  [Esc] Cancel
```

The `confirm_delete` flag in `App` gates destructive key handling — while true, only `y`, `n`, and `Esc` are processed.

### CLI parity

TUI actions should parallel `nemoclaw` CLI commands so users have familiar mental models:

| CLI Command | TUI Equivalent |
| --- | --- |
| `nemoclaw sandbox list` | Sandbox table on Dashboard |
| `nemoclaw sandbox delete <name>` | `[d]` on sandbox detail, then `[y]` to confirm |
| `nemoclaw logs <name>` | `[l]` on sandbox detail to open log viewer |
| `nemoclaw status` | Status in title bar + cluster list |

When adding new TUI features, check what the CLI offers and maintain consistency.

### Scrollable views follow k9s conventions

Any scrollable content (logs, future long lists) should follow the k9s autoscroll pattern:

- **Autoscroll on by default** — when entering a scrollable view, it auto-follows new content
- **Scrolling up pauses** — any upward scroll (keyboard or mouse) disables autoscroll
- **`f` or `G` re-enables** — jump to bottom and resume following
- **Visual indicator** — show `● FOLLOWING` (green) or `○ PAUSED` (yellow) in the panel footer
- **Mouse scroll supported** — `ScrollUp`/`ScrollDown` events move by 3 lines and respect autoscroll state
- **Scroll position shown** — `[current/total]` in the panel footer

State is tracked via `log_autoscroll: bool` on `App`. The `scroll_logs(delta)` method handles both keyboard and mouse input uniformly.

### Long content: truncate + detail popup

When content can exceed the viewport width (log lines, field lists, etc.):

- **Truncate in the list view** — hard-cut at the viewport's inner width and append `…`. This keeps density high and avoids wrapping that breaks the 1-line-per-entry model.
- **Enter opens a detail popup** — a centered overlay showing the full untruncated content with word-wrap. `Esc` or `Enter` closes it. Track the open state via `Option<usize>` index.
- **Drop noise in the list view** — omit empty fields, remove developer-internal info (like module paths / tracing targets) that the user doesn't need at a glance.
- **Smart field ordering** — for known message types (e.g. CONNECT, L7_REQUEST), put the most important fields first and trail with process ancestry / noise. Unknown types sort alphabetically.
- **Show everything in the popup** — the detail popup is where target, all fields (including empty ones if useful), and the full message are visible.

This pattern should be reused for any future view with potentially long entries.

### Vim-style navigation

| Key | Action |
| --- | --- |
| `j` / `Down` | Move selection down |
| `k` / `Up` | Move selection up |
| `g` | Jump to top (logs), disables autoscroll |
| `G` | Jump to bottom (logs), re-enables autoscroll |
| `f` | Follow / re-enable autoscroll (logs) |
| `Tab` / `BackTab` | Switch between panels on Dashboard |
| `Enter` | Select / drill into item; open detail popup in logs |
| `Esc` | Go back one level |
| `q` | Quit (from any screen) |
| `Ctrl+C` | Force quit |

### Keyboard-first, mouse-augmented

All actions are accessible via keyboard shortcuts displayed in the nav bar. The nav bar is context-sensitive — it shows different hints depending on the current screen and focus state. Mouse scrolling is supported as a convenience but never required — every action must have a keyboard equivalent.

### Command mode

`:` enters command mode (like vim). The command bar renders at the bottom with a green `:` prompt and a block cursor. Currently supports:

- `:q` / `:quit` — exit the application

`Esc` returns to normal mode. `Enter` executes the command.

### Screen-specific key hints

**Dashboard (Clusters focus):**
`[Tab] Switch Panel  [Enter] Select  [j/k] Navigate  │  [:] Command  [q] Quit`

**Dashboard (Sandboxes focus):**
Same as above.

**Sandbox (Detail focus):**
`[l] Logs  [d] Delete  │  [Esc] Back to Dashboard  [q] Quit`

**Sandbox (Logs focus):**
`[j/k] Scroll  [Enter] Detail  [g/G] Top/Bottom  [f] Follow  [s] Source: <filter>  │  [Esc] Back  [q] Quit`

## 7. Architecture & Key Files

| File | Purpose |
| --- | --- |
| `crates/navigator-tui/Cargo.toml` | Crate manifest — dependencies on `navigator-core`, `navigator-bootstrap`, `ratatui`, `crossterm`, `tonic`, `tokio` |
| `crates/navigator-tui/src/lib.rs` | Entry point. Event loop, gRPC calls (`refresh_health`, `refresh_sandboxes`, `spawn_log_stream`, `handle_sandbox_delete`), cluster switching, mTLS channel building |
| `crates/navigator-tui/src/app.rs` | `App` state struct, `Screen`/`Focus`/`InputMode`/`LogSourceFilter` enums, `LogLine` struct, `ClusterEntry`, all key handling logic |
| `crates/navigator-tui/src/event.rs` | `Event` enum (`Key`, `Mouse`, `Tick`, `Resize`, `LogLines`), `EventHandler` with mpsc channels and crossterm polling |
| `crates/navigator-tui/src/theme.rs` | `colors` module (NVIDIA_GREEN, EVERGLADE, BG, FG) and `styles` module (all `Style` constants) |
| `crates/navigator-tui/src/ui/mod.rs` | Top-level `draw()` dispatcher, `draw_title_bar`, `draw_nav_bar`, `draw_command_bar`, screen routing |
| `crates/navigator-tui/src/ui/dashboard.rs` | Dashboard screen — cluster list table (top) + sandbox table (bottom) |
| `crates/navigator-tui/src/ui/sandboxes.rs` | Reusable sandbox table widget with columns: Name, Status, Created, Age, Image |
| `crates/navigator-tui/src/ui/sandbox_detail.rs` | Sandbox detail view — name, status, image, created, age, delete confirmation dialog |
| `crates/navigator-tui/src/ui/sandbox_logs.rs` | Structured log viewer — timestamp, source, level, target, message, key=value fields, scroll position, source filter |

### Module dependency flow

```
lib.rs (event loop, gRPC, async tasks)
  ├── app.rs (state + key handling)
  ├── event.rs (Event enum + EventHandler)
  ├── theme.rs (colors + styles)
  └── ui/
        ├── mod.rs (draw dispatcher, chrome)
        ├── dashboard.rs (cluster list + sandbox table layout)
        ├── sandboxes.rs (sandbox table widget)
        ├── sandbox_detail.rs (detail view)
        └── sandbox_logs.rs (log viewer)
```

## 8. Technical Notes

### Dependency constraints

- **`navigator-tui` cannot depend on `navigator-cli`** — this would create a circular dependency. TLS channel building for cluster switching is done directly in `lib.rs` using `tonic::transport` primitives (`Certificate`, `Identity`, `ClientTlsConfig`, `Endpoint`).
- mTLS certs are read from `~/.config/nemoclaw/clusters/<name>/mtls/` (ca.crt, tls.crt, tls.key).

### Proto generated code

Proto types come from `navigator-core` which generates them from `OUT_DIR` via `include!`. They are **not** checked into the repo. Import paths look like:

```rust
use navigator_core::proto::navigator_client::NavigatorClient;
use navigator_core::proto::{ListSandboxesRequest, GetSandboxLogsRequest, ...};
```

### Proto field gotchas

- `DeleteSandboxRequest` uses the `name` field (not `id`):
  ```rust
  let req = navigator_core::proto::DeleteSandboxRequest { name: sandbox_name };
  ```
- `WatchSandboxRequest` has extra fields beyond what you might need — always use `..Default::default()`:
  ```rust
  let req = navigator_core::proto::WatchSandboxRequest {
      id: sandbox_id,
      follow_status: false,
      follow_logs: true,
      follow_events: false,
      log_tail_lines: 0,
      ..Default::default()
  };
  ```
- `SandboxLogLine` proto fields: `sandbox_id`, `timestamp_ms`, `level`, `target`, `message`, `source`, `fields` (HashMap<String, String>).
- `GetSandboxLogsRequest` fields: `sandbox_id`, `lines` (u32), `since_ms` (i64), `sources` (Vec<String>), `min_level` (String).
- `ListSandboxesRequest` fields: `limit` (i64), `offset` (i64).

### gRPC timeouts

All gRPC calls use a 5-second timeout:

```rust
tokio::time::timeout(Duration::from_secs(5), client.health(req)).await
```

The connect timeout for cluster switching is 10 seconds with HTTP/2 keepalive at 10-second intervals.

### Log streaming lifecycle

1. User presses `[l]` on sandbox detail → `pending_log_fetch = true`
2. Event loop sees the flag → calls `spawn_log_stream()`
3. Previous stream handle is aborted via `cancel_log_stream()`
4. New `tokio::spawn` task: fetches initial 500 lines, then streams via `WatchSandbox`
5. Lines arrive as `Event::LogLines` and are appended to `app.sandbox_log_lines`
6. Auto-scroll kicks in if the user is near the bottom (within 5 lines)
7. Stream is cancelled when user presses `Esc` or navigates away (handle is `.abort()`ed)

### Cluster switching lifecycle

1. User selects a different cluster and presses `Enter` → `pending_cluster_switch = Some(name)`
2. Event loop calls `handle_cluster_switch()`
3. New mTLS channel is built via `connect_to_cluster()`
4. On success: `app.client` is replaced, `reset_sandbox_state()` clears all sandbox data, `refresh_data()` fetches health + sandboxes for the new cluster
5. On failure: `status_text` shows the error

## 9. Development Workflow

### Build and run

```bash
# Build the crate
cargo build -p navigator-tui

# Run the TUI against the active cluster
mise run term

# Run with cargo-watch for hot-reload during development
mise run term:dev

# Format
cargo fmt -p navigator-tui

# Lint
cargo clippy -p navigator-tui
```

### Pre-commit

Always run before committing:

```bash
mise run pre-commit
```

### Cluster changes

If you change sandbox or server code that affects the backend, redeploy the cluster:

```bash
mise run cluster:deploy all
```

To pick up new sandbox images after changing sandbox code, delete the pod manually so it gets recreated:

```bash
kubectl delete pod <pod-name> -n <namespace>
```

### Adding a new gRPC call

1. Check the proto definitions in `navigator-core` for available RPCs and message types.
2. Add the call in `lib.rs` following the existing pattern (timeout wrapper, error handling, state update).
3. If the call is triggered by a key press, add a `pending_*` flag to `App` and handle it in the event loop.
4. If the call returns streaming data, spawn it as a background task and send results via `Event` variants.

### Adding a new Event variant

1. Add the variant to `Event` in `event.rs`.
2. Handle it in the `match events.next().await` block in `lib.rs`.
3. Update `App` state as needed from the event data.
