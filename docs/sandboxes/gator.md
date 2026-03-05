<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# See What's Happening in Your Sandbox

Your agent is running inside a sandbox. You need to know: Is it working? Is
something being blocked? Why did that API call fail?

Gator is the answer. It's a terminal dashboard that shows sandbox status and
live activity in a single view.

```console
$ nemoclaw gator
```

<!-- TODO: Add screenshot of the full Gator dashboard layout -->
:::{figure} /_static/gator-overview.png
:alt: Gator dashboard showing sandbox status and live logs
:class: no-scaled-link

*The Gator dashboard. Top: sandbox status. Bottom: live log stream.*
:::

## Is My Sandbox Running?

The status pane at the top shows everything about your sandbox at a glance:

- **Name** and **phase** (Provisioning, Ready, Error)
- **Image** the sandbox is running
- **Providers** attached (which credentials are available)
- **Age** since creation
- **Port forwards** if any are active

<!-- TODO: Add screenshot of the status pane -->
:::{figure} /_static/gator-status-pane.png
:alt: Gator status pane showing sandbox name, phase, providers, and age
:class: no-scaled-link

*Sandbox status: name, phase, image, providers, and active port forwards.*
:::

If the phase shows anything other than **Ready**, the sandbox is still starting
up or has encountered an error. Check the logs pane below for details.

## What Is My Agent Doing Right Now?

The logs pane streams activity in real time. Every outbound connection, every
policy decision, every inference interception appears here as it happens.

Log entries come from two sources:

- **sandbox** — the sandbox supervisor (proxy decisions, policy enforcement,
  SSH connections, process lifecycle)
- **gateway** — the control plane (sandbox creation, phase changes, policy
  distribution)

Press `f` to enable follow mode and auto-scroll to new entries as they arrive.

## Why Was Something Blocked?

Look for entries with `action=deny`. These tell you exactly what was blocked
and why:

```
22:35:19 sandbox INFO CONNECT action=deny dst_host=registry.npmjs.org dst_port=443
```

Each deny entry includes:

| Field | What it tells you |
|---|---|
| `action=deny` | The connection was blocked by policy. |
| `dst_host` | The host the agent tried to reach. |
| `dst_port` | The port (usually 443 for HTTPS). |
| `src_addr` | The source address inside the sandbox. |
| `policy` | Which policy rule was evaluated (or `-` if none matched). |

**What to do:** The agent or something it spawned tried to reach a host that
isn't in your network policy. You have two options:

1. Add the host to your policy if the connection is legitimate. See
   {doc}`/safety-and-privacy/policies` for the iteration workflow.
2. Leave it blocked if the connection shouldn't be allowed.

<!-- TODO: Add screenshot showing deny lines in Gator logs -->
:::{figure} /_static/gator-deny-logs.png
:alt: Gator log pane showing action=deny entries highlighted
:class: no-scaled-link

*Deny entries show the blocked host, port, and the binary that attempted the connection.*
:::

## Why Is My Agent's API Call Being Intercepted?

Look for entries with `action=inspect_for_inference`:

```
22:35:37 sandbox INFO CONNECT action=inspect_for_inference dst_host=integrate.api.nvidia.com dst_port=443
22:35:37 sandbox INFO Intercepted inference request, routing locally kind=chat_completion
```

This means:

- **No network policy matched** the connection (the endpoint+binary combination
  isn't in your policy).
- **But inference routing is configured** (`allowed_routes` is non-empty), so
  the proxy intercepted the call instead of denying it outright.
- The proxy TLS-terminated the connection, detected an inference API pattern,
  and routed it through the inference router.

:::{note}
If you expected these calls to go **directly** to the destination (because
they're from your agent, not from userland code), the most likely cause is a
**binary path mismatch**. The actual process making the HTTP call doesn't match
any binary listed in your network policy.

Check the log entry for the binary path, then update your policy's `binaries`
list to include it. See {doc}`/safety-and-privacy/network-access-rules` for details on
how binary matching works.
:::

## Finding What You Need

Gator provides filtering and navigation to help you focus on what matters:

- Press **`s`** to filter logs by source — show only `sandbox` logs (policy
  decisions) or only `gateway` logs (lifecycle events).
- Press **`f`** to toggle follow mode — auto-scroll to the latest entries.
- Press **`Enter`** on any log entry to open a detail view with the full
  message.
- Use **`j`** / **`k`** to navigate up and down the log list.

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `j` / `k` | Navigate down / up in the log list. |
| `Enter` | Open detail view for the selected entry. |
| `g` / `G` | Jump to top / bottom. |
| `f` | Toggle follow mode (auto-scroll to new entries). |
| `s` | Open source filter (sandbox, gateway, or all). |
| `Esc` | Return to the main view / close detail view. |
| `q` | Quit Gator. |

## What to Do Next

- **Saw something blocked?** Follow the {doc}`/safety-and-privacy/policies` to
  pull your current policy, add the missing endpoint, and push an update —
  without restarting the sandbox.
- **Agent calls being intercepted?** Read
  {doc}`/safety-and-privacy/network-access-rules` to understand the difference between
  agent traffic (goes direct) and userland traffic (goes through inference
  routing).
- **Something else wrong?** Check {doc}`/reference/troubleshooting` for common
  issues and diagnostics.
