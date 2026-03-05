<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Terminal

NemoClaw Terminal is a terminal dashboard that displays sandbox status and live activity in a single view. Use it to monitor agent behavior, diagnose blocked connections, and observe inference interception in real time.

```console
$ nemoclaw gator
```

## Sandbox Status

The status pane at the top of the dashboard displays the following sandbox metadata:

- **Name** and **phase** (`Provisioning`, `Ready`, `Error`)
- **Image** running in the sandbox
- **Providers** attached and their available credentials
- **Age** since creation
- **Port forwards** currently active

A phase other than `Ready` indicates the sandbox is still initializing or has encountered an error. Inspect the logs pane for details.

## Live Log Stream

The logs pane streams activity in real time. Outbound connections, policy decisions, and inference interceptions appear as they occur.

Log entries originate from two sources:

- **sandbox** — the sandbox supervisor (proxy decisions, policy enforcement, SSH connections, process lifecycle).
- **gateway** — the control plane (sandbox creation, phase changes, policy distribution).

Press `f` to enable follow mode and auto-scroll to new entries.

## Diagnosing Blocked Connections

Entries with `action=deny` indicate connections blocked by policy:

```
22:35:19 sandbox INFO CONNECT action=deny dst_host=registry.npmjs.org dst_port=443
```

Each deny entry contains the following fields:

| Field | Description |
|---|---|
| `action=deny` | Connection was blocked by the network policy. |
| `dst_host` | Destination host the process attempted to reach. |
| `dst_port` | Destination port (typically 443 for HTTPS). |
| `src_addr` | Source address inside the sandbox. |
| `policy` | Policy rule that was evaluated, or `-` if no rule matched. |

To resolve a blocked connection:

1. Add the host to the network policy if the connection is legitimate. See {doc}`../safety-and-privacy/policies` for the iteration workflow.
2. Leave it blocked if the connection is unauthorized.

## Diagnosing Inference Interception

Entries with `action=inspect_for_inference` indicate intercepted API calls:

```
22:35:37 sandbox INFO CONNECT action=inspect_for_inference dst_host=integrate.api.nvidia.com dst_port=443
22:35:37 sandbox INFO Intercepted inference request, routing locally kind=chat_completion
```

This sequence indicates:

- No network policy matched the connection (the endpoint and binary combination is not in the policy).
- Inference routing is configured (`allowed_routes` is non-empty), so the proxy intercepted the call instead of denying it.
- The proxy TLS-terminated the connection, detected an inference API pattern, and routed the request through the privacy router.

:::{note}
If these calls should go directly to the destination rather than through inference routing, the most likely cause is a binary path mismatch. The process making the HTTP call does not match any binary listed in the network policy.

Check the log entry for the binary path, then update the `binaries` list in the policy. See {doc}`../safety-and-privacy/network-access-rules` for details on binary matching.
:::

## Filtering and Navigation

The dashboard provides filtering and navigation controls:

- Press **`s`** to filter logs by source — display only `sandbox` logs (policy decisions) or only `gateway` logs (lifecycle events).
- Press **`f`** to toggle follow mode — auto-scroll to the latest entries.
- Press **`Enter`** on a log entry to open the detail view with the full message.
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
| `q` | Quit. |

## Related Topics

- **Blocked connections** — Follow {doc}`../safety-and-privacy/policies` to pull the current policy, add the missing endpoint, and push an update without restarting the sandbox.
- **Inference interception** — See {doc}`../safety-and-privacy/network-access-rules` for the distinction between agent traffic (routed directly) and userland traffic (routed through inference routing).
- **General troubleshooting** — See {doc}`../troubleshooting/cluster-issues` for common issues and diagnostics.
