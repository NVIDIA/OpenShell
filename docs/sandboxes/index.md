<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Sandboxes

An OpenShell sandbox is a safe, private execution environment for an AI agent. Each sandbox runs with multiple layers of protection that prevent unauthorized data access, credential exposure, and network exfiltration. Protection layers include filesystem restrictions (Landlock), system call filtering (seccomp), network namespace isolation, and a privacy-enforcing HTTP CONNECT proxy.

## Sandbox Lifecycle

Every sandbox moves through a defined set of phases:

| Phase | Description |
|---|---|
| Provisioning | The runtime is setting up the sandbox environment, injecting credentials, and applying your policy. |
| Ready | The sandbox is running. The agent process is active and all isolation layers are enforced. You can connect, sync files, and view logs. |
| Error | Something went wrong during provisioning or execution. Check logs with `nemoclaw logs` for details. |
| Deleting | The sandbox is being torn down. The system releases resources and purges credentials. |

## Built-in Default Policy

OpenShell ships a built-in policy that covers common agent workflows out of the box.
When you create a sandbox without `--policy`, the default policy is applied. It controls three things:

| Layer | What It Controls | How It Works |
|---|---|---|
| Filesystem | What the agent can access on disk | Paths are split into read-only and read-write sets. [Landlock LSM](https://docs.kernel.org/security/landlock.html) enforces these restrictions at the kernel level. |
| Network | What the agent can reach on the network | Each policy block pairs allowed destinations (host and port) with allowed binaries (executable paths). The proxy matches every outbound connection to the binary that opened it. Both must match or the connection is denied. |
| Process | What privileges the agent has | The agent runs as an unprivileged user with seccomp filters that block dangerous system calls. No `sudo`, no `setuid`, no path to elevated privileges. |

For the full breakdown of each default policy block and agent compatibility details, see {doc}`../reference/default-policy`.

## Policy Structure

A policy has static sections (`filesystem_policy`, `landlock`, `process`) that are locked at sandbox creation, and dynamic sections (`network_policies`, `inference`) that are hot-reloadable on a running sandbox.

```yaml
version: 1

# Static: locked at sandbox creation. Paths the agent can read vs read/write.
filesystem_policy:
  read_only: [/usr, /lib, /etc]
  read_write: [/sandbox, /tmp]

# Static: Landlock LSM kernel enforcement. best_effort uses highest ABI the host supports.
landlock:
  compatibility: best_effort

# Static: Unprivileged user/group the agent process runs as.
process:
  run_as_user: sandbox
  run_as_group: sandbox

# Dynamic: hot-reloadable. Named blocks of endpoints + binaries allowed to reach them.
network_policies:
  my_api:
    name: my-api
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/bin/curl

# Dynamic: hot-reloadable. Routing hints this sandbox can use for inference (e.g. local, nvidia).
inference:
  allowed_routes: [local]
```

For the complete structure and every field, see the [Policy Schema Reference](../reference/policy-schema.md).

## Network Access Rules

Network access is controlled by policy blocks under `network_policies`. Each block has a **name**, a list of **endpoints** (host, port, protocol, and optional rules), and a list of **binaries** that are allowed to use those endpoints.

Every outbound connection from the sandbox goes through the proxy:

- The proxy queries the {doc}`policy engine <../about/architecture>` with the **destination** (host and port) and the **calling binary**. A connection is allowed only when both match an entry in the same policy block.
- For endpoints with `protocol: rest` and `tls: terminate`, each HTTP request is checked against that endpoint's `rules` (method and path).
- If no endpoint matches and inference routes are configured, the request may be rerouted for inference.
- Otherwise the connection is denied. Endpoints without `protocol` or `tls` allow the TCP stream through without inspecting payloads.

## Next Steps

- **Ready to create your first sandbox?** Start with {doc}`create-and-manage`.
- **Need to supply API keys or tokens?** Set up {doc}`providers` before creating.
- **Want to control what the agent can access?** Write a custom policy in {doc}`policies`.
- **Want a pre-built environment?** Browse the {doc}`community-sandboxes` catalog.
