<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Sandboxes

An OpenShell sandbox is a safe, private execution environment for an AI agent. Each sandbox runs inside a Kubernetes pod with multiple layers of protection that prevent unauthorized data access, credential exposure, and network exfiltration. Protection layers include filesystem restrictions (Landlock), system call filtering (seccomp), network namespace isolation, and a privacy-enforcing HTTP CONNECT proxy.

## Sandbox Lifecycle

Every sandbox moves through a defined set of phases:

| Phase | Description |
|---|---|
| Provisioning | The runtime is setting up the sandbox environment, injecting credentials, and applying your policy. |
| Ready | The sandbox is running. The agent process is active and all isolation layers are enforced. You can connect, sync files, and view logs. |
| Error | Something went wrong during provisioning or execution. Check logs with `nemoclaw logs` for details. |
| Deleting | The sandbox is being torn down. The system releases resources and purges credentials. |

## Built-in Default Policy

NVIDIA OpenShell ships a built-in policy that covers common agent workflows out of the box.
When you create a sandbox without `--policy`, OpenShell applies the default policy. This policy controls three things:

- What the agent can access on disk. Filesystem paths are split into read-only and read-write sets. [Landlock LSM](https://docs.kernel.org/security/landlock.html) enforces these restrictions at the kernel level.
- What the agent can reach on the network. Each network policy block pairs a set of allowed destinations (host and port) with a set of allowed binaries (executable paths inside the sandbox). The proxy resolves every outbound connection to the binary that opened it. A connection is allowed only when both the destination and the calling binary match an entry in the same block. Everything else is denied.
- What privileges the agent has. The agent runs as an unprivileged user with seccomp filters that block dangerous system calls. There is no `sudo`, no `setuid`, and no path to elevated privileges.

### Agent Compatibility

The following table shows the coverage of the default policy for common agents.

| Agent | Coverage | Action Required |
|---|---|---|
| Claude Code | Full | None. Works out of the box. |
| OpenCode | Partial | Add `opencode.ai` endpoint and OpenCode binary paths. |
| Codex | None | Provide a complete custom policy with OpenAI endpoints and Codex binary paths. |

:::{important}
If you run a non-Claude agent without a custom policy, the agent's API calls are denied by the proxy. You must provide a policy that declares the agent's endpoints and binaries.
:::

### What the Default Policy Allows

The default policy defines six network policy blocks, plus filesystem isolation, Landlock enforcement, and process identity. For the full breakdown of each block, see {doc}`../reference/default-policy`.

## Next Steps

- {doc}`create-and-manage`: Create, inspect, connect, monitor, and delete
  sandboxes.
- {doc}`policies`: Write custom policies, configure network rules, and iterate on a running sandbox.
- {doc}`providers`: Create and attach credential providers so agents can
  authenticate with external services.
- {doc}`community-sandboxes`: Use pre-built sandboxes from the community
  catalog.
- [Policy Schema Reference](../reference/policy-schema.md): Complete field reference for the policy YAML.
