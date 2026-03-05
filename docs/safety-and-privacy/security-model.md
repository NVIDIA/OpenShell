<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# The Security Model

When an AI agent runs with unrestricted access to your system, it can read any
file, reach any network host, call any API with your credentials, and install
arbitrary software. NemoClaw's security model exists to prevent all of that.

:::{note}
NemoClaw uses defense in depth. Four independent protection layers --- filesystem,
network, process, and inference --- work together so that no single point of
failure can compromise your environment.
:::

## What Happens Without Protection

Autonomous agents are powerful, but power without boundaries is risk. Here are
four concrete threat scenarios and how NemoClaw addresses each one.

### Data Exfiltration

**Without protection:**
The agent writes a script that reads your source code and uploads it to an
external server using `curl`.

**With NemoClaw:**
The network policy blocks all outbound connections except to hosts you have
explicitly approved. The `curl` command to an unapproved destination is denied
at the proxy before the request ever leaves the sandbox.

---

### Credential Theft

**Without protection:**
The agent reads `~/.ssh/id_rsa`, `~/.aws/credentials`, or other sensitive files
from your home directory and exfiltrates them.

**With NemoClaw:**
Landlock filesystem restrictions limit the agent to declared paths. The agent
can access `/sandbox`, `/tmp`, and read-only system directories --- but not your
home directory, SSH keys, cloud credentials, or anything else outside the
policy.

---

### Unauthorized API Calls

**Without protection:**
The agent code calls `api.openai.com` with your API key, sending proprietary
data to a third-party inference provider you did not approve.

**With NemoClaw:**
The privacy router intercepts outbound API calls and reroutes them to a
backend you control --- a local model, an NVIDIA endpoint, or your own
deployment. The agent's code does not need to change; the rerouting is
transparent. Your data never reaches an unauthorized provider.

---

### Privilege Escalation

**Without protection:**
The agent runs `sudo apt install` to install packages, modifies `/etc/passwd`,
or uses raw sockets to scan your internal network.

**With NemoClaw:**
The agent runs as an unprivileged user with seccomp filters that block
dangerous system calls. Landlock prevents writes outside allowed paths. There
is no `sudo`, no `setuid`, and no path to elevated privileges.

:::{important}
All four layers work together. No single layer is sufficient on its own.
Filesystem restrictions do not prevent network exfiltration. Network policies do
not prevent local privilege escalation. Process restrictions do not control
where inference traffic goes. Defense in depth means every layer covers gaps
that the others cannot.
:::

## Next Steps

- {doc}`policies` --- write and iterate on the policy YAML that configures all four layers
- {doc}`network-access-rules` --- configure network rules, binary matching, and TLS inspection
- {doc}`../inference/index` --- set up private inference backends
