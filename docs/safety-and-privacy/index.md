<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Safety and Privacy

OpenShell wraps every sandbox in four independent protection layers. No single
point of failure can compromise your environment. Each layer covers gaps the
others cannot.

```{mermaid}
graph TB
    subgraph runtime["OpenShell Runtime"]
        direction TB

        subgraph layers["Protection Layers"]
            direction TB

            fs["Filesystem — Landlock LSM"]
            net["Network — Proxy + Policy Engine"]
            proc["Process — seccomp + Unprivileged User"]
            inf["Inference — Privacy Router"]

            subgraph sandbox["Sandbox"]
                agent(["AI Agent"])
            end
        end
    end

    agent -- "read /sandbox ✔" --> fs
    agent -- "read /etc/shadow ✘" --> fs
    agent -- "curl approved.com ✔" --> net
    agent -- "curl evil.com ✘" --> net
    agent -- "sudo install pkg ✘" --> proc
    agent -- "call api.openai.com" --> inf
    inf -- "reroute → your backend ✔" --> net

    style runtime fill:#f5f5f5,stroke:#000000,color:#000000
    style layers fill:#e8e8e8,stroke:#000000,color:#000000
    style sandbox fill:#f5f5f5,stroke:#000000,color:#000000
    style agent fill:#ffffff,stroke:#000000,color:#000000
    style fs fill:#76b900,stroke:#000000,color:#000000
    style net fill:#76b900,stroke:#000000,color:#000000
    style proc fill:#76b900,stroke:#000000,color:#000000
    style inf fill:#76b900,stroke:#000000,color:#000000

    linkStyle default stroke:#76b900,stroke-width:2px
```

## How the Layers Work Together

You control all four layers through a single YAML policy.

| Layer | What It Protects | When It Applies |
|---|---|---|
| **Filesystem** (Landlock LSM) | Prevents reads/writes outside allowed paths. | Locked at sandbox creation. |
| **Network** (Proxy + Policy Engine) | Blocks unauthorized outbound connections. | Hot-reloadable at runtime. |
| **Process** (seccomp + unprivileged user) | Blocks privilege escalation and dangerous syscalls. | Locked at sandbox creation. |
| **Inference** (Privacy Router) | Reroutes API calls to backends you control. | Hot-reloadable at runtime. |

Filesystem and process restrictions are locked at creation time. Network and
inference rules are hot-reloadable on a running sandbox, so you can iterate on
access rules without recreating the sandbox.

## Threat Scenarios

When an AI agent runs with unrestricted access, it can read any file, reach any
network host, call any API with your credentials, and install arbitrary software.
The table below shows how the four layers address concrete threats.

| Threat | Without Protection | With OpenShell |
|---|---|---|
| **Data exfiltration** | Agent uploads source code to an external server via `curl`. | Network policy blocks all outbound connections except explicitly approved hosts. |
| **Credential theft** | Agent reads `~/.ssh/id_rsa` or `~/.aws/credentials` and exfiltrates them. | [Landlock](https://docs.kernel.org/security/landlock.html) limits the agent to declared paths (`/sandbox`, `/tmp`, read-only system dirs). |
| **Unauthorized API calls** | Agent calls `api.openai.com` with your key, sending data to a third-party provider. | Privacy router intercepts and reroutes calls to a backend you control. |
| **Privilege escalation** | Agent runs `sudo apt install`, modifies `/etc/passwd`, or scans the internal network. | Agent runs as an unprivileged user with seccomp filters; no `sudo`, no `setuid`. |

:::{important}
All four layers work together. No single layer is sufficient on its own.
Filesystem restrictions do not prevent network exfiltration. Network policies do
not prevent local privilege escalation. Process restrictions do not control
where inference traffic goes. Defense in depth means every layer covers gaps
that the others cannot.
:::

## Next Steps

- {doc}`default-policies`: The built-in policy that ships with OpenShell and what each block allows.
- {doc}`policies`: Write custom policies, configure network rules, and iterate on a running sandbox.
