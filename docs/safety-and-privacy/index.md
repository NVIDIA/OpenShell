<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Safety and Privacy

NemoClaw wraps every sandbox in four independent protection layers. No single
point of failure can compromise your environment. Each layer covers gaps the
others cannot.

```{mermaid}
graph TB
    subgraph runtime["NemoClaw Runtime"]
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
```

You control all four layers through a single YAML policy. Network and inference
rules are hot-reloadable on a running sandbox. Filesystem and process
restrictions are locked at creation time.

- {doc}`security-model`: Threat scenarios (data exfiltration, credential
  theft, unauthorized API calls, privilege escalation) and how NemoClaw
  addresses each one.
- {doc}`policies`: Author policies, monitor for blocked actions, and
  iterate on rules without restarting sandboxes.
- {doc}`network-access-rules`: Configure endpoint rules, binary matching,
  L7 inspection, and access presets.
