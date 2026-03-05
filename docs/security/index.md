<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Safety and Privacy

NemoClaw provides defense-in-depth safety and privacy protection for AI agents through multiple independent enforcement layers. Each sandbox is governed by a declarative policy that controls what the agent can access, preventing unauthorized data access, exfiltration, and credential exposure.

## Safety and Privacy Model

### How NemoClaw Protects You

Every sandbox enforces four independent protection layers:

| Layer | Mechanism | What It Protects |
|-------|-----------|-----------------|
| **Filesystem** | Landlock LSM | Prevents agents from reading sensitive files or writing outside designated directories. Enforced by the Linux kernel. |
| **System calls** | seccomp BPF | Blocks dangerous low-level operations that could bypass safety controls (e.g., raw network socket creation). |
| **Network** | Network namespace + proxy | Prevents data exfiltration — all traffic goes through the proxy, which inspects and authorizes every connection. |
| **Process** | Privilege separation | Prevents privilege escalation — the agent runs as an unprivileged user. |

These layers are independent — a bypass of one layer does not compromise the others.

### Data Privacy

All outbound network traffic from the sandbox is forced through an HTTP CONNECT proxy, ensuring no data leaves without authorization. The proxy:

1. **Identifies the program** making each connection by inspecting `/proc` — you always know which process is sending data.
2. **Verifies binary integrity** using trust-on-first-use SHA256 hashing — if a binary is tampered with, subsequent requests are denied.
3. **Enforces least-privilege network access** using an embedded OPA engine with per-binary, per-host granularity — only the programs you authorize can reach each endpoint.
4. **Protects private infrastructure** by blocking DNS results pointing to internal IP ranges (RFC 1918, link-local, cloud metadata endpoints), preventing agents from accessing internal services.
5. **Inspects data in transit** when L7 inspection is configured — terminates TLS and examines individual HTTP requests for fine-grained data access control.

### Credential Privacy

Credentials are managed with a privacy-first design:

- API keys and tokens are stored separately from sandbox definitions on the gateway.
- Credentials never appear in Kubernetes pod specs or container configuration.
- Credentials are fetched only at runtime by the sandbox supervisor and injected as environment variables.
- The CLI never displays credential values in its output.

### Communication Security

All communication with the NemoClaw gateway is secured by mutual TLS (mTLS). The PKI is bootstrapped automatically during cluster deployment. Every client (CLI, SDK, sandbox pods) must present a valid certificate signed by the cluster CA — there is no unauthenticated path.

## Policy Overview

Sandbox behavior is governed by policies written in YAML. Policies give you explicit control over:

- **Filesystem access** — which directories are readable and writable, protecting sensitive data.
- **Network access** — which remote hosts each program can connect to, preventing data exfiltration.
- **Inference routing** — which AI model backends the sandbox can use, keeping prompts and responses private.
- **Process privileges** — the user and group the agent runs as, limiting blast radius.

See [Policies](policies.md) for the full guide on writing and managing policies.

### Static vs. Dynamic Fields

Policy fields are divided into two categories:

| Category | Fields | Updatable at Runtime? |
|----------|--------|----------------------|
| **Static** | `filesystem_policy`, `landlock`, `process` | No — applied once at startup, immutable. |
| **Dynamic** | `network_policies`, `inference` | Yes — hot-reloaded within ~30 seconds. |

Static fields are enforced at the kernel level (Landlock, seccomp) and cannot be changed after the sandbox starts. Dynamic fields are evaluated at runtime by the OPA engine and can be updated using `nemoclaw sandbox policy set`.

## In This Section

- [Policies](policies.md) — writing, managing, and iterating on sandbox policies.
- [Network Access Control](network-access.md) — detailed network policy configuration.
- [Policy Schema Reference](../reference/policy-schema.md) — complete YAML schema.
