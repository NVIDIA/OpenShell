---
title:
  page: Sandbox Logging
  nav: Logging
description: How OpenShell logs sandbox activity using standard tracing and OCSF structured events.
topics:
- Generative AI
- Cybersecurity
tags:
- Logging
- OCSF
- Observability
content:
  type: concept
  difficulty: technical_beginner
  audience:
  - engineer
  - data_scientist
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Sandbox Logging

Every OpenShell sandbox produces a log that records network connections, process lifecycle events, filesystem policy decisions, and configuration changes. The log uses two formats depending on the type of event.

## Log Formats

### Standard tracing

Internal operational events use Rust's `tracing` framework with a conventional format:

```
2026-04-01T03:28:39.160Z INFO openshell_sandbox: Fetching sandbox policy via gRPC
2026-04-01T03:28:39.175Z INFO openshell_sandbox: Creating OPA engine from proto policy data
```

These events cover startup plumbing, gRPC communication, and internal state transitions that are useful for debugging but don't represent security-relevant decisions.

### OCSF structured events

Network, process, filesystem, and configuration events use the [Open Cybersecurity Schema Framework (OCSF)](https://ocsf.io) format. OCSF is an open standard for normalizing security telemetry across tools and platforms. OpenShell maps sandbox events to OCSF v1.7.0 event classes.

In the log file, OCSF events appear in a shorthand format designed for quick human and agent scanning:

```
2026-04-01T03:28:39.811Z NET:OPEN [INFO] ALLOWED /usr/bin/curl(57) -> api.github.com:443 [policy:github_api engine:opa]
2026-04-01T03:28:39.886Z HTTP:GET [INFO] ALLOWED GET http://api.github.com/zen [policy:github_api]
2026-04-01T03:28:40.212Z NET:OPEN [MED] DENIED /usr/bin/curl(63) -> httpbin.org:443 [policy:- engine:opa]
```

When viewed through the CLI or TUI (which receive logs via gRPC), OCSF events are labeled with `OCSF` instead of `INFO` to distinguish them from standard tracing:

```
[1775014138.811] [sandbox] [OCSF ] [ocsf] NET:OPEN [INFO] ALLOWED /usr/bin/curl(57) -> api.github.com:443 [policy:github_api engine:opa]
[1775014139.212] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED /usr/bin/curl(63) -> httpbin.org:443 [policy:- engine:opa]
[1775014119.160] [sandbox] [INFO ] [openshell_sandbox] Fetching sandbox policy via gRPC
```

## OCSF Event Classes

OpenShell maps sandbox events to these OCSF classes:

| Shorthand prefix | OCSF class | Class UID | What it covers |
|---|---|---|---|
| `NET:` | Network Activity | 4001 | TCP proxy CONNECT tunnels, bypass detection, DNS failures |
| `HTTP:` | HTTP Activity | 4002 | HTTP FORWARD requests, L7 enforcement decisions |
| `SSH:` | SSH Activity | 4007 | SSH handshakes, authentication, channel operations |
| `PROC:` | Process Activity | 1007 | Process start, exit, timeout, signal failures |
| `FINDING:` | Detection Finding | 2004 | Security findings (nonce replay, proxy bypass, unsafe policy) |
| `CONFIG:` | Device Config State Change | 5019 | Policy load/reload, Landlock, TLS setup, inference routes |
| `LIFECYCLE:` | Application Lifecycle | 6002 | Sandbox supervisor start, SSH server ready |

## Reading the Shorthand Format

The shorthand format follows this pattern:

```
CLASS:ACTIVITY [SEVERITY] ACTION DETAILS [CONTEXT]
```

### Components

**Class and activity** (`NET:OPEN`, `HTTP:GET`, `PROC:LAUNCH`) identify the OCSF event class and what happened. The class name always starts at the same column position for vertical scanning.

**Severity** indicates the OCSF severity of the event:

| Tag | Meaning | When used |
|---|---|---|
| `[INFO]` | Informational | Allowed connections, successful operations |
| `[LOW]` | Low | DNS failures, operational warnings |
| `[MED]` | Medium | Denied connections, policy violations |
| `[HIGH]` | High | Security findings (nonce replay, bypass detection) |
| `[CRIT]` | Critical | Process timeout kills |
| `[FATAL]` | Fatal | Unrecoverable failures |

**Action** (`ALLOWED`, `DENIED`, `BLOCKED`) is the security control disposition. Not all events have an action (informational config events, for example).

**Details** vary by event class:

- Network: `process(pid) -> host:port` with the process identity and destination
- HTTP: `METHOD url` with the HTTP method and target
- SSH: peer address and authentication type
- Process: `name(pid)` with exit code or command line
- Config: description of what changed
- Finding: quoted title with confidence level

**Context** (in brackets at the end) provides the policy rule and enforcement engine that produced the decision.

### Examples

A allowed HTTPS connection:
```
NET:OPEN [INFO] ALLOWED /usr/bin/curl(57) -> api.github.com:443 [policy:github_api engine:opa]
```

An L7 read-only policy denying a POST:
```
HTTP:POST [MED] DENIED POST http://api.github.com/user/repos [policy:github_api]
```

A connection denied because no policy matched:
```
NET:OPEN [MED] DENIED /usr/bin/curl(63) -> httpbin.org:443 [policy:- engine:opa]
```

An SSH handshake accepted:
```
SSH:OPEN [INFO] ALLOWED 10.42.0.31:37494 [auth:NSSH1]
```

A process launched inside the sandbox:
```
PROC:LAUNCH [INFO] sleep(49)
```

A policy reload after a settings change:
```
CONFIG:DETECTED [INFO] Settings poll: config change detected [old_revision:2915564174587774909 new_revision:11008534403127604466 policy_changed:true]
CONFIG:LOADED [INFO] Policy reloaded successfully [policy_hash:0cc0c2b525573c07]
```

## Log File Location

Inside the sandbox, logs are written to `/var/log/`:

| File | Format | Rotation |
|---|---|---|
| `openshell.YYYY-MM-DD.log` | Shorthand + standard tracing | Daily, 3 files max |
| `openshell-ocsf.YYYY-MM-DD.log` | OCSF JSONL (when enabled) | Daily, 3 files max |

Both files rotate daily and retain the 3 most recent files to bound disk usage.

## Next Steps

- [Access logs](accessing-logs.md) through the CLI, TUI, or sandbox filesystem.
- [Enable OCSF JSON export](ocsf-json-export.md) for SIEM integration and compliance.
- Learn about [network policies](../sandboxes/policies.md) that generate these events.
