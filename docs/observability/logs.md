<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Sandbox Logs

View recent logs from a sandbox:

```console
$ nemoclaw sandbox logs my-sandbox
```

## Live Streaming

Stream logs in real time:

```console
$ nemoclaw sandbox logs my-sandbox --tail
```

## Filtering

Filter by source, level, and time range:

```console
$ nemoclaw sandbox logs my-sandbox --tail --source sandbox --level warn
$ nemoclaw sandbox logs my-sandbox --since 5m
$ nemoclaw sandbox logs my-sandbox --source gateway --level error
```

| Flag | Description |
|------|-------------|
| `--tail` | Stream live logs (does not exit). |
| `--source` | Filter by source: `gateway`, `sandbox`, or `all` (repeatable). |
| `--level` | Minimum log level: `error`, `warn`, `info`, `debug`, `trace`. |
| `--since` | Show logs from this duration ago (e.g., `5m`, `1h`, `30s`). |
| `-n <N>` | Number of log lines to fetch (default: 200). |

## Log Sources

| Source | Content |
|--------|---------|
| `gateway` | Gateway-side events: sandbox lifecycle, gRPC calls, pod management. |
| `sandbox` | Sandbox-side events: proxy decisions, policy evaluation, connection allows/denies. |

## Monitoring Denied Actions

When iterating on sandbox policies, the most useful view is sandbox-level deny events:

```console
$ nemoclaw sandbox logs my-sandbox --tail --source sandbox
```

Deny log entries include:

- **Destination host and port** --- what the agent tried to reach.
- **Binary path** --- which program attempted the connection.
- **Deny reason** --- why the connection was blocked (no matching policy, binary mismatch, etc.).

This information drives the [policy iteration loop](../safety-and-privacy/policies.md#the-policy-iteration-loop).

## Log Architecture

Sandbox logs are pushed from the sandbox process to the gateway using a background batching layer. The sandbox collects log entries from its tracing subscriber and streams them to the gateway via gRPC in batches. The gateway stores log entries and makes them available via the CLI's `logs` command.

This push-based model means logs are available even if you are not actively streaming --- you can always retrieve recent logs after the fact.
