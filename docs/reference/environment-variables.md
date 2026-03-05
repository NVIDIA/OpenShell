<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Environment Variables

## CLI Variables

| Variable | Description |
|----------|-------------|
| `NEMOCLAW_CLUSTER` | Override the active cluster name (same as `--cluster` flag). |
| `NEMOCLAW_SANDBOX_POLICY` | Path to default sandbox policy YAML (fallback when `--policy` is not provided). |

## Sandbox Variables

These variables are set inside sandbox processes automatically:

| Variable | Description |
|----------|-------------|
| `NEMOCLAW_SANDBOX` | Set to `1` inside all sandbox processes. |
| `HTTP_PROXY` | Proxy URL for HTTP traffic (set in proxy mode). |
| `HTTPS_PROXY` | Proxy URL for HTTPS traffic (set in proxy mode). |
| `ALL_PROXY` | Proxy URL for all traffic (set in proxy mode). |
| `SSL_CERT_FILE` | Path to the combined CA bundle (system CAs + sandbox ephemeral CA). |
| `NODE_EXTRA_CA_CERTS` | Same CA bundle path, for Node.js applications. |
| `REQUESTS_CA_BUNDLE` | Same CA bundle path, for Python requests library. |

Provider credentials are also injected as environment variables. The specific variables depend on which providers are attached (e.g., `ANTHROPIC_API_KEY` for Claude, `GITHUB_TOKEN` for GitHub).

## Sandbox Supervisor Variables

These are used by the sandbox supervisor process and are not typically set by users:

| Variable | Description |
|----------|-------------|
| `NEMOCLAW_SANDBOX_ID` | Sandbox ID (set by gateway in pod spec). |
| `NEMOCLAW_ENDPOINT` | Gateway gRPC endpoint (set by gateway in pod spec). |
| `NEMOCLAW_POLICY_RULES` | Path to `.rego` file (file mode only). |
| `NEMOCLAW_POLICY_DATA` | Path to YAML policy data file (file mode only). |
| `NEMOCLAW_INFERENCE_ROUTES` | Path to YAML inference routes file (standalone mode). |
| `NEMOCLAW_POLICY_POLL_INTERVAL_SECS` | Override policy poll interval (default: 30 seconds). |
| `NEMOCLAW_SANDBOX_COMMAND` | Default command when none specified (set to `sleep infinity` by server). |
