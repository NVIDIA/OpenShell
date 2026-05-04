<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Policy Advisor end-to-end test

Deterministic, no-LLM exercise of the agent-driven policy loop:

1. Start a sandbox with a read-only GitHub L7 policy.
2. From inside the sandbox, attempt a GitHub contents PUT and assert OpenShell
   returns a structured `policy_denied` 403.
3. Submit a narrow `addRule` proposal through `http://policy.local/v1/proposals`.
4. Approve the draft from the host and retry until the write succeeds.

This proves the proxy, the structured deny body, the `policy.local` HTTP API,
the gateway proposal path, and the hot-reload of approved rules — without
involving an LLM. The user-facing demo (`examples/agent-driven-policy-management/`)
runs the same loop with Codex driving from inside the sandbox.

## Run it

```bash
DEMO_GITHUB_OWNER=<your-handle> \
DEMO_GITHUB_REPO=openshell-policy-demo \
bash e2e/policy-advisor/test.sh
```

Requires an active OpenShell gateway (`openshell gateway start`) and a GitHub
token with contents write on the repository (auto-resolved from `gh auth token`,
`GITHUB_TOKEN`, or `GH_TOKEN`).
