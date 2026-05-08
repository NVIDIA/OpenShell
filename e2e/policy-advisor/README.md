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

Run against an ephemeral Docker gateway:

```bash
DEMO_GITHUB_OWNER=<your-handle> \
DEMO_GITHUB_REPO=openshell-policy-demo \
e2e/with-docker-gateway.sh bash -lc '
  target/debug/openshell settings set --global \
    --key agent_policy_proposals_enabled \
    --value true \
    --yes
  OPENSHELL_BIN="$PWD/target/debug/openshell" bash e2e/policy-advisor/test.sh
'
```

To keep the sandbox for debugging, start a local gateway first with
`mise run gateway:docker`, then run:

```bash
target/debug/openshell settings set --global \
  --key agent_policy_proposals_enabled \
  --value true \
  --yes

OPENSHELL_GATEWAY=docker-dev \
OPENSHELL_BIN="$PWD/target/debug/openshell" \
DEMO_KEEP_SANDBOX=1 \
DEMO_GITHUB_OWNER=<your-handle> \
DEMO_GITHUB_REPO=openshell-policy-demo \
bash e2e/policy-advisor/test.sh
```

Requires Docker, `agent_policy_proposals_enabled=true`, and a GitHub token with
contents write on the repository. The test auto-resolves the token from
`DEMO_GITHUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token`.
