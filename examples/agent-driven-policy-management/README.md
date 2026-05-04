<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Agent-Driven Policy Management Demo

Run the full agent-driven policy loop end-to-end:

1. A Codex agent inside an OpenShell sandbox tries to write a markdown file to
   GitHub via the Contents API.
2. OpenShell denies the request with a structured `policy_denied` 403 because
   the initial policy only allows read-only access to `api.github.com`.
3. The agent reads `/etc/openshell/skills/policy_advisor.md`, drafts the
   narrowest rule needed, and submits it to `http://policy.local/v1/proposals`.
4. You approve the proposal from the host with one keystroke.
5. The sandbox hot-reloads the merged policy and the agent's retry succeeds.

The whole loop usually finishes in under two minutes.

## Prerequisites

- An active OpenShell gateway (`openshell gateway start`).
- `gh auth login` (or a `GITHUB_TOKEN` env var with contents-write on a
  scratch repo).
- `codex login` on the host.
- A scratch GitHub repository with at least one commit on the default branch.
  If you don't have one yet:

  ```shell
  gh repo create "$(gh api user --jq .login)/openshell-policy-demo" \
      --private --add-readme \
      --description "OpenShell policy advisor demo scratch repo"
  ```

## Run it

```shell
bash examples/agent-driven-policy-management/demo.sh
```

That's the whole thing. The demo resolves your GitHub handle from `gh`, picks
`openshell-policy-demo` as the repo, and writes one timestamped markdown file
under `openshell-policy-advisor-demo/` per run.

## Overrides (all optional)

| Env var | Default |
|---|---|
| `DEMO_GITHUB_OWNER` | `gh api user --jq .login` |
| `DEMO_GITHUB_REPO` | `openshell-policy-demo` |
| `DEMO_BRANCH` | `main` |
| `DEMO_RUN_ID` | timestamp |
| `DEMO_GITHUB_TOKEN` | falls back to `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token` |
| `DEMO_KEEP_SANDBOX` | `0` (set `1` to inspect the sandbox after the demo) |
| `DEMO_APPROVAL_TIMEOUT_SECS` | `240` |
| `OPENSHELL_BIN` | `target/debug/openshell` if present, else `openshell` on `PATH` |

## What the agent sees

`policy.template.yaml` is the initial restrictive policy: a read-only L7 REST
rule for `api.github.com` plus the binary set Codex needs. The agent has to
ask for the additional `PUT /repos/.../contents/...` write itself — that's the
proposal you approve.

## What gets approved (trust model)

Every proposal lands in the gateway as a `PolicyChunk` — a structured object
with three parts, each with a different trust level:

| Field | Source | Trust |
|---|---|---|
| `proposed_rule` (host, port, method, path, binary) | agent, schema-validated by the gateway | structured contract — *this* is what you're approving |
| `rationale` (free-form prose) | agent | hint only — a compromised agent can lie here |
| `validation_result` (prover output) | gateway-side prover | trust signal — but this surface is in progress (see [RFC 0001](../../rfc/0001-agent-driven-policy-management.md)) |

The MVP today shows the structured rule plus the agent's rationale in
`openshell rule get` and the TUI inbox panel. The demo's `openshell rule
approve-all` auto-approves to keep the loop short — in a real session a
developer reviews the structured grant before pressing `a`. Prover-backed
validation badges, computed reachability deltas, and a richer "this is what
the rule actually permits" summary are the next phase. For now, **always
approve based on the structured rule, not the agent's rationale.**

## Going further

`e2e/policy-advisor/test.sh` runs the same loop deterministically without an
LLM (curl + the `policy.local` API directly). Use it to validate the proxy and
proposal pipeline when iterating on the sandbox or gateway code.
