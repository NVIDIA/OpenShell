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
   It saves the returned `chunk_id`.
4. The gateway merges the proposed rule with the current sandbox policy, runs
   the policy prover, and stores a concise `validation_result` on the pending
   chunk. This is deterministic control-plane evidence, not agent prose.
5. The agent calls `GET /v1/proposals/{chunk_id}/wait?timeout=300` — a single
   HTTP request that the supervisor holds open until the developer decides.
   This is the load-bearing UX point: the agent burns zero LLM tokens while
   it waits; it's literally sleeping on a socket.
6. You approve the proposal from the host with one keystroke after seeing the
   exact rule and the prover verdict in `openshell rule get`.
7. The agent's `/wait` returns within ~1 second of the approval. The sandbox
   has hot-reloaded the merged policy; the agent retries the original PUT
   once and exits.

The whole loop usually finishes in under two minutes; most of that time is
sandbox cold-start (SSH bring-up + Codex install inside the sandbox), not
the policy round-trip itself.

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

## Driving it manually (real-session UX)

```shell
DEMO_MANUAL_APPROVE=1 bash examples/agent-driven-policy-management/demo.sh
```

Same flow, but the script no longer auto-approves. When the agent submits a
proposal, the demo prints the exact `approve` and `reject --reason` commands
and pauses until you run one from another terminal. This is how you'd review
a coding agent's privilege ask in a real session — read the structured grant,
decide, type one command, watch the agent's `/wait` unblock within ~1s.

Try a rejection-with-guidance to see the full revise-and-resubmit loop:
reject with `--reason "scope to docs/ paths only"` and the agent reads
`rejection_reason`, drafts a tighter proposal, and pauses again.

## Overrides (all optional)

| Env var | Default |
|---|---|
| `DEMO_GITHUB_OWNER` | `gh api user --jq .login` |
| `DEMO_GITHUB_REPO` | `openshell-policy-demo` |
| `DEMO_BRANCH` | `main` |
| `DEMO_RUN_ID` | timestamp |
| `DEMO_GITHUB_TOKEN` | falls back to `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token` |
| `DEMO_KEEP_SANDBOX` | `0` (set `1` to inspect the sandbox after the demo) |
| `DEMO_MANUAL_APPROVE` | `0` (set `1` to pause for host-side `rule approve` / `rule reject --reason`) |
| `DEMO_APPROVAL_TIMEOUT_SECS` | `240` (auto), `1800` (manual mode) |
| `DEMO_CODEX_MODEL` | `gpt-5.4-mini` (pinned for ChatGPT-account compatibility; override if your account supports a different model) |
| `DEMO_CODEX_REASONING` | `low` (the demo task is mechanical; `medium`/`high` slow it down without changing outcomes) |
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
`openshell rule get` and the TUI inbox panel. With prover validation wired
into the gateway, `openshell rule get` also shows a `Validation:` line for
agent-authored chunks. The value is the prover's verdict in OCSF-shorthand
style — one short, scannable string per chunk:

```text
Validation: prover: no new findings
```

```text
Validation: prover: 1 new finding
              capability_expansion: PUT on api.github.com:443 via /usr/bin/curl
```

Other possible verdicts: `validation unavailable` (gateway-side prover infra
issue — surfaces in the gateway log, not as proposal failure), `merge failed:
…` (proposal won't merge into the current policy), and `policy invalid: …`
(merged policy fails the structural safety check).

Read the structured rule (Endpoints + Binary). Read the Validation line.
Approve if both look right. The demo's `openshell rule approve-all`
auto-approves to keep the loop short; in a real session a developer makes
that judgment per chunk before pressing `a`.

## Going further

Two LLM-less regression scripts cover adjacent slices of the same surface
when you're iterating on the sandbox or gateway code:

- `e2e/policy-advisor/test.sh` — drives the original deny-observe-approve
  loop end-to-end against a real GitHub repo, using `curl` from inside the
  sandbox in a retry loop until policy hot-reloads. Exercises the L7 proxy
  enforcement, the proposal-submit path, and the merged-policy reload.
- `e2e/policy-advisor/wait-smoke.sh` — pure wire-contract regression for the
  `GET /v1/proposals/{id}/wait` endpoint shipped here. No LLM, no GitHub, no
  real network traffic; just submits a synthetic proposal, blocks on
  `/wait`, and asserts the developer's approve or `reject --reason` text
  round-trips back into the response body. Faster (~10s) and the right
  thing to add to when changing `policy.local` or the gateway draft-chunk
  persistence.
