<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Multi-Agent Shared Notepad Demo

Run multiple Codex coding agents in parallel OpenShell sandboxes, with a
GitHub repository as the durable shared notepad they coordinate through.

## Why GitHub as a shared notepad?

Long-running agents that produce artifacts — research notes, memory entries,
reports, decision logs — need somewhere durable to write them. The store has
to survive individual sandbox death, accept many concurrent writers safely,
and stay inspectable after the fact. GitHub provides all three for free:

- **Durable across sandbox restarts.** A sandbox can crash mid-run; the
  committed artifact persists.
- **Concurrency control built in.** Every PUT must include the current file
  SHA, and the branch ref serializes commits. Racing writers see HTTP 409
  and retry instead of silently overwriting each other.
- **Auditable.** Every write is a commit with author, message, diff, and
  timestamp. Free observability.
- **Reviewable.** Humans review agent output with the same PR/diff tooling
  they already use for code.
- **No new infra.** Most teams already have a GitHub org.

The pattern works best when artifacts are markdown or other text (so diffs
are useful) and when write rates are moderate (commits per minute, not per
second). For higher rates or structured queries, graduate to a real
datastore — see [Beyond map/reduce](#beyond-mapreduce-memory-architecture-variants)
below.

## What this demo shows

The simplest useful shape: **map/reduce**. N worker agents fan out and write
one note each; one synthesis agent reads them and writes a summary.

```text
runs/<run-id>/notes/agent-1.md   ← worker 1 writes
runs/<run-id>/notes/agent-2.md   ← worker 2 writes
...
runs/<run-id>/summary.md         ← synthesis agent writes
```

Each worker gets a different research angle on the same topic. Workers share
neither filesystem nor container — only the GitHub repository.

The demo also exercises two OpenShell features:

- **Provider-backed credentials.** Sandboxes get placeholders, not the real
  Codex OAuth tokens or the GitHub token. The proxy resolves them at the
  network boundary.
- **Scoped network policy.** Each sandbox can only `GET` and `PUT` paths under
  `/repos/<owner>/<repo>/contents/runs/<run-id>/**`.

## Files in this example

- `demo.sh` — host orchestration. Validates env, creates providers, launches
  sandboxes, waits for completion. Read this to understand how the run is
  driven from the host.
- `runner.sh` — the script that runs **inside each sandbox**. Bootstraps
  Codex OAuth, calls `codex exec`, and writes the result to GitHub. Read this
  to understand the agent side.
- `policy.template.yaml` — the network policy applied to every sandbox in
  the run. Renders to a concrete policy with the configured owner, repo, and
  run id.
- `prompts/worker.md`, `prompts/synthesis.md` — agent instructions.

## Prerequisites

- OpenShell CLI from current `main` (or set `OPENSHELL_BIN` to the binary
  path)
- A running OpenShell gateway: `openshell gateway start`
- Local Codex sign-in on the host: `codex login`
- `gh` (GitHub CLI) signed in, **or** a GitHub PAT with `contents:write`
- `jq` on the host
- A disposable or demo-only GitHub repository

The demo writes under `runs/<run-id>/`. Use a repository created specifically
for this demo, or one you're comfortable with the demo creating files in.

## Quick start

```bash
export DEMO_GITHUB_OWNER=<owner>
export DEMO_GITHUB_REPO=<repo>
export DEMO_GITHUB_TOKEN="$(gh auth token)"

bash examples/multi-agent-notepad/demo.sh
```

`gh auth token` returns a token with whatever scopes you logged in with —
usually broader than `contents:write`. If you'd rather use a scope-limited
PAT, set `DEMO_GITHUB_TOKEN` to that value instead.

By default the script launches five worker agents and one synthesis agent in
the OpenShell `base` image, where Codex is preinstalled. To run a faster
smoke test:

```bash
export DEMO_AGENT_COUNT=2
bash examples/multi-agent-notepad/demo.sh
```

Optional settings:

```bash
export DEMO_TOPIC="How should teams evaluate sandboxed coding agents?"
export DEMO_AGENT_COUNT=5
export DEMO_BRANCH=main
export DEMO_RUN_ID="$(date +%Y%m%d-%H%M%S)"
export DEMO_KEEP_SANDBOXES=0
```

`DEMO_RUN_ID` is used in sandbox names and policy paths, so keep it
lowercase letters, numbers, and `-`. Use a fresh `DEMO_RUN_ID` per run unless
you intentionally want to overwrite a previous run's files.

`DEMO_BRANCH` may contain only letters, numbers, `.`, `_`, and `-`.

If a worker fails, the script prints the relevant log tail and keeps full
logs in a temporary directory. Set `DEMO_KEEP_SANDBOXES=1` to inspect
sandboxes after the run; temporary providers are still removed.

## How credential protection works

The host script reads your local Codex sign-in and creates a temporary
OpenShell provider for the OAuth tokens. It also creates a temporary
provider for the GitHub token. Sandboxes receive provider placeholders, not
the real credential values.

When `codex` or `curl` inside a sandbox sends an authorized request, the
OpenShell proxy resolves the placeholder at the network boundary and
forwards the request upstream with the real credential. The credential
values never sit in the sandbox filesystem.

## Network policy

The script renders `policy.template.yaml` for the configured GitHub
repository and run id. The policy allows:

- Codex traffic to OpenAI and ChatGPT endpoints used by the community base
  image
- Limited Codex plugin metadata reads from `github.com/openai/plugins.git`
- GitHub REST `GET` and `PUT` calls scoped to
  `/repos/<owner>/<repo>/contents/runs/<run-id>/**`

The policy does not grant broad GitHub API access.

## Beyond map/reduce: memory architecture variants

The pile-and-reduce shape in this demo is one of several useful patterns
for using a Git repository as durable agent memory. Each is a different
tradeoff between contention, complexity, and what you can ask of the
artifact afterwards.

### Pile (this demo)

Each agent writes its own file at a unique path. A reducer reads them all
and writes a summary.

- **Best for:** parallel exploration with bounded fan-in (research,
  multi-perspective analysis, code review across files).
- **Contention:** low. Different files have independent SHAs, so the only
  source of 409s is branch-ref locking when many commits land at once. The
  retry loop in `put_contents` handles it.
- **Extension:** hierarchical reduce — k workers per reducer, log(N) levels —
  for runs that exceed what one synthesis agent can chew through.

### Append journal

A long-lived agent (or small team) appends entries to a shared `journal.md`
across many sessions. Useful as chronological memory: "decisions made",
"things learned", "open questions".

- **Best for:** a single agent or a small group continuously writing an
  ordered log.
- **Contention:** high if many writers; the GET-PUT-409-retry pattern is
  load-bearing here. For high-write-rate journals, switch to the Git Data
  API — create blobs concurrently, build one tree, commit once — to avoid
  branch-ref serialization.
- **Extension:** split by month (`journal/2026-05.md`) to bound file size and
  spread contention across files.

### Indexed memory

Agents read and write keyed entries — `memory/<topic>.md` per key. Higher-
level agents look up "what do we know about X?" by reading the relevant
file directly.

- **Best for:** keyed memory that survives across runs and is queried by
  topic.
- **Contention:** per-key, which is usually what you want. Hot keys still
  benefit from the retry loop.
- **Extension:** maintain a `index.md` listing all keys. The index becomes
  the hot spot — update it lazily, or rebuild it from a directory listing
  when needed.

### When to graduate beyond GitHub

GitHub stops being the right backend when you need sustained write rates
above roughly 10/sec, sub-100ms reads, structured queries, or vector search.
At that point reach for Postgres, a KV store, or a vector DB. The shape of
the agent code stays similar — only the storage primitive changes.
