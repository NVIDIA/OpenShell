<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Multi-Agent Shared Notepad Demo

Launch multiple coding agents in parallel OpenShell sandboxes and let them use
a shared markdown notepad. This version uses Codex as the agent runtime and
GitHub as the durable notes backend.

This example demonstrates three OpenShell ideas together:

- multiple isolated agents can run at the same time,
- agents can coordinate through durable shared notes without sharing a
  filesystem,
- Codex OAuth can use provider-backed placeholders instead of storing real
  OAuth tokens in the sandbox filesystem.

GitHub is the backing store in this example because it is familiar, durable,
branch-aware, and easy to inspect. The pattern is the important part: separate
coding agents communicate by reading and writing scoped markdown notes.

## Prerequisites

- OpenShell CLI from current `main` with provider env lookup and `--upload`
  support. If it is not on `PATH`, set `OPENSHELL_BIN` to the binary path.
- A running OpenShell gateway:

  ```bash
  openshell gateway start
  ```

- Local Codex sign-in on the host machine:

  ```bash
  codex login
  codex login status
  ```

- `jq` on the host machine
- A disposable or demo-only GitHub repository to use as the shared notepad
- A GitHub token with permission to write repository contents

Use an empty repository or one created specifically for this demo. The script
writes under `runs/<run-id>/` and will update files at those paths if they
already exist. Do not point the demo at a production repository unless you are
comfortable with it creating and updating files under that prefix.

## Quick Start

```bash
export DEMO_GITHUB_OWNER=<owner>
export DEMO_GITHUB_REPO=<repo>
export DEMO_GITHUB_TOKEN=<token-with-contents-write>

bash examples/multi-agent-notepad/demo.sh
```

If you use the GitHub CLI, you can use your signed-in GitHub session:

```bash
export DEMO_GITHUB_TOKEN="$(gh auth token)"
```

By default the script launches five worker agents and one synthesis agent in
the OpenShell `base` sandbox image, where Codex is preinstalled.
To run a faster smoke test:

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

`DEMO_RUN_ID` is used in sandbox names and policy paths, so keep it to
lowercase letters, numbers, and `-`.
Use a fresh `DEMO_RUN_ID` for each run unless you intentionally want to update
the files from a previous run.

`DEMO_BRANCH` is used in GitHub API calls and output links. For this demo, use
a simple branch name containing only letters, numbers, `.`, `_`, and `-`.

If a worker fails, the script prints the relevant log tail and keeps full logs
in a temporary directory. Set `DEMO_KEEP_SANDBOXES=1` when you want to inspect
the sandboxes after the run; temporary providers are still removed.

## What It Creates

The demo creates a small shared notepad for one multi-agent run. Each worker
writes a note, then the synthesis agent reads those notes and writes a summary:

```text
runs/<run-id>/notes/agent-1.md
runs/<run-id>/notes/agent-2.md
runs/<run-id>/notes/agent-3.md
runs/<run-id>/notes/agent-4.md
runs/<run-id>/notes/agent-5.md
runs/<run-id>/summary.md
```

Each worker gets a different research angle for the same topic. Workers never
share a filesystem or container. The GitHub repository is the shared notepad
and coordination layer.

This is not a general-purpose agent memory system. It is a simple markdown
notepad that isolated agents can use to exchange findings.

If files for the same `DEMO_RUN_ID` already exist, the demo updates them in
place.

## How Credential Protection Works

The host script uses your local Codex sign-in to create a temporary OpenShell
provider for Codex OAuth. It also creates a temporary provider for the GitHub
token. Sandboxes receive provider placeholders, not the real credential values.

When Codex or `curl` sends an authorized request, the OpenShell proxy resolves
the placeholder at the network boundary and forwards the request upstream with
the real credential. The credential values do not need to be copied into the
sandbox filesystem.

## Network Policy

The script renders `policy.template.yaml` for the configured GitHub repository
and run id. The policy allows:

- Codex traffic to OpenAI and ChatGPT endpoints used by the community base image
- limited Codex plugin metadata reads from `github.com/openai/plugins.git`
- GitHub REST `GET` and `PUT` calls scoped to:

  ```text
  /repos/<owner>/<repo>/contents/runs/<run-id>/**
  ```

The policy does not grant broad GitHub API access.
