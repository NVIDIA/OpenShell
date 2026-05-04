<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Agent-Driven Policy Management Demo

Run the first policy-advisor MVP loop from one host-side script:

1. Use the active OpenShell gateway.
2. Create a GitHub provider from a host token.
3. Start a sandbox with read-only L7 GitHub API access.
4. Attempt a GitHub contents write from inside the sandbox and capture the
   structured `policy_denied` response.
5. Submit a narrow policy proposal through `http://policy.local/v1/proposals`.
6. Approve the draft rule from outside the sandbox.
7. Retry the same write and confirm it succeeds.

`demo.sh` is deterministic. It does not launch a real coding agent; it uses the
same sandbox-local interfaces that the agent will use.

`dogfood.sh` runs the next loop: Codex starts inside the sandbox, observes the
structured denial, reads `/etc/openshell/skills/policy_advisor.md`, drafts and
submits a narrow proposal through `policy.local`, then retries after the host
developer approves.

## Prerequisites

- An active OpenShell gateway that includes the current sandbox supervisor
  build.
- `curl`, `jq`, and `ssh` on the host machine.
- The GitHub CLI (`gh`) if you want to create the scratch repo with the command
  below.
- A disposable or demo-safe GitHub repository.
- A GitHub token with contents write permission for that repository.

## Create A Scratch Repo

Use a private scratch repository with an initial README. The README matters
because GitHub does not create the default branch until the first commit exists.

```bash
gh repo create zredlined/openshell-policy-demo \
  --private \
  --add-readme \
  --description "OpenShell policy advisor demo scratch repo"
```

The demo never creates repositories and refuses to overwrite an existing demo
file. Each default run writes a new timestamped file under
`openshell-policy-advisor-demo/`.

## Quick Start

```bash
export DEMO_GITHUB_OWNER=<owner>
export DEMO_GITHUB_REPO=<repo>
export DEMO_GITHUB_TOKEN=<token-with-contents-write>

bash examples/agent-driven-policy-management/demo.sh
```

If you use the GitHub CLI, this also works:

```bash
export DEMO_GITHUB_OWNER=<owner>
export DEMO_GITHUB_REPO=<repo>
export DEMO_GITHUB_TOKEN="$(gh auth token)"

bash examples/agent-driven-policy-management/demo.sh
```

## Codex Dogfood

Sign in to Codex locally, then run:

```bash
codex login

export DEMO_GITHUB_OWNER=<owner>
export DEMO_GITHUB_REPO=<repo>
export DEMO_GITHUB_TOKEN="$(gh auth token)"

bash examples/agent-driven-policy-management/dogfood.sh
```

The host script only orchestrates sandbox lifecycle and developer approval. The
policy proposal is authored by Codex inside the sandbox from the installed
skill, structured denial response, and `policy.local` API.

The demo writes one markdown file under:

```text
openshell-policy-advisor-demo/<run-id>.md
```

The dogfood run writes under:

```text
openshell-policy-advisor-dogfood/<run-id>.md
```

Use a scratch repository or a demo branch if you do not want this file in a
production repository.

## Options

```bash
export OPENSHELL_BIN=/path/to/openshell
export DEMO_BRANCH=main
export DEMO_RUN_ID="$(date +%Y%m%d-%H%M%S)"
export DEMO_FILE_DIR=openshell-policy-advisor-demo
export DEMO_KEEP_SANDBOX=0
export DEMO_APPROVAL_TIMEOUT_SECS=180
```
