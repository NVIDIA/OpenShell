<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Agent-Driven Policy Management Demo

Run the first policy-advisor MVP loop with a real agent:

1. Use the active OpenShell gateway.
2. Create a GitHub provider from a host token.
3. Start a sandbox with your agent command and an uploaded task file.
4. Let the agent hit an OpenShell `policy_denied` response.
5. Let the agent read `/etc/openshell/skills/policy_advisor.md` and submit a
   narrow proposal through `http://policy.local/v1/proposals`.
6. Approve the draft rule from outside the sandbox.
7. Let the agent retry and confirm the GitHub write succeeds.

The shell script is agent-agnostic. It does not know how to sign in to a
specific coding agent. Pass the provider names and sandbox command for the
agent you want to run.

## Prerequisites

- An active OpenShell gateway that includes the current sandbox supervisor
  build.
- `curl` and `jq` on the host machine.
- The GitHub CLI (`gh`) if you want to create the scratch repo with the command
  below.
- A disposable or demo-safe GitHub repository.
- A GitHub token with contents write permission for that repository.
- An agent provider and policy that let your chosen agent run inside the
  sandbox.

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

The included `policy.template.yaml` only defines the GitHub API target for the
policy-management loop. Use `DEMO_POLICY_FILE` to point at a policy that also
allows your chosen agent to reach its model/provider endpoints.

```bash
cp examples/agent-driven-policy-management/.env.example .env
$EDITOR .env

set -a
source .env
set +a

bash examples/agent-driven-policy-management/demo.sh
```

The host script only orchestrates sandbox lifecycle and developer approval. The
policy proposal is authored by the agent inside the sandbox from the installed
skill, structured denial response, and `policy.local` API.

The demo writes one markdown file under:

```text
openshell-policy-advisor-demo/<run-id>.md
```

Use a scratch repository or a demo branch if you do not want this file in a
production repository.

The deterministic non-model validation flow lives in
`examples/agent-driven-policy-management/validation/validation.sh`.

## Options

```bash
export OPENSHELL_BIN=/path/to/openshell
export DEMO_BRANCH=main
export DEMO_RUN_ID="$(date +%Y%m%d-%H%M%S)"
export DEMO_FILE_DIR=openshell-policy-advisor-demo
export DEMO_KEEP_SANDBOX=0
export DEMO_APPROVAL_TIMEOUT_SECS=240
export DEMO_AGENT_PROVIDERS="agent-provider-a agent-provider-b"
```
