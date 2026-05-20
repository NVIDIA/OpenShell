<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# A2A Design Review Demo

Run a small mesh of A2A-compatible agents that collaborate on a GitHub issue
from different perspectives. Each remote agent exposes an Agent Card, streams
task updates, and returns a markdown artifact. The orchestrator builds a
round-by-round design review from those artifacts.

This is the next step after the multi-agent GitHub notepad example:

- The notepad demo uses GitHub files as durable shared coordination state.
- This demo uses A2A messages, tasks, streams, and artifacts as the live
  coordination layer.
- OpenShell keeps each remote agent isolated and gives each agent only the
  policy and credentials it needs.

## What This Demo Shows

The demo starts four A2A agents:

| Agent | Role |
|---|---|
| Planner | Frames the issue and turns critique into the next plan. |
| Security | Reviews credential flow, sandbox policy, prompt injection, and data exfiltration risk. |
| Implementation | Maps the review into concrete implementation and validation steps. |
| Critic | Challenges weak claims and synthesizes the strongest next artifact. |

The agents run multiple rounds. Each agent receives the GitHub issue and the
artifacts already produced by earlier agents, then streams its own task status
and artifact back to the orchestrator.

```text
planner -> security -> implementation -> critic
   ^                                      |
   |------------- next round -------------|
```

## Why A2A Fits OpenShell

A2A provides the collaboration protocol. OpenShell provides the boundary.

The first version of this demo uses A2A's HTTP+JSON binding because it maps
cleanly to OpenShell policy. A future sandboxed orchestrator can be allowed to
fetch only:

- `GET /.well-known/agent-card.json`
- `POST /message:send`
- `POST /message:stream`
- selected task paths such as `GET /tasks/**`

That gives users an understandable policy story: agents can talk to each other
through A2A, but they do not inherit each other's filesystem, provider
credentials, model credentials, or unrelated network access.

## Files

| File | Description |
|---|---|
| `demo.sh` | Starts the local smoke or OpenShell sandbox demo. |
| `a2a-agent.mjs` | Minimal A2A HTTP+JSON remote agent with Agent Card discovery and SSE streaming. |
| `orchestrator.mjs` | Host-side A2A client agent that drives multiple review rounds. |
| `policy.yaml` | Restrictive OpenShell policy for remote worker agents. |
| `sample-issue.json` | Offline issue fixture for the default smoke run. |

## Quick Smoke Test

Prerequisite: Node.js 18 or newer.

Run the protocol flow locally without a gateway:

```shell
DEMO_LOCAL_ONLY=1 bash examples/a2a-design-review/demo.sh
```

The smoke test starts four local A2A servers, runs two collaboration rounds,
and writes a markdown review artifact under `examples/a2a-design-review/`.

## Run With OpenShell

Start a gateway, then run the sandboxed version:

```shell
mise run gateway:docker
bash examples/a2a-design-review/demo.sh
```

The script creates one OpenShell sandbox per remote A2A agent, exposes each
agent's HTTP service through the gateway, discovers each Agent Card, and runs
the design-review loop from the host.

By default the demo uses `sample-issue.json` so it can run without GitHub API
access. Point it at a real open issue by setting `DEMO_ISSUE_URL`:

```shell
DEMO_ISSUE_URL=https://github.com/NVIDIA/OpenShell/issues/123 \
  bash examples/a2a-design-review/demo.sh
```

If you do not provide `DEMO_ISSUE_URL` and want the script to use the latest
open issue from a repository, disable the sample fixture:

```shell
DEMO_USE_SAMPLE_ISSUE=0 DEMO_REPO=NVIDIA/OpenShell \
  bash examples/a2a-design-review/demo.sh
```

Optional settings:

```shell
export DEMO_ROUNDS=3
export DEMO_OUTPUT=/tmp/a2a-design-review.md
export DEMO_KEEP_SANDBOXES=1
```

## Security Model

The worker policy grants no outbound network access. The workers receive A2A
messages through OpenShell service routing and return artifacts through the
same request path.

For a fuller version where the orchestrator also runs inside a sandbox, give
the orchestrator a separate policy that allows only the remote A2A service
URLs and the specific A2A REST paths it needs. If the final artifact should be
written to GitHub, attach a separate GitHub provider and scope the policy to
one repository path, as in the multi-agent notepad demo.

Treat all A2A inputs as untrusted: Agent Cards, messages, artifacts, and task
status can carry prompt-injection content. The orchestrator should summarize
or sanitize remote artifacts before using them as model context in a
production workflow.
