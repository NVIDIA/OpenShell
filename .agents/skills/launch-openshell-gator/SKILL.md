---
name: launch-openshell-gator
description: Launch and supervise OpenShell gator agents. Use when starting gator on issues or PRs, checking gator sandboxes, building the gator sandbox image, restarting stuck gators, inspecting gator logs, or experimenting with gator harness/model overrides. Trigger keywords - launch gator, start gator, run gator, gator sandbox, supervised gator, gator logs, restart gator.
---

# Launch OpenShell Gator

Launch and supervise the repository's headless gator sandbox agent through OpenShell. This skill covers the operator workflow around `scripts/agents/run.sh`; the in-sandbox review and state-machine policy remains the `gator-gate` skill baked into the gator payload.

For gator's PR/issue validation policy, load `gator-gate` inside the launched sandbox. For generic sandbox CLI usage, use `openshell-cli`. For unhealthy gateways or sandbox startup failures, use `debug-openshell-cluster` after the launch preflight identifies a gateway/runtime problem.

## Non-Negotiable Rules

- Keep normal gator launches supervised: use `--watch --background` and let the in-sandbox supervisor own sleeping and relaunching bounded cycles.
- Do not add passive `sleep` loops in the operator session to watch gator. Check logs or status once, then report the current state or launch a proper watcher outside the model session only when explicitly asked.
- Do not change the default gator model in `scripts/agents/gator/agent.yaml` for experiments. Use `CODEX_MODEL=...` and, if needed, a temporary `--from` Docker context or `--codex-bin` override.
- Do not push to contributor branches, approve, merge, post `/ok to test`, or broaden gator scope unless the operator explicitly authorized that action.
- Scope each launch prompt to the requested issue/PR set. Avoid repo-wide gator scans unless the operator asked for repo-wide processing.
- Leave unrelated local files alone, including `.opencode/` artifacts and old gator logs unless the user asks for cleanup.

## Key Paths

| Path | Purpose |
|---|---|
| `scripts/agents/run.sh` | Manifest-driven OpenShell agent launcher. |
| `scripts/agents/gator/agent.yaml` | Gator manifest: default gateway, harness, providers, runtime, skills, and subagents. |
| `scripts/agents/gator/Dockerfile` | Gator sandbox image source. Local launches build this image through OpenShell. |
| `scripts/agents/gator/policy.yaml` | Sandbox policy for the gator agent. |
| `scripts/agents/gator/bin/gh` | Gator-specific `gh` wrapper and same-SHA duplicate-post guard. |
| `scripts/agents/gator/prompts/gator.md` | Rendered top-level prompt template baked into the payload. |
| `scripts/agents/gator/skills/gator-gate/SKILL.md` | In-sandbox gator state-machine skill. |
| `scripts/agents/gator/logs/` | Background launch and supervisor logs. |

## Preflight

Run these checks before launching unless the operator asks for a best-effort launch.

### Step 1: Confirm Repository Root

```bash
git rev-parse --show-toplevel
git status --short --branch
```

Use the repository root as the working directory for all commands. A dirty worktree is allowed, but do not stage or modify unrelated files.

### Step 2: Verify Required Host Tools

```bash
command -v openshell
command -v gh
command -v jq
command -v ruby
```

The local `openshell` wrapper may recompile the CLI. If that fails, fix the local build or ask the operator before changing unrelated source.

### Step 3: Verify GitHub Auth

Use `gh api user` as the health check. It works with provider-scoped tokens and matches gator's own auth guidance.

```bash
gh api user --jq '.login'
gh api repos/NVIDIA/OpenShell --jq '{full_name,default_branch}'
```

If this fails, refresh host `gh` auth before launching. Do not rely on `gh auth status` alone inside provider-backed sandboxes.

### Step 4: Verify Codex Auth For Codex Harness

The default gator harness is Codex. Check that the host has usable Codex auth material:

```bash
jq -e '.tokens.access_token and .tokens.refresh_token and .tokens.account_id' "$HOME/.codex/auth.json" >/dev/null
```

If this fails, run the local Codex login flow outside the gator launch. If Codex was recently reauthenticated and gateway refresh fails later, relaunch with `--reset-refresh` once.

### Step 5: Verify Gateway Is Registered And Alive

Use the target gateway from the operator request or current session context. Do not assume a gateway name. If the operator did not specify one, list registered gateways and ask before launching when the correct target is ambiguous.

```bash
openshell gateway list

gateway_name="<selected-gateway-name>"
[[ "$gateway_name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid gateway name" >&2; exit 1; }

openshell --gateway "$gateway_name" status
openshell --gateway "$gateway_name" sandbox list
```

Expected result: status returns successfully and sandbox listing completes. If the gateway is unreachable, the runtime cannot create sandboxes, or sandbox listing hangs, switch to `debug-openshell-cluster` and fix the gateway before launching gator.

### Step 6: Check Existing Gator Sandboxes

Avoid duplicate gators for the same PR unless intentionally replacing a stuck or stale one.

```bash
gateway_name="<selected-gateway-name>"
[[ "$gateway_name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid gateway name" >&2; exit 1; }

openshell --gateway "$gateway_name" sandbox list
```

Look for names like `gator-pr-<number>-supervised`. If one exists, inspect its log before deleting or relaunching.

## Input Normalization

Never paste raw operator text into shell arguments such as `--gateway`, `--name`, `--from`, issue numbers, or PR numbers. Normalize values before constructing launch commands.

Use the operator-specified gateway or a gateway selected from `openshell gateway list`:

```bash
gateway_name="<selected-gateway-name>"
[[ "$gateway_name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid gateway name" >&2; exit 1; }
```

Use digits only for issue and PR numbers:

```bash
pr_number="<digits-only>"
[[ "$pr_number" =~ ^[0-9]+$ ]] || { echo "invalid PR number" >&2; exit 1; }
```

Use the portable Kubernetes DNS-1123 sandbox-name format even when the selected gateway currently uses another driver:

```bash
sandbox_name="gator-pr-${pr_number}-supervised"
[[ "$sandbox_name" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { echo "invalid sandbox name" >&2; exit 1; }
```

For local image contexts passed to `--from`, use an agent-created path such as `mktemp -d`; do not pass raw user-supplied paths without validating that they are expected local Dockerfile contexts.

## Standard Launches

### Launch A PR Watcher

Use a stable, scoped name and a prompt that names exactly what gator should do.

```bash
gateway_name="<selected-gateway-name>"
pr_number="<digits-only>"
[[ "$gateway_name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid gateway name" >&2; exit 1; }
[[ "$pr_number" =~ ^[0-9]+$ ]] || { echo "invalid PR number" >&2; exit 1; }
sandbox_name="gator-pr-${pr_number}-supervised"
[[ "$sandbox_name" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { echo "invalid sandbox name" >&2; exit 1; }

./scripts/agents/run.sh \
  --agent gator \
  --gateway "$gateway_name" \
  --name "$sandbox_name" \
  --watch \
  --background \
  "Review and monitor PR #${pr_number} through the gator-gate workflow. Scope this invocation only to PR #${pr_number}."
```

The launcher builds the gator sandbox image when needed, stages the immutable payload, imports provider profiles, configures provider credentials and refresh, creates the sandbox, and writes a background log under `scripts/agents/gator/logs/`.

### Launch An Issue Or Issue/PR Pair

```bash
gateway_name="<selected-gateway-name>"
issue_number="<digits-only>"
[[ "$gateway_name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid gateway name" >&2; exit 1; }
[[ "$issue_number" =~ ^[0-9]+$ ]] || { echo "invalid issue number" >&2; exit 1; }
sandbox_name="gator-issue-${issue_number}-supervised"
[[ "$sandbox_name" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { echo "invalid sandbox name" >&2; exit 1; }

./scripts/agents/run.sh \
  --agent gator \
  --gateway "$gateway_name" \
  --name "$sandbox_name" \
  --watch \
  --background \
  "Run gator on issue #${issue_number}. Scope this invocation only to issue #${issue_number}."
```

For a linked pair:

```bash
gateway_name="<selected-gateway-name>"
pr_number="<digits-only>"
issue_number="<digits-only>"
[[ "$gateway_name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid gateway name" >&2; exit 1; }
[[ "$pr_number" =~ ^[0-9]+$ ]] || { echo "invalid PR number" >&2; exit 1; }
[[ "$issue_number" =~ ^[0-9]+$ ]] || { echo "invalid issue number" >&2; exit 1; }
sandbox_name="gator-pr-${pr_number}-supervised"
[[ "$sandbox_name" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { echo "invalid sandbox name" >&2; exit 1; }

./scripts/agents/run.sh \
  --agent gator \
  --gateway "$gateway_name" \
  --name "$sandbox_name" \
  --watch \
  --background \
  "Review and monitor PR #${pr_number} with linked issue #${issue_number} through the gator-gate workflow. Scope this invocation only to PR #${pr_number} and issue #${issue_number}."
```

### Launch With Explicit Maintainer Authorization

Only include authorization in the prompt when the operator explicitly gave it.

```bash
gateway_name="<selected-gateway-name>"
pr_number="<digits-only>"
[[ "$gateway_name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid gateway name" >&2; exit 1; }
[[ "$pr_number" =~ ^[0-9]+$ ]] || { echo "invalid PR number" >&2; exit 1; }
sandbox_name="gator-pr-${pr_number}-supervised"
[[ "$sandbox_name" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { echo "invalid sandbox name" >&2; exit 1; }

./scripts/agents/run.sh \
  --agent gator \
  --gateway "$gateway_name" \
  --name "$sandbox_name" \
  --watch \
  --background \
  "Review and monitor PR #${pr_number} through the gator-gate workflow. Scope this invocation only to PR #${pr_number}. The operator explicitly authorizes applying the test:e2e label and posting /ok to test for the current head SHA if gator determines that is required."
```

## Model Or Image Experiments

Use environment overrides. Do not edit `agent.yaml` for temporary experiments.

```bash
gateway_name="<selected-gateway-name>"
pr_number="<digits-only>"
[[ "$gateway_name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid gateway name" >&2; exit 1; }
[[ "$pr_number" =~ ^[0-9]+$ ]] || { echo "invalid PR number" >&2; exit 1; }
sandbox_name="gator-pr-${pr_number}-gpt56sol-supervised"
[[ "$sandbox_name" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { echo "invalid sandbox name" >&2; exit 1; }

CODEX_MODEL=gpt-5.6-sol \
./scripts/agents/run.sh \
  --agent gator \
  --gateway "$gateway_name" \
  --name "$sandbox_name" \
  --watch \
  --background \
  "Review and monitor PR #${pr_number} through the gator-gate workflow. Scope this invocation only to PR #${pr_number}. This launch is intentionally testing Codex model gpt-5.6-sol via the CLI launcher."
```

If the installed Codex CLI is too old for a model, create a temporary copy of `scripts/agents/gator/`, adjust only that temporary Dockerfile, and launch with that generated context. Keep the repo Dockerfile unchanged unless the version bump is the intended code change.

Example shape:

```bash
gateway_name="<selected-gateway-name>"
pr_number="<digits-only>"
[[ "$gateway_name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid gateway name" >&2; exit 1; }
[[ "$pr_number" =~ ^[0-9]+$ ]] || { echo "invalid PR number" >&2; exit 1; }
sandbox_name="gator-pr-${pr_number}-gpt56sol-supervised"
[[ "$sandbox_name" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { echo "invalid sandbox name" >&2; exit 1; }
tmp_context="$(mktemp -d "${TMPDIR:-/tmp}/gator-codex-XXXXXX")"
cp -R scripts/agents/gator/. "$tmp_context"/

CODEX_MODEL=gpt-5.6-sol \
./scripts/agents/run.sh \
  --agent gator \
  --gateway "$gateway_name" \
  --name "$sandbox_name" \
  --from "$tmp_context" \
  --watch \
  --background \
  "Review and monitor PR #${pr_number} through the gator-gate workflow. Scope this invocation only to PR #${pr_number}."
```

## Monitoring

### Read The Launch Result

The launcher prints the log path when `--background` is used:

```text
Started in background. Log: scripts/agents/gator/logs/<sandbox-name>.log
```

Read that file directly. Important markers:

- `Built image ...` means the local image build completed.
- `Created sandbox: <name>` means OpenShell accepted the sandbox.
- `openshell-agent: starting watch cycle` means the in-sandbox supervisor began a bounded cycle.
- `OpenAI Codex v...` plus `model: ...` confirms the Codex CLI and model actually used.
- `OPENSHELL_AGENT_RESULT {...}` is the bounded-cycle sentinel. In watch mode, the supervisor sleeps and relaunches after this line.
- `openshell-agent: still running watch cycle ...` is a heartbeat during long active model cycles.

### Inspect Active Sandboxes

```bash
gateway_name="<selected-gateway-name>"
sandbox_name="<safe-sandbox-name>"
[[ "$gateway_name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid gateway name" >&2; exit 1; }
[[ "$sandbox_name" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { echo "invalid sandbox name" >&2; exit 1; }

openshell --gateway "$gateway_name" sandbox list
openshell --gateway "$gateway_name" sandbox get "$sandbox_name"
```

If `sandbox get` is not supported by the local CLI shape, use `openshell sandbox --help` and follow the current command help.

### Interpret Common Sentinels

| Sentinel | Meaning | Operator action |
|---|---|---|
| `status=waiting` | Normal watch wait. | Leave sandbox running. |
| `status=blocked` | Human/process blocker. | Read reason; decide whether a human action is needed. |
| `status=transient_failure` | Retryable infrastructure/auth/transport issue. | Let supervisor retry unless repeated failures hit the configured cap. |
| `status=terminal_failure` | Unrecoverable agent failure. | Inspect log and fix/relaunch. |
| `status=complete` | Target closed, merged, or one-shot complete. | Delete sandbox if no longer needed. |

## Restarting A Gator

Restart when the payload must change, the sandbox is wedged without a sentinel, the model/tooling version changed, or a transient failure repeats past the useful retry point.

Before deleting, check that the sandbox is truly stale or that the operator asked for a restart. If a bounded review cycle is actively running and still producing useful output, prefer leaving it alone.

```bash
gateway_name="<selected-gateway-name>"
sandbox_name="<safe-sandbox-name>"
[[ "$gateway_name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid gateway name" >&2; exit 1; }
[[ "$sandbox_name" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { echo "invalid sandbox name" >&2; exit 1; }

openshell --gateway "$gateway_name" sandbox delete "$sandbox_name"
./scripts/agents/run.sh \
  --agent gator \
  --gateway "$gateway_name" \
  --name "$sandbox_name" \
  --watch \
  --background \
  "<same scoped operator prompt, updated only with the reason for relaunch>"
```

When relaunching after a same-SHA infrastructure failure, say that the prior attempt failed before producing a valid review disposition. When relaunching after a draft-only blocker cleared, say that the prior same-SHA disposition was only a draft blocker and the PR is now ready for review.

## Troubleshooting

### Gateway Unreachable

Symptoms: `openshell status` fails, `sandbox list` fails, sandbox remains pending, image build never starts.

Action: load `debug-openshell-cluster` and diagnose the gateway/driver. Do not keep retrying gator launches against a dead gateway.

### Image Build Failure

Symptoms: Dockerfile step failure, missing package, incompatible Codex CLI, registry pull failure.

Actions:

- Confirm the build context is `scripts/agents/gator/` or the intended temporary `--from` context.
- Confirm Docker or the selected gateway runtime can pull `nvcr.io/nvidia/base/ubuntu:noble-20251013`.
- For Codex CLI version experiments, adjust a temporary Docker context first.
- Do not commit Dockerfile version changes unless the repo should permanently use that version.

### Provider Or Credential Failure

Symptoms: host `gh` auth fails, Codex refresh fails, in-sandbox GitHub calls report auth failures, `reviewer_subagent_failed` repeats due Codex auth.

Actions:

- Re-run the GitHub and Codex preflight checks.
- If host Codex auth changed, relaunch with `--reset-refresh` once.
- If Entra or Microsoft auth is involved in a future provider, use the relevant auth skill. Gator's default providers are GitHub and Codex.

### Unsupported `gh pr view --json` Field

Gator may recover by using supported `gh pr view` fields plus REST calls. If it does not, patch the gator prompt or skill to avoid the unsupported field, validate, commit, and relaunch with the updated payload.

### Same-SHA Duplicate Guard Blocks A Needed Comment

The wrapper intentionally blocks duplicate same-head-SHA gator dispositions. A relaunch should not post again for the same SHA unless one of these applies:

- Maintainer explicitly requests a same-SHA public response.
- The PR is merged or closed and needs terminal cleanup.
- The earlier attempt failed before posting.
- The prior marked disposition was only a reviewer infrastructure failure.
- The prior marked disposition was only a draft blocker and the PR is now ready for review.

Do not bypass with `OPENSHELL_GATOR_ALLOW_SAME_SHA_COMMENT=1` unless the operator explicitly confirms a maintainer override.

## Reporting Back

When you launch or inspect gator, report:

- Sandbox name.
- Gateway name.
- Log path.
- Target issue/PR scope.
- Harness and model when relevant.
- Whether image build and sandbox creation succeeded.
- Latest sentinel or heartbeat status.
- Any human action needed.

Keep the report concise. Include exact commands only when they help the operator reproduce or continue the workflow.
