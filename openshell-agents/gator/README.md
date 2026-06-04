# Gator Agent

Launch a headless sandbox harness that runs the `gator-gate` skill against OpenShell issues and pull requests. The default and currently only supported harness is Codex.

## Prerequisites

- `gh` is authenticated on the host and has access to `NVIDIA/OpenShell` and `NVIDIA/OpenShell-Community`.
- For `--harness codex`, `codex login` has created `$HOME/.codex/auth.json`.
- For `--harness codex`, the active gateway has the default `codex` provider profile available.
- A local gateway is available when using the default local Dockerfile source.

## Usage

```shell
./openshell-agents/gator/run.sh \
  --gateway docker-dev \
  --harness codex \
  "Run gator on PR 1536 and keep watching until it closes or merges."
```

By default the launcher uses `openshell-agents/gator` as the sandbox source. Local gateways build `openshell-agents/gator/Dockerfile`, which installs the latest stable `@openai/codex` package at image build time. Use `--from <image>` to run a prebuilt image on remote gateways.

Use `--harness codex` to select Codex explicitly. Other harness names are rejected until their support scripts and provider setup are added under `harnesses/<name>/`.

Use `--codex-bin "$(command -v codex)"` only when the host executable is compatible with the sandbox OS and architecture.

The launcher:

- Imports `providers/github-gator.yaml`.
- Creates or updates the `github-gator` provider from `gh auth token`.
- Selects the requested harness and uploads its scripts from `harnesses/<name>/` into the sandbox payload.
- For `--harness codex`, creates or updates the default `codex` provider from `$HOME/.codex/auth.json` using profile-backed `--from-existing` discovery.
- For `--harness codex`, requests a gateway refresh for the Codex access-token credential when refresh metadata is configured.
- Enables `providers_v2_enabled`, `agent_policy_proposals_enabled`, and `proposal_approval_mode=auto` at gateway scope.
- Uses the gator image policy copied to `/etc/openshell/policy.yaml`.
- Uploads the current `.agents/skills/gator-gate/SKILL.md` into the sandbox payload.
- Uploads `.claude/agents/principal-engineer-reviewer.md` so the selected harness can run a deterministic independent reviewer execution.
- For `--harness codex`, optionally uploads a host Codex executable as `/sandbox/payload/harnesses/codex/codex`.
- Starts the selected harness without a TTY.
- Deletes the sandbox automatically after the harness exits. Pass `--keep` to preserve it for debugging.

The GitHub provider profile intentionally does not allow GraphQL because OpenShell's GraphQL policy can constrain operation fields but not repository arguments. The sandbox prompt instructs the agent to use REST via `gh api` for the two allowed repositories.

Set `GATOR_CODEX_ACCESS_CREDENTIAL_KEY` or pass `--codex-access-key` if the default Codex provider uses a credential key other than `CODEX_AUTH_ACCESS_TOKEN` for the short-lived access token.
