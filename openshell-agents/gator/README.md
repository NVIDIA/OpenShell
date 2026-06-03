# Gator Agent

Launch a headless Codex sandbox that runs the `gator-gate` skill against OpenShell issues and pull requests.

## Prerequisites

- `gh` is authenticated on the host and has access to `NVIDIA/OpenShell` and `NVIDIA/OpenShell-Community`.
- `codex login` has created `$HOME/.codex/auth.json`.
- The active gateway has the default `codex` provider profile available.
- A local gateway is available when using the default local Dockerfile source.

## Usage

```shell
./openshell-agents/gator/run.sh \
  --gateway docker-dev \
  "Run gator on PR 1536 and keep watching until it closes or merges."
```

By default the launcher uses `openshell-agents/gator` as the sandbox source. Local gateways build `openshell-agents/gator/Dockerfile`, which installs the latest stable `@openai/codex` package at image build time. Use `--from <image>` to run a prebuilt image on remote gateways.

Use `--codex-bin "$(command -v codex)"` only when the host executable is compatible with the sandbox OS and architecture.

The launcher:

- Imports `providers/github-gator.yaml`.
- Creates or updates the `github-gator` provider from `gh auth token`.
- Creates or updates the default `codex` provider from `$HOME/.codex/auth.json` using profile-backed `--from-existing` discovery.
- Requests a gateway refresh for the Codex access-token credential when refresh metadata is configured.
- Enables `providers_v2_enabled`, `agent_policy_proposals_enabled`, and `proposal_approval_mode=auto` at gateway scope.
- Uses the gator image policy copied to `/etc/openshell/policy.yaml`.
- Uploads the current `.agents/skills/gator-gate/SKILL.md` into the sandbox payload.
- Optionally uploads a host Codex executable as `/sandbox/payload/codex`.
- Starts `codex exec` without a TTY.
- Deletes the sandbox automatically after Codex exits. Pass `--keep` to preserve it for debugging.

The GitHub provider profile intentionally does not allow GraphQL because OpenShell's GraphQL policy can constrain operation fields but not repository arguments. The sandbox prompt instructs the agent to use REST via `gh api` for the two allowed repositories.

Set `GATOR_CODEX_ACCESS_CREDENTIAL_KEY` or pass `--codex-access-key` if the default Codex provider uses a credential key other than `CODEX_AUTH_ACCESS_TOKEN` for the short-lived access token.
