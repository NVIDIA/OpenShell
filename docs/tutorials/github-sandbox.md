<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Set Up a Sandbox with GitHub Repo Access

Agents often need to work across multiple repositories with different levels of trust. An agent might need full read-write access to a feature repo where it commits code, but only read access to a shared library repo that it references without modifying. OpenShell policies let you express this distinction — the agent can clone and push to one repo while treating another as a read-only dependency.

This tutorial sets up exactly that scenario:

- **alpha-repo** — the agent's working repo. Full read-write access: clone, push, create PRs and issues.
- **bravo-repo** — a reference repo. Read-only access: clone and browse, but push and write API calls are denied.

Access is locked to these two repos. The agent cannot clone, fetch, or call the API for any other repository on GitHub.

By the end you will have:

- A GitHub credential provider injecting your token into the sandbox
- A policy that extends the default with scoped GitHub access to exactly two repos
- A running sandbox where Claude Code, OpenCode, and the `gh` CLI can all interact with GitHub

## Prerequisites

Before you begin, make sure you have:

- Completed the {doc}`Quickstart </about/get-started>` (CLI installed, Docker running)
- A GitHub personal access token (PAT) with `repo` scope, exported as `GITHUB_TOKEN`
- Your agent's API key set (e.g., `ANTHROPIC_API_KEY` for Claude Code)

## Step 1: Create a GitHub Provider

:::{admonition} Already have a sandbox running?
:class: tip

If you followed the Quickstart and already have a sandbox without a GitHub provider, you have two options:

1. **Add a provider to a new sandbox** — delete the existing sandbox, create the provider below, and recreate the sandbox with `--provider my-github` in Step 3.
2. **Set the token inside the sandbox** — connect with `nemoclaw sandbox connect <name>` and run `export GITHUB_TOKEN=<your-token>`. This skips the provider workflow but the token is not persisted across sandbox recreations.
:::

Create a provider that reads your GitHub token from the environment:

```console
$ nemoclaw provider create --name my-github --type github --from-existing
```

This reads `GITHUB_TOKEN` (and `GH_TOKEN` if set) from your shell and stores them in the provider. The sandbox receives these as environment variables at runtime.

For more on provider types, see {doc}`/sandboxes/providers`.

## Step 2: Write the Policy

Create a file called `github-policy.yaml`. This policy starts from the {doc}`default policy </reference/default-policy>` and replaces the GitHub blocks with scoped rules that grant read-write access to `alpha-repo` and read-only access to `bravo-repo`.

Replace `<org>` throughout with your GitHub organization or username.

```yaml
version: 1

# ── Static (locked at sandbox creation) ──────────────────────────

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

# ── Dynamic (hot-reloadable) ─────────────────────────────────────

network_policies:

  # Claude Code ↔ Anthropic API
  claude_code:
    name: claude-code
    endpoints:
      - { host: api.anthropic.com, port: 443, protocol: rest, enforcement: enforce, access: full, tls: terminate }
      - { host: statsig.anthropic.com, port: 443 }
      - { host: sentry.io, port: 443 }
      - { host: raw.githubusercontent.com, port: 443 }
      - { host: platform.claude.com, port: 443 }
    binaries:
      - { path: /usr/local/bin/claude }
      - { path: /usr/bin/node }

  # NVIDIA inference endpoint
  nvidia_inference:
    name: nvidia-inference
    endpoints:
      - { host: integrate.api.nvidia.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
      - { path: /bin/bash }
      - { path: /usr/local/bin/opencode }

  # ── GitHub: git operations (clone, fetch, push) ──────────────

  github_git:
    name: github-git
    endpoints:
      - host: github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        rules:
          # alpha-repo: clone, fetch, and push
          - allow:
              method: GET
              path: "/<org>/alpha-repo.git/info/refs*"
          - allow:
              method: POST
              path: "/<org>/alpha-repo.git/git-upload-pack"
          - allow:
              method: POST
              path: "/<org>/alpha-repo.git/git-receive-pack"
          # bravo-repo: clone and fetch only (no push)
          - allow:
              method: GET
              path: "/<org>/bravo-repo.git/info/refs*"
          - allow:
              method: POST
              path: "/<org>/bravo-repo.git/git-upload-pack"
    binaries:
      - { path: /usr/bin/git }

  # ── GitHub: REST API ─────────────────────────────────────────

  github_api:
    name: github-api
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        rules:
          # GraphQL API (used by gh CLI)
          - allow:
              method: POST
              path: "/graphql"
          # alpha-repo: full read-write (PRs, issues, comments, etc.)
          - allow:
              method: "*"
              path: "/repos/<org>/alpha-repo/**"
          # bravo-repo: read-only
          - allow:
              method: GET
              path: "/repos/<org>/bravo-repo/**"
          - allow:
              method: HEAD
              path: "/repos/<org>/bravo-repo/**"
          - allow:
              method: OPTIONS
              path: "/repos/<org>/bravo-repo/**"
    binaries:
      - { path: /usr/local/bin/claude }
      - { path: /usr/local/bin/opencode }
      - { path: /usr/bin/gh }
      - { path: /usr/bin/curl }

  # ── Package managers ─────────────────────────────────────────

  pypi:
    name: pypi
    endpoints:
      - { host: pypi.org, port: 443 }
      - { host: files.pythonhosted.org, port: 443 }
      - { host: github.com, port: 443 }
      - { host: objects.githubusercontent.com, port: 443 }
      - { host: api.github.com, port: 443 }
      - { host: downloads.python.org, port: 443 }
    binaries:
      - { path: /sandbox/.venv/bin/python }
      - { path: /sandbox/.venv/bin/python3 }
      - { path: /sandbox/.venv/bin/pip }
      - { path: /app/.venv/bin/python }
      - { path: /app/.venv/bin/python3 }
      - { path: /app/.venv/bin/pip }
      - { path: /usr/local/bin/uv }
      - { path: "/sandbox/.uv/python/**" }

  # ── VS Code Remote ──────────────────────────────────────────

  vscode:
    name: vscode
    endpoints:
      - { host: update.code.visualstudio.com, port: 443 }
      - { host: "*.vo.msecnd.net", port: 443 }
      - { host: vscode.download.prss.microsoft.com, port: 443 }
      - { host: marketplace.visualstudio.com, port: 443 }
      - { host: "*.gallerycdn.vsassets.io", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
      - { path: /usr/bin/wget }
      - { path: "/sandbox/.vscode-server/**" }
      - { path: "/sandbox/.vscode-remote-containers/**" }
```

**What the GitHub blocks do:**

| Block | Endpoint | Access |
|---|---|---|
| `github_git` | `github.com:443` | Git Smart HTTP with TLS termination. Clone and fetch allowed for both repos. Push (`git-receive-pack`) allowed only for `alpha-repo`. All other repos are denied. |
| `github_api` | `api.github.com:443` | REST API with TLS termination. Full read-write for `alpha-repo`. Read-only (GET, HEAD, OPTIONS) for `bravo-repo`. All other repos are denied. |

The remaining blocks (`claude_code`, `nvidia_inference`, `pypi`, `vscode`) match the {doc}`default policy </reference/default-policy>` so the sandbox behaves the same as a standard sandbox for everything outside of GitHub.

For background on how network policy blocks work, see [Network Access Rules](/sandboxes/index.md#network-access-rules).

## Step 3: Create the Sandbox

Create the sandbox with both the GitHub provider and your policy:

```console
$ nemoclaw sandbox create \
    --provider my-github \
    --policy github-policy.yaml \
    --keep \
    -- claude
```

The `--keep` flag keeps the sandbox running after Claude Code exits, so you can reconnect or iterate on the policy.

## Step 4: Verify Access

Once Claude Code is running inside the sandbox, ask it to exercise both repos. The policy should allow writes to `alpha-repo` and block writes to `bravo-repo`.

**Test read-write access** — ask Claude to clone, commit, and push to `alpha-repo`:

```text
Clone https://github.com/<org>/alpha-repo.git, add a blank line to the
README, commit, and push.
```

Claude clones the repo, makes the edit, and pushes. The sandbox logs show `action=allow` for both `github.com` (git push) and `api.github.com` (any API calls Claude makes along the way).

**Test read-only enforcement** — ask Claude to try the same thing with `bravo-repo`:

```text
Clone https://github.com/<org>/bravo-repo.git, add a blank line to the
README, commit, and push.
```

Claude clones successfully (read is allowed), but the push fails. The proxy denies `git-receive-pack` for `bravo-repo` and Claude reports the error. You can confirm in the logs:

```console
$ nemoclaw logs <sandbox-name> --tail --source sandbox
```

Look for an `action=deny` entry showing `host=github.com` and `path=/<org>/bravo-repo.git/git-receive-pack`.

**Test API scoping** — ask Claude to create an issue on each repo:

```text
Create a GitHub issue titled "Test from sandbox" on <org>/alpha-repo.
Then try to create the same issue on <org>/bravo-repo.
```

The first issue is created. The second is denied — the policy only allows GET/HEAD/OPTIONS for `bravo-repo`, so the POST to create an issue is blocked.

## Step 5: Iterate on the Policy

To grant access to additional repos or change access levels, edit `github-policy.yaml` and push the update to the running sandbox:

```console
$ nemoclaw policy set <sandbox-name> --policy github-policy.yaml --wait
```

For example, to grant write access to `bravo-repo` as well, add another rule under `github_api`:

```yaml
          - allow:
              method: "*"
              path: "/repos/<org>/bravo-repo/**"
```

And add a push rule under `github_git`:

```yaml
          - allow:
              method: POST
              path: "/<org>/bravo-repo.git/git-receive-pack"
```

For the full iterate workflow (pull current policy, edit, push, verify), see {doc}`/sandboxes/policies`.

## Next Steps

- **Need other credentials?** See {doc}`/sandboxes/providers` for all supported provider types.
- **Want finer policy control?** See {doc}`/sandboxes/policies` for more examples and the iterate workflow.
- **Looking for the full YAML reference?** See the [Policy Schema Reference](/reference/policy-schema.md).
