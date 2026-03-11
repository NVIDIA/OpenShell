---
title:
  page: Set Up a Sandbox with Custom GitHub Policies
  nav: GitHub Sandbox Tutorial
description: Configure a sandbox with per-repository GitHub access policies and credential providers for Claude Code.
topics:
- Generative AI
- Cybersecurity
tags:
- Tutorial
- GitHub
- Sandbox
- Policy
- Claude Code
- Credential Provider
content:
  type: how_to
  difficulty: technical_intermediate
  audience:
  - engineer
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Set Up a Sandbox of Claude Code with a Custom GitHub Policy

This tutorial walks through configuring a sandbox that grants different access levels to two GitHub repositories and enforces these rules at the network layer. The sandbox runs Claude Code as the agent.

The tutorial uses the following two example repositories for illustration purposes.

- A `alpha-repo` repository with read-write access. The agent can clone, push, and call mutating GitHub API endpoints such as pull requests, issues, and comments.
- A `bravo-repo` repository with read-only access. The agent can clone and fetch, but push operations and mutating API calls are denied.
- All other GitHub repositories are denied by default. No clone, fetch, or API call to an unlisted repository is allowed.

After completing this tutorial, the sandbox environment includes the following:

- A GitHub credential provider that injects your GitHub token into the sandbox at runtime.
- A network policy that extends the default policy with per-repository GitHub access rules.
- A running sandbox in which Claude Code operates under the defined access constraints.

## Prerequisites

This tutorial requires the following:

- Completed the {doc}`Quickstart </get-started/quickstart>` tutorial.
- A GitHub personal access token (PAT) with `repo` scope, exported as `GITHUB_TOKEN`.
- An agent API key configured in the environment. For example, `ANTHROPIC_API_KEY` for Claude Code.

## Create a GitHub Provider

In this section, you learn how to create a GitHub provider that injects your token into the sandbox at runtime.

:::{admonition} Already have a sandbox running?
:class: tip

If you completed the Quickstart tutorial and have the default sandbox without a GitHub provider, there are two options to add the provider.

- **Option 1**: Recreate with a provider. Delete the existing sandbox, create the provider below, then recreate the sandbox with `--provider my-github`.
- **Option 2**: Inject the token manually. Connect with `openshell sandbox connect <name>` and run `export GITHUB_TOKEN=<your-token>`. This bypasses the provider workflow. Note that the token does not persist across sandbox recreations.
:::

Create a provider that sources your GitHub token from the host environment:

```console
$ openshell provider create --name my-github --type github --from-existing
```

This command reads `GITHUB_TOKEN` (and `GH_TOKEN` if set) from the current shell session and stores them in the provider configuration. At sandbox startup, the provider injects these values as environment variables into the container.

For additional provider types, refer to {doc}`/sandboxes/providers`.

## Write the Policy

In this section, you learn how to write a policy that extends the default policy with per-repository GitHub access rules.

Run the following command to create a file named `github-policy.yaml` with policy blocks. This policy extends the {doc}`default policy </reference/default-policy>` and overrides the GitHub network blocks with per-repository rules. The `alpha-repo` receives read-write access, the `bravo-repo` receives read-only access, and all other repositories are denied by default.

Replace every occurrence of `<org>` with your GitHub organization or username.

```console
$ cat << 'EOF' > github-policy.yaml
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
EOF
```

The following table summarizes the behavior of the GitHub policy blocks.

| Block | Endpoint | Behavior |
|---|---|---|
| `github_git` | `github.com:443` | Git Smart HTTP protocol with TLS termination. Permits `info/refs` (clone/fetch) for both repositories. Permits `git-receive-pack` (push) for `alpha-repo` only. Denies all operations on unlisted repositories. |
| `github_api` | `api.github.com:443` | REST API with TLS termination. Permits all HTTP methods for `alpha-repo`. Restricts `bravo-repo` to GET, HEAD, and OPTIONS (read-only). Denies API access to unlisted repositories. |

The remaining blocks (`claude_code`, `nvidia_inference`, `pypi`, `vscode`) are identical to the {doc}`default policy </reference/default-policy>`. Sandbox behavior outside of GitHub operations is unchanged.

For details on network policy block structure, refer to [Network Access Rules](/sandboxes/index.md#network-access-rules).

## Create the Sandbox

Run the following command to create the sandbox with the GitHub provider, the custom policy applied, and Claude Code running inside the sandbox:

```console
$ openshell sandbox create \
    --provider my-github \
    --policy github-policy.yaml \
    --keep \
    -- claude
```

The `--keep` flag keeps the sandbox running after Claude Code exits. With this flag, you can reconnect to the same sandbox or apply policy updates without recreating the environment.

## Verify Access

With Claude Code running inside the sandbox, validate that the policy enforces the expected access levels for each repository.

### Verify Read-Write Access

Instruct Claude to clone, commit, and push to `alpha-repo`:

```text
Clone https://github.com/<org>/alpha-repo.git, add a blank line to the
README.md file, commit, and push.
```

The clone, commit, and push operations should complete successfully. Verify that the sandbox logs contain `action=allow` entries for `github.com` (the git push) and `api.github.com` (any associated API calls).

### Verify Read-Only Enforcement

Instruct Claude to perform the same operations on `bravo-repo`:

```text
Clone https://github.com/<org>/bravo-repo.git, add a blank line to the
README.md file, commit, and push.
```

The clone operation succeeds because the policy permits read access. The push operation fails because the proxy denies `git-receive-pack` for `bravo-repo`. Verify the denial by inspecting the sandbox logs:

```console
$ openshell logs <sandbox-name> --tail --source sandbox
```

The output contains an `action=deny` entry with `host=github.com` and `path=/<org>/bravo-repo.git/git-receive-pack`.

### Verify API Scoping

Instruct Claude to create a GitHub issue on each repository:

```text
Create a GitHub issue titled "Test from sandbox" on <org>/alpha-repo.
Then try to create the same issue on <org>/bravo-repo.
```

Expected result is that the issue is created on `alpha-repo`. The request to `bravo-repo` is denied because the policy restricts that repository to GET, HEAD, and OPTIONS methods. The POST required to create an issue is blocked by the proxy.

## Iterate on the Policy

In this section, you learn how to iterate on the policy to modify repository access or add new repositories.

Network policies support hot-reloading. To modify repository access or add new repositories, edit `github-policy.yaml` and run the following command to apply the updated policy to the running sandbox:

```console
$ openshell policy set <sandbox-name> --policy github-policy.yaml --wait
```

For example, to change the access level of `bravo-repo` from read-only to read-write, add the following rule under `github_api`:

```yaml
          - allow:
              method: "*"
              path: "/repos/<org>/bravo-repo/**"
```

Then add the corresponding push rule under `github_git`:

```yaml
          - allow:
              method: POST
              path: "/<org>/bravo-repo.git/git-receive-pack"
```

For the complete policy iteration workflow (pull, edit, push, verify), refer to {doc}`/sandboxes/policies`.

## Next Steps

The following resources cover related topics in greater depth:

- To configure additional credential types, refer to {doc}`/sandboxes/providers`.
- To iterate on policy configuration, refer to {doc}`/sandboxes/policies`.
- To view the policy YAML specification, refer to the [Policy Schema Reference](/reference/policy-schema.md).
