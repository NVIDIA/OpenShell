---
title:
  page: Set Up a Sandbox of Claude Code with a Custom GitHub Policy
  nav: GitHub Sandbox Tutorial
description: Learn the iterative policy workflow by launching a sandbox, diagnosing a GitHub access denial, and applying a custom policy to fix it.
topics:
- Generative AI
- Cybersecurity
tags:
- Tutorial
- GitHub
- Sandbox
- Policy
- Claude Code
content:
  type: tutorial
  difficulty: technical_intermediate
  audience:
  - engineer
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Set Up a Sandbox of Claude Code with a Custom GitHub Policy

This tutorial walks through an iterative sandbox policy workflow. You launch a sandbox, ask Claude Code to push code to GitHub, and observe the default network policy denying the request.
You then diagnose the denial from your machine and from inside the sandbox, apply a custom policy, and verify that the policy update takes effect.

After completing this tutorial, you will have:

- A running sandbox with Claude Code that can push to a GitHub repository.
- A custom network policy that grants GitHub access for a specific repository.
- Experience with the policy iteration workflow: fail, diagnose, update, verify.

:::{note}
This tutorial shows example prompts and responses from Claude Code. The exact wording you see might vary between sessions. Use the examples as a guide for the type of interaction, not as expected output.
:::

## Prerequisites

This tutorial requires the following:

- Completed the {doc}`Quickstart </get-started/quickstart>` tutorial.
- A GitHub personal access token (PAT) with `repo` scope. To create one, go to [GitHub Settings > Developer settings > Personal access tokens](https://github.com/settings/tokens), select **Generate new token (classic)**, check the `repo` scope, and copy the token.
- Your own [Anthropic account](https://console.anthropic.com/) for Claude Code. OpenShell provides the sandbox, not the agent — you need your own account to log in to Claude Code.
- A public GitHub repository you own (used as the push target). A scratch or test repository works well — the tutorial pushes a small file to it. You can [create a new repository](https://github.com/new) with a README if you do not have one handy.

This tutorial uses two terminals to demonstrate the iterative policy workflow:

- **Terminal 1**: The sandbox terminal. You create the sandbox here with `openshell sandbox create` and interact with Claude Code inside it.
- **Terminal 2**: A terminal outside the sandbox on your machine. You use this for viewing the sandbox logs with `openshell term` and applying an updated policy with `openshell policy set`.

Each section below indicates which terminal to use.

## Set up a Sandbox with the Default Policy

Depending on whether you are starting a new sandbox or using an existing one, choose the appropriate tab and follow the instructions.

::::{tab-set}

:::{tab-item} Starting a new sandbox

In terminal 1, create a new sandbox with Claude Code. The {doc}`default policy </reference/default-policy>` is applied automatically, which allows read-only access to GitHub.

Create a {doc}`credential provider </sandboxes/providers>` that injects your GitHub token into the sandbox automatically. The provider reads `GITHUB_TOKEN` from your host environment and sets it as an environment variable inside the sandbox:

```console
$ GITHUB_TOKEN=<your-token>
$ openshell provider create --name my-github --type github --from-existing
$ openshell sandbox create --provider my-github --keep -- claude
```

:::

:::{tab-item} Using an existing sandbox

Connect to a sandbox that is already running and set your GitHub token as an environment variable:

```console
$ openshell sandbox connect <sandbox-name>
$ export GITHUB_TOKEN=<your-token>
```

:::

::::

The `--keep` flag keeps the sandbox running after Claude Code exits, so you can apply policy updates later without recreating the environment.

Claude Code starts inside the sandbox. It prints an authentication link. Open it in your browser, sign in to your Anthropic account, and return to the terminal. When prompted, trust the `/sandbox` workspace to allow Claude Code to read and write files.

## Push Code to GitHub

In terminal 1, ask Claude Code to write a simple script and push it to your repository. Replace `<org>` with your GitHub organization or username and `<repo>` with your repository name.

```text
Write a hello_world.py script and push it to https://github.com/<org>/<repo>.
```

Claude recognizes that it needs GitHub credentials. It asks how you want to authenticate. Provide your GitHub personal access token by pasting it into the conversation. Claude configures authentication and attempts the push.

The push should fail. Claude reports an error, but the failure is not an authentication problem. The default sandbox policy permits read-only access to GitHub and blocks write operations, so the proxy denies the push before the request reaches the GitHub server.

## Diagnose the Denial

In this section, you diagnose the denial from your machine and from inside the sandbox.

### View the Logs from Your Machine

In terminal 2, launch the OpenShell terminal:

```console
$ openshell term
```

The dashboard shows sandbox status and a live stream of policy decisions. Look for entries with `l7_decision=deny`. Select a deny entry to see the full detail:

```text
l7_action:      PUT
l7_target:      /repos/<org>/<repo>/contents/hello_world.py
l7_decision:    deny
dst_host:       api.github.com
dst_port:       443
l7_protocol:    rest
policy:         github_rest_api
l7_deny_reason: PUT /repos/<org>/<repo>/contents/hello_world.py not permitted by policy
```

The log shows that the sandbox proxy intercepted an outbound `PUT` request to `api.github.com` and denied it. The `github_rest_api` policy allows read operations (GET) but blocks write operations (PUT, POST, DELETE) to the GitHub API. A similar denial appears for `github.com` if Claude attempted a git push over HTTPS.

### Ask Claude to Check the Sandbox Logs

In terminal 1, ask Claude Code to check the sandbox logs for denied requests:

```text
Check the sandbox logs for any denied network requests. What is blocking the push?
```

Claude reads the deny entries and identifies the root cause. It explains that the failure is a sandbox network policy restriction, not a token permissions issue:

> The sandbox runs a proxy that enforces policies on outbound traffic. The
> `github_rest_api` policy allows GET requests (used to read the file) but blocks
> PUT/write requests to GitHub. This is a sandbox-level restriction, not a token
> issue. No matter what token you provide, pushes through the API will be blocked
> until the policy is updated.

Both perspectives confirm the same thing: the proxy is doing its job. The default policy is designed to be restrictive. To allow GitHub pushes, you need to update the network policy.

Copy the deny reason from Claude's response — you will paste it into your laptop agent in the next step.

## Update the Policy from Your Laptop

**Terminal 2 (laptop)** — Paste the deny reason from the previous step into your coding agent (for example, Claude Code or Cursor running on your laptop) and ask it to update the sandbox policy. The deny reason gives the agent the context it needs to generate the correct policy rules.

The following is a complete policy example that you can use as a starting point. Expand the dropdown to see the policy. Save it to a file, such as `/tmp/sandbox-policy-update.yaml`.

:::{dropdown} Full reference policy
:icon: code

The following YAML shows a complete policy that extends the {doc}`default policy </reference/default-policy>` with GitHub access for a single repository. Replace `<org>` with your GitHub organization or username and `<repo>` with your repository name.

The `filesystem_policy`, `landlock`, and `process` sections are static. They are read once at sandbox creation and cannot be changed by a hot-reload. They are included here for completeness so the file is self-contained, but only the `network_policies` section takes effect when you apply this to a running sandbox.

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
          - allow:
              method: GET
              path: "/<org>/<repo>.git/info/refs*"
          - allow:
              method: POST
              path: "/<org>/<repo>.git/git-upload-pack"
          - allow:
              method: POST
              path: "/<org>/<repo>.git/git-receive-pack"
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
          # Full read-write access to the repository
          - allow:
              method: "*"
              path: "/repos/<org>/<repo>/**"
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

The following table summarizes the two GitHub-specific blocks:

| Block | Endpoint | Behavior |
|---|---|---|
| `github_git` | `github.com:443` | Git Smart HTTP protocol with TLS termination. Permits `info/refs` (clone/fetch), `git-upload-pack` (fetch data), and `git-receive-pack` (push) for the specified repository. Denies all operations on unlisted repositories. |
| `github_api` | `api.github.com:443` | REST API with TLS termination. Permits all HTTP methods for the specified repository and GraphQL queries. Denies API access to unlisted repositories. |

The remaining blocks (`claude_code`, `nvidia_inference`, `pypi`, `vscode`) are identical to the {doc}`default policy </reference/default-policy>`. The default policy's `github_ssh_over_https` and `github_rest_api` blocks are replaced by the `github_git` and `github_api` blocks above, which grant write access to the specified repository. Sandbox behavior outside of GitHub operations is unchanged.

For details on policy block structure, refer to [Network Access Rules](/sandboxes/index.md#network-access-rules).
:::

Apply the policy to the running sandbox:

```console
$ openshell policy set <sandbox-name> --policy /tmp/sandbox-policy-update.yaml --wait
```

:::{tip}
To find the name of your sandbox, check the output from `openshell sandbox create` or run `openshell sandbox list`.
:::

Network policies are hot-reloadable. The `--wait` flag blocks until the policy engine confirms the new revision loaded, and the update takes effect immediately without restarting the sandbox or reconnecting Claude Code.

## Retry the Push

In terminal 1, ask Claude Code to retry the push:

```text
The sandbox policy has been updated. Try pushing to the repository again.
```

The push completes successfully. The `openshell term` dashboard now shows `l7_decision=allow` entries for `api.github.com` and `github.com` where it previously showed denials.

## Clean Up

When you are finished, delete the sandbox to free cluster resources:

```console
$ openshell sandbox delete <sandbox-name>
```

## Next Steps

The following resources cover related topics in greater depth:

- To add per-repository access levels (read-write vs read-only) or restrict to specific API methods, refer to the [Policy Schema Reference](/reference/policy-schema.md).
- To learn the full policy iteration workflow (pull, edit, push, verify), refer to {doc}`/sandboxes/policies`.
- To inject credentials automatically instead of pasting tokens, refer to {doc}`/sandboxes/providers`.
