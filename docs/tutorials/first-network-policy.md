---
title:
  page: Write Your First Sandbox Network Policy
  nav: First Network Policy
description: See how OpenShell network policies work by creating a sandbox, observing default-deny in action, and applying a fine-grained L7 read-only rule.
topics:
- Generative AI
- Cybersecurity
tags:
- Tutorial
- Policy
- Network Policy
- Sandbox
- Security
content:
  type: tutorial
  difficulty: technical_beginner
  audience:
  - engineer
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Write Your First Sandbox Network Policy

This tutorial shows how OpenShell's network policy system works in under five minutes. You create a sandbox, watch a request get blocked by the default-deny policy, apply a fine-grained L7 rule, and verify that reads are allowed while writes are blocked, all without restarting anything.

After completing this tutorial, you understand:

- How default-deny networking blocks all outbound traffic from a sandbox.
- How to apply a network policy that grants read-only access to a specific API.
- How L7 enforcement distinguishes between HTTP methods such as GET and POST on the same endpoint.
- How to inspect deny logs for a complete audit trail.

## Prerequisites

- A working OpenShell installation. Complete the {doc}`/get-started/quickstart` before proceeding.
- Docker Desktop running on your machine.

## Create a Sandbox

Start by creating a sandbox with no network policies. This gives you a clean environment to observe default-deny behavior.

```console
$ openshell sandbox create --name demo --keep --no-auto-providers
```

`--keep` keeps the sandbox running after you exit so you can reconnect later. `--no-auto-providers` skips the provider setup prompt since this tutorial uses `curl` instead of an AI agent.

You land in an interactive shell inside the sandbox:

```text
sandbox@demo:~$
```

## Try to Reach the GitHub API

With no network policy in place, every outbound connection is blocked. Test this by making a simple API call from inside the sandbox:

```console
$ curl -s https://api.github.com/zen
```

The request fails. By default, all outbound network traffic is denied. The sandbox proxy intercepted the HTTPS CONNECT request to `api.github.com:443` and rejected it because no network policy authorizes `curl` to reach that host.

```text
curl: (56) Received HTTP code 403 from proxy after CONNECT
```

Exit the sandbox. The `--keep` flag keeps it running:

```console
$ exit
```

## Check the Deny Log

Every denied connection produces a structured log entry. Query the sandbox logs from your host to confirm the denial and inspect the reason.

```console
$ openshell logs demo --since 5m
```

You see a line like:

```text
action=deny dst_host=api.github.com dst_port=443 binary=/usr/bin/curl deny_reason="no matching network policy"
```

Every denied connection is logged with the destination, the binary that attempted it, and the reason. Nothing gets out silently.

## Apply a Read-Only GitHub API Policy

To allow the sandbox to reach the GitHub API, define a network policy that grants read-only access. The policy specifies which host, port, binary, and HTTP methods are permitted. Create a file called `github-readonly.yaml` with the following content:

```yaml
version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  github_api:
    name: github-api-readonly
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: read-only
    binaries:
      - { path: /usr/bin/curl }
```

The `filesystem_policy`, `landlock`, and `process` sections preserve the default sandbox settings. This is required because `policy set` replaces the entire policy. The `network_policies` section is the key part: `curl` may make GET, HEAD, and OPTIONS requests to `api.github.com` over HTTPS. Everything else is denied. The proxy terminates TLS using `tls: terminate` to inspect each HTTP request and enforce the `read-only` access preset at the method level.

Apply it:

```console
$ openshell policy set demo --policy github-readonly.yaml --wait
```

`--wait` blocks until the sandbox confirms the new policy is loaded. No restart required. Policies are hot-reloaded.

:::{tip}
This tutorial uses `curl` and `read-only` access to keep things simple. When building policies for real workloads:

- To scope the policy to an agent, replace the `binaries` section with your agent's binary, such as `/usr/local/bin/claude`, instead of `curl`.
- To grant write access, change `access: read-only` to `read-write` or add explicit `rules` for specific paths. Refer to the {doc}`/reference/policy-schema`.
- To allow additional endpoints, stack multiple policies in the same file for PyPI, npm, or your internal APIs. Refer to {doc}`/sandboxes/policies` for examples.
:::

## Verify That GET Works

The policy is now active. Reconnect to the sandbox and retry the same request to confirm that read access works.

```console
$ openshell sandbox connect demo
```

Retry the same request:

```console
$ curl -s https://api.github.com/zen
```

```text
Anything added dilutes everything else.
```

It works. The `read-only` preset allows GET requests through.

## Try a Write

The read-only preset allows GET but blocks mutating methods like POST, PUT, and DELETE. Test this by sending a POST request to the GitHub API while still inside the sandbox:

```console
$ curl -s -X POST https://api.github.com/repos/octocat/hello-world/issues \
    -H "Content-Type: application/json" \
    -d '{"title":"oops"}'
```

```json
{"error":"policy_denied","policy":"github-api-readonly","detail":"POST /repos/octocat/hello-world/issues not permitted by policy"}
```

The CONNECT request succeeded because `api.github.com` is allowed, but the L7 proxy inspected the HTTP method and returned `403`. `POST` is not in the `read-only` preset. An agent with this policy can read code from GitHub but cannot create issues, push commits, or modify anything.

Exit the sandbox:

```console
$ exit
```

## Check the L7 Deny Log

L7 denials are logged separately from connection-level denials. The log entry includes the exact HTTP method and path that the proxy rejected.

```console
$ openshell logs demo --level warn --since 5m
```

```text
l7_decision=deny dst_host=api.github.com l7_action=POST l7_target=/repos/octocat/hello-world/issues l7_deny_reason="POST /repos/octocat/hello-world/issues not permitted by policy"
```

The log captures the exact HTTP method, path, and deny reason. In production, pipe these logs to your SIEM for a complete audit trail of every request your agent makes.

:::{tip}
To log violations without blocking requests, set `enforcement: audit` instead of `enforcement: enforce` in the policy. This is useful for building a policy iteratively: deploy in audit mode, review the logs, and switch to enforce when the rules are correct.
:::

## Clean Up

Delete the sandbox to free resources. This stops all processes and purges any injected credentials.

```console
$ openshell sandbox delete demo
```

:::{tip}
To run this entire walkthrough non-interactively, use the automated demo script:

```console
$ bash examples/sandbox-policy-quickstart/demo.sh
```
:::

## Next Steps

- To walk through a full policy iteration with Claude Code, including diagnosing denials and applying fixes from outside the sandbox, refer to {doc}`/tutorials/github-sandbox`.
