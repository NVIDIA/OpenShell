<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Run OpenCode with NVIDIA Inference

Run [OpenCode](https://opencode.ai) in a OpenShell sandbox with inference routed to NVIDIA API endpoints. You will hit a policy denial, diagnose it from logs, apply a custom policy, and configure inference routing — the same iteration loop used for any new tool.

## Prerequisites

- **Docker** running. See {doc}`quickstart` for details.
- **OpenShell CLI** installed.
- **`NVIDIA_API_KEY`** set on the host with a valid NVIDIA API key.

## Create the Provider

Create a provider explicitly (unlike the Claude tutorial where the CLI auto-discovers):

```console
$ openshell provider create --name nvidia --type nvidia --from-existing
```

`--from-existing` reads `NVIDIA_API_KEY` from the environment. Verify:

```console
$ openshell provider list
```

## Create the Sandbox

```console
$ openshell sandbox create --name opencode-sandbox --provider nvidia --keep -- opencode
```

`--keep` keeps the sandbox running for the following steps. The default policy is built for Claude, not OpenCode, so OpenCode’s endpoints will be denied until you add a custom policy.

## Hit a Policy Denial

Use OpenCode in the sandbox; calls to NVIDIA inference will fail. In a second terminal, tail logs:

```console
$ openshell logs opencode-sandbox --tail
```

Or use `openshell term` for a live view. Look for lines such as:

```
action=deny  host=integrate.api.nvidia.com  binary=/usr/local/bin/opencode  reason="no matching network policy"
action=deny  host=opencode.ai               binary=/usr/bin/node            reason="no matching network policy"
```

Each line gives host, binary, and reason. Use this to decide what to allow in the policy.

## Understand the Denial

The default policy has a `nvidia_inference` entry for a narrow set of binaries (e.g. `/usr/local/bin/claude`, `/usr/bin/node`). OpenCode uses different binaries, and the default has no entry for `opencode.ai`. OpenShell denies by default; you must add a policy that allows the endpoints and binaries OpenCode needs.

## Write a Custom Policy

Create `opencode-policy.yaml` with the content below. It adds `opencode_api`, broadens `nvidia_inference` binaries, sets `inference.allowed_routes` to `nvidia`, and includes GitHub access for OpenCode.

```yaml
version: 1
inference:
  allowed_routes:
    - nvidia
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
network_policies:
  opencode_api:
    name: opencode-api
    endpoints:
      - host: opencode.ai
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/local/bin/opencode
      - path: /usr/bin/node
  nvidia_inference:
    name: nvidia-inference
    endpoints:
      - host: integrate.api.nvidia.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/local/bin/opencode
      - path: /usr/bin/node
      - path: /usr/bin/curl
      - path: /bin/bash
  npm_registry:
    name: npm-registry
    endpoints:
      - host: registry.npmjs.org
        port: 443
    binaries:
      - path: /usr/bin/npm
      - path: /usr/bin/node
      - path: /usr/local/bin/npm
      - path: /usr/local/bin/node
  github_rest_api:
    name: github-rest-api
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/local/bin/opencode
      - path: /usr/bin/node
      - path: /usr/bin/gh
  github_ssh_over_https:
    name: github-ssh-over-https
    endpoints:
      - host: github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/**/info/refs*"
          - allow:
              method: POST
              path: "/**/git-upload-pack"
    binaries:
      - path: /usr/bin/git
```

This policy differs from the default in four key ways:

- `opencode_api`: Allows OpenCode and Node.js to reach `opencode.ai:443`.
- Broader `nvidia_inference` binaries: Adds `/usr/local/bin/opencode`, `/usr/bin/curl`, and `/bin/bash` so OpenCode's subprocesses can reach the NVIDIA endpoint.
- `inference.allowed_routes`: Includes `nvidia` so inference routing works for userland code.
- GitHub access: Scoped to support OpenCode's git operations.

:::{warning}
The `filesystem_policy`, `landlock`, and `process` sections are static. They are set at sandbox creation time and cannot be changed on a running sandbox. To modify these, delete and recreate the sandbox. The `network_policies` and `inference` sections are dynamic and can be hot-reloaded.
:::

## Apply the Policy

Push your custom policy to the running sandbox:

```console
$ openshell policy set opencode-sandbox --policy opencode-policy.yaml --wait
```

The `--wait` flag blocks until the sandbox confirms the policy is loaded.

Verify the policy revision was accepted:

```console
$ openshell policy list opencode-sandbox
```

The latest revision should show status `loaded`.

## Set Up Inference Routing

So far, you have allowed the OpenCode *agent* to reach `integrate.api.nvidia.com` directly through network policy. But code that OpenCode writes and runs inside the sandbox — scripts, notebooks, applications — uses a separate mechanism called the privacy router.

Create an inference route so userland code can access NVIDIA models:

```console
$ openshell inference create \
  --routing-hint nvidia \
  --base-url https://integrate.api.nvidia.com \
  --model-id z-ai/glm5 \
  --api-key $NVIDIA_API_KEY
```

The policy you wrote earlier already includes `nvidia` in `inference.allowed_routes`, so no policy update is needed. If you had omitted it, you would add the route to the policy and push again.

:::{note}
*Network policies* and *inference routes* are two separate enforcement points. Network policies control which hosts the agent binary can reach directly. Inference routes control where LLM API calls from userland code get routed through the privacy proxy.
:::

## Verify the Policy

Tail the logs again:

```console
$ openshell logs opencode-sandbox --tail
```

You should no longer see `action=deny` lines for the endpoints you added. Connections to `opencode.ai`, `integrate.api.nvidia.com`, and GitHub should show `action=allow`.

If you still see denials, read the log line carefully. It tells you the exact host, port, and binary that was blocked. Add the missing entry to your policy and push again with `openshell policy set`. This observe-modify-push cycle is the normal workflow for onboarding any new tool in OpenShell.

## Clean Up

When you are finished, delete the sandbox:

```console
$ openshell sandbox delete opencode-sandbox
```

## Next Steps

- {doc}`../safety-and-privacy/policies`: Full reference on policy YAML structure, static and dynamic fields, and enforcement modes.
- [Write Sandbox Policies (network access rules)](../safety-and-privacy/policies.md#network-access-rules): How the proxy evaluates network rules, L4 and L7 inspection, and TLS termination.
- {doc}`../inference/index`: Inference route configuration, protocol detection, and transparent rerouting.
- {doc}`../sandboxes/providers`: Provider types, credential discovery, and manual and automatic creation.
- {doc}`../safety-and-privacy/security-model`: The four protection layers and how they interact.
