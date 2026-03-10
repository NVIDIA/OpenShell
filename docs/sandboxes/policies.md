<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Customize Sandbox Policies

Use this page to apply and iterate policy changes on running sandboxes. For a full field-by-field YAML definition, use the [Policy Schema Reference](../reference/policy-schema.md).

## Quick Start: Apply a Custom Policy

Pass a policy YAML file when creating the sandbox:

```console
$ openshell sandbox create --policy ./my-policy.yaml --keep -- claude
```

The `--keep` flag keeps the sandbox running after the initial command exits, which is useful when you plan to iterate on the policy.

To avoid passing `--policy` every time, set a default policy with an environment variable:

```console
$ export OPENSHELL_SANDBOX_POLICY=./my-policy.yaml
$ openshell sandbox create --keep -- claude
```

The CLI uses the policy from `OPENSHELL_SANDBOX_POLICY` whenever `--policy` is not explicitly provided.

## Iterate on a Running Sandbox

To change what the sandbox can access, pull the current policy, edit the YAML, and push the update. The workflow is iterative: create the sandbox, monitor logs for denied actions, pull the policy, modify it, push, and verify.

```{mermaid}
flowchart TD
    A["1. Create sandbox with initial policy"] --> B["2. Monitor logs for denied actions"]
    B --> C["3. Pull current policy"]
    C --> D["4. Modify the policy YAML"]
    D --> E["5. Push updated policy"]
    E --> F["6. Verify the new revision loaded"]
    F --> B

    style A fill:#76b900,stroke:#000000,color:#000000
    style B fill:#76b900,stroke:#000000,color:#000000
    style C fill:#76b900,stroke:#000000,color:#000000
    style D fill:#ffffff,stroke:#000000,color:#000000
    style E fill:#76b900,stroke:#000000,color:#000000
    style F fill:#76b900,stroke:#000000,color:#000000

    linkStyle default stroke:#76b900,stroke-width:2px
```

The following steps outline the hot-reload policy update workflow.

1. Create the sandbox with your initial policy by following [Quick Start: Apply a Custom Policy](#quick-start-apply-a-custom-policy) above (or set `OPENSHELL_SANDBOX_POLICY`).

2. Monitor denials — each log entry shows host, port, binary, and reason. Alternatively use `openshell term` for a live dashboard.

   ```console
   $ openshell logs <name> --tail --source sandbox
   ```

3. Pull the current policy. Strip the metadata header (Version, Hash, Status) before reusing the file.

   ```console
   $ openshell policy get <name> --full > current-policy.yaml
   ```

4. Edit the YAML: add or adjust `network_policies` entries, binaries, `access` or `rules`, or `inference.allowed_routes`.

5. Push the updated policy. Exit codes: 0 = loaded, 1 = validation failed, 124 = timeout.

   ```console
   $ openshell policy set <name> --policy current-policy.yaml --wait
   ```

6. Verify the new revision. If status is `loaded`, repeat from step 2 as needed; if `failed`, fix the policy and repeat from step 4.

   ```console
   $ openshell policy list <name>
   ```

## Debug Denied Requests

Check `openshell logs <name> --tail --source sandbox` for the denied host, path, and binary.

When triaging denied requests, check:

- Destination host and port to confirm which endpoint is missing.
- Calling binary path to confirm which `binaries` entry needs to be added or adjusted.
- HTTP method and path (for REST endpoints) to confirm which `rules` entry needs to be added or adjusted.

Then push the updated policy as described above.

## Policy Structure

A policy has static sections (`filesystem_policy`, `landlock`, `process`) that are locked at sandbox creation, and dynamic sections (`network_policies`, `inference`) that are hot-reloadable on a running sandbox.

```yaml
version: 1

# Static: locked at sandbox creation. Paths the agent can read vs read/write.
filesystem_policy:
  read_only: [/usr, /lib, /etc]
  read_write: [/sandbox, /tmp]

# Static: Landlock LSM kernel enforcement. best_effort uses highest ABI the host supports.
landlock:
  compatibility: best_effort

# Static: Unprivileged user/group the agent process runs as.
process:
  run_as_user: sandbox
  run_as_group: sandbox

# Dynamic: hot-reloadable. Named blocks of endpoints + binaries allowed to reach them.
network_policies:
  my_api:
    name: my-api
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/bin/curl

# Dynamic: hot-reloadable. Routing hints this sandbox can use for inference (e.g. local, nvidia).
inference:
  allowed_routes: [local]
```

For the complete structure and every field, see the [Policy Schema Reference](../reference/policy-schema.md).

## Network Access Rules

Network access is controlled by policy blocks under `network_policies`. Each block has a **name**, a list of **endpoints** (host, port, protocol, and optional rules), and a list of **binaries** that are allowed to use those endpoints.

Every outbound connection from the sandbox goes through the proxy:

- The proxy matches the **destination** (host and port) and the **calling binary** to an endpoint in one of your policy blocks. A connection is allowed only when both match.
- For endpoints with `protocol: rest` and `tls: terminate`, each HTTP request is checked against that endpoint's `rules` (method and path).
- If no endpoint matches and inference routes are configured, the request may be rerouted for inference.
- Otherwise the connection is denied. Endpoints without `protocol` or `tls` allow the TCP stream through without inspecting payloads.

## Examples

Add these blocks to the `network_policies` section of your sandbox policy. Apply with `openshell policy set <name> --policy <file> --wait`.
Use **Simple endpoint** for host-level allowlists and **Granular rules** for method/path control.

:::::{tab-set}

::::{tab-item} Simple endpoint
Allow `pip install` and `uv pip install` to reach PyPI:

```yaml
  pypi:
    name: pypi
    endpoints:
      - host: pypi.org
        port: 443
      - host: files.pythonhosted.org
        port: 443
    binaries:
      - { path: /usr/bin/pip }
      - { path: /usr/local/bin/uv }
```

Endpoints without `protocol` or `tls` use TCP passthrough — the proxy allows the stream without inspecting payloads.
::::

::::{tab-item} Granular rules
Allow Claude and the GitHub CLI to reach `api.github.com` with per-path rules: read-only (GET, HEAD, OPTIONS) and GraphQL (POST) for all paths; full write access for `alpha-repo`; and create/edit issues only for `bravo-repo`. Replace `<org_name>` with your GitHub org or username.

```yaml
  github_repos:
    name: github_repos
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/**"
          - allow:
              method: HEAD
              path: "/**"
          - allow:
              method: OPTIONS
              path: "/**"
          - allow:
             method: POST
             path: "/graphql"
          - allow:
              method: "*"
              path: "/repos/<org_name>/alpha-repo/**"
          - allow:
              method: POST
              path: "/repos/<org_name>/bravo-repo/issues"
          - allow:
              method: PATCH
              path: "/repos/<org_name>/bravo-repo/issues/*"
    binaries:
      - { path: /usr/local/bin/claude }
      - { path: /usr/bin/gh }
```

Endpoints with `protocol: rest` and `tls: terminate` enable HTTP request inspection — the proxy decrypts TLS and checks each HTTP request against the `rules` list.
::::

:::::

## Next Steps

- {doc}`index`: The built-in policy that ships with OpenShell and what each block allows.
- [Policy Schema Reference](../reference/policy-schema.md): Complete field reference for the policy YAML.
