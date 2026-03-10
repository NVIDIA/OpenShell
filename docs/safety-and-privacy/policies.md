<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Policy Configuration

A policy is a single YAML document that controls what a sandbox can do: filesystem access, process identity, network access, and inference routing. You attach it when creating a sandbox; the network and inference sections can be updated on a running sandbox without restarting.

## Policy Structure

A policy has five top-level sections: `version`, `filesystem_policy`, `landlock`, `process`, `network_policies`, and `inference`. Static sections (`filesystem_policy`, `landlock`, `process`) are locked at sandbox creation and require recreation to change. Dynamic sections (`network_policies`, `inference`) are hot-reloadable on a running sandbox. The `landlock` section configures [Landlock LSM](https://docs.kernel.org/security/landlock.html) enforcement at the kernel level.

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

For the complete field reference, see the [Policy Schema Reference](../reference/policy-schema.md).

## Network Policy Evaluation

Every outbound connection from the sandbox goes through the proxy. The proxy matches the destination such as host and port and the calling binary to an endpoint in one of the `network_policies` blocks.

- If an endpoint matches the destination and the binary is listed in that block's `binaries`, the connection is allowed.
- For endpoints with `protocol: rest` and `tls: terminate`, each HTTP request is also checked against that endpoint's `rules` (method and path).
- If no endpoint matches and inference routes are configured, the request may be rerouted for inference.
- Otherwise the connection is denied.

Endpoints without `protocol` or `tls` (L4-only) allow the TCP stream through without inspecting payloads. For the full endpoint schema, access presets, and binary matching, see the [Policy Schema Reference](../reference/policy-schema.md).

## Example Policy for GitHub Repository Access

The following policy block allows Claude and the GitHub CLI to reach `api.github.com` with granular per-endpoint rules: read-only (GET, HEAD, OPTIONS) and GraphQL (POST) for all paths; full write access for `alpha-repo`; and create/edit issues only for `bravo-repo`. Replace `<org_name>` with your GitHub org or username.

Add this block to the `network_policies` section of your sandbox policy.

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
          # Read-only access to all GitHub API paths
          - allow:
              method: GET
              path: "/**"
          - allow:
              method: HEAD
              path: "/**"
          - allow:
              method: OPTIONS
              path: "/**"
          # GraphQL API (used by gh CLI for most operations)
          - allow:
             method: POST
             path: "/graphql"
          # alpha-repo: full write access
          - allow:
              method: "*"
              path: "/repos/<org_name>/alpha-repo/**"
          # bravo-repo: create + edit issues
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

Apply with `openshell policy set <name> --policy <file> --wait`.

## Debug Denied Requests

Check `openshell logs <name> --tail --source sandbox` for the denied host, path, and binary. Add or adjust the matching endpoint or rules in the relevant policy block (for example, add a new `allow` rule for the method and path, or add the binary to that block's `binaries` list). See [Hot-Reload Policy Updates](#hot-reload-policy-updates) for the full iteration workflow.

## Apply a Custom Policy

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

## Hot-Reload Policy Updates

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

1. Create the sandbox with your initial policy (or set `OPENSHELL_SANDBOX_POLICY`).

   ```console
   $ openshell sandbox create --policy ./my-policy.yaml --keep -- claude
   ```

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

## Next Steps

- {doc}`default-policies`: The built-in policy that ships with OpenShell and what each block allows.
- [Policy Schema Reference](../reference/policy-schema.md): Complete field reference for the policy YAML.
- [Safety and Privacy](index.md): Threat scenarios and protection layers.
