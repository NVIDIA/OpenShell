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

:::{tip}
For an end-to-end walkthrough that combines this policy with a GitHub credential provider and sandbox creation, see {doc}`/tutorials/github-sandbox`.
:::

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

- **New to policies?** Read about {doc}`policy structure and network access rules <index>` first.
- **Need the full field reference?** See the [Policy Schema Reference](../reference/policy-schema.md).
- **Looking for the default policy breakdown?** See {doc}`../reference/default-policy`.
