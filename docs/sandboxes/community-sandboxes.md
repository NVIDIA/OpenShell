---
title:
  page: Community Sandboxes
  nav: Community Sandboxes
description: Use pre-built sandboxes from the OpenShell Community catalog or contribute your own.
topics:
- Generative AI
- Cybersecurity
tags:
- Community
- Sandbox
- Container Image
- Open Source
content:
  type: concept
  difficulty: technical_beginner
  audience:
  - engineer
  - data_scientist
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Community Sandboxes

Use pre-built sandboxes from the OpenShell Community catalog, or contribute your
own.

## What Are Community Sandboxes

Community sandboxes are ready-to-use environments published in the
[OpenShell Community](https://github.com/NVIDIA/OpenShell-Community) repository.
Each sandbox bundles a Dockerfile, policy, optional skills, and startup scripts
into a single package that you can launch with one command.

## Current Catalog

The following community sandboxes are available in the catalog.

| Sandbox | Description |
|---|---|
| `base` | Foundational image with system tools and dev environment |
| `ollama` | Ollama with cloud and local model support, Claude Code, OpenCode, and Codex pre-installed. Use `ollama launch` inside the sandbox to start coding agents with zero config.
| `openclaw` | Open agent manipulation and control |
| `sdg` | Synthetic data generation workflows |

## Use a Community Sandbox

Launch a community sandbox by name with the `--from` flag:

```console
$ openshell sandbox create --from openclaw
```

When you pass `--from` with a community sandbox name, the CLI:

1. Resolves the name against the
   [OpenShell Community](https://github.com/NVIDIA/OpenShell-Community) repository.
2. Pulls the Dockerfile, policy, skills, and any boot-hook scripts.
3. Builds the container image locally.
4. Creates the sandbox with the bundled configuration applied.

You end up with a running sandbox whose image, policy, and tooling are all
preconfigured by the community package.

### Other Sources

The `--from` flag also accepts:

- Local directory paths: Point to a directory on disk that contains a
  Dockerfile and optional policy/skills:

  ```console
  $ openshell sandbox create --from ./my-sandbox-dir
  ```

- Container image references: Use an existing container image directly:

  ```console
  $ openshell sandbox create --from my-registry.example.com/my-image:latest
  ```

## Contribute a Community Sandbox

Each community sandbox is a directory under `sandboxes/` in the
[OpenShell Community](https://github.com/NVIDIA/OpenShell-Community) repository.
At minimum, a sandbox directory must contain the following files:

- `Dockerfile` that defines the container image.
- `README.md` that describes the sandbox and how to use it.

You can also include the following optional files:

- `policy.yaml` that defines the default policy applied when the sandbox launches.
- `skills/` that contains agent skill definitions bundled with the sandbox.
- `boot.sh` or another startup script that your Dockerfile installs at `/etc/openshell/boot.sh`. OpenShell runs that script as a supervisor-managed child process on every sandbox pod start, including restarts.

To contribute, fork the repository, add your sandbox directory, and open a pull
request. Refer to the repository's
[CONTRIBUTING.md](https://github.com/NVIDIA/OpenShell-Community/blob/main/CONTRIBUTING.md)
for submission guidelines.

:::{note}
The community catalog is designed to grow. If you have built a sandbox that
supports a particular workflow (data processing, simulation, code review,
or anything else), consider contributing it back so others can use it.
:::

## Next Steps

Explore related topics:

- **Need to supply API keys or tokens?** Set up {doc}`manage-providers` for credential management.
- **Want to customize the sandbox policy?** Write custom rules in {doc}`policies`.
