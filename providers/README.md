<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Example provider profiles

These files are reviewable examples. OpenShell does not compile them into any
binary and no gateway loads them on its own: a gateway's profile catalog
contains exactly what an operator imported.

Import one at platform scope:

```shell
openshell provider profile lint   -f providers/github.yaml
openshell provider profile import -f providers/github.yaml --global
```

To import several profiles, put compatible copies in a separate directory:

```shell
openshell provider profile import --from ./selected-profiles --global
```

Drop `--global` to import into the current workspace instead.

The `google-cloud.yaml` example requires the `gcp-metadata` platform adapter,
provided for Linux sandboxes by the supervisor. Windows/MXC does not provide
this adapter. The Vertex example uses bearer-token authentication and does not
require it.

## Read the header before importing

Every file opens with a comment block naming its expected client binaries, the
image layout those paths assume, the credential scope, the endpoint access it
grants, and a smoke test. Read it. A profile's `binaries` list is the control
that decides which processes may reach its endpoints, and several of these
examples name paths from a particular reference image layout
(`/sandbox/.venv`, `/app/.venv`, `/sandbox/.cursor-server`,
`/usr/lib/node_modules/...`). Imported unchanged into a different image, such a
profile matches nothing: the catalog still advertises it, but the credential is
never injected and the traffic is denied.

Copy the file, edit `binaries` and `endpoints` to match your image and your
workload, and import your copy.

## Adapting one

- Give your copy a distinct `id` if it diverges from the example, so the two
  cannot be confused in the catalog.
- Keep `binaries` as narrow as the workload allows. Widening it to match every
  image trades away the binary-scoped least privilege that makes credential
  injection safe.
- Keep `endpoints` limited to the hosts the credential should reach. A
  credential is only sent to the endpoints its profile declares.
- Review non-secret `environment` defaults, `discovery.config_env_vars`, and
  `required_platform_adapter`. Renaming the profile preserves these declarations.
- Run `openshell provider profile lint` before importing.

See [Provider profiles](https://docs.nvidia.com/openshell/latest/how-it-works/providers/profiles) for the
full schema.
