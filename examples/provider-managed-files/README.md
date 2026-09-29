<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Provider-managed sandbox files

This example serves a non-secret TOML configuration file from a provider.
The profile chooses the file name and template. The provider supplies values;
attaching it to a sandbox makes it available for read-only opens before the
workload starts. The sandbox serves the content from memory.

From this directory, with a running gateway:

```shell
openshell profile lint -f acme-config.yaml
openshell profile import -f acme-config.yaml

openshell provider create \
  --name acme-prod \
  --type acme-config \
  --config endpoint=https://api.acme.example \
  --config project=production

openshell sandbox create \
  --name acme-demo \
  --from ubuntu:24.04 \
  --provider acme-prod \
  --no-tty \
  --detach \
  -- sleep infinity

openshell sandbox exec -n acme-demo -- cat /run/openshell/providers/acme-prod/client.toml
openshell sandbox exec -n acme-demo -- printenv ACME_CONFIG_FILE
```

Update the provider to serve new content on the next open:

```shell
openshell provider update acme-prod --config project=staging --wait
openshell sandbox exec -n acme-demo -- cat /run/openshell/providers/acme-prod/client.toml
```

`--wait` returns after the sandbox boundary acknowledges the new provider
environment and file set. Applications must reopen the absolute path to
observe new content; inotify and directory listing do not see these virtual
files. Detaching the provider makes later opens return `ENOENT`:

```shell
openshell sandbox provider detach acme-demo acme-prod --wait
```

The file template can reference only `config.KEY` values. Provider credentials
are not rendered into workload files; they retain OpenShell's endpoint-bound
delivery path.
