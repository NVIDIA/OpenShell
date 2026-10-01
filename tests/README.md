<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# tmachine tests

`tmachine` boots a disposable QEMU guest, prepares a runtime environment,
installs candidate artifacts, and runs a test archive. Its configuration lives
in `tests/config.nix`. The guest uses four CPUs and 4 GiB of RAM; tests run on
the host's native architecture with HVF on Apple Silicon or KVM on Linux.

## K3s conformance

Stage the native musl CLI, candidate gateway/sandbox/supervisor OCI archives,
Helm chart and conformance nextest bundle under `artifacts/`. The existing
`build-artifacts` flake app builds these locally; CI's
`prepare-integration-inputs.yml` stages them from the same source revision.

The `ubuntu-k3s` environment installs K3s, Helm and nextest. Choose the basic
single-replica SQLite/plaintext installer or the PostgreSQL/mTLS installer:

```shell
nix run .#tmachine -- test ubuntu-k3s k3s conformance
nix run .#tmachine -- test ubuntu-k3s k3s-ha-tls conformance
```

`k3s-ha-tls` installs three gateway replicas as a Deployment, the pinned
PostgreSQL fixture from `e2e/kubernetes/postgres-fixture.yaml`, and the chart's
built-in PKI. The gateway and peer connections use TLS; the CLI uses the chart
client certificate and `https://localhost:17670`. Unauthenticated users are
disabled. PostgreSQL uses disposable storage and test-only credentials, with
an unencrypted database connection inside the isolated guest. The fixture
image and Agent Sandbox controller are pulled by the guest during setup.

Installer `prepare_playbooks` run before every test suite, including boots
from a cached installation. K3s preparation waits for the node, PostgreSQL
when present, controller, gateway workload and a successful sandbox-list RPC.
Client certificate files are installed with mode `0600`. A restarting systemd
port-forward exposes the gateway only on guest loopback. Readiness and
conformance failures print cluster inventory, events and bounded workload and
service logs without reading Secret contents.

For an interactive guest using the same installer:

```shell
nix run .#tmachine -- test ubuntu-k3s k3s-ha-tls shell
```

Inside the guest, use `sudo k3s kubectl` for cluster inspection. Conformance
runs as the `tmachine` user using its registered gateway and certificate
bundle. Each test boot gets a disposable overlay of the installed disk.

The branch conformance matrix and manual Integration Test workflow include
the PostgreSQL/mTLS tuple. This setup runs the existing portable conformance
scenarios. HA fault injection and migration of #3825's scale/owner-loss/rollout
scenarios are follow-up work. Three replicas on one K3s node do not establish
node-level HA, database HA, ingress behavior or uninterrupted stream recovery.
