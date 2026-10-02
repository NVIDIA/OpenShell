<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# OpenShift peer-address reproducer

This procedure validates [PR #4087](https://github.com/NVIDIA/OpenShell/pull/4087).
The standard-library-only [Python reproducer](accept-peer.py) connects a client
to a loopback listener inside an OpenShell sandbox. It checks that both
`accept()` and `getpeername()` return the client's address, rather than the
listener's, and that the accepted socket delivers `ping`.

## Prerequisites and deployment

Use an OpenShift cluster whose kernel lacks `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`
(the tested RHCOS kernel is listed below). Have `oc`, `helm`, `mise`, the local
CLI, and the upstream Agent Sandbox controller installed. Authenticate to the
cluster and its development image registry. Run commands from the repository root.

Record the cluster and source version:

```shell
git rev-parse HEAD
oc get clusterversion version -o jsonpath='{.status.desired.version}{"\n"}'
oc get nodes -o custom-columns=NAME:.metadata.name,KERNEL:.status.nodeInfo.kernelVersion
```

Build and stage the sandbox runtime from the checkout, then package it with
the repository's image build task. For a Mac host and x86-64 cluster, use:

```shell
ulimit -n 8192
mise exec -- env RUSTC_WRAPPER= cargo zigbuild --release --locked \
  --target x86_64-unknown-linux-musl -p openshell-sandbox
install -m 0755 target/x86_64-unknown-linux-musl/release/openshell-sandbox \
  deploy/docker/.build/prebuilt-binaries/amd64/openshell-sandbox
PREBUILT_AUTO_STAGE=0 DOCKER_PLATFORM=linux/amd64 IMAGE_TAG=pr4087-de27081b3 \
  mise run docker:build:sandbox
```

Push this uniquely tagged image to a registry the cluster can pull. This run
used Podman and the OpenShift development registry, with `--tls-verify=false`
for that registry's certificate:

```shell
REGISTRY_HOST="$(oc -n openshift-image-registry get route default-route -o jsonpath='{.spec.host}')"
podman push --tls-verify=false localhost/openshell/sandbox:pr4087-de27081b3 \
  "docker://${REGISTRY_HOST}/openshell-images/sandbox:pr4087-de27081b3"
```

Create a separate test deployment using the existing development gateway's
values and gateway/supervisor images. Inspect those values before reuse; this
run used plaintext transport through a local port-forward, no public Route,
and `allowUnauthenticatedUsers: true`. Keep this configuration scoped to the
test deployment. Only the sandbox runtime was rebuilt for this run.

```shell
helm get values openshell -n openshell -o yaml > /tmp/pr4087-existing-values.yaml
oc create namespace openshell-pr4087-test
oc -n openshell-images policy add-role-to-group system:image-puller \
  system:serviceaccounts:openshell-pr4087-test
helm install openshell deploy/helm/openshell -n openshell-pr4087-test \
  -f /tmp/pr4087-existing-values.yaml \
  --set sandboxRuntime.image.tag=pr4087-de27081b3 \
  --set server.otlp.endpoint= --wait --timeout 5m
oc -n openshell-pr4087-test port-forward svc/openshell 18088:8080
```

Keep the port-forward running; execute subsequent commands in another terminal.
The reused values point all runtime images at
`image-registry.openshift-image-registry.svc:5000/openshell-images` and apply
`deploy/helm/openshell/ci/values-openshift-scc.yaml`'s security settings.
No privileged SCC grant was added.

## Run the reproducer

Use a Python image and pass the small script directly; no upload, package
installation, external connection, or forwarded application port is needed.
`target/debug/openshell` is the prebuilt local CLI used in this run.

```shell
CLI=target/debug/openshell
ENDPOINT=http://127.0.0.1:18088
PYTHON_IMAGE=ghcr.io/astral-sh/uv:0.12.17-python3.12-trixie-slim@sha256:9a59bb7206905ccaae4f7dab222fbac47c125a21e5fc16f43f427cd6c940ade3

"$CLI" sandbox create --gateway-endpoint "$ENDPOINT" \
  --name accept-peer-pr4087 --from "$PYTHON_IMAGE" --no-tty \
  -- python3 -c "$(cat e2e/reproducers/accept-peer.py)"
```

Expect exit status 0 and JSON containing `"result": "PASS"`, identical
`client`, `accept_peer`, and `peer` addresses, and
`"preload": "/run/openshell-compat/accept_shim.so"`. Ports vary per run.

The initial command exits and the sandbox becomes Completed. To check the
separate exec launch path, create a sandbox that runs the same check and then
stays alive for ten minutes:

```shell
"$CLI" sandbox create --gateway-endpoint "$ENDPOINT" \
  --name peer-exec-pr4087 --from "$PYTHON_IMAGE" --detach \
  -- python3 -u -c "$(cat e2e/reproducers/accept-peer.py)
import time
time.sleep(600)"

"$CLI" sandbox exec --gateway-endpoint "$ENDPOINT" \
  --no-tty --no-login-shell --timeout 30 peer-exec-pr4087 \
  -- python3 -c "$(cat e2e/reproducers/accept-peer.py)"
```

Expect the same PASS output and exit status 0. For a negative control, start
Python through `env` so its dynamic loader does not receive the preload:

```shell
"$CLI" sandbox exec --gateway-endpoint "$ENDPOINT" \
  --no-tty --no-login-shell --timeout 30 peer-exec-pr4087 \
  -- env -u LD_PRELOAD python3 -c "$(cat e2e/reproducers/accept-peer.py)"
```

On the affected kernel, expect exit status 1 and
`OSError: [Errno 95] Operation not supported` at `server.accept()`. This control
demonstrates that the shim covers the failing call; it is not a comparison
against an independently built base-branch image. On kernels supporting
`WAIT_KILLABLE_RECV`, this control can succeed.

Check the actual workload binary and admission profile:

```shell
oc -n openshell-pr4087-test exec default--accept-peer-pr4087 -c agent \
  -- sha256sum /.openshell/runtime/openshell-sandbox
oc -n openshell-pr4087-test get pod default--accept-peer-pr4087 \
  -o jsonpath='{.metadata.annotations.openshift\.io/scc}{"\n"}{.spec.containers[0].securityContext}{"\n"}{.spec.securityContext}{"\n"}'
```

## Observed results

Run on 2026-10-02 against source commit
`de27081b3` (PR head). OpenShift **4.21.34**, node
`control-plane-cluster-48kkt-1`, kernel **5.14.0-570.141.1.el9_6.x86_64**.

| Check | Result |
| --- | --- |
| Initial command | PASS; client, accept peer, and getpeername ports all 50372 |
| Persistent sandbox's initial command | PASS; all three ports 39438 |
| `sandbox exec` | PASS; all three ports 53330 |
| Exec with preload unset | Expected failure, errno 95 at `accept()`, exit 1 |
| Workload admission | `restricted-v2`; UID/GID 1000780000; all capabilities dropped; privilege escalation disabled; `RuntimeDefault` seccomp; SELinux level `s0:c28,c12` |
| Binary provenance | Deployed binary SHA-256 matched the freshly built local binary |

Recorded runtime binary SHA-256:
`dc004b17fd02c4bc0cb8208850b1dc29dcfa7a76ab80536f5ce8dc0eaf91333c`.

Recorded image digests in `openshell-images`:

- Sandbox: `sha256:8d43dd76b5936386eaee5978d346d79bcc4a89aaee59b1c28ff7330df15d36a7`.
- Gateway (reused): `sha256:83c7fde9ae6a197ab6c7c668086946beafc0eac99f2ea169ff1003fbaca9896d`.
- Supervisor (reused): `sha256:a4404edd399429fe4cc543a923b011d78d82e6e4531172cb8ad7bf9fcc57b6b2`.

This test covers dynamically linked CPython on x86-64 and both workload launch
paths. It does not establish support for Go, static binaries, other
architectures, or every runtime. The sandbox logged an unrelated warning that
the runtime cgroup's `pids.max` is unlimited.

## Cleanup

Remove the test release, namespace, and the scoped registry pull grant. Stop
the port-forward with Ctrl-C. The uniquely tagged registry image remains
available for reruns.

```shell
helm uninstall openshell -n openshell-pr4087-test
oc delete namespace openshell-pr4087-test --wait=true --timeout=120s
oc -n openshell-images policy remove-role-from-group system:image-puller \
  system:serviceaccounts:openshell-pr4087-test
```
