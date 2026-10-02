<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Outbound TCP on the legacy kernel

[outbound-tcp.py](outbound-tcp.py) opens three outbound connections to a separate
TCP echo Pod. On each connection it calls `getpeername()`, records any error,
then sends and receives both 4 bytes and 256 KiB. It compares every echoed byte
with the original payload. Pass `--expect-relay` to require a successful peer
query that returns a loopback address with a nonzero port. Without that flag,
the script records peer-address errors so it can also reproduce the baseline.

## Test procedure

Use an OpenShell Kubernetes gateway whose sandbox namespace is
`openshell-outbound-test`, with the PR-head sandbox runtime deployed. The
[peer-address procedure](accept-peer.md) describes building and deploying that
runtime. Build from the checkout containing the fallback, and use image tag
`pr4087-outbound-fallback` in the build, push, and Helm commands instead of
the baseline tag `pr4087-de27081b3`. For this test, use namespace
`openshell-outbound-test` and local
gateway forwarding port `18089`. Standard chart deployments require working
gateway and workspace PVC provisioning. The recorded run used ephemeral
gateway database and workspace volumes in its temporary test deployment;
the workload's seccomp, capabilities, and network restrictions stayed enabled.

Start the echo fixture and scope the network policy to its exact Service IP:

```shell
oc apply -f e2e/reproducers/outbound-tcp-echo.yaml
oc -n openshell-outbound-test wait --for=condition=Ready pod/echo --timeout=90s
ECHO_IP="$(oc -n openshell-outbound-test get service echo -o jsonpath='{.spec.clusterIP}')"
sed "s/ECHO_IP/${ECHO_IP}/g" e2e/reproducers/outbound-tcp-policy.template.yaml \
  > /tmp/pr4087-outbound-policy.yaml
oc -n openshell-outbound-test port-forward svc/openshell 18089:8080
```

Keep the port-forward running and execute the following in another terminal:

```shell
CLI=target/debug/openshell
ENDPOINT=http://127.0.0.1:18089
HOST=echo.openshell-outbound-test.svc.cluster.local
PYTHON_IMAGE=ghcr.io/astral-sh/uv:0.12.17-python3.12-trixie-slim@sha256:9a59bb7206905ccaae4f7dab222fbac47c125a21e5fc16f43f427cd6c940ade3

"$CLI" sandbox create --gateway-endpoint "$ENDPOINT" \
  --name outbound3-pr4087 --policy /tmp/pr4087-outbound-policy.yaml \
  --from "$PYTHON_IMAGE" --no-tty \
  -- python3 -c "$(cat e2e/reproducers/outbound-tcp.py)" "$HOST" 5432 --expect-relay
```

Expect `connect`, `getpeername`, and both `echo` stages to report PASS for
attempts 0, 1, and 2, with exit status 0. In legacy mode the peer address is the
loopback relay, not the echo Service's IP. For a before/after comparison, run
the probe without `--expect-relay` against the earlier runtime image first;
the recorded baseline below shows errno 95. Then deploy the fallback runtime
and run the strict check above.

Check the exec launch path, then repeat without the accept shim:

```shell
"$CLI" sandbox create --gateway-endpoint "$ENDPOINT" \
  --name outbound-exec --policy /tmp/pr4087-outbound-policy.yaml \
  --from "$PYTHON_IMAGE" --detach \
  -- python3 -c 'import time; time.sleep(600)'

"$CLI" sandbox exec --gateway-endpoint "$ENDPOINT" \
  --no-tty --no-login-shell --timeout 60 outbound-exec \
  -- python3 -c "$(cat e2e/reproducers/outbound-tcp.py)" "$HOST" 5432 --expect-relay

"$CLI" sandbox exec --gateway-endpoint "$ENDPOINT" \
  --no-tty --no-login-shell --timeout 60 outbound-exec \
  -- env -u LD_PRELOAD python3 -c "$(cat e2e/reproducers/outbound-tcp.py)" "$HOST" 5432 --expect-relay
```

Both exec commands should produce the same data-transfer results. Check the
server logs and supervisor IPs to verify the relay path:

```shell
oc -n openshell-outbound-test logs echo | rg 'echoed_bytes=262148'
oc -n openshell-outbound-test get pods -l openshell.ai/boundary-role=supervisor \
  -o custom-columns=NAME:.metadata.name,IP:.status.podIP
```

The server should record three nonempty connections per invocation, each
echoing 262148 bytes. Their peer IP should be the supervisor's. Zero-byte
connections from the node are the echo Pod's readiness probes.

## Recorded baseline before the fallback

The earlier behavior was validated on 2026-10-02, OpenShift **4.21.34**, kernel
**5.14.0-570.141.1.el9_6.x86_64**, using PR-head sandbox commit `de27081b3`.
The deployed binary matched SHA-256
`dc004b17fd02c4bc0cb8208850b1dc29dcfa7a76ab80536f5ce8dc0eaf91333c`.
Gateway and supervisor image digests were the reused images recorded in
[the peer-address report](accept-peer.md#observed-results).

| Invocation | Connections | Echoes | `getpeername()` | Exit |
| --- | --- | --- | --- | --- |
| Initial workload | 3 successful | 4 bytes and 256 KiB matched on each | errno 95 on all 3 | 0 |
| `sandbox exec` | 3 successful | 4 bytes and 256 KiB matched on each | errno 95 on all 3 | 0 |
| Exec without `LD_PRELOAD` | 3 successful | 4 bytes and 256 KiB matched on each | errno 95 on all 3 | 0 |

The first invocation's echo server saw supervisor `10.232.1.68` as its peer.
Supervisor logs recorded `ALLOWED` decisions for Python connecting to the echo
host on port 5432. The workload was admitted under `restricted-v2`, ran as UID/GID
1000780000, dropped all capabilities, and disabled privilege escalation.

The baseline established that outbound TCP data transfer works even when the
peer query fails. The fallback changes that query to `CONTINUE`: the kernel
now reports the loopback relay's address. Clients that require the original
upstream address may still be incompatible. This probe does not validate TLS,
Internet routing, or application-client compatibility.

## Fallback regression validation

Native ARM64 Linux tests run as a non-root user verified the fallback with a
real seccomp listener and TCP connection: legacy mode returned a loopback peer
with a nonzero port, and modern mode returned the original upstream destination.
Additional tests covered local sockets, unconnected sockets, and the modern
substitution path. All 196 sandbox library tests passed.

The fallback was also validated on 2026-10-02 on the same OpenShift 4.21.34
cluster and kernel 5.14.0-570.141.1.el9_6.x86_64, with `--expect-relay`:

| Invocation | Connections | Echoes | `getpeername()` | Exit |
| --- | --- | --- | --- | --- |
| Initial workload | 3 successful | 4 bytes and 256 KiB matched on each | loopback address and nonzero port on all 3 | 0 |
| `sandbox exec` | 3 successful | 4 bytes and 256 KiB matched on each | loopback address and nonzero port on all 3 | 0 |
| Exec without `LD_PRELOAD` | 3 successful | 4 bytes and 256 KiB matched on each | loopback address and nonzero port on all 3 | 0 |

The runtime image was
`image-registry.openshift-image-registry.svc:5000/openshell-images/sandbox:pr4087-outbound-fallback`,
digest `sha256:4afb424c54d158ad06ab39c9b47dfea7c1815d58acf5dd404d1377aba36c6b59`.
The deployed binary matched SHA-256
`544abc2524174e8fa0cb4a452b5c6d76c2bcbce77c923cace4860a74579c0bc8`.
The echo server recorded nine connections carrying 262148 bytes each, from
supervisor IPs `10.232.1.80` (initial workload) and `10.232.1.78` (exec).
Supervisor logs recorded policy `ALLOWED` decisions for the echo destination.
The workload used `restricted-v2`, UID/GID 1000790000, all capabilities dropped,
and privilege escalation disabled. Gateway and supervisor images were unchanged.

## Cleanup

Delete the named test sandboxes before removing a temporary gateway. Stop the
port-forward with Ctrl-C. Remove the namespace and pull grant only if they
were created for this test:

```shell
"$CLI" sandbox delete --gateway-endpoint "$ENDPOINT" outbound3-pr4087 outbound-exec
oc delete -f e2e/reproducers/outbound-tcp-echo.yaml
helm uninstall openshell -n openshell-outbound-test
oc delete namespace openshell-outbound-test --wait=true --timeout=120s
oc -n openshell-images policy remove-role-from-group system:image-puller \
  system:serviceaccounts:openshell-outbound-test
```
