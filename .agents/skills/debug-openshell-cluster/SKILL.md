---
name: debug-openshell-cluster
description: Debug why a openshell cluster failed to start or is unhealthy. Use when the user has a failed `openshell gateway start`, cluster health check failure, or wants to diagnose cluster infrastructure issues. Trigger keywords - debug cluster, cluster failing, cluster not starting, deploy failed, cluster troubleshoot, cluster health, cluster diagnose, why won't my cluster start, health check failed, gateway start failed, gateway not starting.
---

# Debug OpenShell Cluster

Diagnose why a openshell cluster failed to start after `openshell gateway start`.

Use **only** `openshell` CLI commands (`openshell status`, `openshell doctor logs`, `openshell doctor exec`) to inspect and fix the cluster. Do **not** use raw `docker`, `podman`, `ssh`, or `kubectl` commands directly — always go through the `openshell doctor` interface. The CLI auto-resolves local vs remote gateways, so the same commands work everywhere.

## Overview

`openshell gateway start` creates a container (via Docker or Podman) running k3s with the OpenShell server deployed via Helm. The build and deploy scripts use a container-engine abstraction layer (`tasks/scripts/container-engine.sh`) that auto-detects Docker or Podman and provides a unified `ce` command interface. Set `CONTAINER_ENGINE=docker` or `CONTAINER_ENGINE=podman` to override auto-detection. The deployment stages, in order, are:

1. **Pre-deploy check**: `openshell gateway start` in interactive mode prompts to **reuse** (keep volume, clean stale nodes) or **recreate** (destroy everything, fresh start). `mise run cluster` always recreates before deploy.
2. Ensure cluster image is available (local build or remote pull)
3. Create container network (`openshell-cluster`) and volume (`openshell-cluster-{name}`)
4. Create and start a privileged container (`openshell-cluster-{name}`)
5. Wait for k3s to generate kubeconfig (up to 60s)
6. **Clean stale nodes**: Remove any `NotReady` k3s nodes left over from previous container instances that reused the same persistent volume
7. **Prepare local images** (if `OPENSHELL_PUSH_IMAGES` is set): In `internal` registry mode, bootstrap waits for the in-cluster registry and pushes tagged images there. In `external` mode, bootstrap uses legacy `ctr -n k8s.io images import` push-mode behavior.
8. **Reconcile TLS PKI**: Load existing TLS secrets from the cluster; if missing, incomplete, or malformed, generate fresh PKI (CA + server + client certs). Apply secrets to cluster. If rotation happened and the OpenShell workload is already running, rollout restart and wait for completion (failed rollout aborts deploy).
9. **Store CLI mTLS credentials**: Persist client cert/key/CA locally for CLI authentication.
10. Wait for cluster health checks to pass (up to 6 min):
    - k3s API server readiness (`/readyz`)
    - `openshell` statefulset ready in `openshell` namespace
    - TLS secrets `openshell-server-tls` and `openshell-client-tls` exist in `openshell` namespace
    - Sandbox supervisor binary exists at `/opt/openshell/bin/openshell-sandbox` (emits `HEALTHCHECK_MISSING_SUPERVISOR` marker if absent)

For local deploys, metadata endpoint selection depends on the container engine and its connectivity:

- default local Docker socket (`unix:///var/run/docker.sock`): `https://127.0.0.1:{port}` (default port 8080)
- TCP Docker daemon (`DOCKER_HOST=tcp://<host>:<port>`): `https://<host>:{port}` for non-loopback hosts
- Podman (rootless): `https://127.0.0.1:{port}` via `host.containers.internal` (the Podman equivalent of `host.docker.internal`)

The host port is configurable via `--port` on `openshell gateway start` (default 8080) and is stored in `ClusterMetadata.gateway_port`.

The TCP host is also added as an extra gateway TLS SAN so mTLS hostname validation succeeds.

The default cluster name is `openshell`. The container is `openshell-cluster-{name}`.

## Prerequisites

- Docker or Podman must be running (locally or on the remote host). The build system auto-detects which engine is available; set `CONTAINER_ENGINE=docker` or `CONTAINER_ENGINE=podman` to override.
- For rootless Podman: ensure the Podman socket is active (`systemctl --user start podman.socket`) and subuid/subgid ranges are configured (`sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $(whoami)`)
- The `openshell` CLI must be available
- For remote clusters: SSH access to the remote host

## Tools Available

All diagnostics go through three `openshell` commands. They auto-resolve local vs remote gateways — the same commands work for both:

```bash
# Quick connectivity check
openshell status

# Fetch container logs
openshell doctor logs --lines 100
openshell doctor logs --tail          # stream live

# Run any command inside the gateway container (KUBECONFIG is pre-configured)
openshell doctor exec -- kubectl get pods -A
openshell doctor exec -- kubectl -n openshell logs statefulset/openshell --tail=100
openshell doctor exec -- cat /etc/rancher/k3s/registries.yaml
openshell doctor exec -- df -h /
openshell doctor exec -- free -h
openshell doctor exec -- sh           # interactive shell
```

## Workflow

When the user asks to debug a cluster failure, **run diagnostics automatically** through the steps below in order. Stop and report findings as soon as a root cause is identified. Do not ask the user to choose which checks to run.

### Determine Context

Before running commands, establish:

1. **Cluster name**: Default is `openshell`, giving container name `openshell-cluster-openshell`
2. **Remote or local**: The `openshell doctor` commands auto-resolve this from gateway metadata — no special flags needed for the active gateway
3. **Config directory**: `~/.config/openshell/gateways/{name}/`

### Step 0: Quick Connectivity Check

Run `openshell status` first. This immediately reveals:
- Which gateway and endpoint the CLI is targeting
- Whether the CLI can reach the server (mTLS handshake success/failure)
- The server version if connected

Common errors at this stage:
- **`tls handshake eof`**: The server isn't running or mTLS credentials are missing/mismatched
- **`connection refused`**: The container isn't running or port mapping is broken
- **`No gateway configured`**: No gateway has been deployed yet

### Step 1: Check Container Logs

Get recent container logs to identify startup failures:

```bash
openshell doctor logs --lines 100
```

Look for:

- DNS resolution failures in the entrypoint script
- k3s startup errors (certificate issues, port binding failures)
- Manifest copy errors from `/opt/openshell/manifests/`
- `iptables` or `cgroup` errors (privilege/capability issues)
- `Warning: br_netfilter does not appear to be loaded` — this is advisory only; many kernels work without the explicit module. Only act on it if you also see DNS failures or pod-to-service connectivity problems (see Common Failure Patterns).

### Step 2: Check k3s Cluster Health

Verify k3s itself is functional:

```bash
# API server readiness
openshell doctor exec -- kubectl get --raw="/readyz"

# Node status
openshell doctor exec -- kubectl get nodes -o wide

# All pods
openshell doctor exec -- kubectl get pods -A -o wide
```

If `/readyz` fails, k3s is still starting or has crashed. Check container logs (Step 1).

If pods are in `CrashLoopBackOff`, `ImagePullBackOff`, or `Pending`, investigate those pods specifically.

Also check for node pressure conditions that cause the kubelet to evict pods and reject scheduling:

```bash
# Check node conditions (DiskPressure, MemoryPressure, PIDPressure)
openshell doctor exec -- kubectl get nodes -o jsonpath="{range .items[*]}{.metadata.name}{range .status.conditions[*]} {.type}={.status}{end}{\"\n\"}{end}"

# Check disk usage inside the container
openshell doctor exec -- df -h /

# Check memory usage
openshell doctor exec -- free -h
```

If any pressure condition is `True`, pods will be evicted and new ones rejected. The bootstrap now detects `HEALTHCHECK_NODE_PRESSURE` markers from the health-check script and aborts early with a clear diagnosis. To fix: free disk/memory on the host, then recreate the gateway.

### Step 3: Check OpenShell Server StatefulSet

The OpenShell server is deployed via a HelmChart CR as a StatefulSet named `openshell` in the `openshell` namespace. Check its status:

```bash
# StatefulSet status
openshell doctor exec -- kubectl -n openshell get statefulset/openshell -o wide

# OpenShell pod logs
openshell doctor exec -- kubectl -n openshell logs statefulset/openshell --tail=100

# Describe statefulset for events
openshell doctor exec -- kubectl -n openshell describe statefulset/openshell

# Helm install job logs (the job that installs the OpenShell chart)
openshell doctor exec -- kubectl -n kube-system logs -l job-name=helm-install-openshell --tail=200
```

Common issues:

- **Replicas 0/0**: The StatefulSet has been scaled to zero — no pods are running. This can happen after a failed deploy, manual scale-down, or Helm values misconfiguration. Fix: `openshell doctor exec -- kubectl -n openshell scale statefulset openshell --replicas=1`
- **ImagePullBackOff**: The component image failed to pull. In `internal` mode, verify internal registry readiness and pushed image tags (Step 5). In `external` mode, check `/etc/rancher/k3s/registries.yaml` credentials/endpoints and DNS (Step 8). Default external registry is `ghcr.io/nvidia/openshell/` (public, no auth required). If using a private registry, ensure `--registry-username` and `--registry-token` (or `OPENSHELL_REGISTRY_USERNAME`/`OPENSHELL_REGISTRY_TOKEN`) were provided during deploy.
- **CrashLoopBackOff**: The server is crashing. Check pod logs for the actual error.
- **Pending**: Insufficient resources or scheduling constraints.

### Step 4: Check Networking

The OpenShell server is exposed via a NodePort service on port `30051`:

```bash
# Service status
openshell doctor exec -- kubectl -n openshell get service/openshell
```

Expected port: `30051/tcp` (mapped to configurable host port, default 8080; set via `--port` on deploy).

### Step 5: Check Image Availability

Component images (server, sandbox) can reach kubelet via two paths:

**Local/external pull mode** (default local via `mise run cluster`): Local images are tagged to the configured local registry base (default `127.0.0.1:5000/openshell/*`), pushed to that registry, and pulled by k3s via `registries.yaml` mirror endpoint (typically `host.docker.internal:5000`). The `cluster` task pushes prebuilt local tags (`openshell/*:dev`, falling back to `localhost:5000/openshell/*:dev` or `127.0.0.1:5000/openshell/*:dev`).

Gateway image builds now stage a partial Rust workspace from `deploy/docker/Dockerfile.images`. If cargo fails with a missing manifest under `/build/crates/...`, or an imported symbol exists locally but is missing in the image build, verify that every current gateway dependency crate (including `openshell-driver-kubernetes` and `openshell-ocsf`) is copied into the staged workspace there.

```bash
# Verify image refs currently used by openshell deployment
openshell doctor exec -- kubectl -n openshell get statefulset openshell -o jsonpath="{.spec.template.spec.containers[*].image}"

# Verify registry mirror/auth endpoint configuration
openshell doctor exec -- cat /etc/rancher/k3s/registries.yaml
```

**Legacy push mode**: Images are imported into the k3s containerd `k8s.io` namespace.

```bash
# Check if images were imported into containerd (k3s default namespace is k8s.io)
openshell doctor exec -- ctr -a /run/k3s/containerd/containerd.sock images ls | grep openshell
```

**External pull mode** (remote deploy, or local with `OPENSHELL_REGISTRY_HOST`/`IMAGE_REPO_BASE` pointing at a non-local registry): Images are pulled from an external registry at runtime. The entrypoint generates `/etc/rancher/k3s/registries.yaml`.

```bash
# Verify registries.yaml exists and has credentials
openshell doctor exec -- cat /etc/rancher/k3s/registries.yaml

# Test pulling an image manually from inside the cluster
openshell doctor exec -- crictl pull ghcr.io/nvidia/openshell/gateway:latest
```

If `registries.yaml` is missing or has wrong values, verify env wiring (`OPENSHELL_REGISTRY_HOST`, `OPENSHELL_REGISTRY_INSECURE`, username/password for authenticated registries).

### Step 6: Check mTLS / PKI

TLS certificates are generated by the `openshell-bootstrap` crate (using `rcgen`) and stored as K8s secrets before the Helm release installs. There is no PKI job or cert-manager — certificates are applied directly via `kubectl apply`.

```bash
# Check if the three TLS secrets exist
openshell doctor exec -- kubectl -n openshell get secret openshell-server-tls openshell-server-client-ca openshell-client-tls

# Inspect server cert expiry (if openssl is available in the container)
openshell doctor exec -- sh -c 'kubectl -n openshell get secret openshell-server-tls -o jsonpath="{.data.tls\.crt}" | base64 -d | openssl x509 -noout -dates 2>/dev/null || echo "openssl not available"'

# Check if CLI-side mTLS files exist locally
ls -la ~/.config/openshell/gateways/<name>/mtls/
```

On redeploy, bootstrap reuses existing secrets if they are valid PEM. If secrets are missing or malformed, fresh PKI is generated and the OpenShell workload is automatically restarted. If the rollout restart fails after rotation, the deploy aborts and CLI-side certs are not updated. Certificates use rcgen defaults (effectively never expire).

If the local mTLS files are missing but the secrets exist in the cluster, you can extract them manually:

```bash
mkdir -p ~/.config/openshell/gateways/<name>/mtls
openshell doctor exec -- kubectl -n openshell get secret openshell-client-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > ~/.config/openshell/gateways/<name>/mtls/ca.crt
openshell doctor exec -- kubectl -n openshell get secret openshell-client-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > ~/.config/openshell/gateways/<name>/mtls/tls.crt
openshell doctor exec -- kubectl -n openshell get secret openshell-client-tls -o jsonpath='{.data.tls\.key}' | base64 -d > ~/.config/openshell/gateways/<name>/mtls/tls.key
```

Common mTLS issues:
- **Secrets missing**: The `openshell` namespace may not have been created yet (Helm controller race). Bootstrap waits up to 2 minutes for the namespace.
- **mTLS mismatch after manual secret deletion**: Delete all three secrets and redeploy — bootstrap will regenerate and restart the workload.
- **CLI can't connect after redeploy**: Check that `~/.config/openshell/gateways/<name>/mtls/` contains `ca.crt`, `tls.crt`, `tls.key` and that they were updated at deploy time.
- **Local mTLS files missing**: The gateway was deployed but CLI credentials weren't persisted (e.g., interrupted deploy). Extract from the cluster secret as shown above.

### Step 7: Check Kubernetes Events

Events catch scheduling failures, image pull errors, and resource issues:

```bash
openshell doctor exec -- kubectl get events -A --sort-by=.lastTimestamp | tail -n 50
```

Look for:

- `FailedScheduling` — resource constraints
- `ImagePullBackOff` / `ErrImagePull` — registry auth failure or DNS issue (check `/etc/rancher/k3s/registries.yaml`)
- `CrashLoopBackOff` — application crashes
- `OOMKilled` — memory limits too low
- `FailedMount` — volume issues

### Step 8: Check GPU Device Plugin and CDI (GPU gateways only)

Skip this step for non-GPU gateways.

The NVIDIA device plugin DaemonSet must be running and healthy before GPU sandboxes can be created. It uses CDI injection (`deviceListStrategy: cdi-cri`) to inject GPU devices into sandbox pods — no `runtimeClassName` is set on sandbox pods.

```bash
# DaemonSet status — numberReady must be >= 1
openshell doctor exec -- kubectl get daemonset -n nvidia-device-plugin

# Device plugin pod logs — look for "CDI" lines confirming CDI mode is active
openshell doctor exec -- kubectl logs -n nvidia-device-plugin -l app.kubernetes.io/name=nvidia-device-plugin --tail=50

# List CDI devices registered by the device plugin (requires nvidia-ctk in the cluster image).
# Device plugin CDI entries use the vendor string "k8s.device-plugin.nvidia.com" so entries
# will be prefixed "k8s.device-plugin.nvidia.com/gpu=". If the list is empty, CDI spec
# generation has not completed yet.
openshell doctor exec -- nvidia-ctk cdi list

# Verify CDI spec files were generated on the node
openshell doctor exec -- ls /var/run/cdi/

# Helm install job logs for the device plugin chart
openshell doctor exec -- kubectl -n kube-system logs -l job-name=helm-install-nvidia-device-plugin --tail=100

# Confirm a GPU sandbox pod has no runtimeClassName (CDI injection, not runtime class)
openshell doctor exec -- kubectl get pod -n openshell -o jsonpath='{range .items[*]}{.metadata.name}{" runtimeClassName="}{.spec.runtimeClassName}{"\n"}{end}'
```

Common issues:

- **DaemonSet 0/N ready**: The device plugin chart may still be deploying (k3s Helm controller can take 1–2 min) or the pod is crashing. Check pod logs.
- **`nvidia-ctk cdi list` returns no `k8s.device-plugin.nvidia.com/gpu=` entries**: CDI spec generation has not completed. The device plugin may still be starting or the `cdi-cri` strategy isn't active. Verify `deviceListStrategy: cdi-cri` is in the rendered Helm values.
- **No CDI spec files at `/var/run/cdi/`**: Same as above — device plugin hasn't written CDI specs yet.
- **`HEALTHCHECK_GPU_DEVICE_PLUGIN_NOT_READY` in health check logs**: Device plugin has no ready pods. Check DaemonSet events and pod logs.

### Step 9: Check DNS Resolution

DNS misconfiguration is a common root cause, especially on remote/Linux hosts:

```bash
# Check the resolv.conf k3s is using for pod DNS
openshell doctor exec -- cat /etc/rancher/k3s/resolv.conf

# Test DNS from inside the container
openshell doctor exec -- sh -c 'nslookup google.com || wget -q -O /dev/null http://google.com && echo "network ok" || echo "network unreachable"'
```

Check the entrypoint's DNS decision in the container logs:

```bash
openshell doctor logs --lines 20
```

The entrypoint (`cluster-entrypoint.sh`) sets k3s pod DNS via a single strategy with one fallback:

1. **Docker DNS proxy** (`setup_dns_proxy()`): reads the `DOCKER_OUTPUT` iptables chain to discover where Docker's embedded DNS (`127.0.0.11`) is actually listening, installs DNAT rules so k3s pods can reach it via the container's `eth0` IP, and writes `nameserver <eth0-ip>` to `/etc/rancher/k3s/resolv.conf`. On success logs: `Setting up DNS proxy: <ip>:53 -> 127.0.0.11`.
2. **Public DNS fallback**: if `setup_dns_proxy()` fails for any reason, logs `Warning: Could not discover Docker DNS ports from iptables` and writes `nameserver 8.8.8.8` / `nameserver 8.8.4.4` to `/etc/rancher/k3s/resolv.conf`.

After either path, `verify_dns()` runs `nslookup` (5 retries) against the configured registry host (default `ghcr.io`). On failure it emits `DNS_PROBE_FAILED` into the logs. The Rust-side bootstrap (`runtime.rs` / `lib.rs`) watches for this marker and aborts early rather than spinning for the full 6-minute timeout.

**Important:** there are two independent DNS paths inside the cluster container. The entrypoint only writes `/etc/rancher/k3s/resolv.conf` (pod DNS). The container's system `/etc/resolv.conf` (used by containerd for image pulls and by `nslookup`) is set by Docker or Podman at container start and is never touched by the entrypoint. These can point at different nameservers.

**Under Podman:** `setup_dns_proxy()` always fails — Podman does not create a `DOCKER_OUTPUT` chain. k3s pod DNS always falls back to `8.8.8.8`/`8.8.4.4`. The cluster container runs on a named Podman bridge network, which uses **netavark + aardvark-dns**. Aardvark-dns listens on the bridge gateway IP (e.g. `10.89.x.1`) and forwards external queries to the host resolver. Podman sets the container's system `/etc/resolv.conf` to that address — so `nslookup ghcr.io` works fine even when `8.8.8.8` is blocked. This means **`DNS_PROBE_FAILED` is never emitted under Podman** even when pod-level DNS is broken: the entrypoint's `verify_dns()` and the Rust-side `probe_container_dns()` both call bare `nslookup`, which hits aardvark-dns via the system resolv.conf, not the k3s resolv.conf. Pod DNS failures surface later as CoreDNS upstream forwarding timeouts, not as an early bootstrap abort.

To debug Podman pod DNS failures: check `/etc/rancher/k3s/resolv.conf` confirms `8.8.8.8` is there, then verify `8.8.8.8:53` UDP is reachable from the host with `nc -vzu 8.8.8.8 53`.

If DNS is broken, all image pulls from the distribution registry will fail, as will pods that need external network access.

**Sandbox agent DNS is a separate enforcement layer.** The cluster DNS above controls what k3s pods and containerd can resolve. It has no bearing on what agent workloads inside sandboxes can reach. The sandbox supervisor (`openshell-sandbox`) creates an isolated Linux network namespace for each agent process with a veth pair, then installs iptables rules inside that namespace that REJECT all outbound UDP — including port 53 — except traffic destined for the supervisor's CONNECT proxy. Agent workloads cannot make raw DNS queries regardless of what nameservers are configured anywhere in the cluster. DNS must go through the HTTP CONNECT proxy. This is a kernel-enforced boundary at the netns level, not a configuration setting. The bypass monitor detects and logs any direct DNS attempt with the hint: `"DNS queries should route through the sandbox proxy; check resolver configuration"`.

## Common Failure Patterns

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `tls handshake eof` from `openshell status` | Server not running or mTLS credentials missing/mismatched | Check StatefulSet replicas (Step 3) and mTLS files (Step 6) |
| StatefulSet `0/0` replicas | StatefulSet scaled to zero (failed deploy, manual scale-down, or Helm misconfiguration) | `openshell doctor exec -- kubectl -n openshell scale statefulset openshell --replicas=1` |
| Local mTLS files missing | Deploy was interrupted before credentials were persisted | Extract from cluster secret `openshell-client-tls` (Step 6) |
| Container not found | Image not built | `mise run docker:build:cluster` (local, works with both Docker and Podman) or re-deploy (remote) |
| Container exited, OOMKilled | Insufficient memory | Increase host memory or reduce workload |
| Container exited, non-zero exit | k3s crash, port conflict, privilege issue | Check `openshell doctor logs` for details |
| `/readyz` fails | k3s still starting or crashed | Wait longer or check container logs for k3s errors |
| OpenShell pods `Pending` | Insufficient CPU/memory for scheduling, or PVC not bound | `openshell doctor exec -- kubectl describe pod -n openshell` and `openshell doctor exec -- kubectl get pvc -n openshell` |
| OpenShell pods `CrashLoopBackOff` | Server application error | `openshell doctor exec -- kubectl -n openshell logs statefulset/openshell` |
| OpenShell pods `ImagePullBackOff` (push mode) | Images not imported or wrong containerd namespace | Check `openshell doctor exec -- ctr -a /run/k3s/containerd/containerd.sock -n k8s.io images ls` (Step 5) |
| OpenShell pods `ImagePullBackOff` (pull mode) | Registry auth or DNS issue | Check `openshell doctor exec -- cat /etc/rancher/k3s/registries.yaml` and DNS (Step 8) |
| Image import fails | Corrupt tar stream or containerd not ready | Retry after k3s is fully started; check container logs |
| Push mode images not found by kubelet | Imported into wrong containerd namespace | Must use `k3s ctr -n k8s.io images import`, not `k3s ctr images import` |
| mTLS secrets missing | Bootstrap couldn't apply secrets (namespace not ready) | Check deploy logs and verify `openshell` namespace exists (Step 6) |
| mTLS mismatch after redeploy | PKI rotated but workload not restarted, or rollout failed | Check that all three TLS secrets exist and that the openshell pod restarted after cert rotation (Step 6) |
| Helm install job failed | Chart values error or dependency issue | `openshell doctor exec -- kubectl -n kube-system logs -l job-name=helm-install-openshell` |
| NFD/GFD DaemonSets present (`node-feature-discovery`, `gpu-feature-discovery`) | Cluster was deployed before NFD/GFD were disabled (pre-simplify-device-plugin change) | These are harmless but add overhead. Clean up: `openshell doctor exec -- kubectl delete daemonset -n nvidia-device-plugin -l app.kubernetes.io/name=node-feature-discovery` and similarly for GFD. The `nvidia.com/gpu.present` node label is no longer applied; device plugin scheduling no longer requires it. |
| Podman socket not found | Rootless Podman service not started | `systemctl --user start podman.socket` and verify with `podman info` |
| Container creation fails with subuid/subgid error (Podman) | Missing user namespace ID mappings | `sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $(whoami)` then `podman system migrate` |
| Cgroups v1 detected (Podman) | Podman driver requires unified cgroup hierarchy | Set `systemd.unified_cgroup_hierarchy=1` kernel parameter and reboot |
| `--restart=always` ignored (Podman rootless) | Rootless Podman does not support `--restart=always` for containers | Use a systemd user service instead: `loginctl enable-linger $(whoami)` then create a `~/.config/systemd/user/` unit |
| Architecture mismatch (remote) | Built on arm64, deploying to amd64 | Cross-build the image for the target architecture |
| Port conflict | Another service on the configured gateway host port (default 8080) | Stop conflicting service or use `--port` on `openshell gateway start` to pick a different host port |
| gRPC connect refused to `127.0.0.1:443` in CI | Docker daemon is remote (`DOCKER_HOST=tcp://...`) but metadata still points to loopback | Verify metadata endpoint host matches `DOCKER_HOST` and includes non-loopback host |
| DNS failures inside container (Docker) | `setup_dns_proxy()` failed to find `DOCKER_OUTPUT` iptables chain | `openshell doctor logs --lines 20` for `Warning: Could not discover Docker DNS ports`; try `docker network prune -f` and redeploy |
| Pod external name resolution fails (Podman) | `setup_dns_proxy()` always fails under Podman; k3s resolv.conf falls back to `8.8.8.8`/`8.8.4.4`, which is blocked on this network | `DNS_PROBE_FAILED` will NOT appear — entrypoint and Rust-side probes resolve via aardvark-dns (system `/etc/resolv.conf`), not the k3s resolv.conf; check `openshell doctor exec -- cat /etc/rancher/k3s/resolv.conf` to confirm fallback; verify `8.8.8.8:53` UDP reachable from host via `nc -vzu 8.8.8.8 53` |
| Pods can't reach kube-dns / ClusterIP services | `br_netfilter` not loaded; bridge traffic bypasses iptables DNAT rules | `sudo modprobe br_netfilter` on the host, then `echo br_netfilter \| sudo tee /etc/modules-load.d/br_netfilter.conf` to persist. Known to be required on Jetson Linux 5.15-tegra; other kernels (e.g. standard x86/aarch64 Linux) may have bridge netfilter built in and work without the module. The entrypoint logs a warning when `/proc/sys/net/bridge/bridge-nf-call-iptables` is absent but does not abort — only act on it if DNS or service connectivity is actually broken. |
| Node DiskPressure / MemoryPressure / PIDPressure | Insufficient disk, memory, or PIDs on host | Free disk (`docker system prune -a --volumes`), increase memory, or expand host resources. Bootstrap auto-detects via `HEALTHCHECK_NODE_PRESSURE` marker |
| Pods evicted with "The node had condition: [DiskPressure]" | Host disk full, kubelet evicting pods | Free disk space on host, then `openshell gateway destroy <name> && openshell gateway start` |
| `metrics-server` errors in logs | Normal k3s noise, not the root cause | These errors are benign — look for the actual failing health check component |
| Stale NotReady nodes from previous deploys | Volume reused across container recreations | The deploy flow now auto-cleans stale nodes; if it still fails, manually delete NotReady nodes (see Step 2) or choose "Recreate" when prompted |
| gRPC `UNIMPLEMENTED` for newer RPCs in push mode | Helm values still point at older pulled images instead of the pushed refs | Verify rendered `openshell-helmchart.yaml` uses the expected push refs (`server`, `sandbox`, `pki-job`) and not `:latest` |
| Sandbox pods crash with `/opt/openshell/bin/openshell-sandbox: no such file or directory` | Supervisor binary missing from cluster image | The cluster image was built/published without the `supervisor-builder` target in `deploy/docker/Dockerfile.images`. Rebuild with `mise run docker:build:cluster` and recreate gateway. Bootstrap auto-detects via `HEALTHCHECK_MISSING_SUPERVISOR` marker |
| `HEALTHCHECK_MISSING_SUPERVISOR` in health check logs | `/opt/openshell/bin/openshell-sandbox` not found in gateway container | Rebuild cluster image: `mise run docker:build:cluster`, then `openshell gateway destroy <name> && openshell gateway start` |
| `nvidia-ctk cdi list` returns no `k8s.device-plugin.nvidia.com/gpu=` entries | CDI specs not yet generated by device plugin | Device plugin may still be starting; wait and retry, or check pod logs (Step 8) |

## Full Diagnostic Dump

Run all diagnostics at once for a comprehensive report:

```bash
echo "=== Connectivity Check ==="
openshell status

echo "=== Container Logs (last 50 lines) ==="
openshell doctor logs --lines 50

echo "=== k3s Readiness ==="
openshell doctor exec -- kubectl get --raw='/readyz'

echo "=== Nodes ==="
openshell doctor exec -- kubectl get nodes -o wide

echo "=== Node Conditions ==="
openshell doctor exec -- kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{range .status.conditions[*]} {.type}={.status}{end}{"\n"}{end}'

echo "=== Disk Usage ==="
openshell doctor exec -- df -h /

echo "=== All Pods ==="
openshell doctor exec -- kubectl get pods -A -o wide

echo "=== Failing Pods ==="
openshell doctor exec -- kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded

echo "=== OpenShell StatefulSet ==="
openshell doctor exec -- kubectl -n openshell get statefulset/openshell -o wide

echo "=== OpenShell Service ==="
openshell doctor exec -- kubectl -n openshell get service/openshell

echo "=== TLS Secrets ==="
openshell doctor exec -- kubectl -n openshell get secret openshell-server-tls openshell-server-client-ca openshell-client-tls

echo "=== Recent Events ==="
openshell doctor exec -- kubectl get events -A --sort-by=.lastTimestamp | tail -n 50

echo "=== Helm Install OpenShell Logs ==="
openshell doctor exec -- kubectl -n kube-system logs -l job-name=helm-install-openshell --tail=100

echo "=== Registry Configuration ==="
openshell doctor exec -- cat /etc/rancher/k3s/registries.yaml

echo "=== Supervisor Binary ==="
openshell doctor exec -- ls -la /opt/openshell/bin/openshell-sandbox

echo "=== DNS Configuration ==="
openshell doctor exec -- cat /etc/rancher/k3s/resolv.conf

# GPU gateways only
echo "=== GPU Device Plugin ==="
openshell doctor exec -- kubectl get daemonset -n nvidia-device-plugin
openshell doctor exec -- nvidia-ctk cdi list
```
