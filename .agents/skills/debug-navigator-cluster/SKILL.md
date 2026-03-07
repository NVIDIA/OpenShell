---
name: debug-navigator-cluster
description: Debug why a nemoclaw cluster failed to start or is unhealthy. Use when the user has a failed `nemoclaw gateway start`, cluster health check failure, or wants to diagnose cluster infrastructure issues. Trigger keywords - debug cluster, cluster failing, cluster not starting, deploy failed, cluster troubleshoot, cluster health, cluster diagnose, why won't my cluster start, health check failed, gateway start failed, gateway not starting.
---

# Debug NemoClaw Cluster

Diagnose why a nemoclaw cluster failed to start after `nemoclaw gateway start`.

## Overview

`nemoclaw gateway start` creates a Docker container running k3s with the NemoClaw server and Envoy Gateway deployed via Helm. The deployment stages, in order, are:

1. **Pre-deploy check**: `nemoclaw gateway start` in interactive mode prompts to **reuse** (keep volume, clean stale nodes) or **recreate** (destroy everything, fresh start). `mise run cluster` always recreates before deploy.
2. Ensure cluster image is available (local build or remote pull)
3. Create Docker network (`navigator-cluster`) and volume (`navigator-cluster-{name}`)
4. Create and start a privileged Docker container (`navigator-cluster-{name}`)
5. Wait for k3s to generate kubeconfig (up to 60s)
6. **Clean stale nodes**: Remove any `NotReady` k3s nodes left over from previous container instances that reused the same persistent volume
7. **Prepare local images** (if `NEMOCLAW_PUSH_IMAGES` is set): In `internal` registry mode, bootstrap waits for the in-cluster registry and pushes tagged images there. In `external` mode, bootstrap uses legacy `ctr -n k8s.io images import` push-mode behavior.
7. **Reconcile TLS PKI**: Load existing TLS secrets from the cluster; if missing, incomplete, or malformed, generate fresh PKI (CA + server + client certs). Apply secrets to cluster. If rotation happened and the NemoClaw workload is already running, rollout restart and wait for completion (failed rollout aborts deploy).
8. **Store CLI mTLS credentials**: Persist client cert/key/CA locally for CLI authentication.
9. Wait for cluster health checks to pass (up to 6 min):
   - k3s API server readiness (`/readyz`)
    - `navigator` statefulset ready in `navigator` namespace
   - `navigator-gateway` Gateway programmed in `navigator` namespace
   - TLS secrets `navigator-server-tls` and `navigator-client-tls` exist

For local deploys, metadata endpoint selection now depends on Docker connectivity:

- default local Docker socket (`unix:///var/run/docker.sock`): `https://127.0.0.1:{port}` (default port 8080)
- TCP Docker daemon (`DOCKER_HOST=tcp://<host>:<port>`): `https://<host>:{port}` for non-loopback hosts

The host port is configurable via `--port` on `nemoclaw gateway start` (default 8080) and is stored in `ClusterMetadata.gateway_port`.

The TCP host is also added as an extra gateway TLS SAN so mTLS hostname validation succeeds.

The default cluster name is `nemoclaw`. The container is `navigator-cluster-{name}`.

## Prerequisites

- Docker must be running (locally or on the remote host)
- The `nemoclaw` CLI must be available
- For remote clusters: SSH access to the remote host

## Workflow

When the user asks to debug a cluster failure, **run diagnostics automatically** through the steps below in order. Stop and report findings as soon as a root cause is identified. Do not ask the user to choose which checks to run.

### Determine Context

Before running commands, establish:

1. **Cluster name**: Default is `nemoclaw`, giving container name `navigator-cluster-nemoclaw`
2. **Remote or local**: If the user deployed with `--remote <host>`, all Docker commands must target that host
3. **Config directory**: `~/.config/nemoclaw/clusters/{name}/`

For remote clusters, prefix Docker commands with SSH:

```bash
# Remote docker commands
ssh <host> docker <command>

# Remote kubectl inside the container
ssh <host> docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl <command>'
```

For local clusters, run Docker commands directly:

```bash
docker <command>
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl <command>'
```

### Step 1: Check Docker Container State

First, determine if the container exists and its state:

```bash
docker ps -a --filter name=navigator-cluster- --format 'table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}'
```

If the container does not exist:

```bash
# Check if the image is available
docker images 'navigator/cluster*' --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}'
```

If the image is missing, re-deploy so bootstrap can pull the published cluster image (or set `NEMOCLAW_CLUSTER_IMAGE` explicitly).

If the container exists but is not running, inspect it:

```bash
docker inspect navigator-cluster-<name> --format '{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{.State.Error}}'
```

- **OOMKilled=true**: The host doesn't have enough memory.
- **ExitCode != 0**: k3s crashed. Proceed to Step 2 for logs.

### Step 2: Check Container Logs

Get recent container logs to identify startup failures:

```bash
docker logs navigator-cluster-<name> --tail 100
```

Look for:

- DNS resolution failures in the entrypoint script
- k3s startup errors (certificate issues, port binding failures)
- Manifest copy errors from `/opt/navigator/manifests/`
- `iptables` or `cgroup` errors (privilege/capability issues)

### Step 3: Check k3s Cluster Health

Verify k3s itself is functional:

```bash
# API server readiness
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get --raw="/readyz"'

# Node status
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get nodes -o wide'

# All pods
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get pods -A -o wide'
```

If `/readyz` fails, k3s is still starting or has crashed. Check container logs (Step 2).

If pods are in `CrashLoopBackOff`, `ImagePullBackOff`, or `Pending`, investigate those pods specifically.

### Step 4: Check NemoClaw Server StatefulSet

The NemoClaw server is deployed via a HelmChart CR as a StatefulSet with persistent storage. Check its status:

```bash
# StatefulSet status
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n navigator get statefulset/navigator -o wide'

# NemoClaw pod logs
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n navigator logs statefulset/navigator --tail=100'

# Describe statefulset for events
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n navigator describe statefulset/navigator'

# Helm install job logs (the job that installs the NemoClaw chart)
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n kube-system logs -l job-name=helm-install-navigator --tail=200'
```

Common issues:

- **ImagePullBackOff**: The component image failed to pull. In `internal` mode, verify internal registry readiness and pushed image tags (Step 6). In `external` mode, check `/etc/rancher/k3s/registries.yaml` credentials/endpoints and DNS (Step 8). Default external registry is `d1i0nduu2f6qxk.cloudfront.net/navigator/`.
- **CrashLoopBackOff**: The server is crashing. Check pod logs for the actual error.
- **Pending**: Insufficient resources or scheduling constraints.

### Step 5: Check Gateway and Networking

The Envoy Gateway provides HTTP/gRPC ingress:

```bash
# Gateway status
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n navigator get gateway/navigator-gateway'

# Check port bindings on the host
docker port navigator-cluster-<name>
```

Expected ports: `6443/tcp`, `30051/tcp` (mapped to configurable host port, default 8080; set via `--port` on deploy).
Only one local cluster can run on a Docker host at a time because `6443` is fixed.
`mise run cluster` handles this by removing conflicting local `navigator-cluster-*` containers first.

If ports are missing or conflicting, another process may be using them. Check with:

```bash
# On the host (or remote host)
ss -tlnp | grep -E ':(6443|8080)\s'
```

If using Docker-in-Docker (`DOCKER_HOST=tcp://docker:2375`), verify metadata points at `https://docker` (not `https://127.0.0.1`).

### Step 6: Check Image Availability

Component images (server, sandbox, pki-job) can reach kubelet via two paths:

**Local/external pull mode** (default local via `mise run cluster` / `mise run cluster:build`): Local images are tagged to the configured local registry base (default `127.0.0.1:5000/navigator/*`), pushed to that registry, and pulled by k3s via `registries.yaml` mirror endpoint (typically `host.docker.internal:5000`). `cluster:build` builds then pushes images; `cluster` pushes prebuilt local tags (`navigator/*:dev`, falling back to `localhost:5000/navigator/*:dev` or `127.0.0.1:5000/navigator/*:dev`).

```bash
# Verify image refs currently used by nemoclaw deployment
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n navigator get deploy navigator -o jsonpath="{.spec.template.spec.containers[*].image}"'

# Verify registry mirror/auth endpoint configuration
docker exec navigator-cluster-<name> cat /etc/rancher/k3s/registries.yaml
```

**Legacy push mode** (`mise run cluster:push`): Images are imported into the k3s containerd `k8s.io` namespace.

```bash
# Check if images were imported into containerd (k3s default namespace is k8s.io)
docker exec navigator-cluster-<name> ctr -a /run/k3s/containerd/containerd.sock images ls | grep navigator
```

If images are missing, re-import with:

```bash
docker save <image-ref> | docker exec -i navigator-cluster-<name> ctr -a /run/k3s/containerd/containerd.sock images import -
```

**External pull mode** (remote deploy, or local with `NEMOCLAW_REGISTRY_HOST`/`IMAGE_REPO_BASE` pointing at a non-local registry): Images are pulled from an external registry at runtime. The entrypoint generates `/etc/rancher/k3s/registries.yaml`.

```bash
# Verify registries.yaml exists and has credentials
docker exec navigator-cluster-<name> cat /etc/rancher/k3s/registries.yaml

# Test pulling an image manually from inside the cluster
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml crictl pull d1i0nduu2f6qxk.cloudfront.net/navigator/pki-job:latest'
```

If `registries.yaml` is missing or has wrong values, verify env wiring (`NEMOCLAW_REGISTRY_HOST`, `NEMOCLAW_REGISTRY_INSECURE`, username/password for authenticated registries).

### Step 7: Check mTLS / PKI

TLS certificates are generated by the `navigator-bootstrap` crate (using `rcgen`) and stored as K8s secrets before the Helm release installs. There is no PKI job or cert-manager — certificates are applied directly via `kubectl apply`.

```bash
# Check if the three TLS secrets exist
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n navigator get secret navigator-server-tls navigator-server-client-ca navigator-client-tls'

# Inspect server cert expiry (if openssl is available in the container)
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n navigator get secret navigator-server-tls -o jsonpath="{.data.tls\.crt}" | base64 -d | openssl x509 -noout -dates 2>/dev/null || echo "openssl not available"'

# Check if CLI-side mTLS files exist locally
ls -la ~/.config/nemoclaw/clusters/<name>/mtls/
```

On redeploy, bootstrap reuses existing secrets if they are valid PEM. If secrets are missing or malformed, fresh PKI is generated and the NemoClaw workload is automatically restarted. If the rollout restart fails after rotation, the deploy aborts and CLI-side certs are not updated. Certificates use rcgen defaults (effectively never expire).

Common mTLS issues:
- **Secrets missing**: The `navigator` namespace may not have been created yet (Helm controller race). Bootstrap waits up to 2 minutes for the namespace.
- **mTLS mismatch after manual secret deletion**: Delete all three secrets and redeploy — bootstrap will regenerate and restart the workload.
- **CLI can't connect after redeploy**: Check that `~/.config/nemoclaw/clusters/<name>/mtls/` contains `ca.crt`, `tls.crt`, `tls.key` and that they were updated at deploy time.

### Step 8: Check Kubernetes Events

Events catch scheduling failures, image pull errors, and resource issues:

```bash
docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get events -A --sort-by=.lastTimestamp' | tail -n 50
```

Look for:

- `FailedScheduling` — resource constraints
- `ImagePullBackOff` / `ErrImagePull` — registry auth failure or DNS issue (check `/etc/rancher/k3s/registries.yaml`)
- `CrashLoopBackOff` — application crashes
- `OOMKilled` — memory limits too low
- `FailedMount` — volume issues

### Step 9: Check DNS Resolution

DNS misconfiguration is a common root cause, especially on remote/Linux hosts:

```bash
# Check the resolv.conf k3s is using
docker exec navigator-cluster-<name> cat /etc/rancher/k3s/resolv.conf

# Test DNS resolution from inside the container
docker exec navigator-cluster-<name> sh -c 'nslookup google.com || wget -q -O /dev/null http://google.com && echo "network ok" || echo "network unreachable"'

# Check the entrypoint's DNS decision (in container logs)
docker logs navigator-cluster-<name> 2>&1 | head -20
```

The entrypoint script selects DNS resolvers in this priority:

1. Viable nameservers from `/etc/resolv.conf` (not loopback/link-local)
2. Docker `ExtServers` from `/etc/resolv.conf` comments
3. Host gateway IP (Docker Desktop only, `192.168.*`)
4. Fallback to `8.8.8.8` / `8.8.4.4`

If DNS is broken, all image pulls from the distribution registry will fail, as will pods that need external network access (PKI job, cert-manager).

## Common Failure Patterns

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Container not found | Image not built | `mise run docker:build:cluster` (local) or re-deploy (remote) |
| Container exited, OOMKilled | Insufficient memory | Increase host memory or reduce workload |
| Container exited, non-zero exit | k3s crash, port conflict, privilege issue | Check `docker logs` and `docker inspect` for details |
| `/readyz` fails | k3s still starting or crashed | Wait longer or check container logs for k3s errors |
| NemoClaw pods `Pending` | Insufficient CPU/memory for scheduling, or PVC not bound | Check `kubectl describe pod` for scheduling failures and `kubectl get pvc -n navigator` for volume status |
| NemoClaw pods `CrashLoopBackOff` | Server application error | Check `kubectl logs` on the crashing pod |
| NemoClaw pods `ImagePullBackOff` (push mode) | Images not imported or wrong containerd namespace | Check `k3s ctr -n k8s.io images ls` for component images (Step 6) |
| NemoClaw pods `ImagePullBackOff` (pull mode) | Registry auth or DNS issue | Check `/etc/rancher/k3s/registries.yaml` credentials and DNS (Step 8) |
| Image import fails (`k3s ctr` exit code != 0) | Corrupt tar stream or containerd not ready | Retry after k3s is fully started; check container logs |
| Push mode images not found by kubelet | Imported into wrong containerd namespace | Must use `k3s ctr -n k8s.io images import`, not `k3s ctr images import` |
| Gateway not `Programmed` | Envoy Gateway not ready | Check `envoy-gateway-system` pods and Helm install logs |
| mTLS secrets missing | Bootstrap couldn't apply secrets (namespace not ready, kubectl exec failure) | Check deploy logs and verify `navigator` namespace exists (Step 7) |
| mTLS mismatch after redeploy | PKI rotated but workload not restarted, or rollout failed | Check that all three TLS secrets exist and that the navigator pod restarted after cert rotation (Step 7) |
| Helm install job failed | Chart values error or dependency issue | Check `helm-install-navigator` job logs in `kube-system` |
| Architecture mismatch (remote) | Built on arm64, deploying to amd64 | Cross-build the image for the target architecture |
| SSH connection failed (remote) | SSH key/host/Docker issues | Test `ssh <host> docker ps` manually |
| Port conflict | Another service on 6443 or the configured gateway host port (default 8080) | Stop conflicting service or use `--port` on `nemoclaw gateway start` to pick a different host port |
| gRPC connect refused to `127.0.0.1:443` in CI | Docker daemon is remote (`DOCKER_HOST=tcp://...`) but metadata still points to loopback | Verify metadata endpoint host matches `DOCKER_HOST` and includes non-loopback host |
| DNS failures inside container | Entrypoint DNS detection failed | Check `/etc/rancher/k3s/resolv.conf` and container startup logs |
| `metrics-server` errors in logs | Normal k3s noise, not the root cause | These errors are benign — look for the actual failing health check component |
| Stale NotReady nodes from previous deploys | Volume reused across container recreations | The deploy flow now auto-cleans stale nodes; if it still fails, manually delete NotReady nodes (see Step 3) or choose "Recreate" when prompted |
| gRPC `UNIMPLEMENTED` for newer RPCs in push mode | Helm values still point at older pulled images instead of the pushed refs | Verify rendered `navigator-helmchart.yaml` uses the expected push refs (`server`, `sandbox`, `pki-job`) and not `:latest` |

## Remote Cluster Debugging

For clusters deployed with `--remote <host>`, all commands must target the remote Docker daemon.

**Option A: SSH prefix** (simplest):

```bash
ssh <host> docker ps -a
ssh <host> docker logs navigator-cluster-<name>
ssh <host> docker exec navigator-cluster-<name> sh -lc 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get pods -A'
```

**Option B: Docker SSH context**:

```bash
docker -H ssh://<host> ps -a
docker -H ssh://<host> logs navigator-cluster-<name>
```

**Setting up kubectl access** (requires tunnel):

```bash
nemoclaw gateway tunnel --name <name> --remote <host>
# Then in another terminal:
export KUBECONFIG=~/.config/nemoclaw/clusters/<name>/kubeconfig
kubectl get pods -A
```

## Full Diagnostic Dump

Run all diagnostics at once for a comprehensive report:

```bash
HOST="<host>"  # leave empty for local, or set to SSH destination
NAME="nemoclaw"  # cluster name
CONTAINER="navigator-cluster-${NAME}"
KCFG="KUBECONFIG=/etc/rancher/k3s/k3s.yaml"

# Helper: run docker command locally or remotely
run() { if [ -n "$HOST" ]; then ssh "$HOST" "$@"; else "$@"; fi; }

echo "=== Container State ==="
run docker ps -a --filter "name=${CONTAINER}" --format 'table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}'
run docker inspect "${CONTAINER}" --format '{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{.State.Error}}' 2>/dev/null

echo "=== Container Logs (last 50 lines) ==="
run docker logs "${CONTAINER}" --tail 50 2>&1

echo "=== k3s Readiness ==="
run docker exec "${CONTAINER}" sh -lc "${KCFG} kubectl get --raw='/readyz'" 2>&1

echo "=== Nodes ==="
run docker exec "${CONTAINER}" sh -lc "${KCFG} kubectl get nodes -o wide" 2>&1

echo "=== All Pods ==="
run docker exec "${CONTAINER}" sh -lc "${KCFG} kubectl get pods -A -o wide" 2>&1

echo "=== Failing Pods ==="
run docker exec "${CONTAINER}" sh -lc "${KCFG} kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded" 2>&1

echo "=== NemoClaw StatefulSet ==="
run docker exec "${CONTAINER}" sh -lc "${KCFG} kubectl -n navigator get statefulset/navigator -o wide" 2>&1

echo "=== NemoClaw Gateway ==="
run docker exec "${CONTAINER}" sh -lc "${KCFG} kubectl -n navigator get gateway/navigator-gateway" 2>&1

echo "=== Recent Events ==="
run docker exec "${CONTAINER}" sh -lc "${KCFG} kubectl get events -A --sort-by=.lastTimestamp" 2>&1 | tail -n 50

echo "=== PKI Job Logs ==="
run docker exec "${CONTAINER}" sh -lc "${KCFG} kubectl -n navigator logs -l job-name=navigator-gateway-pki --tail=100" 2>&1

echo "=== Helm Install NemoClaw Logs ==="
run docker exec "${CONTAINER}" sh -lc "${KCFG} kubectl -n kube-system logs -l job-name=helm-install-navigator --tail=100" 2>&1

echo "=== Registry Configuration ==="
run docker exec "${CONTAINER}" cat /etc/rancher/k3s/registries.yaml 2>&1

echo "=== DNS Configuration ==="
run docker exec "${CONTAINER}" cat /etc/rancher/k3s/resolv.conf 2>&1

echo "=== Port Bindings ==="
run docker port "${CONTAINER}" 2>&1
```
