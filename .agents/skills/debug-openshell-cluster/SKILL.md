---
name: debug-openshell-cluster
description: Debug why an OpenShell gateway deployment is unhealthy, unreachable, or unable to create sandboxes. Use when the user has a gateway health failure, Docker/Podman runtime issue, Helm install failure, Kubernetes scheduling issue, TLS secret issue, VM driver issue, or sandbox startup problem. Trigger keywords - debug gateway, gateway failing, deployment failing, helm install failing, cluster health, gateway health, gateway not starting, health check failed, sandbox pending, docker driver, podman driver, vm driver.
---

# Debug OpenShell Gateway Deployment

Diagnose a gateway and its selected compute platform. Do not assume OpenShell provisions Kubernetes or runs a k3s container. OpenShell targets a reachable gateway endpoint backed by Docker, Podman, Kubernetes, or the experimental VM driver.

Use `openshell` first to identify the active endpoint. Then use the platform tools that match the gateway's compute driver: `docker`, `podman`, `kubectl`/`helm`, or VM driver logs.

## Overview

The target deployment flow is:

1. Operator starts or deploys the gateway with system packages, systemd, Helm, or a development task. The CLI does not start, stop, or destroy gateway services.
2. Operator configures the compute driver.
3. Operator provides TLS and SSH relay material for the deployment mode.
4. The CLI registers a reachable gateway endpoint with `openshell gateway add`.
5. The gateway creates sandboxes through the selected compute driver.

For local evaluation only, TLS may be disabled and the gateway can be reached through `http://127.0.0.1:<port>`.

## Prerequisites

- The `openshell` CLI must be available for endpoint checks.
- Know the active gateway name and endpoint, or be able to inspect local gateway metadata.
- Know the compute platform: Docker, Podman, Kubernetes, or VM.
- For Kubernetes: `kubectl` must target the cluster that hosts OpenShell and Helm version 3 or later must be available.
- For Docker or Podman: the runtime socket must be reachable from the gateway host.

## Workflow

Run diagnostics in order and stop once the root cause is clear.

### Step 1: Check CLI Reachability

```bash
openshell gateway info
openshell status
```

Common findings:

- `No active gateway`: register one with `openshell gateway add <endpoint>`.
- Connection refused: gateway process is not running, service exposure is wrong, or a port-forward/proxy is not active.
- TLS/certificate errors: CLI mTLS bundle does not match the gateway CA, or the gateway is running with unexpected TLS settings.

### Step 2: Identify the Compute Platform

Use gateway metadata, deployment values, or the user's setup notes to identify the driver.

| Platform | Primary checks |
|---|---|
| Docker | Gateway process logs, Docker daemon health, sandbox containers, image pulls. |
| Podman | Podman socket, rootless networking, sandbox containers, image pulls. |
| Kubernetes | Helm release, StatefulSet, service, secrets, sandbox pods, events. |
| VM | VM driver logs, rootfs availability, host virtualization support. |

### Step 3: Check Docker-Backed Gateways

```bash
docker info
docker ps --filter name=openshell
docker logs <container> --tail=200
openshell status
```

Common findings:

- Docker daemon unavailable: start Docker Desktop or Docker Engine.
- Gateway process stopped: inspect exit status and logs.
- Sandbox image missing or pull denied: verify image reference and registry credentials.
- Sandbox never registers: check gateway logs and supervisor callback endpoint.

For source checkout development, restart the local gateway with:

```bash
mise run gateway:docker
```

### Step 4: Check Podman-Backed Gateways

```bash
podman info
podman ps --filter name=openshell
podman logs <container> --tail=200
openshell status
```

Common findings:

- Podman socket unavailable: start or expose the user socket.
- Rootless networking unavailable: inspect Podman network configuration.
- Sandbox image missing or pull denied: verify image reference and registry credentials.
- Supervisor cannot call back: check callback endpoint and gateway logs.

### Step 5: Check Kubernetes Helm Gateways

```bash
helm -n openshell status openshell
helm -n openshell get values openshell
kubectl -n openshell get statefulset,pod,svc,pvc
kubectl -n openshell logs statefulset/openshell --tail=200
kubectl -n openshell rollout status statefulset/openshell
```

Look for failed installs, unexpected values, missing namespace, wrong image tag, TLS settings that do not match the registered endpoint, and scheduling failures.

Check required Helm deployment secrets:

```bash
kubectl -n openshell get secret \
  openshell-ssh-handshake \
  openshell-server-tls \
  openshell-server-client-ca \
  openshell-client-tls
```

Check the image references currently used by the gateway deployment:

```bash
kubectl -n openshell get statefulset openshell -o jsonpath="{.spec.template.spec.containers[*].image}{\"\n\"}{.spec.template.spec.containers[*].env[?(@.name==\"OPENSHELL_SUPERVISOR_IMAGE\")].value}{\"\n\"}"
helm -n openshell get values openshell | grep -E 'repository|tag|supervisorImage'
```

The gateway image and `server.supervisorImage` should use the same build tag in branch and E2E deploys. A stale supervisor image can make sandbox behavior lag behind gateway policy or proto changes.

For plaintext local evaluation, confirm the chart has:

```bash
helm -n openshell get values openshell | grep -E 'disableTls|grpcEndpoint'
```

Expected shape:

```yaml
server:
  disableTls: true
  grpcEndpoint: http://openshell.openshell.svc.cluster.local:8080
```

Check service exposure:

```bash
kubectl -n openshell get svc openshell -o wide
kubectl -n openshell get endpoints openshell
```

For local port-forward testing:

```bash
kubectl -n openshell port-forward svc/openshell 8080:8080
openshell gateway add http://127.0.0.1:8080 --local --name local
openshell status
```

If the gateway is healthy but sandbox creation fails:

```bash
kubectl -n openshell get pods
kubectl -n openshell get events --sort-by=.lastTimestamp | tail -n 50
kubectl -n openshell logs statefulset/openshell --tail=200
```

Check the configured sandbox namespace:

```bash
helm -n openshell get values openshell | grep sandboxNamespace
```

Then inspect sandbox resources in that namespace.

### Step 6: Check VM-Backed Gateways

Use the VM driver logs and host diagnostics available in the user's environment. Verify:

- The VM driver process is running and reachable by the gateway.
- The runtime rootfs exists and matches the expected architecture.
- Host virtualization support is enabled.
- The sandbox supervisor can establish its callback connection to the gateway.

Then run:

```bash
openshell status
openshell logs <sandbox-name>
```

## Common Failure Patterns

| Symptom | Likely cause | Check |
|---|---|---|
| `openshell status` fails | Gateway endpoint unreachable or auth mismatch | `openshell gateway info`, gateway logs |
| Gateway starts but sandbox create fails | Compute driver cannot reach runtime | Docker/Podman/Kubernetes/VM driver logs |
| Docker or Podman sandbox never registers | Wrong callback endpoint or supervisor startup failure | Gateway logs and sandbox container logs |
| Kubernetes gateway pod pending | PVC unbound, taint, selector, or insufficient resources | `kubectl -n openshell describe pod <pod>` |
| Kubernetes gateway pod crash loops | Missing secret, bad DB URL, bad TLS config | `kubectl -n openshell logs statefulset/openshell` |
| CLI TLS error | Local mTLS bundle does not match server cert/CA | Check `~/.config/openshell/gateways/<name>/mtls/` |
| Image pull failure | Gateway or sandbox image cannot be pulled | Runtime events and image pull credentials |
| `K8s namespace not ready` with `envoy-gateway-openshell.yaml: the server could not find the requested resource` | Optional Gateway API manifest was applied without Envoy Gateway CRDs, or k3s Helm controller startup exceeded the namespace wait | Apply `deploy/kube/manifests/envoy-gateway-openshell.yaml` manually only after Envoy Gateway is installed and `grpcRoute` is enabled |

## Reporting

When handing results back to the user, include:

- Active gateway endpoint and auth mode.
- Compute platform and driver.
- Gateway process or workload status.
- Recent gateway log summary.
- Missing or malformed TLS or SSH relay material.
- Service exposure status.
- Sandbox workload status.
- The exact command that failed and the shortest fix.
