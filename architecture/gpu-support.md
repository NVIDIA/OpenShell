# Plan: GPU Support for Cluster Bootstrapping

## Summary

Add NVIDIA GPU passthrough support to the cluster bootstrap flow. When a user runs
`openshell gateway start --gpu`, the Docker container is created with GPU device
requests, the NVIDIA container runtime is available inside k3s, and the NVIDIA
k8s-device-plugin is deployed so Kubernetes workloads can request `nvidia.com/gpu`
resources.

## Assumptions

- The target host has NVIDIA drivers installed and working (`nvidia-smi` succeeds)
- The host has the NVIDIA Container Toolkit installed (Docker can run `--gpus all`)
- The cluster uses a single Docker image; GPU behavior is activated at runtime via `--gpu`

## Architecture Overview

The GPU pipeline has four layers, each of which must work for workloads to get GPU access:

```
Host GPU drivers & NVIDIA Container Toolkit
    └─ Docker: --gpus all (DeviceRequests in bollard API)
        └─ k3s/containerd: nvidia-container-runtime on PATH → auto-detected
            └─ k8s: nvidia-device-plugin DaemonSet advertises nvidia.com/gpu
                └─ Pods: request nvidia.com/gpu in resource limits
```

---

## Changes Required

### 1. CLI: Add `--gpu` flag to `gateway start`

**File:** `crates/navigator-cli/src/main.rs` (~line 646-718)

Add a `--gpu` boolean flag to the `GatewayCommands::Start` variant:

```rust
/// Enable NVIDIA GPU passthrough.
///
/// Passes all host GPUs into the cluster container and deploys
/// the NVIDIA k8s-device-plugin so Kubernetes workloads can
/// request `nvidia.com/gpu` resources. Requires NVIDIA drivers
/// and the NVIDIA Container Toolkit on the host.
#[arg(long)]
gpu: bool,
```

Thread the flag through the dispatch at ~line 1189 into `gateway_admin_deploy`.

**File:** `crates/navigator-cli/src/run.rs` (~line 1063)

Add `gpu: bool` parameter to `gateway_admin_deploy()`. Pass it into `DeployOptions`.

### 2. Bootstrap library: Thread GPU option

**File:** `crates/navigator-bootstrap/src/lib.rs`

Add `pub gpu: bool` to `DeployOptions` (~line 101), defaulting to `false` in `new()`.

Add builder method:
```rust
pub fn with_gpu(mut self, gpu: bool) -> Self {
    self.gpu = gpu;
    self
}
```

In `deploy_gateway_with_logs()` (~line 246), extract `options.gpu` and pass it to `ensure_container()`.

### 3. Docker container creation: GPU device requests

**File:** `crates/navigator-bootstrap/src/docker.rs` (~line 234)

Add `gpu: bool` parameter to `ensure_container()`.

When `gpu` is true, add GPU device passthrough to the `HostConfig`:

```rust
if gpu {
    host_config.device_requests = Some(vec![DeviceRequest {
        driver: Some("nvidia".to_string()),
        count: Some(-1), // all GPUs
        capabilities: Some(vec![vec![
            "gpu".to_string(),
            "utility".to_string(),
            "compute".to_string(),
        ]]),
        ..Default::default()
    }]);
}
```

The bollard crate (`v0.20`) exposes `DeviceRequest` in `bollard::models::DeviceRequest` —
this is the programmatic equivalent of `docker run --gpus all`.

With `--gpus all` via DeviceRequests, Docker + NVIDIA Container Toolkit handles device
injection automatically (the runtime hook injects `/dev/nvidia*` devices and NVIDIA
libraries). No manual device/bind mounts needed.

Additionally, pass an environment variable to the entrypoint:
```rust
if gpu {
    env_vars.push("GPU_ENABLED=true".to_string());
}
```

### 4. Dockerfile.cluster: Install NVIDIA Container Runtime

**File:** `deploy/docker/Dockerfile.cluster`

Use a multi-stage build to install the NVIDIA Container Toolkit binaries from an
Ubuntu stage, then copy them into the k3s Alpine image. This makes the
`nvidia-container-runtime` binary available on PATH so k3s auto-detects it.

```dockerfile
# --- Stage: nvidia-toolkit (only used for runtime binaries) ---
FROM ubuntu:24.04 AS nvidia-toolkit
RUN apt-get update && apt-get install -y --no-install-recommends \
        gpg curl ca-certificates && \
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
        | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg && \
    curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
        | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
        | tee /etc/apt/sources.list.d/nvidia-container-toolkit.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends nvidia-container-toolkit && \
    rm -rf /var/lib/apt/lists/*

# --- Main stage ---
FROM rancher/k3s:${K3S_VERSION}

# Copy NVIDIA Container Toolkit binaries from the build stage.
# k3s auto-detects nvidia-container-runtime on PATH and registers it as
# a containerd runtime class.
COPY --from=nvidia-toolkit /usr/bin/nvidia-container-runtime /usr/bin/
COPY --from=nvidia-toolkit /usr/bin/nvidia-container-runtime-hook /usr/bin/
COPY --from=nvidia-toolkit /usr/bin/nvidia-container-cli /usr/bin/
COPY --from=nvidia-toolkit /usr/bin/nvidia-ctk /usr/bin/
# Copy the shared libraries that nvidia-container-cli depends on
COPY --from=nvidia-toolkit /usr/lib/x86_64-linux-gnu/libnvidia-container* /usr/lib/
```

**Note:** The NVIDIA Container Toolkit binaries depend on `libnvidia-container.so`.
The multi-stage COPY includes these shared libraries. At runtime, when `--gpus` is
used, Docker's NVIDIA runtime hook injects the actual GPU driver libraries
(`libcuda.so`, etc.) from the host into the container, so we don't need to bundle those.

**Note:** Adding ~15MB to the base image is acceptable for single-image simplicity.
Could gate behind a build arg later if needed.

### 5. Cluster Entrypoint: Conditionally deploy GPU manifests

**File:** `deploy/docker/cluster-entrypoint.sh`

Add a section gated on the `GPU_ENABLED` environment variable that copies the
NVIDIA device plugin HelmChart manifest into the k3s manifests directory.
Place after the existing manifest copy block (after ~line 311):

```sh
# ---------------------------------------------------------------------------
# GPU support: deploy NVIDIA device plugin when GPU_ENABLED=true
# ---------------------------------------------------------------------------
if [ "${GPU_ENABLED:-}" = "true" ]; then
    echo "GPU support enabled — deploying NVIDIA device plugin"

    # Copy the GPU-specific manifests (HelmChart CRs for nvidia-device-plugin)
    GPU_MANIFESTS="/opt/openshell/gpu-manifests"
    if [ -d "$GPU_MANIFESTS" ]; then
        for manifest in "$GPU_MANIFESTS"/*.yaml; do
            [ ! -f "$manifest" ] && continue
            cp "$manifest" "$K3S_MANIFESTS/"
        done
    fi
fi
```

### 6. NVIDIA Device Plugin Helm Chart CR

Create a new HelmChart CR manifest that uses k3s's built-in Helm controller to
install the NVIDIA device plugin from its official Helm repository.

**File:** `deploy/kube/gpu-manifests/nvidia-device-plugin-helmchart.yaml` **(new file)**

```yaml
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: nvidia-device-plugin
  namespace: kube-system
spec:
  repo: https://nvidia.github.io/k8s-device-plugin
  chart: nvidia-device-plugin
  version: "0.17.1"
  targetNamespace: nvidia-device-plugin
  createNamespace: true
  valuesContent: |-
    runtimeClassName: nvidia
    gfd:
      enabled: true
    nfd:
      enabled: true
```

This single chart deploys:
- The NVIDIA device plugin DaemonSet (advertises `nvidia.com/gpu` resources)
- GPU Feature Discovery (labels nodes with GPU properties)
- Node Feature Discovery (dependency for GFD)

The `runtimeClassName: nvidia` ensures the device plugin pods use the nvidia
RuntimeClass that k3s auto-creates when it detects the nvidia runtime.

**NVIDIA RuntimeClass:** k3s automatically creates RuntimeClass entries for detected
alternative runtimes, including `nvidia`. Per the k3s docs, no manual RuntimeClass
is needed.

### 7. Dockerfile.cluster: Copy GPU manifests

**File:** `deploy/docker/Dockerfile.cluster`

Add a COPY for the GPU-specific manifests and create the directory:

```dockerfile
RUN mkdir -p /var/lib/rancher/k3s/server/manifests \
             /var/lib/rancher/k3s/server/static/charts \
             /etc/rancher/k3s \
             /opt/openshell/manifests \
             /opt/openshell/charts \
             /opt/openshell/gpu-manifests

# Copy GPU-specific manifests (deployed conditionally by entrypoint when GPU_ENABLED=true)
COPY deploy/kube/gpu-manifests/*.yaml /opt/openshell/gpu-manifests/
```

### 8. Containerd Configuration for NVIDIA Runtime

k3s v1.35+ auto-detects `nvidia-container-runtime` on PATH and registers it as a
containerd runtime. Per the [k3s docs](https://docs.k3s.io/advanced#nvidia-container-runtime):

> "K3s will automatically detect alternative container runtimes if they are present
> when K3s starts."

No manual containerd config template is needed. k3s generates the appropriate
`config.toml` entries automatically. The `nvidia` RuntimeClass is also created
automatically.

If needed in the future, `--default-runtime=nvidia` can be added to the k3s
server args to make nvidia the default runtime for all pods.

### 9. Health Check Updates (Optional, Phase 2)

**File:** `deploy/docker/cluster-healthcheck.sh`

Optionally extend the health check to verify GPU availability when `GPU_ENABLED=true`:

```sh
if [ "${GPU_ENABLED:-}" = "true" ]; then
    # Verify nvidia-device-plugin pods are running
    if ! kubectl get ds -n nvidia-device-plugin -o jsonpath='{.items[0].status.numberReady}' 2>/dev/null | grep -q '[1-9]'; then
        echo "HEALTHCHECK_GPU_NOT_READY"
        exit 1
    fi
fi
```

This is optional for the initial implementation and can be added as a follow-up.

---

## File Change Summary

| File | Change |
|------|--------|
| `crates/navigator-cli/src/main.rs` | Add `--gpu` flag to `GatewayCommands::Start`; thread through dispatch |
| `crates/navigator-cli/src/run.rs` | Add `gpu` param to `gateway_admin_deploy` |
| `crates/navigator-bootstrap/src/lib.rs` | Add `gpu: bool` to `DeployOptions` + builder; pass to `ensure_container()` |
| `crates/navigator-bootstrap/src/docker.rs` | Add `gpu` param to `ensure_container`; add `DeviceRequest` to `HostConfig`; add `GPU_ENABLED` env var |
| `deploy/docker/Dockerfile.cluster` | Multi-stage build for NVIDIA Container Toolkit binaries; copy GPU manifests dir |
| `deploy/docker/cluster-entrypoint.sh` | Conditional GPU manifest deployment when `GPU_ENABLED=true` |
| `deploy/kube/gpu-manifests/nvidia-device-plugin-helmchart.yaml` | **New file** — HelmChart CR for NVIDIA device plugin + GFD + NFD |
| `deploy/docker/cluster-healthcheck.sh` | (Optional Phase 2) GPU readiness check |

---

## Call Chain

```
openshell gateway start --gpu
  └─ main.rs: GatewayCommands::Start { gpu: true, ... }
      └─ run.rs: gateway_admin_deploy(..., gpu=true)
          └─ DeployOptions::new(name).with_gpu(true)
              └─ lib.rs: deploy_gateway_with_logs(options)
                  └─ docker.rs: ensure_container(..., gpu=true)
                      ├─ HostConfig.device_requests = [DeviceRequest { driver: "nvidia", count: -1 }]
                      └─ env_vars.push("GPU_ENABLED=true")
                          └─ Container starts → cluster-entrypoint.sh
                              ├─ GPU_ENABLED=true → copies nvidia-device-plugin-helmchart.yaml
                              └─ k3s starts, detects nvidia-container-runtime on PATH
                                  ├─ Registers nvidia RuntimeClass
                                  ├─ Helm controller deploys nvidia-device-plugin
                                  └─ Device plugin DaemonSet discovers GPUs → advertises nvidia.com/gpu
```

---

## Testing Plan

1. **Unit**: Verify `DeployOptions { gpu: true }` produces a `DeviceRequest` in the container config
2. **Integration**: On a GPU-equipped host, run `openshell gateway start --gpu` and verify:
   - `docker inspect` shows GPU device requests
   - `kubectl get runtimeclass nvidia` exists
   - `kubectl get ds -n nvidia-device-plugin` shows the device plugin running
   - `kubectl get nodes -o json | jq '.items[].status.allocatable["nvidia.com/gpu"]'` shows GPU count
3. **Smoke test**: Run a pod with `runtimeClassName: nvidia` and `nvidia.com/gpu: 1` that executes `nvidia-smi`

---

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| NVIDIA Container Toolkit Ubuntu binaries incompatible with k3s Alpine | Test the multi-stage COPY thoroughly; the Go binaries should work cross-distro. `libnvidia-container` is the only C library dependency. |
| Image size increase (~15MB) for non-GPU users | Acceptable tradeoff for single-image simplicity. Could gate behind build arg later. |
| k3s doesn't auto-detect nvidia runtime | Fallback: add an explicit containerd config template in the entrypoint when GPU_ENABLED=true |
| Device plugin helm chart pull fails (no internet in air-gapped) | The HelmChart CR uses `repo:` which requires internet. For air-gapped, chart could be bundled. This is a follow-up concern. |
| Host NVIDIA driver version mismatch with container toolkit | The container toolkit is forward-compatible. Document minimum driver version requirement. |

---

## Out of Scope (Future Work)

- GPU-enabled sandbox image (`deploy/docker/sandbox/Dockerfile.nvidia` already exists as placeholder)
- GPU time-slicing / MPS configuration
- Multi-GPU partitioning
- Air-gapped NVIDIA chart bundling
- GPU selection (specific GPU IDs vs all)
- MIG (Multi-Instance GPU) support
