# GPU Rootfs Manifests

These Kubernetes manifests are injected into the VM rootfs when
`build-rootfs.sh --gpu` is used. During a **full** rootfs build they are
also copied into the k3s auto-deploy manifest directory so they are
applied at pre-init time.

**Phase 2:** deployment from `openshell-vm-init.sh` when
`GPU_ENABLED=true` is not implemented yet; that path will copy or
reconcile these manifests at VM boot.

## NVIDIA Driver Compatibility

| Property | Value |
|---|---|
| Driver branch | 570.x (open kernel modules) |
| Minimum compute capability | sm_70 (Volta V100 and newer) |
| Container toolkit | nvidia-container-toolkit 1.17.x |
| Device plugin Helm chart | 0.18.2 |

### Why open kernel modules?

The 570.x open kernel modules are required for data-center GPUs
(Volta, Turing, Ampere, Hopper, Blackwell). They are the
NVIDIA-recommended driver for passthrough and container workloads.
Consumer GPUs (GeForce) prior to Turing (sm_75) are **not supported**
with open modules — use the proprietary driver branch if needed.

### Host requirements

- IOMMU enabled in BIOS and kernel (`intel_iommu=on` or `amd_iommu=on`)
- GPU bound to `vfio-pci` driver on the host
- `/dev/vfio/vfio` and `/dev/vfio/<group>` accessible
- Host NVIDIA driver version >= 570 (must match or exceed guest driver)

### Files

- `nvidia-device-plugin.yaml` — HelmChart CR that deploys the NVIDIA
  k8s-device-plugin via the k3s Helm controller.
- `nvidia-runtime-class.yaml` — RuntimeClass object so pods can use
  `runtimeClassName: nvidia`.
