# Kubernetes User Namespace Support

## Context

Kubernetes v1.36 graduated user namespace support to GA (`spec.hostUsers: false`). This feature maps container UID 0 to an unprivileged host UID, making capabilities like `CAP_SYS_ADMIN` container-scoped rather than host-scoped. This is a significant defense-in-depth improvement for OpenShell sandbox pods, which currently require `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, and `SYSLOG` capabilities.

The sandbox supervisor already runs as UID 0 inside the container and performs all privileged operations (namespace creation, seccomp, Landlock) locally — user namespaces confine these powers to the container without breaking functionality.

## Design

**Two-layer configuration:**
- Cluster-wide default: `enable_user_namespaces` on `Config` / `KubernetesComputeConfig` (env var `OPENSHELL_ENABLE_USER_NAMESPACES`, default `false`)
- Per-sandbox override: `optional bool user_namespaces` on `SandboxTemplate` in the proto, translated to `platform_config.host_users` for the K8s driver

**Capability additions when enabled:** Add `SETUID`, `SETGID`, `DAC_READ_SEARCH` to the pod security context (matching the Podman driver at `crates/openshell-driver-podman/src/container.rs:393-400`) — needed because the bounding set is reset inside a user namespace.

**No changes to:** seccomp filters (CLONE_NEWUSER block stays), Landlock, supervisor privilege-drop logic, init containers, and workspace volume ownership semantics (ID-mapped mounts handle ownership transparently). The only mount-related change is the supervisor `hostPath` type in Step 7.

## Changes

### 1. Proto: add `user_namespaces` field to `SandboxTemplate`
**File:** `proto/openshell.proto`

Add `optional bool user_namespaces = 10;` to the `SandboxTemplate` message. Using `optional` distinguishes "not set" (use cluster default) from explicit true/false.

### 2. Core config: add `enable_user_namespaces` to server config
**File:** `crates/openshell-core/src/config.rs`

Add field to `Config`:
```rust
#[serde(default)]
pub enable_user_namespaces: bool,
```
Wire the env var `OPENSHELL_ENABLE_USER_NAMESPACES` (clap handles this on the standalone driver binary; for the in-process server path, `Config` serde does it).

### 3. K8s driver config: add field
**File:** `crates/openshell-driver-kubernetes/src/config.rs`

Add `pub enable_user_namespaces: bool` to `KubernetesComputeConfig`.

### 4. Server: wire config and translate proto field
**File:** `crates/openshell-server/src/lib.rs`

Pass `config.enable_user_namespaces` into the `KubernetesComputeConfig` construction.

**File:** `crates/openshell-server/src/compute/mod.rs` (`build_platform_config`)

Translate the new `SandboxTemplate.user_namespaces` field into `platform_config`:
```rust
if let Some(user_ns) = template.user_namespaces {
    fields.insert("host_users".into(), Value { kind: Some(Kind::BoolValue(!user_ns)) });
}
```

The public API uses `user_namespaces: true` (positive sense) while the K8s driver expects `host_users: false` (K8s convention). The driver inverts this back via `!host_users` to resolve the final pod-level `hostUsers` field.

### 5. K8s driver: add `platform_config_bool` helper
**File:** `crates/openshell-driver-kubernetes/src/driver.rs`

New helper following the existing `platform_config_string` / `platform_config_struct` pattern.

### 6. K8s driver: apply `hostUsers: false` and extended capabilities
**File:** `crates/openshell-driver-kubernetes/src/driver.rs`

- Pass `enable_user_namespaces` through `sandbox_to_k8s_spec` -> `sandbox_template_to_k8s`
- After the `runtimeClassName` block, resolve the effective setting: per-sandbox `platform_config.host_users` overrides cluster default
- Insert `spec.hostUsers: false` when user namespaces are enabled
- Extend the capability list with `SETUID`, `SETGID`, `DAC_READ_SEARCH` when enabled

### 7. K8s driver: change hostPath type to `Directory`
**File:** `crates/openshell-driver-kubernetes/src/driver.rs` (`supervisor_volume`)

Change `"type": "DirectoryOrCreate"` to `"type": "Directory"`. The supervisor path is pre-provisioned during cluster setup; `DirectoryOrCreate` could fail under user namespaces when the mapped UID can't create host directories.

### 8. Standalone driver binary: wire CLI arg
**File:** `crates/openshell-driver-kubernetes/src/main.rs`

Add `#[arg(long, env = "OPENSHELL_ENABLE_USER_NAMESPACES")]` and pass to config construction.

### 9. Helm chart
**File:** `deploy/helm/openshell/values.yaml` — add `enableUserNamespaces: false` under `server:`

**File:** `deploy/helm/openshell/templates/statefulset.yaml` — add conditional env var block:
```yaml
{{- if .Values.server.enableUserNamespaces }}
- name: OPENSHELL_ENABLE_USER_NAMESPACES
  value: "true"
{{- end }}
```

## Risks

| Risk | Mitigation |
|------|------------|
| GPU + user namespaces may conflict (NVIDIA device plugin) | Log a warning when both `gpu: true` and user namespaces are enabled; test before enabling by default |
| hostPath volume ownership with ID-mapped mounts | Step 7 changes to `Directory` type; mount is read-only so ownership doesn't matter for execution |
| sysfs remount in netns setup | Already avoided -- code uses `nsenter` instead of `ip netns exec` (documented at `netns.rs:685`) |
| Requires Linux 5.12+ and supporting runtime | Feature defaults to `false`; failure mode is a clear Kubernetes pod event |
| Nested container environments (DinD / k3s-in-Docker) | Does not work in the local dev cluster; see section below |

## Nested k3s / Docker-in-Docker limitation

User namespaces require **ID-mapped mounts** (Linux 5.12+) so the kernel can transparently remap file ownership between the container's UID space and the host's UID space. When k3s runs inside a Docker container (the `mise run cluster` dev environment), the inner container's root filesystem sits on an overlayfs layer managed by the outer Docker daemon. The overlayfs driver in this nested configuration does not support `MOUNT_ATTR_IDMAP`, so `runc` fails at container init:

```
failed to set MOUNT_ATTR_IDMAP on .../etc-hosts: invalid argument
(maybe the filesystem used doesn't support idmap mounts on this kernel?)
```

This is a kernel/filesystem constraint, not an OpenShell bug. The pod spec is generated correctly (`hostUsers: false`, extended capabilities), but the container runtime cannot fulfil the mount request.

**Where user namespaces work:**
- Bare-metal or VM-based Kubernetes clusters where the node's root filesystem is ext4/xfs/btrfs (all support ID-mapped mounts since Linux 5.12-5.19).
- Managed Kubernetes services (EKS, GKE, AKS) on nodes running a supported kernel.

**Where they do not work:**
- k3s-in-Docker / kind / Docker-in-Docker dev clusters where the inner container uses overlayfs on top of the outer container's overlayfs. The nested overlayfs does not support `MOUNT_ATTR_IDMAP`.
- Nodes running kernels older than 5.12.
- Nodes using filesystems that have not added ID-mapped mount support (e.g., NFS on older kernels).

The e2e test (`e2e/rust/tests/user_namespaces.rs`) accounts for this by verifying only the pod spec fields (`hostUsers`, capabilities) rather than attempting to run a command inside the sandbox.

## Deploying to a real cluster with Helm

User namespaces can be tested end-to-end on Kubernetes 1.33+ clusters where the feature is available (beta through 1.35, GA in 1.36+) with a supporting container runtime. Deploy the gateway with Helm and set `server.enableUserNamespaces=true`:

```shell
helm install openshell deploy/helm/openshell -n openshell \
  --set server.enableUserNamespaces=true \
  --set server.sandboxImage="ghcr.io/nvidia/openshell-community/sandboxes/base:latest" \
  ...
```

The supervisor binary must be present at `/opt/openshell/bin/openshell-sandbox` on every node (hostPath mount). On SELinux-enforcing nodes (RHEL, CoreOS), label it with `chcon -t container_file_t`.

This has been validated end-to-end on OCP 4.22 (K8s 1.35.3, CRI-O 1.35, RHEL CoreOS, kernel 5.14) with full SSH tunnel, workspace init, and sandbox command execution under user namespace isolation. See [kubernetes-user-namespaces-ocp-testing.md](kubernetes-user-namespaces-ocp-testing.md) for the complete step-by-step reproduction guide.

## Verification

1. `mise run pre-commit` -- lint and format pass
2. `mise run test` -- unit tests pass including new tests for:
   - `hostUsers: false` present/absent in generated pod spec based on config combinations
   - Extended capability list when user namespaces enabled
   - `platform_config_bool` helper
   - `Directory` type on supervisor volume
3. `mise run e2e` -- the `user_namespaces` test verifies pod spec correctness against the local dev cluster
4. On a Kubernetes 1.33+ cluster with user namespace support available (OCP, GKE, EKS, bare-metal): deploy with Helm, create a sandbox, and verify `cat /proc/self/uid_map` shows a non-identity mapping (UID 0 maps to a high host UID)
