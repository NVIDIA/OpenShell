---
authors:
  - "@cheese-head"
state: review
---

# VM-Driver Lifecycle Extension API

## Summary

This RFC makes `openshell-driver-vm` extensible without splitting the VM
driver into multiple driver crates.

It introduces three core changes:

1. `template.platform_config.runtime_class_name` selects the VM backend:
   `libkrun`, `qemu`, or omitted for the default.
2. `VmLifecycleExtension` lets in-tree extensions participate in VM
   launch, launch result handling, delete, and restart reconcile.
3. `VmLaunchPlan` exposes typed rootfs/storage, network, and device
   attachments so extensions can provide hardware resources without raw
   QEMU argument injection.

The default behavior is unchanged: if no backend is requested and no
extension is configured, the VM driver behaves as it does today.

## Goals

- Let users request QEMU without also requesting a GPU.
- Keep `libkrun` as the default VM backend.
- Give in-tree VM extensions a supported way to add launch-time
  resources such as VFIO devices, DPU-backed NICs, vDPA devices, vTPMs,
  encrypted volumes, or audit hooks.
- Keep extension state isolated by extension and sandbox.
- Make restart reconcile explicit, observable, and advisory by default.
- Keep user-facing resource requests separate from VM-driver internal
  attachment details.

## Non-Goals

- A new `openshell-driver-qemu` crate.
- Out-of-tree extension support.
- A public resource-claim API.
- Treating `runtime_class_name` as a network attachment selector.
- Replacing gateway-level compute hooks.
- Automatic VM restart within the same sandbox lifetime.

## Core Components

### Runtime Class

`template.platform_config.runtime_class_name` selects the VM backend:

```yaml
spec:
  template:
    platform_config:
      runtime_class_name: qemu
```

Supported values:

| Value | Behavior |
| --- | --- |
| omitted | Use the driver default, initially `libkrun`. |
| `libkrun` | Use the existing libkrun path. |
| `qemu` | Use QEMU. The default QEMU plan uses TAP and vsock. |

GPU selection remains independent from backend selection. A GPU request
with `libkrun` is rejected with a clear error. A GPU request with
`qemu` uses the existing QEMU + VFIO GPU path.

### Lifecycle Extension

`VmLifecycleExtension` is an in-process VM-driver extension trait.
Extensions are compiled into the VM driver and registered by name.

An extension can:

- allocate per-sandbox state before VM launch;
- add validated environment variables or bounded extra launcher
  arguments;
- add or replace typed rootfs, network, and device attachments;
- react to launch success or launch failure;
- clean up on sandbox delete;
- reconcile its external state after driver restart.

The VM driver remains the source of truth for sandbox lifecycle. An
extension owns only the external or attached state it allocates.

### Launch Plan

Before spawning the VM, the driver builds a `VmLaunchPlan`.
Configured extensions receive that plan and may mutate validated,
driver-owned fields before the launcher command is rendered.

The selected backend is fixed before extensions run. An extension may
not change `libkrun` to `qemu`, or `qemu` to `libkrun`, after the VM
driver has allocated backend-specific resources.

### Attachments

Launch attachments are typed driver-internal values:

```rust
enum VmStorageAttachment {
    HostFile { path, read_only },
    HostBlockDevice { path, read_only },
    DpuProvisioned { id, device, read_only },
}

struct VmRootfsConfig {
    root: VmStorageAttachment,
    overlay: VmStorageAttachment,
    image: Option<VmStorageAttachment>,
}

enum VmNetworkAttachment {
    Tap { ifname, guest_ip, host_ip, mac, gateway_port },
    VfioPci { bdf, mac },
    Vdpa { device, mac },
}

enum VmDeviceAttachment {
    VfioPci { bdf, id },
    Vsock { cid },
}
```

The default VM driver builds the same plan as before: host-file rootfs,
host-file overlay, optional host-file prepared image disk, TAP
networking for QEMU, a vhost-vsock device, and optional GPU VFIO.

DPU or hardware-specific extensions can replace `network`, `devices`, or
`rootfs` with typed attachments. For example, a DPU extension can remove
the default TAP attachment and provide a VFIO PCI network function, a
vDPA device, or a DPU-provisioned root block device.

`LauncherArgs` exists as a bounded escape hatch. The renderer validates
allowed flag prefixes, maximum counts, maximum lengths, and
reserved driver-owned flag prefixes before the command is spawned. It
is not the primary hardware-integration mechanism.

### Extension State

Each extension may return a `PersistedExtensionState` from
`before_vm_launch`.

State is stored per sandbox and per extension:

```text
<state_root>/sandboxes/<sandbox_id>/extensions/<extension_name>.json
```

The driver passes that state back only to the extension that created it.
This supports multiple extensions without state collisions.

### Reconcile

Reconcile runs when the driver starts:

1. `reconcile_before_restore`: extension-level health and global checks.
2. VM driver reloads persisted sandboxes.
3. `reconcile_after_restore`: extension checks restored live sandboxes
   against external or attached state.

Reconcile outcomes:

| Outcome | Meaning |
| --- | --- |
| `Ok` | No drift. |
| `Advisory(report)` | Drift found; report only. |
| `Authoritative(report)` | Drift found; extension may repair or clean up. |
| `Failed(status, report)` | Reconcile could not complete. |

`advisory` is the default. An extension can perform authoritative repair
only when both are true:

- the extension declares support for authoritative reconcile;
- the operator sets `reconcile_mode = "authoritative"` for that
  extension.

Otherwise authoritative outcomes are demoted to advisory behavior.

## Operator Configuration

Extensions are configured in VM-driver TOML:

```toml
[vm]
extensions = ["logging"]

[vm.extension."logging"]
reconcile_mode = "advisory"

[vm.extension."logging".timeouts]
before_vm_launch_ms = 15000
```

Rules:

- unknown extension names fail driver startup;
- extension order follows the config list;
- unknown config keys fail startup via typed deserialization;
- absent or empty `extensions` means no extension chain;
- no extension can enable itself at runtime.

## Relationship to Resource Requests

This API is not the public resource request model.

Public sandbox intent, such as "I need one GPU", "I need a DPU-backed
network function", or "I need a vDPA network device", should be
expressed through typed sandbox resource requirements or
driver-specific config namespaces.

The VM driver then realizes that request after it has been selected.
For example:

- a portable GPU request may compile into QEMU VFIO GPU arguments;
- a DPU-backed NIC request may compile into a DPU extension-provided
  `VmNetworkAttachment::VfioPci`;
- a vDPA request may compile into `VmNetworkAttachment::Vdpa`;
- a DPU-backed rootfs request may compile into
  `VmStorageAttachment::DpuProvisioned`;
- a plain QEMU backend request may use TAP because that is how the QEMU
  backend connects networking by default.

`runtime_class_name` chooses the VM backend. It should not be overloaded
to mean "use TAP", "use VFIO", or "use vDPA".

## TAP, VFIO, and vDPA

This RFC enables the VM driver to support TAP, VFIO, and vDPA, but it
does not define a final user-facing selector for all of them.

Current interpretation:

| User intent | Intended path |
| --- | --- |
| Use QEMU | `template.platform_config.runtime_class_name = "qemu"` |
| Use default libkrun path | omit `template.platform_config.runtime_class_name` or set `libkrun` |
| Use QEMU's normal TAP networking | selected implicitly by QEMU backend |
| Attach a GPU by VFIO | typed GPU resource request plus VM driver realization |
| Attach a DPU-backed VF/SF | typed device or generic resource request plus DPU extension |
| Attach vDPA | typed resource request plus VM extension |
| Use DPU-provisioned rootfs | typed storage/resource request plus VM extension |

The important boundary is:

- user-facing requests describe *what* the sandbox needs;
- VM-driver extensions describe *how* this VM driver realizes that need.

## Lifecycle Flow

Create path:

```text
gateway selects VM driver
  -> VM driver selects backend from template.platform_config.runtime_class_name
  -> driver builds VmLaunchPlan
  -> extension.before_vm_launch in config order
  -> driver validates the final typed launch plan
  -> driver renders launcher config and arguments
  -> driver spawns VM
  -> extension.after_vm_launch_succeeded
     or extension.after_vm_launch_failed in config order
```

Delete path:

```text
gateway deletes sandbox
  -> driver terminates VM if needed
  -> extension.after_sandbox_deleted in config order
  -> driver removes sandbox state
```

Restart path:

```text
driver starts
  -> extension.reconcile_before_restore
  -> driver restores live sandbox records
  -> extension.reconcile_after_restore
  -> conditions and metrics report drift or failure
```

## Observability

The driver emits extension metrics and conditions for:

- hook duration and outcome;
- rollback count;
- reconcile outcome;
- dropped condition or OCSF events;
- launcher argument validation failures;
- unhealthy extensions.

OCSF events emitted by extensions are stamped by the driver with:

- `extension_layer = "vm-driver"`
- `extension_name = <extension name>`

## Compatibility

- Empty extension chain preserves existing behavior.
- Omitted `runtime_class_name` preserves existing backend selection.
- QEMU + GPU continues to work through the existing path.
- QEMU without GPU becomes valid.
- `bound_threshold_ms` defaults to `0`, preserving today's
  ready-after-spawn behavior unless operators opt in to a liveness
  threshold.

## Open Questions

- Should TAP, VFIO, and vDPA get a shared typed network attachment
  request shape, or remain separate resource classes?
- Should per-sandbox backend or bound-threshold overrides be added?
- Should runtime extension reload be supported later?