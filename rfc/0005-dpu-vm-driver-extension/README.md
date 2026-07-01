---
authors:
  - "@cheese-head"
state: review
---

# RFC 0005 - DPU VM-Driver Extension

## Summary

This RFC adds an in-tree DPU extension for `openshell-driver-vm`.
The extension is vendor-neutral at the host-driver layer, with
BlueField as the first concrete coordinator backend.

The extension lets the VM driver attach a DPU-backed VF/SF to a sandbox
VM, pass the device through to the guest, and delegate L2/L3/L4 network
policy enforcement to a DPU-side coordinator. When the coordinator
supports storage provisioning, the same extension boundary can also
provide a DPU-provisioned rootfs block device to the VM driver.

Default OpenShell builds and deployments without DPU hardware are
unchanged. The extension runs only when `dpu` is listed in VM-driver
extension config.

## Goals

- Provide an in-tree DPU consumer of the VM-driver lifecycle extension
  API.
- Keep host-side DPU integration vendor-neutral.
- Use BlueField as the first concrete backend without requiring DOCA or
  Comch in the OpenShell tree.
- Let DPU coordinators watch sandbox network policy directly from the
  gateway.
- Scope DPU policy access by coordinator identity.
- Preserve existing in-guest L7 policy enforcement and add DPU-side
  L2/L3/L4 enforcement for the VF/SF data path.
- Make policy delivery projection-based so future DPU-capable policy
  domains can be added explicitly.
- Keep DPU operator settings separate from portable sandbox resource
  requests.
- Use the VM driver's typed launch-plan attachments for VF/SF, vDPA, and
  DPU-provisioned storage rather than raw QEMU argument injection.

## Non-Goals

- Defining a separate VM-driver lifecycle extension API.
- Shipping DOCA SDK, Comch transport, or vendor-proprietary link
  dependencies.
- Replacing the in-guest OPA/L7 proxy.
- A final public API for choosing DPU-only networking, vDPA, or
  DPU-provisioned rootfs.
- Multi-DPU per-host scheduling.
- Moving a running sandbox between DPUs.
- Live migration or hot-plug of DPU attachments.
- A required SNAP implementation in the first upstream slice.

## Core Components

### Host Extension

`openshell-dpu-extension` implements `VmLifecycleExtension` and
registers as `dpu` in the VM driver's extension registry.

The extension:

- calls a `DpuCoordinator` before VM launch to allocate a VF/SF;
- updates the VM launch plan with typed network, device, and optional
  storage attachments;
- persists attachment state under the sandbox's extension state;
- reports launch, detach, policy, and health events;
- detaches on sandbox delete;
- reconciles DPU state after driver restart.

### Coordinator Trait

`DpuCoordinator` abstracts the host-to-DPU attachment lifecycle.

The trait covers:

- `health`: firmware, SR-IOV mode, OVS offload, and required control
  checks;
- `attach`: allocate a VF/SF or vDPA endpoint, install initial
  enforcement, and return typed VM attachment details;
- `provision_rootfs` (optional capability): prepare or expose a
  DPU-backed rootfs/block device and return a typed storage attachment;
- `detach`: idempotently release an attachment;
- `list`: report coordinator-known attachments;
- `reconcile`: compare host-restored state with coordinator state;
- `watch_attachment_events`: stream policy and health events back to
  the host extension.

The host extension is written against this trait rather than against
BlueField-specific code.

### Coordinator Backends

This RFC defines two in-tree coordinator backends:

| Backend | Purpose | Default |
| --- | --- | --- |
| `fake` | Unit and integration testing without DPU hardware. | on |
| `bluefield-grpc` | mTLS gRPC client for the BlueField coordinator daemon. | off |

Other vendors can add new coordinator backends without changing the
host extension contract.

### BlueField Coordinator

`openshell-bluefield-coordinator` is the DPU-side daemon. It runs on
the BlueField ARM cores and owns:

- VF/SF allocation;
- vDPA endpoint allocation when supported;
- optional DPU-backed rootfs/block-device provisioning;
- representor and OVS programming;
- policy application and verification;
- durable on-DPU attachment registry;
- policy streaming from the gateway;
- event emission back to the host extension.

The host driver instructs the coordinator to attach and detach
sandboxes. The coordinator owns policy enforcement and policy updates.

### Gateway Policy Stream

`WatchSandboxPolicies` is a gateway RPC for DPU coordinators.

It streams authorized policy projections to coordinator identities. The
initial projection is `NetworkScope`, which is the only projection this
RFC requires. The stream uses:

- `INITIAL` events for initial state;
- `DELTA` events for updates;
- `REMOVED` events for deletion;
- monotonic `seq` values;
- slow-consumer disconnects;
- per-coordinator authorization.

There is no polling fallback. If the gateway does not support the
stream, the DPU extension fails startup cleanly.

### Policy Projections

The gateway must not send the full sandbox policy blob to the DPU.
Instead, it emits explicit, versioned projections. Each projection has
its own schema, capability gate, authorization check, and threat-model
treatment.

The first projection is `NetworkScope`, covering L2/L3/L4 enforcement
for the VF/SF data path. Future projections may be added for domains a
DPU or SmartNIC can actually enforce, such as HTTP/L7 inspection,
credential handling, or selected sandbox identity metadata.

Projection rules:

- projections are opt-in by coordinator capability;
- projections are scoped to delegated sandboxes only;
- each projection exposes the minimum fields needed for enforcement;
- fields that are not enforceable by the DPU stay out of the
  projection;
- credentials and sensitive metadata require their own projection and
  authorization, not implicit inclusion in `NetworkScope`.

Example shape:

```proto
message PolicyProjection {
  string sandbox_id = 1;
  string attachment_id = 2;
  NetworkScope network = 10;
  HttpScope http = 11;          // optional future projection
  CredentialScope credentials = 12; // optional future projection
  MetadataScope metadata = 13;  // optional future projection
}
```

This keeps the policy stream generic without turning it into a broad
"read all policy" channel.

### Policy Reader Role

The gateway adds a `policy-reader` role for DPU coordinators.

The role is scoped to the sandboxes delegated to that coordinator. A
coordinator identity cannot subscribe to the whole fleet's network
policy. The gateway validates sandbox registration against the
coordinator's attachment-derived allowlist.

### NetworkScope

`NetworkScope` is the initial policy projection sent to the DPU. It
contains only the L2/L3/L4 fields a network fabric can enforce.

It does not include:

- filesystem policy;
- process policy;
- L7 request-body or operation-level policy;
- provider credentials;
- unrelated sandbox metadata.

Those domains can be added only through separate projections with
separate coordinator capabilities and authorization rules.

## Relationship to Resource Requests

The DPU extension is not a public resource request API.

Portable sandbox intent such as "attach a DPU-backed VF/SF" should be
expressed through typed device or generic resource requirements with a
stable class name, count, selectors, and namespaced parameters.

The VM driver realizes that request after it has been selected:

```text
resource requirement
  -> gateway selects VM driver
  -> VM driver builds launch plan
  -> dpu extension allocates VF/SF, vDPA, or DPU rootfs as requested
  -> dpu extension updates typed launch-plan attachments
  -> VM driver validates and renders the final launch plan
```

Deployment-specific settings remain extension config, including:

- coordinator backend;
- coordinator endpoint;
- mTLS material;
- initial policy behavior;
- stale policy behavior;
- rate limits;
- `reconcile_mode`.

Public request fields describe what the sandbox needs. DPU extension
config describes how this deployment provides it.

## VM Launch Plan Integration

The DPU extension consumes the VM driver's typed launch plan. It does
not primarily contribute raw QEMU arguments.

The extension may update:

- `plan.network`: replace the default TAP attachment with
  `VmNetworkAttachment::VfioPci` for a VF/SF, or
  `VmNetworkAttachment::Vdpa` for a vDPA endpoint;
- `plan.devices`: add supporting `VmDeviceAttachment::VfioPci` devices
  when the DPU integration needs a non-network PCI device passed through;
- `plan.rootfs`: replace the default host-file root block device with
  `VmStorageAttachment::DpuProvisioned` when the coordinator exposes a
  DPU-provisioned rootfs/block device.

The default QEMU path still uses host-file rootfs plus TAP/vsock. A DPU
extension can deliberately omit TAP by replacing `plan.network` before
the driver validates and renders the launcher configuration.

## Operator Configuration

The extension is enabled through VM-driver config:

```toml
[vm]
extensions = ["dpu"]

[vm.extension."dpu"]
coordinator = "bluefield-grpc"     # or "fake"
coordinator_endpoint = "https://192.168.100.2:8443"
coordinator_ca_path  = "/etc/openshell/dpu/coordinator-ca.pem"
client_cert_path     = "/etc/openshell/dpu/host-client.pem"
client_key_path      = "/etc/openshell/dpu/host-client.key"

initial_policy = "wait-initial"    # "wait-initial" | "baseline"
initial_policy_timeout_ms = 5000
network_class_defaults = "dpu-ovs-isolated"

stale_threshold_ms = 30000
on_stale = "keep-last-known"       # "keep-last-known" | "deny-all"

reconcile_mode = "advisory"        # or "authoritative"
max_attach_qps = 50
max_attachments = 1024
```

Unknown keys fail startup through typed config deserialization.

## Attachment Lifecycle

Create path:

```text
VM driver selected
  -> dpu.before_vm_launch
  -> coordinator.attach
  -> coordinator installs initial enforcement
  -> extension returns PersistedExtensionState
  -> extension updates plan.network / plan.devices / plan.rootfs
  -> VM driver validates and renders typed attachments
  -> VM driver launches sandbox
  -> extension reports bound or detaches on launch failure
```

Delete path:

```text
gateway deletes sandbox
  -> VM driver terminates VM if needed
  -> dpu.after_sandbox_deleted
  -> coordinator.detach
  -> extension state removed
```

The attachment lifetime equals the sandbox lifetime. VM process exit
does not immediately detach the DPU resource; delete does.

### DPU-Provisioned Rootfs

If the coordinator advertises rootfs provisioning, `attach` or
`provision_rootfs` may return a DPU-backed block device. The host
extension represents that as `VmStorageAttachment::DpuProvisioned`.

The RFC intentionally keeps the storage backend behind the coordinator
trait. A BlueField implementation may use SNAP, NVMe emulation, a block
device exposed to the host, or another mechanism, but the VM driver only
sees the typed storage attachment and renders it into the QEMU storage
configuration.

## Initial Policy Bootstrap

The extension must avoid exposing a VF/SF to a guest before enforcement
is installed.

Two modes are supported:

| Mode | Behavior |
| --- | --- |
| `wait-initial` | Register sandbox, wait for gateway `INITIAL`, apply it, then return from `attach`. Timeout fails the create. |
| `baseline` | Apply `network_class_defaults`, return from `attach`, then replace with gateway `INITIAL` when it arrives. |

`wait-initial` is the default because it fails closed when the policy
stream is unavailable.

## Reconcile

On driver restart:

1. `reconcile_before_restore` calls `DpuCoordinator::health`.
2. The VM driver reloads persisted sandbox state.
3. `reconcile_after_restore` compares restored host state with
   coordinator state.

Advisory is the default:

- orphaned DPU attachments are reported as drift;
- no cleanup is performed;
- operators can inspect conditions and logs.

Authoritative reconcile is opt-in:

- the extension must support authoritative behavior;
- the operator must set `reconcile_mode = "authoritative"`;
- the coordinator may garbage-collect attachments it still owns but
  the host driver no longer knows about.

## Lease Fencing

Every attachment has:

- `attachment_id`;
- `lease_generation`;
- `sandbox_id`;
- `host_instance_id`.

`lease_generation` is monotonic per attachment. The coordinator rejects
stale detach or reconcile operations whose generation is older than the
highest generation it has observed for that attachment.

This prevents an old host process or stale restored state from
corrupting a newer attachment allocation.

## Failure Behavior

Policy and coordinator failures can be configured to fail open or fail
closed where appropriate.

Recommended defaults:

| Failure | Default |
| --- | --- |
| Gateway policy stream down before attach | fail closed in `wait-initial` |
| Policy update apply failure | keep last known policy |
| Previous policy unusable or stale | emit `PolicyStale`; optional deny-all |
| Coordinator health missing required controls | refuse new attaches |
| Stale host detach operation | reject by lease generation |

## Security Model

The strongest property is available only when the DPU has an out-of-band
path to the gateway that the host cannot observe or terminate.

With that topology:

- VF/SF egress traverses the DPU representor and can be enforced even
  if the guest is compromised.
- The host driver is not in the policy-read path.
- DPU policy-stream credentials are scoped to the coordinator's
  delegated sandboxes and authorized projections.
- Sensitive policy domains such as L7, credentials, and metadata are
  not exposed unless their projection is explicitly enabled.

Important limitation:

- The default QEMU path still has TAP + virtio-net. A DPU extension must
  replace the network plan and omit TAP for deployments that require all
  guest egress to traverse the DPU-controlled data path. If TAP remains
  present, this RFC enforces only the VF/SF or vDPA data path and does
  not claim all guest egress is DPU-enforced.

## mTLS and Identity

The BlueField coordinator authenticates to the gateway with a dedicated
coordinator credential.

Requirements:

- coordinator private key stays on the DPU;
- gateway maps coordinator identity to an allowlist of sandbox
  attachments;
- cert renewal and revocation are supported;
- CA rotation uses a dual-trust window;
- host proxying of the stream is allowed only for explicitly configured
  development scenarios.

## Observability

The extension and coordinator emit:

- driver-level conditions such as `DpuCoordinatorHealthy`;
- per-sandbox conditions such as `DpuAttachInProgress`,
  `DpuAttachmentBound`, `DpuPolicyApplied`, `DpuPolicyDegraded`,
  `DpuPolicyStale`, and `DpuFirmwareDegraded`;
- OCSF events tagged with the VM-driver extension name;
- coordinator metrics for policy apply latency, offload status,
  event stream reconnects, attachment count, and stale policy count.

## Compatibility

- Default builds do not compile the BlueField gRPC backend.
- The fake backend keeps host-side tests available without hardware.
- The extension does not run unless configured.
- Existing VM sandboxes are unaffected.
- Existing in-guest L7 enforcement remains in place.
- No DOCA, Comch, or proprietary SDK dependency is introduced.

## Open Questions

- Should the DPU resource class be a standard typed device class or a
  generic resource extension?
- What public resource/profile should select DPU-only networking, vDPA,
  or DPU-provisioned rootfs?
- Should `reconcile_mode` remain advisory by default for DPU, or should
  some deployments opt into authoritative by default?
- Should the shared DPU proto remain vendor-neutral, or should vendors
  own separate coordinator protos behind the same trait?
- Should topology verification fail closed automatically at coordinator
  startup?

