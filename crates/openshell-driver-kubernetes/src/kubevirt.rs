// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `KubeVirt` runtime mode (proof of concept).
//!
//! When `[openshell.drivers.kubernetes] runtime = "kubevirt"` is configured,
//! the driver provisions sandboxes as `kubevirt.io/v1` `VirtualMachine`
//! objects instead of `agents.x-k8s.io` Sandbox CRs. The `KubeVirt` controller
//! (VM -> VMI -> virt-launcher pod) plays the role the Agent Sandbox
//! controller plays in the pod runtime.
//!
//! Resource model per sandbox:
//! - one `VirtualMachine` carrying the standard `OpenShell` ownership labels
//!   (the durable lifecycle handle; `runStrategy: Once` mirrors the pod
//!   path's `restartPolicy: Never` — supervisor exit is terminal),
//! - one bootstrap `Secret` referenced through a `cloudInitNoCloud` volume
//!   (transport only — the guest init parses the ISO itself, no cloud-init
//!   software required). It carries the boundary bootstrap artifacts only:
//!   the boundary config (claims, supervisor address, public verification
//!   keys), the session TLS key/cert, and the workload uid/gid. No gateway
//!   token, no endpoint, no JWT — nothing the guest could use against the
//!   gateway,
//! - one egress-fence `NetworkPolicy` plus the namespace-wide launcher
//!   isolation floor (deny-all ingress and egress for every
//!   virt-launcher pod; the per-sandbox fence adds only the supervisor
//!   allowance), both owner-referenced to the `VirtualMachine`,
//! - one workspace `PersistentVolumeClaim` mounted by the guest init at
//!   `/sandbox` (mirrors the pod path's PVC-backed workspace), and a
//!   dedicated supervisor Pod with its per-sandbox Service when the
//!   dedicated topology is configured.
//!
//! What the `PoC` deliberately skips: GPU, managed/operator workspace modes,
//! mTLS to the gateway, live-migration/VMI-replacement semantics, and
//! arbitrary OCI sandbox images as VM disks (the guest image is a
//! purpose-built containerDisk).

use std::collections::BTreeMap;

use std::time::Duration;

use k8s_openapi::api::core::v1::{
    PersistentVolumeClaim, PersistentVolumeClaimSpec, VolumeResourceRequirements,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, ApiResource, DeleteParams, ListParams, ObjectList, Preconditions};
use kube::core::DynamicObject;
use kube::{Client, Error as KubeError};
use openshell_core::driver_utils::{
    LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID, LABEL_SANDBOX_NAME,
    LABEL_SANDBOX_WORKSPACE,
};
use openshell_core::proto::compute::v1::{
    DriverCondition, DriverSandbox as Sandbox, DriverSandboxStatus as SandboxStatus,
};

use crate::KubernetesDriverError;
use crate::config::{KubernetesComputeConfig, KubernetesRuntimeMode, WorkspaceMode};
use crate::driver::{sandbox_annotations, sandbox_labels};

pub const KUBEVIRT_GROUP: &str = "kubevirt.io";
pub const KUBEVIRT_VERSION: &str = "v1";
const KUBEVIRT_VM_PLURAL: &str = "virtualmachines";
const KUBEVIRT_RUN_STRATEGY: &str = "Once";

/// Kernel and initramfs locations inside the purpose-built guest image
/// (see `e2e/kubevirt/` for the image build).
const KUBEVIRT_GUEST_KERNEL_PATH: &str = "/boot/vmlinuz-virt";
const KUBEVIRT_GUEST_INITRD_PATH: &str = "/boot/initramfs-virt";
const KUBEVIRT_KERNEL_ARGS: &str =
    "console=ttyS0 root=/dev/vda rw rootfstype=ext4 modules=ext4 init=/opt/openshell/init";

/// Condition reason set on `Ready=False` while the VM is booting. Matches the
/// gateway's transient-reason vocabulary so the sandbox stays `Provisioning`
/// rather than `Error`.
const REASON_VM_NOT_READY: &str = "Starting";

/// Non-transient condition reason: the gateway's phase mapper maps this to
/// the public `Error` phase rather than leaving the sandbox provisioning.
const REASON_VM_FAILED: &str = "VMFailed";

/// Non-transient condition reason for a dedicated generation whose
/// supervisor Pod is gone (`restartPolicy: Never`): without a supervisor
/// the boundary can never connect, so the sandbox maps to the public
/// `Error` phase instead of provisioning forever.
pub const REASON_SUPERVISOR_FAILED: &str = "SupervisorFailed";

/// Non-transient condition reason for a create whose Halted window
/// outlived the deadline (M7): the gateway died mid-create and nothing is
/// driving the VM to `Once`.
pub const REASON_CREATE_TIMED_OUT: &str = "CreateTimedOut";

/// How long the launcher's image-pull backoff may persist before the
/// snapshot maps it to a terminal failure (L4): kubelet retries with
/// exponential backoff (capped at five minutes), so a pull that has not
/// succeeded after two minutes — four failed attempts — is effectively
/// permanent, and the CLI's provision timeout would otherwise expire with
/// only the configuration gate's message. Below the threshold the state
/// stays transient: a slow registry can legitimately back off once.
pub const IMAGE_PULL_BACKOFF_TERMINAL_AFTER_MS: i64 = 2 * 60 * 1000;

/// Parse the Kubernetes RFC 3339 timestamp format to Unix milliseconds,
/// through `k8s-openapi`'s `Time` (already a dependency — the same
/// deserializer the API types use).
fn rfc3339_to_unix_ms(value: &str) -> Option<i64> {
    serde_json::from_value::<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>(
        serde_json::Value::String(value.to_string()),
    )
    .ok()
    .map(|time| time.0.as_millisecond())
}

/// VM annotation recording why the guest image could not be digest-pinned
/// (the side-loaded case: the launcher's init container reports a bare
/// `sha256:` config digest with no repository, which is not pullable).
/// Surfaced as an `ImagePin` condition by the snapshot.
pub const IMAGE_PIN_STATE_ANNOTATION: &str = "openshell.ai/kubevirt-image-pin-state";
/// The annotation's value for the unpinnable side-loaded case.
pub const IMAGE_PIN_NO_REPOSITORY_DIGEST: &str = "no-repository-digest";

/// The digest decision for one observed launcher init-container imageID
/// (M6 digest pinning, option A):
/// - `Patch(String)`: a registry-backed `repo@sha256:<manifest digest>` —
///   the VM spec can be pinned to it verbatim;
/// - `SideLoaded`: a bare `sha256:<config digest>` with no repository
///   (the k3d/ctr side-load path) — never patchable, the tag stays;
/// - `Absent`: nothing observed yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestImageDigest {
    Patch(String),
    SideLoaded,
    Absent,
}

/// Read the guest image digest from the launcher Pod's init containers:
/// `KubeVirt` runs the containerDisk as init containers (`volumerootdisk`,
/// `volumekernel-boot-volume`), so `containerStatuses` holds the
/// virt-launcher image instead. The launcher also runs other init
/// containers (`guest-console-log`) on the VIRT-LAUNCHER image, whose
/// digest must never be pinned — so the status is matched by the image
/// reference the VM spec currently names, not by position or name.
pub fn guest_image_digest(
    launcher_pod: &k8s_openapi::api::core::v1::Pod,
    guest_image: &str,
) -> GuestImageDigest {
    let Some(status) = launcher_pod.status.as_ref() else {
        return GuestImageDigest::Absent;
    };
    let Some(init_statuses) = status.init_container_statuses.as_ref() else {
        return GuestImageDigest::Absent;
    };
    // Match by the POD SPEC's init container image — exactly what KubeVirt
    // rendered from the VM spec — not the status `.image`: the CRI may
    // report the status image under a DIFFERENT name the node knows the
    // same digest as (e.g. a side-loaded copy of a registry-pulled tag),
    // and matching on the status reference silently skips the pin.
    let spec_images: std::collections::HashMap<&str, &str> = launcher_pod
        .spec
        .as_ref()
        .and_then(|spec| spec.init_containers.as_ref())
        .map(|containers| {
            containers
                .iter()
                .map(|container| {
                    (
                        container.name.as_str(),
                        container.image.as_deref().unwrap_or(""),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    for container in init_statuses.iter().filter(|container| {
        spec_images
            .get(container.name.as_str())
            .is_some_and(|spec_image| image_ref_matches(spec_image, guest_image))
    }) {
        let image_id = container.image_id.as_str();
        if image_id.is_empty() {
            continue;
        }
        if image_id.contains('@') {
            // A registry-backed reference: repo@sha256:<manifest digest>.
            return GuestImageDigest::Patch(image_id.to_string());
        }
        // A bare sha256:<config digest>: the side-loaded path, not
        // pullable as a reference.
        return GuestImageDigest::SideLoaded;
    }
    GuestImageDigest::Absent
}

/// Whether a container status `image` reference names the same image as the
/// VM spec's guest image. Containerd normalizes references (adds
/// `docker.io/` and `library/`), so the comparison is on the last path
/// components (repository and tag).
fn image_ref_matches(status_image: &str, guest_image: &str) -> bool {
    fn tail(reference: &str) -> &str {
        // Strip a registry host (contains a port, a dot, or is
        // "localhost"; a repository path's first segment never does),
        // then drop a leading "library/" for docker hub official images.
        let no_host = match reference.split_once('/') {
            Some((host, rest))
                if host.contains(':') || host.contains('.') || host == "localhost" =>
            {
                rest
            }
            _ => reference,
        };
        no_host.strip_prefix("library/").unwrap_or(no_host)
    }
    tail(status_image) == tail(guest_image)
}

/// The VMI's not-ready-since time in Unix milliseconds, from its `Ready`/// The VMI's not-ready-since time in Unix milliseconds, from its `Ready`
/// condition's `lastTransitionTime`. `None` when the VMI carries no such
/// condition — the caller then keeps the pull-backoff state transient
/// (timing fails open, isolation never does).
pub fn vmi_not_ready_since_ms(vmi: &DynamicObject) -> Option<i64> {
    let condition = vmi
        .data
        .get("status")?
        .get("conditions")?
        .as_array()?
        .iter()
        .find(|condition| {
            condition.get("type").and_then(serde_json::Value::as_str) == Some("Ready")
        })?;
    let stamped = condition.get("lastTransitionTime")?.as_str()?;
    rfc3339_to_unix_ms(stamped)
}

/// Classify a terminal VM failure from the printable status and the paired
/// VMI's phase. Returns a human-readable summary when the VM has failed.
///
/// Terminal printable statuses (per `KubeVirt` v1.9's
/// `VirtualMachinePrintableStatus`): `CrashLoopBackOff`,
/// `ErrorUnschedulable`, `ErrorPvcNotFound`, and `DataVolumeError` mean the
/// VM cannot run and will not recover on its own.
///
/// Deliberately **not** terminal:
/// - `Unknown` (the controller could not obtain the VM state) can appear
///   transiently during apiserver/communication hiccups; mapping it to
///   `Error` would flip a booting sandbox to `Error` on a blip.
/// - `ErrImagePull` / `ImagePullBackOff`: kubelet retries the pull, so they
///   stay transient — but the condition message carries the printable
///   status so the cause is visible while the sandbox provisions.
/// - A `Failed` or `Succeeded` VMI under a not-ready VM **is** terminal: the
///   guest exited (kernel panic, supervisor death, or a completed `Once`
///   run). Without the VMI signal those states are indistinguishable from
///   a not-yet-booted VM, whose printable status is also `Stopped`.
pub fn terminal_vm_failure(
    printable_status: &str,
    vmi_phase: Option<&str>,
    vm_ready: bool,
) -> Option<String> {
    match printable_status {
        "CrashLoopBackOff" | "ErrorUnschedulable" | "ErrorPvcNotFound" | "DataVolumeError" => {
            return Some(format!("printableStatus {printable_status}"));
        }
        _ => {}
    }
    if !vm_ready {
        match vmi_phase {
            Some("Failed") => return Some("VirtualMachineInstance phase Failed".to_string()),
            Some("Succeeded") => {
                return Some("VirtualMachineInstance phase Succeeded (guest exited)".to_string());
            }
            _ => {}
        }
    }
    None
}

/// Namespaced API for `kubevirt.io/v1` `virtualmachines`.
pub fn virtual_machine_api(client: &Client, namespace: &str) -> Api<DynamicObject> {
    Api::namespaced_with(client.clone(), namespace, &virtual_machine_api_resource())
}

pub fn virtual_machine_api_resource() -> ApiResource {
    ApiResource {
        group: KUBEVIRT_GROUP.to_string(),
        version: KUBEVIRT_VERSION.to_string(),
        api_version: format!("{KUBEVIRT_GROUP}/{KUBEVIRT_VERSION}"),
        kind: "VirtualMachine".to_string(),
        plural: KUBEVIRT_VM_PLURAL.to_string(),
    }
}

/// Check that the cluster serves `kubevirt.io/v1` virtualmachines.
pub async fn kubevirt_available(client: &Client, namespace: &str) -> Result<(), String> {
    let api = virtual_machine_api(client, namespace);
    match api.list(&ListParams::default().limit(1)).await {
        Ok(_) => Ok(()),
        Err(KubeError::Api(err)) if err.code == 404 => Err(format!(
            "kubevirt.io/{KUBEVIRT_VERSION} virtualmachines is not served by this cluster; \
             install KubeVirt to use runtime = \"kubevirt\""
        )),
        Err(err) => Err(err.to_string()),
    }
}

/// Everything the renderer needs for one sandbox.
pub struct KubeVirtSandboxParams<'a> {
    pub sandbox: &'a Sandbox,
    pub config: &'a KubernetesComputeConfig,
    pub namespace: &'a str,
    /// `KubeVirt` resource name (`{workspace}--{name}` in shared mode).
    pub kube_name: &'a str,
}

/// Render the workspace PVC. The guest init formats it on first boot (sentinel
/// guarded, same pattern as the pod path's init-container seeding) and mounts
/// it at `/sandbox`.
pub fn render_workspace_pvc(params: &KubeVirtSandboxParams<'_>) -> PersistentVolumeClaim {
    let storage_class = (!params.config.workspace_storage_class.is_empty())
        .then(|| params.config.workspace_storage_class.clone());
    PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(workspace_pvc_name(params.kube_name)),
            namespace: Some(params.namespace.to_string()),
            labels: Some(sandbox_labels(
                params.sandbox,
                Some(&params.config.gateway_id),
            )),
            annotations: Some(sandbox_annotations(params.sandbox)),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            resources: Some(VolumeResourceRequirements {
                requests: Some(BTreeMap::from([(
                    "storage".to_string(),
                    Quantity(params.config.workspace_default_storage_size.clone()),
                )])),
                ..Default::default()
            }),
            storage_class_name: storage_class,
            ..Default::default()
        }),
        status: None,
    }
}

/// Render the `VirtualMachine`.
pub fn render_virtual_machine(params: &KubeVirtSandboxParams<'_>) -> DynamicObject {
    let sandbox = params.sandbox;
    let kubevirt = &params.config.kubevirt;
    // The kernel args boot the purpose-built initramfs init, which mounts
    // the containerDisk root read-only and stacks a writable tmpfs overlay
    // (the guest root is writable at runtime and fresh from the image on
    // every boot — the guest is untrusted once a workload has run).
    let kernel_args = KUBEVIRT_KERNEL_ARGS;
    let mut labels = sandbox_labels(sandbox, Some(&params.config.gateway_id));
    let annotations = sandbox_annotations(sandbox);

    let mut container_disk = serde_json::json!({
        "image": kubevirt.guest_image,
    });
    if !kubevirt.guest_image_pull_policy.is_empty() {
        container_disk["imagePullPolicy"] = serde_json::json!(kubevirt.guest_image_pull_policy);
    }

    let disks = vec![
        serde_json::json!({"name": "rootdisk", "disk": {"bus": "virtio"}}),
        serde_json::json!({"name": "cloudinit", "disk": {"bus": "virtio"}}),
    ];
    let mut volumes = vec![
        serde_json::json!({"name": "rootdisk", "containerDisk": container_disk}),
        serde_json::json!({
            "name": "cloudinit",
            "cloudInitNoCloud": {
                "secretRef": {"name": bootstrap_secret_name(params.kube_name)}
            }
        }),
    ];
    // The workspace PVC is a filesystem volume (the cluster's default
    // storage class provisions filesystem PVCs), which KubeVirt shares
    // with the guest via virtio-fs rather than as a block disk.
    let mut filesystems = Vec::new();
    if kubevirt.workspace_pvc {
        filesystems.push(serde_json::json!({
            "name": "workspace",
            "virtiofs": {}
        }));
        volumes.push(serde_json::json!({
            "name": "workspace",
            "persistentVolumeClaim": {"claimName": workspace_pvc_name(params.kube_name)}
        }));
    }

    // VMI inherits template labels; keeping the OpenShell ownership labels
    // there makes VMI-scoped tooling (describe, events) correlate as well.
    labels.insert(
        KUBEVIRT_VM_LABEL.to_string(),
        KUBEVIRT_VM_LABEL_VALUE.to_string(),
    );
    // The boundary-role workload label: KubeVirt propagates template labels
    // to the virt-launcher pod, and the shared supervisor's ingress
    // NetworkPolicy (deploy/helm/openshell/templates/
    // supervisor-networkpolicy.yaml) admits connections only from pods
    // carrying this label.
    labels.insert(
        crate::isolation::BOUNDARY_ROLE_LABEL.to_string(),
        "workload".to_string(),
    );
    // The boundary-pair label binds the launcher pod to this sandbox's pair,
    // exactly as the pod path's workload pods carry it: the dedicated
    // topology's control NetworkPolicy and egress fence select the pair's
    // two roles with it (isolation.rs pair_role_labels).
    labels.insert(
        crate::isolation::BOUNDARY_PAIR_LABEL.to_string(),
        crate::sandbox_runtime::pair_label_value(&sandbox.id),
    );

    // Direct kernel boot: the guest image is purpose-built (see
    // `e2e/kubevirt/`), so no bootloader is installed in the rootfs. The
    // kernel and initramfs live next to the rootfs disk inside the same
    // containerDisk image.
    let mut kernel_boot_container = serde_json::json!({
        "image": kubevirt.guest_image,
        "kernelPath": KUBEVIRT_GUEST_KERNEL_PATH,
        "initrdPath": KUBEVIRT_GUEST_INITRD_PATH,
    });
    if !kubevirt.guest_image_pull_policy.is_empty() {
        kernel_boot_container["imagePullPolicy"] =
            serde_json::json!(kubevirt.guest_image_pull_policy);
    }

    let data = serde_json::json!({
        "spec": {
            "runStrategy": KUBEVIRT_RUN_STRATEGY,
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "domain": {
                        "firmware": {
                            "kernelBoot": {
                                "container": kernel_boot_container,
                                "kernelArgs": kernel_args
                            }
                        },
                        "cpu": {"cores": kubevirt.cpu_cores},
                        "resources": {"requests": {"memory": kubevirt.memory}},
                        "devices": {
                            "disks": disks,
                            "filesystems": filesystems,
                            "interfaces": [{"name": "default", "masquerade": {}}],
                            // Minimal device surface: a root guest drives every
                            // emulated device, so nothing optional is attached.
                            // No graphics, no memory balloon, no VSOCK — the
                            // serial console stays for the boot log. Still
                            // present per the live domain XML: the guest-agent
                            // virtio-serial channel (KubeVirt adds it
                            // unconditionally; a hook sidecar is the removal
                            // path, pending a design call), the q35 implicit
                            // PS/2 input devices, the iTCO watchdog (a root
                            // guest can arm it for an in-place reset — the
                            // reset detection covers it), and empty SATA/SCSI
                            // controllers. The RFC documents the full
                            // inventory.
                            "autoattachGraphicsDevice": false,
                            "autoattachMemBalloon": false,
                            "autoattachInputDevice": false,
                            "autoattachVSOCK": false,
                            "autoattachSerialConsole": true
                        }
                    },
                    "volumes": volumes,
                    "networks": [{"name": "default", "pod": {}}]
                }
            }
        }
    });

    let mut obj = DynamicObject::new(params.kube_name, &virtual_machine_api_resource());
    obj.metadata = ObjectMeta {
        name: Some(params.kube_name.to_string()),
        namespace: Some(params.namespace.to_string()),
        labels: Some(sandbox_labels(sandbox, Some(&params.config.gateway_id))),
        annotations: Some(annotations),
        ..Default::default()
    };
    obj.data = data;
    obj
}

/// Label set on the VM template so the VMI (and virt-launcher pod) carry the
/// `OpenShell` ownership markers.
const KUBEVIRT_VM_LABEL: &str = "kubevirt.io/domain";
const KUBEVIRT_VM_LABEL_VALUE: &str = "openshell";

/// The workload identity the `KubeVirt` guest's boundary runs as. The guest
/// image provisions this uid/gid (the `sandbox` user in the Alpine guest).
pub const KUBEVIRT_WORKLOAD_UID: u32 = 10001;
pub const KUBEVIRT_WORKLOAD_GID: u32 = 10001;

/// The workload identity and mode claim for a config: root mode runs as
/// uid/gid 0 with the "root" mode claim; the sandboxed default keeps the
/// provisioned sandbox uid/gid with the "sandboxed" claim.
pub fn guest_workload_identity(
    config: &KubernetesComputeConfig,
) -> (u32, u32, crate::config::KubeVirtWorkloadMode) {
    match config.kubevirt.workload {
        crate::config::KubeVirtWorkloadMode::Root => {
            (0, 0, crate::config::KubeVirtWorkloadMode::Root)
        }
        crate::config::KubeVirtWorkloadMode::Sandboxed => (
            KUBEVIRT_WORKLOAD_UID,
            KUBEVIRT_WORKLOAD_GID,
            crate::config::KubeVirtWorkloadMode::Sandboxed,
        ),
    }
}

/// Set on the `VirtualMachine` while the driver's create still holds it
/// `Halted` (the W6 window between capturing the VM's UID and patching
/// `runStrategy` to `Once`). A `Halted` VM with this annotation maps to a
/// `Bootstrapping=True` condition — the gateway composes `Provisioning`,
/// the same escape the pod path uses for a starting generation — instead
/// of `Suspended=True`, which would compose `Stopped` and withdraw the
/// shared-supervisor instance before the guest's boundary can dial. A
/// `Halted` VM WITHOUT the annotation is a user stop (`Suspended=True`).
pub const KUBEVIRT_CREATE_IN_FLIGHT_ANNOTATION: &str = "openshell.ai/kubevirt-create-in-flight";

/// How long the create's Halted window may last before the driver maps the
/// VM to a terminal create timeout (M7). The window is seconds in a healthy
/// create; a gateway that died mid-create leaves the VM Halted with the
/// in-flight annotation, and a gateway restarted from a clean database has
/// no sandbox record for its own provisioning-deadline reclaim — the
/// driver-side deadline makes the wedge visible (public Error) either way.
pub const KUBEVIRT_CREATE_DEADLINE_MS: i64 = 10 * 60 * 1000;

/// The create's in-flight annotation value: the Unix-millisecond timestamp
/// of the Halted-window start (older revisions wrote a bare "true", which
/// parses to no deadline).
/// The guest image the VM actually boots: the containerDisk reference in
/// the VM spec's direct kernel boot (M6: the claim tracks what runs, not
/// the configured string — after a config change, start must not claim an
/// image the VM is not booting).
pub fn kubevirt_boot_image(vm: &DynamicObject) -> String {
    vm.data
        .pointer("/spec/template/spec/domain/firmware/kernelBoot/container/image")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn kubevirt_create_in_flight_since(obj: &DynamicObject) -> Option<i64> {
    obj.metadata
        .annotations
        .as_ref()?
        .get(KUBEVIRT_CREATE_IN_FLIGHT_ANNOTATION)?
        .parse::<i64>()
        .ok()
}

pub fn bootstrap_secret_name(kube_name: &str) -> String {
    format!("{kube_name}-bootstrap")
}

pub fn workspace_pvc_name(kube_name: &str) -> String {
    format!("{kube_name}-workspace")
}

/// Map a `VirtualMachine` object to a driver sandbox snapshot without VMI
/// phase context. Production paths join the VMI phase (see
/// [`sandbox_from_vm_object_with_vmi`]); this convenience wrapper exists for
/// callers with only a VM object at hand.
#[cfg(test)]
fn sandbox_from_vm_object(
    namespace: &str,
    obj: DynamicObject,
) -> Result<(String, Sandbox), String> {
    sandbox_from_vm_object_with_vmi(namespace, obj, None)
}

/// Map a `VirtualMachine` object, joined with its paired VMI's phase, to a
/// driver sandbox snapshot.
///
/// Backend observations only: the gateway still composes public `Ready` from
/// the supervisor relay session, exactly as with Sandbox CRs. `vmi_phase` is
/// the phase of the paired `VirtualMachineInstance` when known (the VMI
/// carries the same labels); it distinguishes a failed or completed guest
/// from one that has not booted yet.
#[cfg(test)]
fn sandbox_from_vm_object_with_vmi(
    namespace: &str,
    obj: DynamicObject,
    vmi_phase: Option<&str>,
) -> Result<(String, Sandbox), String> {
    sandbox_from_vm_object_with_runtime(namespace, obj, vmi_phase, None, None, None)
}

/// The full snapshot join: the VM object, its VMI's phase, the dedicated
/// supervisor Pod's failure (when its generation's supervisor is gone or
/// crashed), and the fence drift marker (when the watch reconciler restored
/// a drifted or deleted fence).
pub fn sandbox_from_vm_object_with_runtime(
    namespace: &str,
    obj: DynamicObject,
    vmi_phase: Option<&str>,
    supervisor_failure: Option<&str>,
    fence_restored_at: Option<&str>,
    vmi_not_ready_since_ms: Option<i64>,
) -> Result<(String, Sandbox), String> {
    let kube_name = obj.metadata.name.clone().unwrap_or_default();

    if !is_openshell_managed(&obj) {
        return Err(format!("object {kube_name} not managed by openshell"));
    }
    let Some(id) = annotation_or_label(&obj, LABEL_SANDBOX_ID) else {
        return Err(format!("object {kube_name} missing sandbox id"));
    };
    let Some(name) = annotation_or_label(&obj, LABEL_SANDBOX_NAME) else {
        return Err(format!("object {kube_name} missing sandbox name"));
    };
    let Some(workspace) = annotation_or_label(&obj, LABEL_SANDBOX_WORKSPACE) else {
        return Err(format!("object {kube_name} missing sandbox workspace"));
    };

    let namespace = obj
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| namespace.to_string());
    let status = vm_status_from_object(
        &obj,
        &name,
        vmi_phase,
        supervisor_failure,
        fence_restored_at,
        vmi_not_ready_since_ms,
    );

    Ok((
        kube_name,
        Sandbox {
            id,
            name,
            namespace,
            spec: None,
            status,
            workspace,
        },
    ))
}

/// Translate VM status into driver conditions:
/// - `status.ready == true` becomes a backend `Ready=True` observation.
///   Without a connected supervisor session the gateway still reports
///   `Provisioning` ("`SupervisorNotConnected`") — the central readiness
///   invariant.
/// - `runStrategy: Halted` becomes `Suspended=True` (public `Stopped`).
/// - a terminal VMI phase (`Failed`/`Succeeded` while the VM is not ready) or
///   a terminal printable status (e.g. `CrashLoopBackOff`)
///   becomes `Ready=False` with the non-transient `VMFailed` reason so the
///   gateway surfaces the sandbox as `Error` instead of provisioning forever.
/// - a deletion timestamp becomes `deleting`.
fn vm_status_from_object(
    obj: &DynamicObject,
    sandbox_name: &str,
    vmi_phase: Option<&str>,
    supervisor_failure: Option<&str>,
    fence_restored_at: Option<&str>,
    vmi_not_ready_since_ms: Option<i64>,
) -> Option<SandboxStatus> {
    let status = obj.data.get("status")?;
    let status_obj = status.as_object()?;

    let ready = status_obj
        .get("ready")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    // Only an explicit `runStrategy: Halted` maps to `Suspended`. A fresh VM
    // (or one whose `Once` VMI exited) also reports `printableStatus:
    // Stopped`; treating that as Suspended would flip a provisioning sandbox
    // to public `Stopped`.
    let halted = obj
        .data
        .get("spec")
        .and_then(|spec| spec.get("runStrategy"))
        .and_then(serde_json::Value::as_str)
        == Some("Halted");
    // The create path holds the VM `Halted` while it captures the UID and
    // builds the fence, bootstrap Secret, and shared-instance registration
    // before patching `runStrategy` to `Once`. During that window the
    // annotation above is present: report `Bootstrapping` (the gateway
    // composes `Provisioning`) rather than `Suspended` (which composes
    // `Stopped` and withdraws the supervisor instance the create just
    // registered).
    let create_in_flight = obj
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(KUBEVIRT_CREATE_IN_FLIGHT_ANNOTATION))
        .is_some_and(|value| !value.is_empty());
    let stopped = halted && !create_in_flight;

    let printable = status_obj
        .get("printableStatus")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    let terminal = terminal_vm_failure(printable, vmi_phase, ready).or_else(|| {
        // L4: an image-pull backoff that has persisted past the threshold
        // is terminal — the pull is effectively permanent, and the gateway
        // would otherwise surface only the configuration gate's message
        // until the CLI's provision timeout expires.
        (printable == "ImagePullBackOff"
            && vmi_not_ready_since_ms.is_some_and(|since| {
                openshell_core::time::now_ms() - since > IMAGE_PULL_BACKOFF_TERMINAL_AFTER_MS
            }))
        .then(|| "guest image pull stuck in backoff (the image cannot be pulled)".to_string())
    });

    // A create whose Halted window outlived the deadline is a terminal
    // failure (M7): the gateway died mid-create, and a gateway restarted
    // from a clean database has no record to reclaim with.
    let create_timed_out = halted
        && create_in_flight
        && kubevirt_create_in_flight_since(obj).is_some_and(|since| {
            openshell_core::time::now_ms() - since > KUBEVIRT_CREATE_DEADLINE_MS
        });

    // The image-pin state annotation (M6 digest pinning, side-loaded case)
    // surfaces as an ImagePin condition so operators see that the guest
    // image cannot be digest-pinned.
    let image_not_pinned = matches!(
        obj.metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(IMAGE_PIN_STATE_ANNOTATION))
            .map(String::as_str),
        Some(IMAGE_PIN_NO_REPOSITORY_DIGEST)
    );

    // A dedicated generation whose supervisor Pod is gone or crashed is a
    // terminal failure (`restartPolicy: Never`): the boundary can never
    // connect, so the sandbox surfaces as Error rather than provisioning
    // forever. It wins over the not-ready fallback but not over an
    // already-terminal VM failure. Suppressed while the VM is halted OR
    // halting (`printableStatus: Stopping` — the VMI is terminating): the
    // supervisor exiting then is the expected end of a stop, not a failure
    // (S1 — mapping it aborted stops whose supervisor Pod exited while the
    // stop was still in flight).
    let supervisor_failed =
        supervisor_failure.filter(|_| terminal.is_none() && !halted && printable != "Stopping");

    let mut conditions = Vec::new();
    conditions.push(DriverCondition {
        r#type: "Ready".to_string(),
        status: if ready && terminal.is_none() && supervisor_failed.is_none() {
            "True"
        } else {
            "False"
        }
        .to_string(),
        reason: if terminal.is_some() {
            REASON_VM_FAILED.to_string()
        } else if supervisor_failed.is_some() {
            REASON_SUPERVISOR_FAILED.to_string()
        } else if ready {
            "VMReady".to_string()
        } else if create_timed_out {
            REASON_CREATE_TIMED_OUT.to_string()
        } else {
            REASON_VM_NOT_READY.to_string()
        },
        message: terminal
            .map(|terminal| format!("VirtualMachine failed: {terminal}"))
            .or_else(|| {
                supervisor_failed
                    .map(|failure| format!("dedicated supervisor Pod failed: {failure}"))
            })
            .or_else(|| ready.then(|| "VirtualMachineInstance is running".to_string()))
            .or_else(|| {
                create_timed_out.then(|| {
                    "the create's Halted window outlived the deadline (the gateway \
                     likely died mid-create); stop or delete the sandbox"
                        .to_string()
                })
            })
            .unwrap_or_else(|| {
                // Surface the VMI's phase alongside the printable status
                // so launcher-side problems are visible (L4).
                vmi_phase.map_or_else(
                    || format!("VirtualMachine status: {printable}"),
                    |phase| format!("VirtualMachine status: {printable} (VMI {phase})"),
                )
            }),
        transition_time: None,
    });
    // The watch reconciler re-fenced a drifted or deleted fence and stamped
    // this marker; surface the event so operators see that isolation
    // briefly depended on the namespace-wide default-deny floor.
    if image_not_pinned {
        conditions.push(DriverCondition {
            r#type: "ImagePin".to_string(),
            status: "False".to_string(),
            reason: "NoRepositoryDigest".to_string(),
            message: "image not pinned: no repository digest (side-loaded guest \
                     image); the configured tag is used directly"
                .to_string(),
            transition_time: None,
        });
    }
    if let Some(restored_at) = fence_restored_at {
        conditions.push(DriverCondition {
            r#type: "FenceRestored".to_string(),
            status: "True".to_string(),
            reason: "ReFencedAfterDrift".to_string(),
            message: format!(
                "the egress fence drifted or was deleted and was re-created by the driver \
                 (restored at {} Unix seconds)",
                restored_at
                    .parse::<i64>()
                    .map(|millis| millis / 1000)
                    .map_or_else(|_| restored_at.to_string(), |seconds| seconds.to_string())
            ),
            transition_time: None,
        });
    }
    if halted && create_in_flight {
        conditions.push(DriverCondition {
            r#type: "Bootstrapping".to_string(),
            status: "True".to_string(),
            reason: "SandboxRuntimeGenerationStarting".to_string(),
            message: "driver create is provisioning the VirtualMachine's companions".to_string(),
            transition_time: None,
        });
    }
    if stopped {
        conditions.push(DriverCondition {
            r#type: "Suspended".to_string(),
            status: "True".to_string(),
            reason: "VMHalted".to_string(),
            message: "VirtualMachine runStrategy is Halted".to_string(),
            transition_time: None,
        });
    }

    Some(SandboxStatus {
        name: sandbox_name.to_string(),
        // The VMI is created with the same name as the VM.
        instance_id: obj.metadata.name.clone().unwrap_or_default(),
        agent_fd: String::new(),
        sandbox_fd: String::new(),
        conditions,
        deleting: obj.metadata.deletion_timestamp.is_some(),
        ..Default::default()
    })
}

fn is_openshell_managed(obj: &DynamicObject) -> bool {
    obj.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(LABEL_MANAGED_BY))
        .or_else(|| {
            obj.metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(LABEL_MANAGED_BY))
        })
        .map(String::as_str)
        == Some(LABEL_MANAGED_BY_VALUE)
}

fn annotation_or_label(obj: &DynamicObject, key: &str) -> Option<String> {
    obj.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(key))
        .or_else(|| obj.metadata.labels.as_ref().and_then(|l| l.get(key)))
        .cloned()
}

/// Single-quote a value for the shell-sourceable user-data file.
#[cfg(test)]
fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._-/:+=@".contains(c))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// True when the driver is configured for the `KubeVirt` runtime.
pub fn is_kubevirt_mode(config: &KubernetesComputeConfig) -> bool {
    config.runtime == KubernetesRuntimeMode::KubeVirt
}

/// Shared-mode namespace the VM resources render into.
pub fn kubevirt_namespace(config: &KubernetesComputeConfig) -> Result<String, String> {
    if config.workspace_mode != WorkspaceMode::Shared {
        return Err(format!(
            "kubevirt runtime (PoC) supports only the shared workspace mode; configured mode is {}",
            config.workspace_mode
        ));
    }
    Ok(config.namespace.clone())
}

/// List driver-owned VMs by label selector.
pub async fn list_virtual_machines(
    client: &Client,
    config: &KubernetesComputeConfig,
    selector: &str,
) -> Result<ObjectList<DynamicObject>, KubernetesDriverError> {
    let namespace = kubevirt_namespace(config).map_err(KubernetesDriverError::Message)?;
    let api = virtual_machine_api(client, &namespace);
    api.list(&ListParams::default().labels(selector))
        .await
        .map_err(KubernetesDriverError::from_kube)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(
        unused_imports,
        reason = "used by the tests below; the inline test above also imports super"
    )]
    use super::*;
    use crate::KubernetesComputeConfig;
    use openshell_core::proto::compute::v1::DriverSandbox as Sandbox;

    fn sandbox() -> Sandbox {
        Sandbox {
            id: "sbx-id".to_string(),
            name: "demo".to_string(),
            namespace: "openshell-e2e-ns".to_string(),
            spec: None,
            status: None,
            workspace: "default".to_string(),
        }
    }

    fn config() -> KubernetesComputeConfig {
        KubernetesComputeConfig {
            runtime: KubernetesRuntimeMode::KubeVirt,
            namespace: "openshell-e2e-ns".to_string(),
            gateway_id: "e2e-gateway".to_string(),
            grpc_endpoint: "http://172.18.0.1:18085/".to_string(),
            kubevirt: crate::KubeVirtConfig {
                guest_image: "openshell/sandbox-vm:test".to_string(),
                guest_image_pull_policy: "IfNotPresent".to_string(),
                cpu_cores: 2,
                memory: "2Gi".to_string(),
                workspace_pvc: true,
                workload: crate::config::KubeVirtWorkloadMode::default(),
            },
            shared_supervisor: Some(crate::SharedSupervisorConfig {
                service_name: "openshell-supervisor".to_string(),
                service_namespace: "openshell".to_string(),
                runtime_port: 5500,
                token_secret_name: "openshell-supervisor-token".to_string(),
            }),
            ..KubernetesComputeConfig::default()
        }
    }

    fn params<'a>(
        sandbox: &'a Sandbox,
        config: &'a KubernetesComputeConfig,
    ) -> KubeVirtSandboxParams<'a> {
        KubeVirtSandboxParams {
            sandbox,
            config,
            namespace: "openshell-e2e-ns",
            kube_name: "default--demo",
        }
    }

    #[test]
    fn virtual_machine_renders_kubevirt_contract() {
        let cfg = config();
        let vm = render_virtual_machine(&params(&sandbox(), &cfg));

        assert_eq!(vm.metadata.name.as_deref(), Some("default--demo"));
        assert_eq!(vm.metadata.namespace.as_deref(), Some("openshell-e2e-ns"));
        let labels = vm.metadata.labels.expect("labels");
        assert_eq!(
            labels.get(LABEL_MANAGED_BY).map(String::as_str),
            Some("openshell")
        );

        assert_eq!(vm.data["spec"]["runStrategy"], "Once");

        let domain = &vm.data["spec"]["template"]["spec"]["domain"];
        assert_eq!(domain["cpu"]["cores"], 2);
        assert_eq!(domain["resources"]["requests"]["memory"], "2Gi");
        // Direct kernel boot from the purpose-built image.
        assert_eq!(
            domain["firmware"]["kernelBoot"]["container"]["image"],
            "openshell/sandbox-vm:test"
        );
        assert_eq!(
            domain["firmware"]["kernelBoot"]["container"]["kernelPath"],
            "/boot/vmlinuz-virt"
        );
        let kernel_args = domain["firmware"]["kernelBoot"]["kernelArgs"]
            .as_str()
            .expect("kernel args");
        assert!(kernel_args.contains("root=/dev/vda"));
        assert!(kernel_args.contains("init=/opt/openshell/init"));

        let volumes = vm.data["spec"]["template"]["spec"]["volumes"]
            .as_array()
            .unwrap();
        let names: Vec<&str> = volumes
            .iter()
            .map(|v| v["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["rootdisk", "cloudinit", "workspace"]);
        assert_eq!(
            volumes[1]["cloudInitNoCloud"]["secretRef"]["name"],
            "default--demo-bootstrap"
        );
        assert_eq!(
            volumes[2]["persistentVolumeClaim"]["claimName"],
            "default--demo-workspace"
        );

        // The template labels carry the boundary pair and workload role:
        // KubeVirt propagates them to the VMI and virt-launcher pod, where
        // the pod path's control NetworkPolicy and the egress fence select
        // the pair's two roles (isolation.rs pair_role_labels).
        let template_labels = &vm.data["spec"]["template"]["metadata"]["labels"];
        assert_eq!(
            template_labels["openshell.ai/boundary-pair"], "sbx-id",
            "the launcher pod must carry this sandbox's pair label"
        );
        assert_eq!(
            template_labels["openshell.ai/boundary-role"], "workload",
            "the launcher pod must carry the workload role label"
        );

        let filesystems = vm.data["spec"]["template"]["spec"]["domain"]["devices"]["filesystems"]
            .as_array()
            .unwrap();
        assert_eq!(filesystems.len(), 1);
        assert_eq!(filesystems[0]["name"], "workspace");
    }

    #[test]
    fn virtual_machine_minimizes_the_device_surface() {
        // The reviewer's condition 6: a root guest drives every emulated
        // device, so nothing optional is attached — no graphics, no memory
        // balloon, no input. The serial console stays for the boot log.
        let cfg = config();
        let vm = render_virtual_machine(&params(&sandbox(), &cfg));
        let devices = &vm.data["spec"]["template"]["spec"]["domain"]["devices"];
        assert_eq!(devices["autoattachGraphicsDevice"], false);
        assert_eq!(devices["autoattachMemBalloon"], false);
        assert_eq!(devices["autoattachInputDevice"], false);
        assert_eq!(devices["autoattachSerialConsole"], true);
    }

    #[test]
    fn virtual_machine_omits_workspace_without_pvc() {
        let mut cfg = config();
        cfg.kubevirt.workspace_pvc = false;
        let vm = render_virtual_machine(&params(&sandbox(), &cfg));
        let volumes = vm.data["spec"]["template"]["spec"]["volumes"]
            .as_array()
            .unwrap();
        assert_eq!(volumes.len(), 2);
        assert_eq!(
            vm.data["spec"]["template"]["spec"]["domain"]["devices"]["filesystems"]
                .as_array()
                .map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn vm_status_maps_conditions() {
        let cfg = config();
        let vm = render_virtual_machine(&params(&sandbox(), &cfg));
        let mut with_status = vm.clone();
        with_status.data["status"] = serde_json::json!({"ready": true});
        let (_, sbx) =
            sandbox_from_vm_object("openshell-e2e-ns", with_status).expect("managed vm converts");
        let status = sbx.status.expect("status");
        let ready = status
            .conditions
            .iter()
            .find(|c| c.r#type == "Ready")
            .expect("ready condition");
        assert_eq!(ready.status, "True");

        // A halted VM reports Suspended.
        let mut halted = vm;
        halted.data["spec"]["runStrategy"] = serde_json::json!("Halted");
        halted.data["status"] = serde_json::json!({"ready": false});
        let (_, sbx) = sandbox_from_vm_object("openshell-e2e-ns", halted).expect("managed vm");
        let status = sbx.status.expect("status");
        assert!(
            status
                .conditions
                .iter()
                .any(|c| c.r#type == "Suspended" && c.status == "True")
        );

        // A freshly created VM (runStrategy Once, not ready) must NOT report
        // Suspended even though printableStatus is Stopped.
        let mut fresh = render_virtual_machine(&params(&sandbox(), &config()));
        fresh.data["status"] = serde_json::json!({"ready": false, "printableStatus": "Stopped"});
        let (_, sbx) = sandbox_from_vm_object("openshell-e2e-ns", fresh).expect("managed vm");
        let status = sbx.status.expect("status");
        assert!(!status.conditions.iter().any(|c| c.r#type == "Suspended"));
    }

    #[test]
    fn unmanaged_vm_is_rejected() {
        let cfg = config();
        let mut vm = render_virtual_machine(&params(&sandbox(), &cfg));
        vm.metadata
            .labels
            .as_mut()
            .unwrap()
            .remove(LABEL_MANAGED_BY);
        assert!(sandbox_from_vm_object("openshell-e2e-ns", vm).is_err());
    }

    #[test]
    fn kubevirt_namespace_rejects_non_shared_modes() {
        let mut cfg = config();
        cfg.workspace_mode = WorkspaceMode::Managed;
        assert!(kubevirt_namespace(&cfg).is_err());
        assert!(kubevirt_namespace(&config()).is_ok());
    }

    #[test]
    fn shell_quote_keeps_values_lossless() {
        assert_eq!(shell_quote("simple-value.1"), "simple-value.1");
        assert_eq!(shell_quote("has space"), "'has space'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }
}

/// How `start` should drive a `runStrategy: Once` VM back to running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KubeVirtStartPlan {
    /// The VM is halted: a single `runStrategy: Once` patch boots a fresh
    /// VMI.
    PatchOnce,
    /// The VMI is live or booting (Pending/Scheduling/Scheduled/Running):
    /// start is idempotent. The gateway admits retries from the `Starting`
    /// phase, and tearing down a healthy boot to "really start" would turn
    /// every retry into a restart. The start returns the current runtime
    /// identity.
    AlreadyRunning,
    /// The VMI is terminal (`Succeeded`/`Failed`) or gone while the strategy
    /// is `Once` and the VM reports `Stopped`: a completed VMI makes an
    /// `Once` -> `Once` patch a silent no-op, so boot requires bouncing
    /// through `Halted` first so `KubeVirt` discards the dead VMI.
    BounceHaltedThenOnce,
}

/// Decide how `start` must drive the VM, from the run strategy, the VM's
/// ready flag and printable status, and the paired VMI's phase. Extracted
/// for unit tests. Never tears down a VMI it does not positively know is
/// terminal: unknown phases and missing-context combinations are treated as
/// a boot in progress.
#[must_use]
pub fn kubevirt_start_plan(
    run_strategy: &str,
    vm_ready: bool,
    vmi_phase: Option<&str>,
    printable_status: &str,
) -> KubeVirtStartPlan {
    // A halted VM always needs the `Once` patch, whatever VMI phase is
    // still reported: `stop` only waits for the VM's ready flag to clear,
    // so a VMI in graceful shutdown can still show Running (or any other
    // phase) here. Returning AlreadyRunning for those would silently leave
    // the VM halted. The driver waits out a lingering VMI before patching.
    if run_strategy == "Halted" {
        return KubeVirtStartPlan::PatchOnce;
    }
    match vmi_phase {
        // Live or booting VMI: idempotent no-op.
        Some("Pending" | "Scheduling" | "Scheduled" | "Running" | "WaitingForSync") => {
            KubeVirtStartPlan::AlreadyRunning
        }
        // Terminal VMI: the Once->Once patch would be ignored.
        Some("Succeeded" | "Failed") => KubeVirtStartPlan::BounceHaltedThenOnce,
        // Unknown phase (KubeVirt could not obtain state): conservatively
        // treat as live.
        Some(_) => KubeVirtStartPlan::AlreadyRunning,
        None => {
            if run_strategy == "Once" && !vm_ready && printable_status == "Stopped" {
                // The VMI object is gone and the VM reports Stopped under
                // Once: a dead VMI the controller will not replace on a
                // no-op patch.
                KubeVirtStartPlan::BounceHaltedThenOnce
            } else {
                // No VMI object yet under Once with a printable status that
                // implies the controller is creating one: boot in progress.
                KubeVirtStartPlan::AlreadyRunning
            }
        }
    }
}

/// Namespaced API for `kubevirt.io/v1` `virtualmachineinstances`.
pub fn virtual_machine_instance_api(client: &Client, namespace: &str) -> Api<DynamicObject> {
    Api::namespaced_with(
        client.clone(),
        namespace,
        &ApiResource {
            group: KUBEVIRT_GROUP.to_string(),
            version: KUBEVIRT_VERSION.to_string(),
            api_version: format!("{KUBEVIRT_GROUP}/{KUBEVIRT_VERSION}"),
            kind: "VirtualMachineInstance".to_string(),
            plural: "virtualmachineinstances".to_string(),
        },
    )
}

/// Delete an object and wait until it is actually gone from the API.
///
/// Companion resources (the bootstrap Secret, the workspace PVC with its
/// `pvc-protection` finalizer and provisioner cleanup, proxy companions)
/// take time to terminate; an immediate recreate collides with the dying
/// object and surfaces as a confusing `AlreadyExists`. Fails with a clear
/// error when the object is still present after `timeout`.
pub async fn delete_and_wait(
    api: &Api<DynamicObject>,
    name: &str,
    what: &str,
    timeout: Duration,
) -> Result<(), KubernetesDriverError> {
    let _ = api.delete(name, &DeleteParams::default()).await;
    wait_until_gone(api, name, what, timeout).await
}

/// Delete an object with a UID precondition and wait until it is gone, so a
/// concurrent replacement of the same name is never deleted.
pub async fn delete_and_wait_with_uid(
    api: &Api<DynamicObject>,
    name: &str,
    what: &str,
    uid: &str,
    timeout: Duration,
) -> Result<(), KubernetesDriverError> {
    let preconditions = DeleteParams::default().preconditions(Preconditions {
        uid: Some(uid.to_string()),
        resource_version: None,
    });
    let _ = api.delete(name, &preconditions).await;
    wait_until_gone(api, name, what, timeout).await
}

async fn wait_until_gone(
    api: &Api<DynamicObject>,
    name: &str,
    what: &str,
    timeout: Duration,
) -> Result<(), KubernetesDriverError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match api.get(name).await {
            Err(KubeError::Api(err)) if err.code == 404 => return Ok(()),
            Err(err) => {
                return Err(KubernetesDriverError::Message(format!(
                    "failed to confirm deletion of {what} {name}: {err}"
                )));
            }
            Ok(_) => {}
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(KubernetesDriverError::Message(format!(
                "timed out after {}s waiting for {what} {name} to terminate",
                timeout.as_secs()
            )));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// A companion resource this create path provisioned, identified by its API
/// resource and UID so rollback only ever deletes objects this create made
/// (a concurrent create may have replaced an orphan with its own).
#[derive(Debug, Clone)]
pub struct CreatedCompanion {
    pub resource: ApiResource,
    pub name: String,
    pub uid: String,
}

/// Best-effort rollback of exactly the companions this create made. Deletes
/// carry UID preconditions, so a companion already replaced by a concurrent
/// create is left alone.
pub async fn rollback_companions(client: &Client, namespace: &str, created: &[CreatedCompanion]) {
    for companion in created {
        let api =
            Api::<DynamicObject>::namespaced_with(client.clone(), namespace, &companion.resource);
        let preconditions = DeleteParams::default().preconditions(Preconditions {
            uid: Some(companion.uid.clone()),
            resource_version: None,
        });
        let _ = api.delete(&companion.name, &preconditions).await;
    }
}

#[cfg(test)]
mod kubevirt_review_tests {
    use super::*;
    use crate::KubernetesComputeConfig;
    use openshell_core::proto::compute::v1::DriverSandbox as Sandbox;

    fn review_sandbox() -> Sandbox {
        Sandbox {
            id: "sbx-id".to_string(),
            name: "demo".to_string(),
            namespace: "openshell-e2e-ns".to_string(),
            spec: None,
            status: None,
            workspace: "default".to_string(),
        }
    }

    fn review_config() -> KubernetesComputeConfig {
        KubernetesComputeConfig {
            runtime: KubernetesRuntimeMode::KubeVirt,
            namespace: "openshell-e2e-ns".to_string(),
            gateway_id: "e2e-gateway".to_string(),
            grpc_endpoint: "http://172.18.0.1:18085/".to_string(),
            kubevirt: crate::KubeVirtConfig {
                guest_image: "openshell/sandbox-vm:test".to_string(),
                guest_image_pull_policy: "IfNotPresent".to_string(),
                cpu_cores: 2,
                memory: "2Gi".to_string(),
                workspace_pvc: true,
                workload: crate::config::KubeVirtWorkloadMode::default(),
            },
            shared_supervisor: Some(crate::SharedSupervisorConfig {
                service_name: "openshell-supervisor".to_string(),
                service_namespace: "openshell".to_string(),
                runtime_port: 5500,
                token_secret_name: "openshell-supervisor-token".to_string(),
            }),
            ..KubernetesComputeConfig::default()
        }
    }

    fn review_params<'a>(
        sandbox: &'a Sandbox,
        config: &'a KubernetesComputeConfig,
    ) -> KubeVirtSandboxParams<'a> {
        KubeVirtSandboxParams {
            sandbox,
            config,
            namespace: "openshell-e2e-ns",
            kube_name: "default--demo",
        }
    }

    #[test]
    fn start_plan_is_idempotent_during_boot() {
        use super::KubeVirtStartPlan;
        // A start admitted from Starting during the boot window must not
        // restart a healthy, booting VM (the gateway admits retries from
        // Starting, and the VM is Once + not ready throughout the window).
        for phase in ["Pending", "Scheduling", "Scheduled", "Running"] {
            assert_eq!(
                kubevirt_start_plan("Once", false, Some(phase), "Starting"),
                KubeVirtStartPlan::AlreadyRunning,
                "a booting VMI ({phase}) must not be bounced"
            );
        }
        // So is a ready VM and an unrecognized VMI phase.
        assert_eq!(
            kubevirt_start_plan("Once", true, Some("Running"), "Running"),
            KubeVirtStartPlan::AlreadyRunning
        );
        assert_eq!(
            kubevirt_start_plan("Once", false, Some("Unknown"), "Unknown"),
            KubeVirtStartPlan::AlreadyRunning
        );
        // No VMI object yet while the controller creates one: boot starting.
        assert_eq!(
            kubevirt_start_plan("Once", false, None, "Provisioning"),
            KubeVirtStartPlan::AlreadyRunning
        );
    }

    #[test]
    fn start_plan_bounces_dead_once_vm() {
        use super::KubeVirtStartPlan;
        // A terminal VMI under Once makes the Once->Once patch a no-op.
        for phase in ["Succeeded", "Failed"] {
            assert_eq!(
                kubevirt_start_plan("Once", false, Some(phase), "Stopped"),
                KubeVirtStartPlan::BounceHaltedThenOnce,
                "a terminal VMI ({phase}) must be bounced"
            );
        }
        // A gone VMI with a Stopped printable under Once is also dead.
        assert_eq!(
            kubevirt_start_plan("Once", false, None, "Stopped"),
            KubeVirtStartPlan::BounceHaltedThenOnce
        );
        // A halted VM boots with one patch; a ready VM is left alone.
        assert_eq!(
            kubevirt_start_plan("Halted", false, None, "Stopped"),
            KubeVirtStartPlan::PatchOnce
        );
        assert_eq!(
            kubevirt_start_plan("Once", true, None, "Running"),
            KubeVirtStartPlan::AlreadyRunning
        );
    }

    #[test]
    fn start_plan_halved_vm_always_patches_despite_lingering_vmi() {
        use super::KubeVirtStartPlan;
        // `stop` only waits for the VM's ready flag; a VMI in graceful
        // shutdown can still report any phase. A start issued right after
        // stop must patch Once (after waiting out the VMI), never report
        // AlreadyRunning and silently leave the VM halted.
        for phase in ["Running", "Succeeded", "Failed", "Pending", "Unknown"] {
            assert_eq!(
                kubevirt_start_plan("Halted", false, Some(phase), "Stopping"),
                KubeVirtStartPlan::PatchOnce,
                "a halted VM with a lingering VMI ({phase}) must patch"
            );
        }
        assert_eq!(
            kubevirt_start_plan("Halted", false, Some("Succeeded"), "Stopped"),
            KubeVirtStartPlan::PatchOnce
        );
    }

    #[test]
    fn terminal_failure_maps_vmi_and_printable_states() {
        // A failed or completed VMI under a not-ready VM is terminal.
        assert!(terminal_vm_failure("Stopped", Some("Failed"), false).is_some());
        assert!(terminal_vm_failure("Stopped", Some("Succeeded"), false).is_some());
        // KubeVirt's terminal printable statuses stand on their own
        // (VirtualMachinePrintableStatus, KubeVirt v1.9).
        for status in [
            "CrashLoopBackOff",
            "ErrorUnschedulable",
            "ErrorPvcNotFound",
            "DataVolumeError",
        ] {
            assert!(
                terminal_vm_failure(status, None, false).is_some(),
                "{status} must be terminal"
            );
        }
        // Image-pull problems are transient (kubelet retries) but visible:
        // the caller puts the printableStatus in the condition message.
        for status in ["ErrImagePull", "ImagePullBackOff"] {
            assert!(
                terminal_vm_failure(status, None, false).is_none(),
                "{status} must stay transient"
            );
        }
        // Unknown (controller could not obtain state) can appear transiently;
        // mapping it to Error would flip a booting sandbox on a blip.
        assert!(terminal_vm_failure("Unknown", None, false).is_none());
        // A running VM, a not-yet-booted VM, and a missing VMI are not
        // terminal: those stay provisioning.
        assert!(terminal_vm_failure("Running", Some("Running"), true).is_none());
        assert!(terminal_vm_failure("Stopped", None, false).is_none());
        assert!(terminal_vm_failure("Starting", Some("Pending"), false).is_none());
        assert!(terminal_vm_failure("WaitingForVolumeBinding", None, false).is_none());
        // A Succeeded VMI under a ready VM is not a failure signal.
        assert!(terminal_vm_failure("Running", Some("Succeeded"), true).is_none());
    }

    #[test]
    fn halted_vm_in_create_window_maps_to_bootstrapping_not_suspended() {
        // The create path holds the VM Halted while it builds the fence,
        // bootstrap Secret, and shared-instance registration. With the
        // in-flight annotation present, the snapshot must carry
        // `Bootstrapping=True` and no `Suspended=True` — the gateway
        // composes Provisioning (keeping the supervisor instance) rather
        // than Stopped (which withdraws it before the guest dials).
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["spec"]["runStrategy"] = serde_json::json!("Halted");
        vm.data["status"] = serde_json::json!({"ready": false, "printableStatus": "Stopped"});
        vm.metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                KUBEVIRT_CREATE_IN_FLIGHT_ANNOTATION.to_string(),
                openshell_core::time::now_ms().to_string(),
            );
        let (_, sbx) =
            sandbox_from_vm_object_with_vmi("openshell-e2e-ns", vm, None).expect("converts");
        let conditions = sbx.status.unwrap().conditions;
        assert!(
            conditions
                .iter()
                .any(|condition| condition.r#type == "Bootstrapping" && condition.status == "True"),
            "in-flight Halted VM must report Bootstrapping: {conditions:?}"
        );
        assert!(
            !conditions
                .iter()
                .any(|condition| condition.r#type == "Suspended" && condition.status == "True"),
            "in-flight Halted VM must not report Suspended: {conditions:?}"
        );

        // Without the annotation the same Halted VM is a user stop:
        // Suspended=True, no Bootstrapping.
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["spec"]["runStrategy"] = serde_json::json!("Halted");
        vm.data["status"] = serde_json::json!({"ready": false, "printableStatus": "Stopped"});
        let (_, sbx) =
            sandbox_from_vm_object_with_vmi("openshell-e2e-ns", vm, None).expect("converts");
        let conditions = sbx.status.unwrap().conditions;
        assert!(
            conditions
                .iter()
                .any(|condition| condition.r#type == "Suspended" && condition.status == "True"),
            "user-stopped Halted VM must report Suspended: {conditions:?}"
        );
        assert!(
            !conditions
                .iter()
                .any(|condition| condition.r#type == "Bootstrapping"),
            "user-stopped Halted VM must not report Bootstrapping: {conditions:?}"
        );
    }

    #[test]
    fn supervisor_failure_while_vm_halting_is_not_an_error() {
        // S1: while the VM is halting (`printableStatus: Stopping` — the
        // VMI is terminating), the dedicated supervisor Pod exiting
        // (restartPolicy Never -> Failed) is the EXPECTED end of a stop,
        // not a failure. Mapping it to SupervisorFailed aborted in-flight
        // stops ("sandbox lifecycle changed while stop completed").
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["spec"]["runStrategy"] = serde_json::json!("Once");
        vm.data["status"] = serde_json::json!({"ready": false, "printableStatus": "Stopping"});
        let (_, sbx) = sandbox_from_vm_object_with_runtime(
            "openshell-e2e-ns",
            vm,
            Some("Running"),
            Some("supervisor Pod failed (restartPolicy Never)"),
            None,
            None,
        )
        .expect("converts");
        let ready = sbx.status.clone().unwrap().conditions[0].clone();
        assert_eq!(ready.status, "False");
        assert_ne!(
            ready.reason, REASON_SUPERVISOR_FAILED,
            "a supervisor exiting while the VM halts must not be SupervisorFailed"
        );
        // And the sandbox is NOT terminal: no Error-mapping reason, so the
        // gateway keeps composing Stopping/Stopped from the desired state.
        assert!(
            !sbx.status
                .unwrap()
                .conditions
                .iter()
                .any(|condition| condition.reason == REASON_SUPERVISOR_FAILED),
            "no condition may carry SupervisorFailed while the VM is halting"
        );

        // Control: the same failed supervisor Pod on a Running (not
        // halting) VM still maps to the terminal Error — the suppression
        // must not hide genuine crashes.
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["spec"]["runStrategy"] = serde_json::json!("Once");
        vm.data["status"] = serde_json::json!({"ready": true, "printableStatus": "Running"});
        let (_, sbx) = sandbox_from_vm_object_with_runtime(
            "openshell-e2e-ns",
            vm,
            Some("Running"),
            Some("supervisor Pod failed (restartPolicy Never)"),
            None,
            None,
        )
        .expect("converts");
        let ready = sbx.status.unwrap().conditions[0].clone();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason, REASON_SUPERVISOR_FAILED);
    }

    #[test]
    fn supervisor_failure_maps_to_terminal_error() {
        // M2: a dedicated generation whose supervisor Pod is gone or
        // crashed maps the sandbox to the public Error phase (a
        // non-transient Ready=False reason) instead of provisioning
        // forever.
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["spec"]["runStrategy"] = serde_json::json!("Once");
        vm.data["status"] = serde_json::json!({"ready": false, "printableStatus": "Running"});
        let (_, sbx) = sandbox_from_vm_object_with_runtime(
            "openshell-e2e-ns",
            vm,
            Some("Running"),
            Some("supervisor Pod is gone"),
            None,
            None,
        )
        .expect("converts");
        let ready = sbx.status.unwrap().conditions[0].clone();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason, REASON_SUPERVISOR_FAILED);
        assert!(ready.message.contains("supervisor Pod is gone"));
        // The real M2 case: the VM still reports ready when its supervisor
        // Pod is deleted under it — the failure must still surface as a
        // terminal Error, not hide behind VMReady.
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["spec"]["runStrategy"] = serde_json::json!("Once");
        vm.data["status"] = serde_json::json!({"ready": true, "printableStatus": "Running"});
        let (_, sbx) = sandbox_from_vm_object_with_runtime(
            "openshell-e2e-ns",
            vm,
            Some("Running"),
            Some("supervisor Pod is gone"),
            None,
            None,
        )
        .expect("converts");
        let ready = sbx.status.unwrap().conditions[0].clone();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason, REASON_SUPERVISOR_FAILED);
        // Without the failure the same VM stays transient.
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["spec"]["runStrategy"] = serde_json::json!("Once");
        vm.data["status"] = serde_json::json!({"ready": false, "printableStatus": "Running"});
        let (_, sbx) = sandbox_from_vm_object_with_runtime(
            "openshell-e2e-ns",
            vm,
            Some("Running"),
            None,
            None,
            None,
        )
        .expect("converts");
        let ready = sbx.status.unwrap().conditions[0].clone();
        assert_eq!(ready.reason, REASON_VM_NOT_READY);
    }

    #[test]
    fn create_window_watch_event_stays_bootstrapping() {
        // The watch re-emits snapshots during the create's Halted window,
        // before the dedicated supervisor Pod exists; even if a failure
        // were reported for that window, the snapshot must stay
        // Bootstrapping (Provisioning), never SupervisorFailed (Error).
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["spec"]["runStrategy"] = serde_json::json!("Halted");
        vm.data["status"] = serde_json::json!({"ready": false, "printableStatus": "Stopped"});
        vm.metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                KUBEVIRT_CREATE_IN_FLIGHT_ANNOTATION.to_string(),
                openshell_core::time::now_ms().to_string(),
            );
        let (_, sbx) = sandbox_from_vm_object_with_runtime(
            "openshell-e2e-ns",
            vm,
            None,
            Some("supervisor Pod is gone"),
            None,
            None,
        )
        .expect("converts");
        let conditions = sbx.status.unwrap().conditions;
        let ready = conditions.iter().find(|c| c.r#type == "Ready").unwrap();
        assert_eq!(ready.reason, REASON_VM_NOT_READY);
        assert!(
            conditions
                .iter()
                .any(|condition| condition.r#type == "Bootstrapping" && condition.status == "True")
        );
    }

    #[test]
    fn stale_create_window_maps_to_terminal_timeout() {
        // M7: a create whose Halted window outlived the deadline (the
        // gateway died mid-create; a gateway restarted from a clean
        // database has no record to reclaim with) maps the sandbox to the
        // public Error phase instead of provisioning forever.
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["spec"]["runStrategy"] = serde_json::json!("Halted");
        vm.data["status"] = serde_json::json!({"ready": false, "printableStatus": "Stopped"});
        vm.metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                KUBEVIRT_CREATE_IN_FLIGHT_ANNOTATION.to_string(),
                (openshell_core::time::now_ms() - KUBEVIRT_CREATE_DEADLINE_MS - 1).to_string(),
            );
        let (_, sbx) =
            sandbox_from_vm_object_with_runtime("openshell-e2e-ns", vm, None, None, None, None)
                .expect("converts");
        let conditions = sbx.status.unwrap().conditions;
        let ready = conditions.iter().find(|c| c.r#type == "Ready").unwrap();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason, REASON_CREATE_TIMED_OUT);
        assert!(ready.message.contains("outlived the deadline"));
        // A fresh window stays Bootstrapping (Provisioning), not Error.
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["spec"]["runStrategy"] = serde_json::json!("Halted");
        vm.data["status"] = serde_json::json!({"ready": false, "printableStatus": "Stopped"});
        vm.metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                KUBEVIRT_CREATE_IN_FLIGHT_ANNOTATION.to_string(),
                openshell_core::time::now_ms().to_string(),
            );
        let (_, sbx) =
            sandbox_from_vm_object_with_runtime("openshell-e2e-ns", vm, None, None, None, None)
                .expect("converts");
        let conditions = sbx.status.unwrap().conditions;
        assert!(
            conditions
                .iter()
                .any(|condition| condition.r#type == "Bootstrapping" && condition.status == "True")
        );
        let ready = conditions.iter().find(|c| c.r#type == "Ready").unwrap();
        assert_eq!(ready.reason, REASON_VM_NOT_READY);
    }

    #[test]
    fn guest_image_digest_classifies_launcher_init_containers() {
        use k8s_openapi::api::core::v1::{Container, ContainerStatus, Pod, PodSpec, PodStatus};
        const GUEST: &str = "openshell/sandbox-vm:test";
        // statuses: (name, status image, imageID); specs: the pod spec's
        // init container image references (what KubeVirt rendered from the
        // VM spec — the selection key).
        let pod = |statuses: &[(&str, &str, &str)], specs: &[(&str, &str)]| {
            let status = PodStatus {
                init_container_statuses: Some(
                    statuses
                        .iter()
                        .map(|(name, image, image_id)| ContainerStatus {
                            name: name.to_string(),
                            image: image.to_string(),
                            image_id: image_id.to_string(),
                            ..ContainerStatus::default()
                        })
                        .collect(),
                ),
                ..PodStatus::default()
            };
            let spec = PodSpec {
                init_containers: Some(
                    specs
                        .iter()
                        .map(|(name, image)| Container {
                            name: name.to_string(),
                            image: Some(image.to_string()),
                            ..Container::default()
                        })
                        .collect(),
                ),
                ..PodSpec::default()
            };
            Pod {
                status: Some(status),
                spec: Some(spec),
                ..Pod::default()
            }
        };
        // The launcher runs other init containers (guest-console-log) on
        // the VIRT-LAUNCHER image whose digest must never be pinned: the
        // status is matched by the POD SPEC image (what KubeVirt rendered
        // from the VM spec), keyed by container name.
        let spec = [
            ("guest-console-log", "quay.io/kubevirt/virt-launcher:v1.9.1"),
            ("volumerootdisk", GUEST),
            ("volumekernel-boot-volume", GUEST),
        ];
        let launcher_statuses = [
            (
                "guest-console-log",
                "quay.io/kubevirt/virt-launcher:v1.9.1",
                "quay.io/kubevirt/virt-launcher@sha256:53e6d121",
            ),
            (
                "volumerootdisk",
                "docker.io/openshell/sandbox-vm:test",
                "docker.io/openshell/sandbox-vm@sha256:5a58c279",
            ),
            (
                "volumekernel-boot-volume",
                "docker.io/openshell/sandbox-vm:test",
                "docker.io/openshell/sandbox-vm@sha256:5a58c279",
            ),
        ];
        assert_eq!(
            guest_image_digest(&pod(&launcher_statuses, &spec), GUEST),
            GuestImageDigest::Patch(
                "docker.io/openshell/sandbox-vm@sha256:5a58c279".to_string()
            )
        );
        // The node knows the same digest under ANOTHER name (a side-loaded
        // copy of the registry tag): the status .image disagrees with the
        // VM spec, but the POD SPEC image — the selection key — matches,
        // so the pin still resolves.
        let renamed = [
            (
                "guest-console-log",
                "quay.io/kubevirt/virt-launcher:v1.9.1",
                "quay.io/kubevirt/virt-launcher@sha256:53e6d121",
            ),
            (
                "volumerootdisk",
                "docker.io/kvreview/openshell-sandbox-vm:dev",
                "k3d-kvreview-registry:5050/openshell-sandbox-vm@sha256:fe7f1fae",
            ),
            (
                "volumekernel-boot-volume",
                "docker.io/kvreview/openshell-sandbox-vm:dev",
                "k3d-kvreview-registry:5050/openshell-sandbox-vm@sha256:fe7f1fae",
            ),
        ];
        assert_eq!(
            guest_image_digest(&pod(&renamed, &spec), GUEST),
            GuestImageDigest::Patch(
                "k3d-kvreview-registry:5050/openshell-sandbox-vm@sha256:fe7f1fae".to_string()
            )
        );
        // Side-loaded (k3d/ctr import): a bare config digest, no
        // repository — never patchable.
        let side_loaded = [
            (
                "guest-console-log",
                "quay.io/kubevirt/virt-launcher:v1.9.1",
                "quay.io/kubevirt/virt-launcher@sha256:53e6d121",
            ),
            (
                "volumerootdisk",
                "docker.io/openshell/sandbox-vm:test",
                "sha256:5a58c279",
            ),
        ];
        assert_eq!(
            guest_image_digest(&pod(&side_loaded, &spec), GUEST),
            GuestImageDigest::SideLoaded
        );
        // Nothing observed yet (no statuses, or none matching the guest
        // image).
        assert_eq!(
            guest_image_digest(&Pod::default(), GUEST),
            GuestImageDigest::Absent
        );
        let empty = [(
            "volumerootdisk",
            "docker.io/openshell/sandbox-vm:test",
            "",
        )];
        assert_eq!(
            guest_image_digest(&pod(&empty, &spec), GUEST),
            GuestImageDigest::Absent
        );
        // Reference normalization: containerd's docker.io/library form
        // matches a bare short reference.
        assert!(image_ref_matches(
            "docker.io/library/busybox:1.36",
            "busybox:1.36"
        ));
        assert!(!image_ref_matches(
            "quay.io/kubevirt/virt-launcher:v1.9.1",
            GUEST
        ));
    }

    #[test]
    fn side_loaded_image_surfaces_image_pin_condition() {
        // M6 (option A): a side-loaded guest image cannot be digest-pinned;
        // the reconciler's annotation surfaces as an ImagePin condition so
        // operators see the unpinned state.
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["status"] = serde_json::json!({"ready": true});
        vm.metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                IMAGE_PIN_STATE_ANNOTATION.to_string(),
                IMAGE_PIN_NO_REPOSITORY_DIGEST.to_string(),
            );
        let (_, sbx) =
            sandbox_from_vm_object_with_runtime("openshell-e2e-ns", vm, None, None, None, None)
                .expect("converts");
        let conditions = sbx.status.unwrap().conditions;
        let pin = conditions
            .iter()
            .find(|condition| condition.r#type == "ImagePin")
            .expect("ImagePin condition present");
        assert_eq!(pin.status, "False");
        assert_eq!(pin.reason, "NoRepositoryDigest");
        assert!(pin.message.contains("no repository digest"));
        // Without the annotation there is no condition.
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["status"] = serde_json::json!({"ready": true});
        let (_, sbx) =
            sandbox_from_vm_object_with_runtime("openshell-e2e-ns", vm, None, None, None, None)
                .expect("converts");
        assert!(
            !sbx.status
                .unwrap()
                .conditions
                .iter()
                .any(|condition| condition.r#type == "ImagePin")
        );
    }

    #[test]
    fn fence_restored_marker_surfaces_as_condition() {
        // M1: the reconciler's restore marker surfaces as a FenceRestored
        // condition so operators see that isolation briefly depended on
        // the namespace-wide default-deny floor.
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["status"] = serde_json::json!({"ready": true});
        vm.metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                "openshell.ai/kubevirt-fence-restored-at".to_string(),
                "1760000000000".to_string(),
            );
        let (_, sbx) = sandbox_from_vm_object_with_runtime(
            "openshell-e2e-ns",
            vm,
            None,
            None,
            Some("1760000000000"),
            None,
        )
        .expect("converts");
        let conditions = sbx.status.unwrap().conditions;
        let restored = conditions
            .iter()
            .find(|condition| condition.r#type == "FenceRestored")
            .expect("FenceRestored condition present");
        assert_eq!(restored.status, "True");
        assert_eq!(restored.reason, "ReFencedAfterDrift");
        // Without the marker there is no condition.
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["status"] = serde_json::json!({"ready": true});
        let (_, sbx) =
            sandbox_from_vm_object_with_runtime("openshell-e2e-ns", vm, None, None, None, None)
                .expect("converts");
        assert!(
            !sbx.status
                .unwrap()
                .conditions
                .iter()
                .any(|condition| condition.r#type == "FenceRestored")
        );
    }

    #[test]
    fn rfc3339_parser_reads_kubernetes_timestamps() {
        // The parser backs the image-pull-backoff terminal rule (L4).
        assert_eq!(
            rfc3339_to_unix_ms("2026-11-02T21:34:56Z"),
            Some(1_793_655_296_000)
        );
        assert_eq!(rfc3339_to_unix_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            rfc3339_to_unix_ms("2026-11-02T21:34:56.123Z"),
            Some(1_793_655_296_123)
        );
        assert_eq!(rfc3339_to_unix_ms("not-a-timestamp"), None);
    }

    #[test]
    fn image_pull_backoff_becomes_terminal_after_the_threshold() {
        // L4: below the threshold the backoff stays transient (a slow
        // registry can legitimately back off); past it the pull is
        // effectively permanent and the sandbox maps to Error with a
        // message users see, instead of hiding behind the gateway's
        // configuration gate until the CLI's provision timeout.
        let cfg = review_config();
        let stale = || {
            let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
            vm.data["status"] =
                serde_json::json!({"ready": false, "printableStatus": "ImagePullBackOff"});
            vm
        };
        let fresh_since = openshell_core::time::now_ms();
        let (_, sbx) = sandbox_from_vm_object_with_runtime(
            "openshell-e2e-ns",
            stale(),
            None,
            None,
            None,
            Some(fresh_since),
        )
        .expect("converts");
        let ready = sbx.status.unwrap().conditions[0].clone();
        assert_eq!(ready.reason, REASON_VM_NOT_READY);
        assert!(ready.message.contains("ImagePullBackOff"));

        let stale_since = openshell_core::time::now_ms() - IMAGE_PULL_BACKOFF_TERMINAL_AFTER_MS - 1;
        let (_, sbx) = sandbox_from_vm_object_with_runtime(
            "openshell-e2e-ns",
            stale(),
            None,
            None,
            None,
            Some(stale_since),
        )
        .expect("converts");
        let ready = sbx.status.unwrap().conditions[0].clone();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason, REASON_VM_FAILED);
        assert!(ready.message.contains("image pull"));

        // No timestamp: the rule cannot fire (timing fails open).
        let (_, sbx) =
            sandbox_from_vm_object_with_runtime("openshell-e2e-ns", stale(), None, None, None, None)
                .expect("converts");
        let ready = sbx.status.unwrap().conditions[0].clone();
        assert_eq!(ready.reason, REASON_VM_NOT_READY);
    }

    #[test]
    fn transient_image_pull_status_is_visible_in_condition_message() {
        // ErrImagePull stays transient but the condition message must carry
        // the printableStatus so the cause reaches the user.
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["status"] =
            serde_json::json!({"ready": false, "printableStatus": "ImagePullBackOff"});
        let (_, sbx) =
            sandbox_from_vm_object_with_vmi("openshell-e2e-ns", vm, None).expect("converts");
        let ready = sbx.status.unwrap().conditions[0].clone();
        assert_eq!(ready.reason, "Starting");
        assert!(
            ready.message.contains("ImagePullBackOff"),
            "message must name the pull problem: {}",
            ready.message
        );
    }

    #[test]
    fn vm_status_marks_terminal_vmi_as_error() {
        let cfg = review_config();
        let mut vm = render_virtual_machine(&review_params(&review_sandbox(), &cfg));
        vm.data["spec"]["runStrategy"] = serde_json::json!("Once");
        vm.data["status"] = serde_json::json!({"ready": false, "printableStatus": "Stopped"});

        // Without the VMI phase the not-ready VM stays transient (Starting).
        let (_, sbx) =
            sandbox_from_vm_object_with_vmi("openshell-e2e-ns", vm.clone(), None).expect("converts");
        let ready = sbx.status.unwrap().conditions[0].clone();
        assert_eq!(ready.reason, "Starting");

        // With a Failed VMI the same VM reports the non-transient VMFailed
        // reason, which the gateway maps to the public Error phase.
        let (_, sbx) = sandbox_from_vm_object_with_vmi("openshell-e2e-ns", vm, Some("Failed"))
            .expect("converts");
        let ready = sbx.status.unwrap().conditions[0].clone();
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason, "VMFailed");
        assert!(ready.message.contains("Failed"));
    }

    #[test]
    fn grpc_endpoint_is_required_only_for_the_dedicated_topology() {
        // The dedicated topology's supervisor Pod must reach the gateway,
        // exactly as the pod path's supervisor Pods do, so grpc_endpoint is
        // required (and any scheme is fine: the supervisor carries client
        // TLS material, so the https:// shape the TLS demo uses is valid).
        let mut cfg = review_config();
        cfg.shared_supervisor = None;
        cfg.grpc_endpoint = "https://openshell-gateway.ns.svc:8080".to_string();
        assert!(cfg.validate_kubevirt_config().is_ok());
        cfg.grpc_endpoint = String::new();
        let err = cfg
            .validate_kubevirt_config()
            .expect_err("dedicated without grpc_endpoint is refused");
        assert!(
            err.contains("grpc_endpoint"),
            "message should name the key: {err}"
        );
        // The shared topology's guest never learns the gateway endpoint
        // (the boundary resolves the shared supervisor's Service through
        // the API), so grpc_endpoint is neither required nor restricted.
        let mut cfg = review_config();
        cfg.supervisor_topology = Some(crate::SupervisorTopology::Gateway);
        cfg.grpc_endpoint = String::new();
        assert!(cfg.validate_kubevirt_config().is_ok());
    }

    #[test]
    fn root_workload_mode_requires_dedicated_supervisor() {
        // The privileged root-workload class requires the dedicated
        // supervisor: a shared supervisor would let a parser bug reached
        // by a hostile root guest cross tenants.
        let mut cfg = review_config();
        cfg.kubevirt.workload = crate::config::KubeVirtWorkloadMode::Root;
        cfg.shared_supervisor = None;
        assert!(cfg.validate_kubevirt_config().is_ok());

        cfg.supervisor_topology = Some(crate::SupervisorTopology::Gateway);
        let err = cfg
            .validate_kubevirt_config()
            .expect_err("root + gateway topology is refused");
        assert!(
            err.contains("requires the dedicated supervisor topology"),
            "message should name the requirement: {err}"
        );

        // The sandboxed default is fine with either topology.
        let mut cfg = review_config();
        cfg.kubevirt.workload = crate::config::KubeVirtWorkloadMode::Sandboxed;
        cfg.supervisor_topology = Some(crate::SupervisorTopology::Gateway);
        assert!(cfg.validate_kubevirt_config().is_ok());
    }

    #[test]
    fn validate_configuration_surfaces_kubevirt_rules() {
        // The startup validation entry point must include the kubevirt
        // rules and the shared topology rules for the kubevirt runtime.
        // The default (dedicated) topology validates cleanly.
        let mut cfg = review_config();
        cfg.shared_supervisor = None;
        assert!(cfg.validate_configuration().is_ok());

        // A dedicated generation without grpc_endpoint cannot run its
        // supervisor Pod.
        let mut cfg = review_config();
        cfg.shared_supervisor = None;
        cfg.grpc_endpoint = String::new();
        let err = cfg
            .validate_configuration()
            .expect_err("dedicated without grpc_endpoint is refused");
        assert!(
            err.contains("grpc_endpoint"),
            "message should name the key: {err}"
        );

        // The gateway topology requires shared_supervisor (enforced by the
        // shared validate_supervisor_topology, not kubevirt-specific rules).
        let mut cfg = review_config();
        cfg.supervisor_topology = Some(crate::SupervisorTopology::Gateway);
        cfg.shared_supervisor = None;
        let err = cfg
            .validate_configuration()
            .expect_err("gateway topology without shared supervisor is refused");
        assert!(
            err.contains("requires shared_supervisor"),
            "message should name the requirement: {err}"
        );

        // The workspace topology is rejected, as on the pod path.
        let mut cfg = review_config();
        cfg.supervisor_topology = Some(crate::SupervisorTopology::Workspace);
        cfg.shared_supervisor = None;
        assert!(cfg.validate_configuration().is_err());

        let mut cfg = review_config();
        cfg.supervisor_topology = Some(crate::SupervisorTopology::Gateway);
        cfg.kubevirt.guest_image = String::new();
        let err = cfg
            .validate_configuration()
            .expect_err("empty guest_image is refused");
        assert!(
            err.contains("guest_image"),
            "message should name the key: {err}"
        );
    }
}

/// Decode the gateway's launch authentication for the start-path token
/// refresh. Empty input skips the refresh (with a warning: the guest keeps
/// the create-time token, which expires under the gateway JWT TTL); a
/// malformed bundle is an error rather than a silent stale-token fallback.
pub fn decode_launch_authentication(
    encoded: &[u8],
) -> Result<Option<openshell_core::jwt::SandboxLaunchAuthentication>, KubernetesDriverError> {
    if encoded.is_empty() {
        tracing::warn!(
            "start carried no launch authentication; the guest keeps the create-time \
             sandbox token, which expires under the gateway JWT TTL"
        );
        return Ok(None);
    }
    serde_json::from_slice::<openshell_core::jwt::SandboxLaunchAuthentication>(encoded)
        .map(Some)
        .map_err(|error| {
            KubernetesDriverError::Precondition(format!(
                "invalid launch authentication bundle: {error}"
            ))
        })
}
