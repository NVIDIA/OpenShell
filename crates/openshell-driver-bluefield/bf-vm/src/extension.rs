// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! BlueField VM lifecycle extension: VF passthrough.
//!
//! This extension claims a host VF for a sandbox, binds it to `vfio-pci`,
//! persists enough state to recover after a driver restart, and releases the
//! VF on launch failure or delete. It does not program any DPU datapath; that
//! is layered on in later stages.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use openshell_core::proto::compute::v1::DriverSandbox as Sandbox;
use openshell_vfio::SysfsRoot;

use crate::gpu::mac_from_sandbox_id;
use crate::lifecycle::{
    BackendFeature, ExtensionActivation, ExtensionDescriptor, GuestResource, LaunchAbortReason,
    LaunchPlan, LifecycleError, LifecycleExtension, LifecycleResult, PciPassthroughDevice,
    RestoreContext,
};

use bf_inventory::{VfPool, VfSlot};

use crate::config::{
    bluefield_kernel_from_config, guest_egress_from_config, reject_deferred_proxy,
};
use crate::guest_egress::{self, GuestEgress};
use crate::kernel::{BluefieldKernel, MELLANOX_VF_MODULES};
use crate::slots::{HostSlotConfig, prepare_host_slots, resolve_host_pf_bdf};
use crate::state::{self, AttachmentRecord, EXTENSION_NAME};
use crate::vf::{HostReadiness, SysfsHostReadiness, SysfsVfBinder, VfBinder};

pub use crate::cli::BluefieldDriverArgs;
pub use crate::config::BluefieldDriverConfig;

fn deterministic_vf_mac(sandbox_id: &str) -> String {
    let key = format!("bluefield-vf:{sandbox_id}");
    let mac = mac_from_sandbox_id(&key);
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn qemu_kernel_from_config(config: &BluefieldDriverConfig) -> Result<BluefieldKernel, String> {
    let image = crate::qemu_kernel_resolver::resolve_qemu_kernel_image(
        config.kernel_image.clone(),
        &crate::qemu_kernel_resolver::default_runtime_roots(),
    )?;
    let mut kernel = bluefield_kernel_from_config(config)
        .unwrap_or_else(|| BluefieldKernel::from_image(image.clone()));
    if kernel.image.is_none() {
        kernel.image = Some(image);
    }
    if kernel.required_modules.is_empty() {
        kernel.required_modules = MELLANOX_VF_MODULES
            .iter()
            .map(|module| (*module).to_string())
            .collect();
    }
    Ok(kernel)
}

/// BlueField lifecycle extension: claims a VF, binds it for passthrough, and
/// wires optional guest egress into the launch plan.
#[derive(Debug)]
pub struct BluefieldExtension {
    pool: VfPool,
    egress: Option<GuestEgress>,
    kernel: Option<BluefieldKernel>,
    readiness: Arc<dyn HostReadiness>,
    binder: Arc<dyn VfBinder>,
    attachments: Mutex<HashMap<String, AttachmentRecord>>,
}

impl BluefieldExtension {
    #[must_use]
    pub fn new(pool: VfPool) -> Self {
        Self {
            pool,
            egress: None,
            kernel: None,
            readiness: Arc::new(SysfsHostReadiness::default()),
            binder: Arc::new(SysfsVfBinder::default()),
            attachments: Mutex::new(HashMap::new()),
        }
    }

    /// Build a host-side extension from VM-driver config. Discovers the local
    /// VFs under the configured host PF, applies the operator's reservations,
    /// and returns an extension that binds one VF per sandbox.
    ///
    /// Returns `Ok(None)` when `config.enabled` is false so callers keep the
    /// upstream default driver behavior unchanged.
    pub fn from_driver_config(config: &BluefieldDriverConfig) -> Result<Option<Self>, String> {
        if !config.enabled {
            return Ok(None);
        }
        reject_deferred_proxy(config)?;

        let host_pf = resolve_host_pf_bdf(config)?;
        let sysfs = SysfsRoot::system();
        let slots = prepare_host_slots(HostSlotConfig::from(config), &sysfs, &host_pf)?;
        let kernel = qemu_kernel_from_config(config)?;

        let extension = Self::new(VfPool::new(slots))
            .with_kernel(kernel)
            .with_host_readiness(Arc::new(SysfsHostReadiness::new(sysfs.clone())))
            .with_vf_binder(Arc::new(SysfsVfBinder::new(sysfs)));

        Ok(Some(extension.apply_runtime_options(config)?))
    }

    /// In this stage a compute node binds a VF the same way the all-in-one
    /// role does; the leader-driven assignment path is layered on later.
    pub fn from_compute_node_config(
        config: &BluefieldDriverConfig,
    ) -> Result<Option<Self>, String> {
        Self::from_driver_config(config)
    }

    fn apply_runtime_options(mut self, config: &BluefieldDriverConfig) -> Result<Self, String> {
        if let Some(egress) = guest_egress_from_config(config)? {
            self = self.with_guest_egress(egress);
        }
        Ok(self)
    }

    #[must_use]
    pub fn with_guest_egress(mut self, egress: GuestEgress) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Select the BlueField guest kernel (image or profile) and the VF driver
    /// modules to load in guest-init.
    #[must_use]
    pub fn with_kernel(mut self, kernel: BluefieldKernel) -> Self {
        self.kernel = Some(kernel);
        self
    }

    /// Override the host VF-passthrough readiness probe (defaults to a
    /// real-`/sys` [`SysfsHostReadiness`]).
    #[must_use]
    pub fn with_host_readiness(mut self, readiness: Arc<dyn HostReadiness>) -> Self {
        self.readiness = readiness;
        self
    }

    fn with_vf_binder(mut self, binder: Arc<dyn VfBinder>) -> Self {
        self.binder = binder;
        self
    }

    fn record_attachment(&self, sandbox_id: &str, record: AttachmentRecord) {
        self.attachments
            .lock()
            .expect("bluefield attachments lock poisoned")
            .insert(sandbox_id.to_string(), record);
    }

    fn take_attachment(&self, sandbox_id: &str) -> Option<AttachmentRecord> {
        self.attachments
            .lock()
            .expect("bluefield attachments lock poisoned")
            .remove(sandbox_id)
    }

    fn release_binding(&self, sandbox_state_dir: &Path, slot: &VfSlot) -> LifecycleResult<()> {
        self.binder.release_slot(slot).map_err(|err| {
            LifecycleError::new(format!("bluefield: release VF {}: {err}", slot.host_bdf))
        })?;
        state::remove_bind_state(sandbox_state_dir)
    }

    fn claim_slot(&self, sandbox_id: &str) -> LifecycleResult<VfSlot> {
        let mut slot = self.pool.claim(sandbox_id).ok_or_else(|| {
            LifecycleError::resource_exhausted(format!(
                "bluefield: no free VF for sandbox {sandbox_id}"
            ))
        })?;
        if slot.guest_mac.is_none() {
            slot.guest_mac = Some(deterministic_vf_mac(sandbox_id));
        }
        Ok(slot)
    }
}

#[tonic::async_trait]
impl LifecycleExtension for BluefieldExtension {
    fn name(&self) -> &str {
        EXTENSION_NAME
    }

    fn activation(&self) -> ExtensionActivation {
        ExtensionActivation::Global
    }

    fn descriptor(&self) -> ExtensionDescriptor {
        let mut descriptor = ExtensionDescriptor::new(EXTENSION_NAME);
        descriptor.required_backend_features = vec![
            BackendFeature::PciPassthrough,
            BackendFeature::GuestInitDropins,
        ];
        descriptor
    }

    async fn configure_launch(
        &self,
        sandbox: &Sandbox,
        _state_dir: &Path,
        plan: &mut LaunchPlan,
    ) -> LifecycleResult<()> {
        // VF passthrough requires QEMU; guest egress needs an init drop-in.
        plan.require_backend_feature(BackendFeature::PciPassthrough);
        plan.require_backend_feature(BackendFeature::GuestInitDropins);
        plan.guest_init_dropins.push(guest_egress::dropin());

        // Declare the VF as a passthrough device now (before the backend is
        // resolved and validated) so the driver promotes the launch to QEMU
        // and the non-GPU launch guard sees a concrete device backing. The
        // actual vfio-pci bind happens in `before_launch`; the claim is
        // idempotent per sandbox, so claiming here and there is safe.
        let slot = self.claim_slot(&sandbox.id)?;
        plan.add_resource(GuestResource::PciPassthrough(PciPassthroughDevice::new(
            slot.host_bdf,
        )));

        // Select the BlueField guest kernel + load its VF driver modules so the
        // assigned VF is not an inert PCI function in the guest.
        if let Some(kernel) = &self.kernel {
            kernel.apply(plan)?;
        }
        Ok(())
    }

    async fn before_launch(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
        plan: &mut LaunchPlan,
    ) -> LifecycleResult<()> {
        let slot = self.claim_slot(&sandbox.id)?;

        // Fail closed if this host can't actually pass the VF through (IOMMU
        // off, device missing, group conflict). ResourceExhausted lets the
        // scheduler retry on a capable host rather than booting a broken VM.
        if let Err(reason) = self.readiness.check_passthrough(&slot.host_bdf) {
            self.pool.release(&sandbox.id);
            return Err(LifecycleError::resource_exhausted(format!(
                "bluefield: host cannot pass through {}: {reason}",
                slot.host_bdf
            )));
        }

        // Fail closed on kernel image drift (missing / hash mismatch).
        if let Some(kernel) = &self.kernel
            && let Err(err) = kernel.validate()
        {
            self.pool.release(&sandbox.id);
            return Err(LifecycleError::resource_exhausted(err.to_string()));
        }

        let guard = match self.binder.bind_slot(&slot) {
            Ok(guard) => guard,
            Err(err) => {
                self.pool.release(&sandbox.id);
                return Err(LifecycleError::resource_exhausted(format!(
                    "bluefield: bind VF {} to vfio-pci: {err}",
                    slot.host_bdf
                )));
            }
        };

        if let Err(err) = state::persist_bind_state(&sandbox.id, state_dir, &slot) {
            drop(guard);
            self.pool.release(&sandbox.id);
            return Err(err);
        }
        // QEMU owns the device now; do not restore it on guard drop.
        guard.disarm();

        self.record_attachment(&sandbox.id, AttachmentRecord { slot: slot.clone() });

        // Attach the bound VF to the guest as a passthrough device (idempotent
        // with the declaration made in `configure_launch`).
        plan.add_resource(GuestResource::PciPassthrough(PciPassthroughDevice::new(
            slot.host_bdf.clone(),
        )));

        if let Some(egress) = &self.egress {
            plan.env.extend(egress.env(&slot));
        }
        Ok(())
    }

    async fn after_launch_failed(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
        _reason: LaunchAbortReason,
    ) -> LifecycleResult<()> {
        if let Some(record) = self.take_attachment(&sandbox.id)
            && let Err(err) = self.release_binding(state_dir, &record.slot)
        {
            tracing::warn!(
                sandbox_id = %sandbox.id,
                error = %err,
                "bluefield: failed to release VF binding after launch failure"
            );
        }
        self.pool.release(&sandbox.id);
        Ok(())
    }

    async fn after_delete(&self, sandbox: &Sandbox, state_dir: &Path) -> LifecycleResult<()> {
        if let Some(record) = self.take_attachment(&sandbox.id) {
            self.release_binding(state_dir, &record.slot)?;
        }
        self.pool.release(&sandbox.id);
        Ok(())
    }

    async fn before_restore(&self, ctx: &RestoreContext) -> LifecycleResult<()> {
        // A restore onto a misprovisioned host must fail closed exactly like a
        // fresh launch.
        if let Some(kernel) = &self.kernel
            && let Err(err) = kernel.validate()
        {
            return Err(LifecycleError::resource_exhausted(err.to_string()));
        }
        let bind_state = state::load_bind_state(&ctx.sandbox.id, &ctx.state_dir)?;
        let mut slot = self
            .pool
            .claim_by_host_bdf(&ctx.sandbox.id, &bind_state.host_bdf)
            .ok_or_else(|| {
                LifecycleError::resource_exhausted(format!(
                    "bluefield: persisted VF {} is not available for sandbox {}",
                    bind_state.host_bdf, ctx.sandbox.id
                ))
            })?;
        if slot.guest_mac.is_none() {
            slot.guest_mac = bind_state
                .guest_mac
                .clone()
                .or_else(|| Some(deterministic_vf_mac(&ctx.sandbox.id)));
        }
        let guard = self.binder.adopt_slot(&slot).map_err(|err| {
            LifecycleError::resource_exhausted(format!(
                "bluefield: adopt VF {} from persisted state: {err}",
                slot.host_bdf
            ))
        })?;
        guard.disarm();
        self.record_attachment(&ctx.sandbox.id, AttachmentRecord { slot });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[derive(Debug)]
    struct AlwaysReady;
    impl HostReadiness for AlwaysReady {
        fn check_passthrough(&self, _host_bdf: &str) -> Result<(), String> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct NeverReady;
    impl HostReadiness for NeverReady {
        fn check_passthrough(&self, _host_bdf: &str) -> Result<(), String> {
            Err("IOMMU disabled".to_string())
        }
    }

    #[derive(Debug)]
    struct TestVfBinding;
    impl crate::vf::VfBinding for TestVfBinding {
        fn disarm(self: Box<Self>) {}
    }

    #[derive(Debug)]
    struct TestVfBinder;
    impl VfBinder for TestVfBinder {
        fn bind_slot(&self, _slot: &VfSlot) -> Result<Box<dyn crate::vf::VfBinding>, String> {
            Ok(Box::new(TestVfBinding))
        }
        fn adopt_slot(&self, _slot: &VfSlot) -> Result<Box<dyn crate::vf::VfBinding>, String> {
            Ok(Box::new(TestVfBinding))
        }
        fn release_slot(&self, _slot: &VfSlot) -> Result<(), String> {
            Ok(())
        }
    }

    fn sandbox(id: &str) -> Sandbox {
        Sandbox {
            id: id.to_string(),
            name: id.to_string(),
            ..Default::default()
        }
    }

    fn state_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "openshell-bluefield-{name}-{}-{}",
            std::process::id(),
            state::now_millis()
        ))
    }

    fn passthrough_bdfs(plan: &LaunchPlan) -> Vec<&str> {
        plan.resources
            .iter()
            .map(|resource| match resource {
                GuestResource::PciPassthrough(device) => device.host_bdf.as_str(),
            })
            .collect()
    }

    fn sample_plan() -> LaunchPlan {
        LaunchPlan {
            backend: crate::runtime::VmBackend::Qemu,
            vcpus: 2,
            mem_mib: 2048,
            required_backends: Vec::new(),
            required_backend_features: Vec::new(),
            kernel_profile: None,
            kernel_image: None,
            gpu_bdf: None,
            tap_device: None,
            guest_ip: None,
            host_ip: None,
            vsock_cid: None,
            guest_mac: None,
            gateway_port: None,
            guest_init_dropins: Vec::new(),
            env: Vec::new(),
            resources: Vec::new(),
        }
    }

    fn ext(pool: VfPool) -> BluefieldExtension {
        BluefieldExtension::new(pool)
            .with_host_readiness(Arc::new(AlwaysReady))
            .with_vf_binder(Arc::new(TestVfBinder))
    }

    #[tokio::test]
    async fn before_launch_claims_slot_records_bind_state_and_injects_egress_env() {
        let extension = ext(VfPool::new([
            VfSlot::new("vf0", "0000:03:00.2").with_representor("pf0vf0")
        ]))
        .with_guest_egress(GuestEgress {
            address_cidr: "10.0.120.10/22".to_string(),
            gateway: "10.0.120.254".to_string(),
        });

        let mut plan = sample_plan();
        let state = state_dir("launch-env");
        extension
            .before_launch(&sandbox("sandbox-1"), &state, &mut plan)
            .await
            .unwrap();

        assert!(
            plan.env
                .iter()
                .any(|e| e == "OPENSHELL_VM_DATA_IP=10.0.120.10/22")
        );
        assert_eq!(passthrough_bdfs(&plan), vec!["0000:03:00.2"]);

        let bind_state = state::load_bind_state("sandbox-1", &state).unwrap();
        assert_eq!(bind_state.host_bdf, "0000:03:00.2");

        let record = extension
            .take_attachment("sandbox-1")
            .expect("attachment recorded");
        assert_eq!(record.slot.host_bdf, "0000:03:00.2");
        let _ = std::fs::remove_dir_all(&state);
    }

    #[tokio::test]
    async fn before_launch_fails_closed_when_pool_exhausted() {
        let extension = ext(VfPool::new([]));
        let mut plan = sample_plan();
        let err = extension
            .before_launch(&sandbox("sandbox-1"), &PathBuf::from("/tmp/s"), &mut plan)
            .await
            .unwrap_err();
        assert!(err.is_resource_exhausted());
    }

    #[tokio::test]
    async fn before_launch_fails_closed_when_host_not_vfio_ready() {
        let extension = BluefieldExtension::new(VfPool::new([VfSlot::new("vf0", "0000:03:00.2")]))
            .with_host_readiness(Arc::new(NeverReady))
            .with_vf_binder(Arc::new(TestVfBinder));

        let mut plan = sample_plan();
        let err = extension
            .before_launch(&sandbox("sandbox-1"), &PathBuf::from("/tmp/s"), &mut plan)
            .await
            .unwrap_err();
        assert!(err.is_resource_exhausted());

        // Slot was released so a later capable host can claim it.
        assert!(extension.pool.claim("sandbox-2").is_some());
    }

    #[tokio::test]
    async fn after_delete_releases_slot_and_state() {
        let extension = ext(VfPool::new([VfSlot::new("vf0", "0000:03:00.2")]));
        let state = state_dir("delete");
        let mut plan = sample_plan();
        extension
            .before_launch(&sandbox("sb-del"), &state, &mut plan)
            .await
            .unwrap();
        extension
            .after_delete(&sandbox("sb-del"), &state)
            .await
            .unwrap();

        assert!(extension.take_attachment("sb-del").is_none());
        assert!(state::load_bind_state("sb-del", &state).is_err());
        let _ = std::fs::remove_dir_all(&state);
    }

    #[tokio::test]
    async fn configure_launch_selects_kernel_and_declares_vf_passthrough() {
        let extension = BluefieldExtension::new(VfPool::new([VfSlot::new("vf0", "0000:03:00.2")]))
            .with_kernel(BluefieldKernel::from_image(
                "/opt/openshell/kernels/bf-vmlinux",
            ));

        let mut plan = sample_plan();
        extension
            .configure_launch(&sandbox("sandbox-1"), &PathBuf::from("/tmp/s"), &mut plan)
            .await
            .unwrap();

        assert_eq!(
            plan.kernel_image.as_deref(),
            Some(Path::new("/opt/openshell/kernels/bf-vmlinux"))
        );
        assert!(
            plan.required_backend_features
                .contains(&BackendFeature::ExternalKernelImage)
        );
        // The VF is declared as a passthrough device so the driver promotes
        // the launch to QEMU and the non-GPU guard sees a concrete device.
        assert!(
            plan.required_backend_features
                .contains(&BackendFeature::PciPassthrough)
        );
        assert_eq!(passthrough_bdfs(&plan), vec!["0000:03:00.2"]);
    }

    #[tokio::test]
    async fn before_restore_reclaims_and_records() {
        let state = state_dir("restore");
        let initial = ext(VfPool::new([
            VfSlot::new("vf0", "0000:03:00.2").with_representor("pf0vf0")
        ]));
        let mut plan = sample_plan();
        initial
            .before_launch(&sandbox("sb-restore"), &state, &mut plan)
            .await
            .unwrap();

        let extension = ext(VfPool::new([
            VfSlot::new("vf0", "0000:03:00.2").with_representor("pf0vf0")
        ]));
        let ctx = RestoreContext {
            sandbox: sandbox("sb-restore"),
            state_dir: state.clone(),
        };
        extension.before_restore(&ctx).await.unwrap();

        let record = extension
            .take_attachment("sb-restore")
            .expect("attachment recorded");
        assert_eq!(record.slot.host_bdf, "0000:03:00.2");
        let _ = std::fs::remove_dir_all(&state);
    }
}
