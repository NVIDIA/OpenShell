// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Guest kernel selection for the BlueField extension.
//!
//! A VF-passthrough guest needs the in-guest NIC driver (`mlx5_core`, and
//! `mlx5_ib` for RDMA) plus the PCI/auxiliary-bus plumbing; without it the
//! assigned VF is an inert PCI function. Rather than baking NVIDIA/Mellanox
//! drivers into the *upstream* default guest kernel (which would couple
//! upstream to NVIDIA hardware), the extension selects its own BlueField
//! kernel via the existing [`LaunchPlan`] seam — keeping the generic kernel
//! NVIDIA-free.
//!
//! Two ways to express the requirement:
//!
//! - [`BluefieldKernel::image`] — a concrete kernel path. Consumed end-to-end
//!   today: it becomes `plan.kernel_image` and requires
//!   [`BackendFeature::ExternalKernelImage`] (QEMU-only).
//! - [`BluefieldKernel::profile`] — a named profile (e.g. `"bluefield"`). The
//!   intended abstraction, but a no-op at boot until a profile→image registry
//!   lands in the runtime; recorded on `plan.kernel_profile` for now.
//!
//! Kernel selection here is purely about *function* (making the VF work) and
//! must come from driver/extension config — never a tenant-settable field.
//! Tier-2 (DPU) enforcement holds regardless of the guest kernel.

use std::path::{Path, PathBuf};

use crate::lifecycle::{
    BackendFeature, GuestInitDropin, LaunchPlan, LifecycleError, LifecycleResult,
};

/// Guest-init drop-in that loads the VF driver modules. Sorted before the
/// `50-` egress drop-in so the NIC exists when egress is configured.
pub const MODULES_DROPIN_NAME: &str = "40-bluefield-kernel-modules.sh";

/// Default modules for a Mellanox/NVIDIA VF. `mlx5_core` brings up the
/// ethernet function; `mlx5_ib` adds the RDMA verbs path (GPUDirect/RoCE).
/// Loading a built-in (`=y`) module via `modprobe` is a harmless no-op, so
/// this list is safe whether the BlueField kernel compiles them in or as
/// modules.
pub const MELLANOX_VF_MODULES: &[&str] = &["mlx5_core", "mlx5_ib"];

/// BlueField guest-kernel requirement for a sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BluefieldKernel {
    /// Concrete kernel image path (QEMU `-kernel`). Driver/extension-owned.
    pub image: Option<PathBuf>,
    /// Named kernel profile, for the future profile→image registry.
    pub profile: Option<String>,
    /// Expected kernel release (`uname -r`). Pins the image to the rootfs
    /// module bundle: guest-init asserts the running kernel matches before
    /// loading modules, so kernel↔rootfs drift fails loudly at boot instead
    /// of `modprobe` finding the wrong `/lib/modules/<ver>`.
    pub version: Option<String>,
    /// Expected lowercase hex SHA-256 of the kernel image. When set,
    /// [`Self::validate`] refuses to launch unless the on-host image matches,
    /// so every host in the fleet runs the identical vetted kernel.
    pub image_sha256: Option<String>,
    /// Modules guest-init should `modprobe` before VF bring-up.
    pub required_modules: Vec<String>,
}

impl BluefieldKernel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A BlueField kernel supplied as a concrete image, with the default
    /// Mellanox VF modules.
    #[must_use]
    pub fn from_image(image: impl Into<PathBuf>) -> Self {
        Self {
            image: Some(image.into()),
            profile: None,
            version: None,
            image_sha256: None,
            required_modules: MELLANOX_VF_MODULES
                .iter()
                .map(|m| (*m).to_string())
                .collect(),
        }
    }

    /// A BlueField kernel referenced by profile name, with the default
    /// Mellanox VF modules.
    #[must_use]
    pub fn from_profile(profile: impl Into<String>) -> Self {
        Self {
            image: None,
            profile: Some(profile.into()),
            version: None,
            image_sha256: None,
            required_modules: MELLANOX_VF_MODULES
                .iter()
                .map(|m| (*m).to_string())
                .collect(),
        }
    }

    #[must_use]
    pub fn with_modules(mut self, modules: impl IntoIterator<Item = String>) -> Self {
        self.required_modules = modules.into_iter().collect();
        self
    }

    /// Pin the expected guest kernel release (`uname -r`). Asserted in-guest
    /// before module load to catch kernel↔rootfs drift.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Pin the expected SHA-256 (lowercase hex) of the kernel image, enforced
    /// by [`Self::validate`] so every host runs the identical vetted image.
    #[must_use]
    pub fn with_image_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.image_sha256 = Some(sha256.into());
        self
    }

    /// Optional preflight check. The driver also validates `kernel_image`
    /// existence at provisioning, but calling this early gives a clearer
    /// error before the VM is built. FS-touching, so it is not run from
    /// [`Self::apply`].
    pub fn validate(&self) -> LifecycleResult<()> {
        if let Some(image) = &self.image {
            if !image.is_file() {
                return Err(LifecycleError::new(format!(
                    "bluefield kernel image does not exist: {}",
                    image.display()
                )));
            }
            if let Some(expected) = &self.image_sha256 {
                let actual = file_sha256(image).map_err(|err| {
                    LifecycleError::new(format!(
                        "hashing bluefield kernel image {}: {err}",
                        image.display()
                    ))
                })?;
                if !actual.eq_ignore_ascii_case(expected) {
                    return Err(LifecycleError::new(format!(
                        "bluefield kernel image hash mismatch for {}: expected {expected}, got {actual}",
                        image.display()
                    )));
                }
            }
        }
        Ok(())
    }

    /// Apply this requirement to the launch plan: select the kernel and
    /// register the module-loading drop-in. Pure (no filesystem access) so
    /// it is trivially testable; existence is enforced by the driver and by
    /// [`Self::validate`].
    pub fn apply(&self, plan: &mut LaunchPlan) -> LifecycleResult<()> {
        if let Some(image) = &self.image {
            plan.kernel_image = Some(image.clone());
            plan.require_backend_feature(BackendFeature::ExternalKernelImage);
        }
        if let Some(profile) = &self.profile {
            plan.kernel_profile = Some(profile.clone());
        }
        if !self.required_modules.is_empty() {
            plan.require_backend_feature(BackendFeature::GuestInitDropins);
            plan.guest_init_dropins.push(self.modules_dropin());
        }
        Ok(())
    }

    fn modules_dropin(&self) -> GuestInitDropin {
        let mut script = String::from(
            "#!/bin/bash\n# OpenShell BlueField VF kernel modules (scaffold).\nset -eu\n",
        );
        if let Some(version) = &self.version {
            // Fail loudly on kernel↔rootfs drift before touching modules.
            script.push_str(&format!(
                "want={version}\nhave=\"$(uname -r)\"\nif [ \"$have\" != \"$want\" ]; then echo \"openshell: guest kernel $have != expected $want (kernel/rootfs drift)\" >&2; exit 1; fi\n"
            ));
        }
        for module in &self.required_modules {
            // modprobe of a built-in module is a no-op returning success.
            script.push_str(&format!(
                "modprobe {module} || echo \"openshell: failed to modprobe {module}\" >&2\n"
            ));
        }
        GuestInitDropin::new(MODULES_DROPIN_NAME, script.into_bytes())
    }
}

/// Lowercase-hex SHA-256 of a file's contents.
///
/// TODO(scaffold): reads the whole image into memory; stream once kernels
/// are large enough to matter.
fn file_sha256(path: &Path) -> std::io::Result<String> {
    use core::fmt::Write as _;
    use sha2::{Digest, Sha256};

    let bytes = std::fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(hex, "{byte:02x}").expect("writing to String never fails");
    }
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_plan() -> LaunchPlan {
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

    #[test]
    fn image_sets_plan_and_requires_external_kernel() {
        let mut plan = empty_plan();
        BluefieldKernel::from_image("/opt/openshell/kernels/bluefield-vmlinux")
            .apply(&mut plan)
            .unwrap();
        assert_eq!(
            plan.kernel_image.as_deref(),
            Some(Path::new("/opt/openshell/kernels/bluefield-vmlinux"))
        );
        assert!(
            plan.required_backend_features
                .contains(&BackendFeature::ExternalKernelImage)
        );
    }

    #[test]
    fn profile_is_recorded_without_external_kernel_feature() {
        let mut plan = empty_plan();
        BluefieldKernel::from_profile("bluefield")
            .apply(&mut plan)
            .unwrap();
        assert_eq!(plan.kernel_profile.as_deref(), Some("bluefield"));
        assert!(
            !plan
                .required_backend_features
                .contains(&BackendFeature::ExternalKernelImage)
        );
    }

    #[test]
    fn modules_emit_modprobe_dropin() {
        let mut plan = empty_plan();
        BluefieldKernel::from_profile("bluefield")
            .apply(&mut plan)
            .unwrap();
        let dropin = plan
            .guest_init_dropins
            .iter()
            .find(|d| d.name == MODULES_DROPIN_NAME)
            .expect("modules drop-in present");
        let script = String::from_utf8(dropin.contents.clone()).unwrap();
        assert!(script.contains("modprobe mlx5_core"));
        assert!(script.contains("modprobe mlx5_ib"));
    }

    #[test]
    fn validate_rejects_missing_image() {
        let err = BluefieldKernel::from_image("/no/such/kernel")
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn validate_enforces_image_hash() {
        let path = std::env::temp_dir().join(format!("bf-kernel-{}", std::process::id()));
        std::fs::write(&path, b"fake-kernel-bytes").unwrap();
        let good = file_sha256(&path).unwrap();

        assert!(
            BluefieldKernel::from_image(path.clone())
                .with_image_sha256(good)
                .validate()
                .is_ok()
        );

        let err = BluefieldKernel::from_image(path.clone())
            .with_image_sha256("deadbeef")
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn version_pin_emits_guest_uname_assertion() {
        let mut plan = empty_plan();
        BluefieldKernel::from_profile("bluefield")
            .with_version("6.8.0-openshell-bf")
            .apply(&mut plan)
            .unwrap();
        let dropin = plan
            .guest_init_dropins
            .iter()
            .find(|d| d.name == MODULES_DROPIN_NAME)
            .expect("modules drop-in present");
        let script = String::from_utf8(dropin.contents.clone()).unwrap();
        assert!(script.contains("want=6.8.0-openshell-bf"));
        assert!(script.contains("uname -r"));
    }
}
