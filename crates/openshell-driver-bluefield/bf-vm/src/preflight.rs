// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Aggregated host preflight for the VM/QEMU BlueField passthrough path.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreflightInput {
    pub(crate) host_pf: String,
    pub(crate) vf_bdfs: Vec<String>,
    pub(crate) qemu_kernel_image: PathBuf,
}

pub(crate) trait HostProbe: std::fmt::Debug + Send + Sync {
    fn command_exists(&self, name: &str) -> bool;
    fn path_exists(&self, path: &Path) -> bool;
    fn iommu_groups_populated(&self) -> bool;
    fn vfio_pci_available(&self) -> bool;
    fn check_passthrough(&self, bdf: &str) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub(crate) struct RealHostProbe;

impl HostProbe for RealHostProbe {
    fn command_exists(&self, name: &str) -> bool {
        std::env::var_os("PATH")
            .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn iommu_groups_populated(&self) -> bool {
        std::fs::read_dir("/sys/kernel/iommu_groups")
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false)
    }

    fn vfio_pci_available(&self) -> bool {
        Path::new("/sys/bus/pci/drivers/vfio-pci").exists()
            || Path::new("/sys/module/vfio_pci").exists()
    }

    fn check_passthrough(&self, bdf: &str) -> Result<(), String> {
        openshell_vfio::validate_pci_for_passthrough(&openshell_vfio::SysfsRoot::system(), bdf)
            .map_err(|err| err.to_string())
    }
}

pub(crate) fn run_preflight(probe: &dyn HostProbe, input: &PreflightInput) -> Result<(), String> {
    let mut failures = Vec::new();

    require_command(probe, "qemu-system-x86_64", &mut failures);
    require_command(probe, "ip", &mut failures);
    require_command(probe, "nft", &mut failures);
    require_command(probe, "debugfs", &mut failures);
    if !probe.command_exists("mkfs.ext4") && !probe.command_exists("mke2fs") {
        failures.push("missing mkfs.ext4 or mke2fs; install e2fsprogs".to_string());
    }
    if !probe.path_exists(Path::new("/dev/kvm")) {
        failures.push("missing /dev/kvm; enable KVM virtualization on the host".to_string());
    }
    if !probe.iommu_groups_populated() {
        failures.push(
            "IOMMU groups are not populated; boot with intel_iommu=on iommu=pt or amd_iommu=on iommu=pt"
                .to_string(),
        );
    }
    if !probe.vfio_pci_available() {
        failures.push("vfio-pci is not available; load it with modprobe vfio-pci".to_string());
    }
    if input.vf_bdfs.is_empty() {
        failures.push(format!(
            "BlueField host PF {} has no usable VFs after reservations",
            input.host_pf
        ));
    }
    if !probe.path_exists(&input.qemu_kernel_image) {
        failures.push(format!(
            "BlueField QEMU kernel image does not exist: {}",
            input.qemu_kernel_image.display()
        ));
    }
    for vf in &input.vf_bdfs {
        if let Err(reason) = probe.check_passthrough(vf) {
            failures.push(format!("VF {vf} is not ready for passthrough: {reason}"));
        }
    }

    if failures.is_empty() {
        return Ok(());
    }

    Err(format!(
        "BlueField QEMU host preflight failed:\n- {}",
        failures.join("\n- ")
    ))
}

fn require_command(probe: &dyn HostProbe, name: &str, failures: &mut Vec<String>) {
    if !probe.command_exists(name) {
        failures.push(format!("missing {name} in PATH"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::path::PathBuf;

    #[derive(Debug, Default)]
    struct StubProbe {
        commands: HashSet<&'static str>,
        paths: HashSet<&'static str>,
        iommu_groups: bool,
        vfio_loaded: bool,
        passthrough_ok: bool,
    }

    impl HostProbe for StubProbe {
        fn command_exists(&self, name: &str) -> bool {
            self.commands.contains(name)
        }

        fn path_exists(&self, path: &std::path::Path) -> bool {
            self.paths.contains(path.to_string_lossy().as_ref())
        }

        fn iommu_groups_populated(&self) -> bool {
            self.iommu_groups
        }

        fn vfio_pci_available(&self) -> bool {
            self.vfio_loaded
        }

        fn check_passthrough(&self, _bdf: &str) -> Result<(), String> {
            self.passthrough_ok
                .then_some(())
                .ok_or_else(|| "IOMMU group conflict".to_string())
        }
    }

    #[test]
    fn preflight_reports_multiple_failures_together() {
        let probe = StubProbe::default();
        let input = PreflightInput {
            host_pf: "0000:b1:00.0".to_string(),
            vf_bdfs: vec!["0000:b1:04.1".to_string()],
            qemu_kernel_image: PathBuf::from("/missing/vmlinux"),
        };

        let err = run_preflight(&probe, &input).unwrap_err();

        assert!(err.contains("qemu-system-x86_64"));
        assert!(err.contains("/dev/kvm"));
        assert!(err.contains("IOMMU"));
        assert!(err.contains("vfio-pci"));
        assert!(err.contains("IOMMU group conflict"));
        assert!(err.contains("/missing/vmlinux"));
    }

    #[test]
    fn preflight_passes_when_all_required_inputs_are_present() {
        let probe = StubProbe {
            commands: HashSet::from(["qemu-system-x86_64", "ip", "nft", "debugfs", "mkfs.ext4"]),
            paths: HashSet::from(["/dev/kvm", "/runtime/vmlinux"]),
            iommu_groups: true,
            vfio_loaded: true,
            passthrough_ok: true,
        };
        let input = PreflightInput {
            host_pf: "0000:b1:00.0".to_string(),
            vf_bdfs: vec!["0000:b1:04.1".to_string()],
            qemu_kernel_image: PathBuf::from("/runtime/vmlinux"),
        };

        run_preflight(&probe, &input).unwrap();
    }
}
