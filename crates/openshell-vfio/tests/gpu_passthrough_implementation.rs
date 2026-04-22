// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for GPU passthrough on real hardware.
//!
//! Gated by `OPENSHELL_VM_GPU_E2E=1`. On machines without a real GPU,
//! all tests early-return and pass.

use openshell_vfio::{
    GpuBindGuard, HostNvidiaVfioReadiness, prepare_gpu_for_passthrough,
    probe_host_nvidia_vfio_readiness,
};

fn gpu_e2e_enabled() -> bool {
    std::env::var("OPENSHELL_VM_GPU_E2E").as_deref() == Ok("1")
}

#[test]
fn nvidia_gpu_passthrough_is_available() {
    if !gpu_e2e_enabled() {
        eprintln!("OPENSHELL_VM_GPU_E2E not set — skipping GPU passthrough gate test");
        return;
    }
    assert!(
        openshell_vfio::nvidia_gpu_available_for_vm_passthrough(None),
        "GPU passthrough gate returned false on a GPU CI runner — \
         check VFIO binding and cloud-hypervisor runtime bundle"
    );
}

#[test]
fn bind_and_rebind_real_gpu() {
    if !gpu_e2e_enabled() {
        return;
    }

    let state = prepare_gpu_for_passthrough(None).expect("should find and bind a GPU");

    let results = probe_host_nvidia_vfio_readiness();
    let (_, readiness) = results
        .iter()
        .find(|(a, _)| a == &state.pci_addr)
        .expect("bound GPU should appear in probe");
    assert_eq!(*readiness, HostNvidiaVfioReadiness::VfioBoundReady);

    state.restore().expect("restore should succeed");

    let results = probe_host_nvidia_vfio_readiness();
    let (_, readiness) = results
        .iter()
        .find(|(a, _)| a == &state.pci_addr)
        .expect("restored GPU should appear in probe");
    assert_eq!(*readiness, HostNvidiaVfioReadiness::BoundToNvidia);
}

#[test]
fn safety_checks_pass_on_ci_gpu() {
    if !gpu_e2e_enabled() {
        return;
    }

    // `prepare_gpu_for_passthrough` runs all safety checks internally
    // (display-attached, IOMMU enabled, VFIO modules loaded, sysfs
    // permissions). Success here validates that the CI GPU is headless,
    // IOMMU is on, and VFIO modules are loaded.
    let state = prepare_gpu_for_passthrough(None)
        .expect("all safety checks should pass on a headless CI GPU");
    assert!(!state.pci_addr.is_empty());

    state.restore().expect("restore should succeed");
}

#[test]
fn guard_restores_on_drop_real_gpu() {
    if !gpu_e2e_enabled() {
        return;
    }

    let state = prepare_gpu_for_passthrough(None).expect("should find and bind a GPU");
    let pci_addr = state.pci_addr.clone();

    let guard = GpuBindGuard::new(state);
    drop(guard);

    let output = std::process::Command::new("nvidia-smi")
        .arg("--query-gpu=pci.bus_id")
        .arg("--format=csv,noheader")
        .output()
        .expect("nvidia-smi should be available after guard drop");
    assert!(
        output.status.success(),
        "nvidia-smi failed after guard drop"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized_addr = pci_addr.to_uppercase();
    assert!(
        stdout.to_uppercase().contains(&normalized_addr),
        "nvidia-smi should list the restored GPU {pci_addr}, got: {stdout}"
    );
}

#[test]
fn auto_select_finds_ci_gpu() {
    if !gpu_e2e_enabled() {
        return;
    }

    let state = prepare_gpu_for_passthrough(None).expect("auto-select should find a GPU on CI");
    assert!(!state.pci_addr.is_empty());
    assert!(state.did_bind);

    state.restore().expect("restore should succeed");
}
