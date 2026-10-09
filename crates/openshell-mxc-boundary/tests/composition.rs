// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Guard the relay-free library boundary without starting a mock runtime.

#[test]
fn dedicated_boundary_does_not_embed_driver_or_supervisor() {
    let manifest = include_str!("../Cargo.toml");
    assert!(manifest.contains("name = \"openshell-windows-sandbox\""));
    assert!(!manifest.contains("openshell-driver-mxc"));
    assert!(!manifest.contains("openshell-supervisor"));
    let runtime = include_str!("../src/runtime.rs");
    assert!(!runtime.contains("openshell-supervisor-relay"));
}

#[test]
fn shared_runtime_keeps_platform_audit_interpretation_in_backend_extension() {
    let protocol = include_str!("../../openshell-sandbox-backend/src/boundary_protocol.rs");
    assert!(!protocol.contains("MxcSandboxAuditEvidence"));
    assert!(!protocol.contains("WindowsMxc"));
    let runtime = include_str!("../../openshell-sandbox-backend/src/runtime.rs");
    assert!(runtime.contains("self.audit_validator.validate(&confirmation.backend_audit)?"));
    assert!(runtime.contains("confirmation.properties != properties"));
    let composition = include_str!("../../openshell-supervisor/src/backend_setup/mxc.rs");
    assert!(composition.contains("MxcRuntimeBackend::new"));
    assert!(composition.contains("impl BackendSetup for MxcBackendSetup"));
    assert!(composition.contains("impl PreparedBackend for MxcLaunch"));
    let supervisor = include_str!("../../openshell-supervisor/src/lib.rs");
    assert!(!supervisor.contains("serde_json::from_slice(&backend_descriptor.payload)"));
    assert!(!supervisor.contains("OpenShellRuntimeBackend::discover_policy"));
    assert!(!supervisor.contains("MxcReverseTcpConnector"));
    let backend = include_str!("../src/backend.rs");
    assert!(backend.contains("impl IsolationBackend for MxcRuntimeBackend"));
    assert!(backend.contains("MxcBoundaryAuditValidator"));
    assert!(backend.contains("self.transport.attach(descriptor, sandbox).await"));
}

#[test]
fn proxy_launch_data_does_not_extend_shared_isolation_contracts() {
    let contract = include_str!("../../openshell-isolation-interface/src/contract.rs");
    let protocol = include_str!("../../openshell-sandbox-backend/src/boundary_protocol.rs");
    assert!(!contract.contains("DirectProxyConfiguration"));
    assert!(!contract.contains("direct_proxy_configuration"));
    assert!(!protocol.contains("direct_proxy"));
    for driver in [
        include_str!("../../openshell-driver-docker/src/isolation.rs"),
        include_str!("../../openshell-driver-kubernetes/src/isolation.rs"),
        include_str!("../../openshell-driver-vm/src/isolation/mod.rs"),
    ] {
        assert!(!driver.contains("direct_proxy"));
    }
}

#[test]
fn only_dedicated_sandbox_delegates_to_the_windows_boundary_library() {
    let manifest = include_str!("../../openshell-sandbox/Cargo.toml");
    assert!(!manifest.contains("\nwindows = "));
    assert!(!manifest.contains("openshell-mxc-boundary"));
    let sandbox = include_str!("../../openshell-sandbox/src/boundary_server.rs");
    assert!(!sandbox.contains("openshell_mxc_boundary::run"));
    assert!(!sandbox.contains("mod windows;"));
    let main = include_str!("../src/main.rs");
    assert!(main.contains("openshell_mxc_boundary::run(&args.bootstrap)"));
    let driver = include_str!("../../openshell-driver-mxc/src/driver.rs");
    assert!(driver.contains("sibling_binary(\"openshell-windows-sandbox.exe\")"));
}
