// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Environment variable names that make up the BlueField driver's external
//! configuration contract.
//!
//! Centralizing the names here gives the host-side driver, the guest-init
//! path, and any future runtime adapters (containers, Kubernetes) a single
//! source of truth. The values are `&'static str` so they can be referenced
//! both from `clap` `env = ...` attributes and from plain `std::env` lookups.

/// Master switch that enables the BlueField driver.
pub const BLUEFIELD: &str = "OPENSHELL_BLUEFIELD";

/// Deployment role: `all-in-one`, `control-plane`, or `compute-node`.
pub const BLUEFIELD_ROLE: &str = "OPENSHELL_BLUEFIELD_ROLE";

/// gRPC endpoint of the control-plane controller (compute-node role).
pub const BLUEFIELD_CONTROLLER_ENDPOINT: &str = "OPENSHELL_BLUEFIELD_CONTROLLER_ENDPOINT";

/// Directory holding the mutual-TLS material for the controller channel.
pub const BLUEFIELD_TLS_DIR: &str = "OPENSHELL_BLUEFIELD_TLS_DIR";

/// Expected TLS server name for the controller certificate.
pub const BLUEFIELD_TLS_DOMAIN: &str = "OPENSHELL_BLUEFIELD_TLS_DOMAIN";

/// Host physical function (netdev name or PCI BDF) backing the VFs.
pub const BLUEFIELD_HOST_PF: &str = "OPENSHELL_BLUEFIELD_HOST_PF";

/// Comma-separated VF indexes reserved from the assignable pool.
pub const BLUEFIELD_RESERVED_VF_INDEXES: &str = "OPENSHELL_BLUEFIELD_RESERVED_VF_INDEXES";

/// Identifier of the PF used when computing per-function keys.
pub const BLUEFIELD_PF_KEY: &str = "OPENSHELL_BLUEFIELD_PF_KEY";

/// Source NAT IP applied on the DPU for sandbox egress.
pub const BLUEFIELD_SNAT_IP: &str = "OPENSHELL_BLUEFIELD_SNAT_IP";

/// Uplink port on the DPU that carries sandbox egress.
pub const BLUEFIELD_UPLINK_PORT: &str = "OPENSHELL_BLUEFIELD_UPLINK_PORT";

/// Path to the BlueField guest kernel image.
pub const BLUEFIELD_KERNEL_IMAGE: &str = "OPENSHELL_BLUEFIELD_KERNEL_IMAGE";

/// Expected version string for the guest kernel image.
pub const BLUEFIELD_KERNEL_VERSION: &str = "OPENSHELL_BLUEFIELD_KERNEL_VERSION";

/// Expected SHA-256 of the guest kernel image.
pub const BLUEFIELD_KERNEL_SHA256: &str = "OPENSHELL_BLUEFIELD_KERNEL_SHA256";

/// Comma-separated guest kernel modules to load.
pub const BLUEFIELD_KERNEL_MODULES: &str = "OPENSHELL_BLUEFIELD_KERNEL_MODULES";

/// Egress CIDR assigned to a single sandbox function.
pub const BLUEFIELD_EGRESS_CIDR: &str = "OPENSHELL_BLUEFIELD_EGRESS_CIDR";

/// Comma-separated pool of egress CIDRs handed out per function.
pub const BLUEFIELD_EGRESS_CIDR_POOL: &str = "OPENSHELL_BLUEFIELD_EGRESS_CIDR_POOL";

/// Default gateway for sandbox egress traffic.
pub const BLUEFIELD_EGRESS_GATEWAY: &str = "OPENSHELL_BLUEFIELD_EGRESS_GATEWAY";

/// Comma-separated DNS resolvers advertised to the sandbox.
pub const BLUEFIELD_EGRESS_DNS: &str = "OPENSHELL_BLUEFIELD_EGRESS_DNS";

/// Proxy placement: `none` or `dpu`.
pub const BLUEFIELD_PROXY_PLACEMENT: &str = "OPENSHELL_BLUEFIELD_PROXY_PLACEMENT";

/// Explicit proxy URL injected into the sandbox when proxying is enabled.
pub const BLUEFIELD_EXPLICIT_PROXY_URL: &str = "OPENSHELL_BLUEFIELD_EXPLICIT_PROXY_URL";

/// Guest data-path egress mode (e.g. `external-vf`).
pub const VM_DATA_EGRESS: &str = "OPENSHELL_VM_DATA_EGRESS";

/// Guest data-path IP assignment mode (e.g. `static`).
pub const VM_DATA_IP_MODE: &str = "OPENSHELL_VM_DATA_IP_MODE";

/// Guest data-path interface address in CIDR notation.
pub const VM_DATA_IP: &str = "OPENSHELL_VM_DATA_IP";

/// Guest data-path default gateway.
pub const VM_DATA_GW: &str = "OPENSHELL_VM_DATA_GW";

/// Guest data-path interface MAC address.
pub const VM_DATA_MAC: &str = "OPENSHELL_VM_DATA_MAC";
