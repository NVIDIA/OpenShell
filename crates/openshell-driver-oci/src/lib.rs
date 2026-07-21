// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCI compute driver for `OpenShell`.
//!
//! Constructs sandboxes from Linux kernel primitives (namespaces, cgroups
//! v2, a configurable low-level OCI runtime) by driving a system-provided
//! `containerd` rather than a container engine daemon (Docker/Podman) or a
//! hypervisor. See the crate's `README.md` and the module-level docs on
//! [`driver`] for the current scope and what has/has not been verified
//! against a real system.

pub mod config;
pub mod driver;
pub mod gpu;
pub mod grpc;
pub mod network;
pub mod runtime;
pub mod spec;

pub use config::OciComputeConfig;
pub use driver::OciComputeDriver;
pub use grpc::ComputeDriverService;
