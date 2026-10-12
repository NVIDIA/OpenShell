// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Networking component of the `OpenShell` supervisor.
//!
//! Owns the egress proxy, L7 enforcement, OPA policy engine, identity cache,
//! TLS interception, and credential injection. The denial-event channel is
//! owned by the orchestrator; this crate produces denials but does not
//! aggregate them.

mod google_cloud_metadata;
#[cfg(target_os = "windows")]
pub mod host;
pub mod identity;
pub mod identity_source;
pub mod l7;
pub mod opa;
pub(crate) mod policy_dns;
pub mod policy_local;
pub mod procfs;
pub mod proxy;
pub mod run;
pub mod sigv4;
mod spiffe_endpoint;
mod token_grant;
pub mod upstream_proxy;

#[cfg(test)]
pub(crate) use openshell_driver_vm::allocation_tracking as test_alloc;
#[cfg(test)]
#[global_allocator]
static TEST_ALLOCATOR: openshell_driver_vm::allocation_tracking::CountingAllocator =
    openshell_driver_vm::allocation_tracking::CountingAllocator;
#[cfg(all(test, target_os = "linux"))]
mod test_support;
