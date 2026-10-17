// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Networking component of the `OpenShell` supervisor.
//!
//! Owns the egress proxy, L7 enforcement, the OPA and Cedar policy engines,
//! identity cache, TLS interception, and credential injection. The denial-event channel is
//! owned by the orchestrator; this crate produces denials but does not
//! aggregate them.

mod binary_resolution;
pub mod cedar_only;
#[cfg(test)]
mod cedar_parity_tests;
mod cedar_provider_rules;
mod google_cloud_metadata;
#[cfg(target_os = "windows")]
pub mod host;
pub mod identity;
pub mod identity_source;
pub mod l7;
mod network_middleware;
pub mod opa;
pub(crate) mod policy_data;
pub(crate) mod policy_dns;
pub mod policy_engine;
pub mod policy_local;
pub mod policy_types;
pub mod policy_validation;
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
#[cfg(test)]
mod test_support;
