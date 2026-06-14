// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Networking component of the `OpenShell` supervisor.
//!
//! Owns the egress proxy, L7 enforcement, OPA policy engine, identity cache,
//! inference routing, and TLS interception. The denial-event channel is
//! owned by the orchestrator; this crate produces denials but does not
//! aggregate them.

pub mod identity;
pub mod inference_routes;
pub mod l7;
pub mod opa;
pub mod policy_local;
pub mod procfs;
pub mod proxy;
pub mod run;
mod spiffe_endpoint;
mod token_grant;
