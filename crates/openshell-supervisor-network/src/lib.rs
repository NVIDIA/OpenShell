// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Networking component of the `OpenShell` supervisor.
//!
//! Owns the egress proxy, L7 enforcement, OPA policy engine, identity cache,
//! inference routing, TLS interception, and denial aggregation. Populated by
//! follow-up commits as modules migrate out of `openshell-sandbox`.

pub mod bypass_monitor;
pub mod denial;
pub mod denial_aggregator;
pub mod identity;
pub mod inference_routes;
pub mod l7;
pub mod mechanistic_mapper;
pub mod opa;
pub mod policy_local;
pub mod procfs;
pub mod proxy;
pub mod run;
