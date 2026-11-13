// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Code shared by the `OpenShell` desktop compute drivers.
//!
//! Everything here is used only by the Docker, Podman, and VM drivers. Items
//! that core (the gateway, supervisor, or the Kubernetes driver) also uses live
//! in `openshell-driver-sdk` instead. This crate depends on the SDK and never on
//! `openshell-core`, so it can move with the drivers.

pub mod config;
pub mod driver_utils;
pub mod gpu;
pub mod local_api_socket;
pub mod network_trust;
pub mod proto_struct;
pub mod resource_admission;
