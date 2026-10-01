// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Metadata that lets an edge proxy send a sandbox's long-lived connections
//! straight to the gateway replica holding its supervisor session.

/// Response metadata naming the replica that owns a sandbox's supervisor session.
pub const OWNER_REPLICA_HEADER: &str = "x-openshell-owner";

/// Request metadata asking the edge proxy to route to a specific replica.
pub const ROUTE_REPLICA_HEADER: &str = "x-openshell-replica";
