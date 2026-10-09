// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Trusted launch metadata for an endpoint-registered Sandbox Protocol backend.

use std::collections::BTreeMap;
use std::net::IpAddr;

use openshell_core::SandboxSessionId;
use openshell_isolation_interface::contract::{OuterFenceGuarantees, ResolvedWorkloadIdentity};
use serde::{Deserialize, Serialize};

use crate::boundary_protocol::SandboxTlsClientConfig;

/// Delivered by the trusted driver separately from its opaque backend payload.
/// Endpoint selection belongs to operator configuration, not launch data.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedLaunch {
    pub backend_name: String,
    pub sandbox_id: String,
    pub generation: String,
    pub session_id: SandboxSessionId,
    pub workload_identity: ResolvedWorkloadIdentity,
    pub tls: SandboxTlsClientConfig,
    #[serde(default)]
    pub host_gateway_ip: Option<IpAddr>,
    pub resource_claims: BTreeMap<String, String>,
    pub outer_fence: OuterFenceGuarantees,
}
