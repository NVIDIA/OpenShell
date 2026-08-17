// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Transport-neutral egress inputs and authorization results.
//!
//! Explicit proxy adapters normalize their protocol-specific request into an
//! [`EgressIntent`]. Authorization then returns an [`EgressDecision`] that is
//! consumed by destination validation and relay selection. Keeping these types
//! independent of CONNECT and forward HTTP prevents policy behavior from
//! drifting as more adapters are added.

use super::destination::DestinationValidationPlan;
use crate::opa::NetworkAction;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub(super) struct L7ConfigSnapshot {
    pub(super) config: crate::l7::L7EndpointConfig,
}

#[derive(Debug, Clone)]
pub(super) struct L7RouteSnapshot {
    pub(super) configs: Vec<L7ConfigSnapshot>,
    /// Policy generation used to materialize this L7 route.
    pub(super) l7_policy_generation: u64,
}

/// Endpoint metadata materialized for an allowed egress decision.
///
/// Adapters materialize these fields from the authoritative policy snapshot at
/// their existing timing boundaries so upstream-connect behavior stays stable.
#[derive(Debug, Clone)]
pub(super) struct EndpointDecision {
    pub(super) tls_mode: crate::l7::TlsMode,
    pub(super) l7_route: Option<L7RouteSnapshot>,
    /// Destination authorization selected from the captured endpoint metadata.
    pub(super) destination: Option<DestinationValidationPlan>,
    /// Raw endpoint configs returned with the authoritative egress decision.
    pub(super) policy_configs: Vec<regorus::Value>,
    /// Full endpoint identities and metadata captured in the same generation.
    #[allow(dead_code, reason = "consumed when the policy DNS adapter lands")]
    pub(super) matched_endpoints: Vec<crate::opa::MatchedEndpoint>,
    /// Whether policy matched the requested hostname exactly (not by glob).
    pub(super) exact_declared_host: bool,
}

impl Default for EndpointDecision {
    fn default() -> Self {
        Self {
            tls_mode: crate::l7::TlsMode::Auto,
            l7_route: None,
            destination: None,
            policy_configs: Vec::new(),
            matched_endpoints: Vec::new(),
            exact_declared_host: false,
        }
    }
}

impl EndpointDecision {
    pub(super) fn from_authorization(authorization: &crate::opa::EgressAuthorization) -> Self {
        Self {
            policy_configs: authorization.endpoint_configs.clone(),
            matched_endpoints: authorization.matched_endpoints.clone(),
            exact_declared_host: authorization.exact_declared_endpoint_host,
            ..Self::default()
        }
    }
}

/// Userland surface through which an external egress request arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EgressTransport {
    Connect,
    ForwardHttp,
    /// Future transparent TCP adapter fed by the policy DNS registry.
    #[allow(dead_code, reason = "constructed when transparent TCP adapter lands")]
    TransparentTcp,
}

/// Destination requested by an explicit proxy adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RequestedDestination {
    pub(super) host: String,
    pub(super) port: u16,
}

/// Transport-neutral description of an external egress request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EgressIntent {
    pub(super) transport: EgressTransport,
    pub(super) destination: RequestedDestination,
}

impl EgressIntent {
    pub(super) fn connect(host: String, port: u16) -> Self {
        Self::new(EgressTransport::Connect, host, port)
    }

    pub(super) fn forward_http(host: String, port: u16) -> Self {
        Self::new(EgressTransport::ForwardHttp, host, port)
    }

    #[cfg(test)]
    pub(super) fn transparent_tcp(host: String, port: u16) -> Self {
        Self {
            transport: EgressTransport::TransparentTcp,
            destination: RequestedDestination { host, port },
        }
    }

    fn new(transport: EgressTransport, host: String, port: u16) -> Self {
        Self {
            transport,
            destination: RequestedDestination { host, port },
        }
    }
}

/// Why process identity is absent from an egress decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) enum IdentityUnavailableReason {
    EndpointOnlyMode,
    LookupFailed,
    #[cfg(not(target_os = "linux"))]
    UnsupportedPlatform,
}

/// Process evidence captured for policy evaluation and audit logging.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) enum ProcessIdentityEvidence {
    Available,
    Unavailable(IdentityUnavailableReason),
}

/// Result of authorizing a normalized egress intent.
///
/// The policy action and endpoint metadata are one atomic snapshot. Adapters
/// may parse that metadata later, but they never query a second generation.
pub(super) struct EgressDecision {
    pub(super) intent: EgressIntent,
    pub(super) action: NetworkAction,
    /// Policy generation used for the complete authorization snapshot.
    pub(super) policy_generation: u64,
    /// Whether process identity evidence was available to policy evaluation.
    pub(super) identity: ProcessIdentityEvidence,
    /// Endpoint behavior hydrated for destination validation and relays.
    pub(super) endpoint: EndpointDecision,
    /// Resolved binary path.
    pub(super) binary: Option<PathBuf>,
    /// PID owning the socket.
    pub(super) binary_pid: Option<u32>,
    /// Ancestor binary paths from process tree walk.
    pub(super) ancestors: Vec<PathBuf>,
    /// Cmdline-derived absolute paths (for script detection).
    pub(super) cmdline_paths: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapters_create_transport_specific_intents() {
        let connect = EgressIntent::connect("api.example.com".to_string(), 443);
        let forward = EgressIntent::forward_http("api.example.com".to_string(), 80);

        assert_eq!(connect.transport, EgressTransport::Connect);
        assert_eq!(connect.destination.host, "api.example.com");
        assert_eq!(connect.destination.port, 443);
        assert_eq!(forward.transport, EgressTransport::ForwardHttp);
        assert_eq!(forward.destination.port, 80);

        let transparent = EgressIntent::transparent_tcp("db.example.com".to_string(), 5432);
        assert_eq!(transparent.transport, EgressTransport::TransparentTcp);
        assert_eq!(transparent.destination.host, "db.example.com");
        assert_eq!(transparent.destination.port, 5432);
    }
}
