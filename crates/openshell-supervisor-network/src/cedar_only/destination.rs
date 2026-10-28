// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The address checks of one allowed Cedar connection.

use std::net::IpAddr;
use std::sync::Arc;

use openshell_policy_cedar::{CedarEngine, IpNet, NetworkConnectRequest, NetworkEvaluation};

use super::ProviderRanges;

/// How the resolved addresses of one allowed Cedar connection are checked.
///
/// Carries the connection's decision made before its host resolved, and the
/// policy that made it, so each resolved address is evaluated against the
/// same policy generation. The admission rules that use it live in
/// `proxy::destination`.
#[derive(Clone)]
pub struct CedarDestination {
    pub(super) engine: Arc<CedarEngine>,
    pub(super) request: NetworkConnectRequest,
    pub(super) evaluation: NetworkEvaluation,
    /// The `allowed_ips` of the matching provider endpoints that have them.
    pub(super) provider_ranges: Vec<ProviderRanges>,
}

impl CedarDestination {
    /// The `allowed_ips` of each matching provider endpoint that has them.
    ///
    /// Each must admit every address, but they never admit an address
    /// Cedar's own rules reject: providers grant no access.
    pub(crate) fn provider_ranges(&self) -> &[ProviderRanges] {
        &self.provider_ranges
    }

    /// The `destination_ip` ranges of each allowing permit that has them.
    pub(crate) fn address_conditions(&self) -> &[Vec<IpNet>] {
        &self.evaluation.address_conditions
    }

    /// Whether an allowing permit has no `destination_ip` condition.
    pub(crate) fn unconstrained_permit(&self) -> bool {
        self.evaluation.unconstrained_permit
    }

    /// Whether an allowing permit names the connection's host and port
    /// exactly.
    pub(crate) fn names_endpoint(&self) -> bool {
        self.evaluation.names_endpoint
    }

    /// Returns whether Cedar allows the connection to resolved address `ip`,
    /// with every policy: permits with their `destination_ip` ranges, and
    /// forbids with their address conditions, which were false in the
    /// CONNECT-time decision made with the address absent.
    ///
    /// # Errors
    ///
    /// Returns the evaluation error; callers reject the address.
    pub(crate) fn allows(&self, ip: IpAddr) -> Result<bool, String> {
        let request = NetworkConnectRequest {
            destination_ip: Some(ip),
            ..self.request.clone()
        };
        self.engine
            .evaluate_network(&request)
            .map(|decision| decision.is_allow())
            .map_err(|e| e.to_string())
    }
}

impl std::fmt::Debug for CedarDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CedarDestination")
            .field("request", &self.request)
            .field("evaluation", &self.evaluation)
            .field("provider_ranges", &self.provider_ranges)
            .finish_non_exhaustive()
    }
}

impl PartialEq for CedarDestination {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.engine, &other.engine)
            && self.request == other.request
            && self.evaluation == other.evaluation
            && self.provider_ranges == other.provider_ranges
    }
}

impl Eq for CedarDestination {}
