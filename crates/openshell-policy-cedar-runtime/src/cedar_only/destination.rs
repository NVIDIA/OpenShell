// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The address checks of one allowed Cedar connection.

use std::net::IpAddr;
use std::sync::Arc;

use openshell_policy_cedar::{CedarEngine, IpNet, NetworkConnectRequest, NetworkEvaluation};

use super::ProviderRanges;
use openshell_core::net::{is_always_blocked_ip, is_internal_ip};

/// How the resolved addresses of one allowed Cedar connection are checked.
///
/// Carries the connection's decision made before its host resolved, and the
/// policy that made it, so each resolved address is evaluated against the
/// same policy generation. The proxy calls these admission rules through
/// the shared resolved-address policy contract.
pub(super) struct CedarDestination {
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
    fn provider_ranges(&self) -> &[ProviderRanges] {
        &self.provider_ranges
    }

    /// The `destination_ip` ranges of each allowing permit that has them.
    fn address_conditions(&self) -> &[Vec<IpNet>] {
        &self.evaluation.address_conditions
    }

    /// Whether an allowing permit has no `destination_ip` condition.
    fn unconstrained_permit(&self) -> bool {
        self.evaluation.unconstrained_permit
    }

    /// Whether an allowing permit names the connection's host and port
    /// exactly.
    fn names_endpoint(&self) -> bool {
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
    fn allows(&self, ip: IpAddr) -> Result<bool, String> {
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

/// Returns why a Cedar sandbox rejects resolved address `ip` for a
/// connection to `host`, or `None` when it is admitted.
///
/// Reproduces the YAML modes on the connection's allowing permits, never
/// admitting an address that YAML would reject whichever matching endpoint
/// it consulted first:
///
/// - Loopback, link-local (including cloud metadata), and unspecified
///   addresses are always rejected.
/// - Every allowing permit with a `destination_ip` condition must admit the
///   address, as a YAML endpoint's `allowed_ips` restricts every address.
/// - A private address also needs a permit that names the host exactly, or
///   only permits with `destination_ip` conditions; a permit without one is
///   public-only unless it names the host, as a YAML endpoint without
///   `allowed_ips` is.
/// - Every matching provider endpoint with `allowed_ips` must admit the
///   address, as those ranges restrict a YAML provider endpoint's
///   connections. They only narrow: providers grant no access, so they never
///   count toward admitting a private address.
/// - Cedar, with every policy, must allow the connection to the address.
fn cedar_address_rejection(cedar: &CedarDestination, host: &str, ip: IpAddr) -> Option<String> {
    if is_always_blocked_ip(ip) {
        return Some(format!(
            "{host} resolves to always-blocked address {ip}, connection rejected"
        ));
    }
    let conditions = cedar.address_conditions();
    if !conditions
        .iter()
        .all(|ranges| ranges.iter().any(|range| range.contains(&ip)))
    {
        return Some(format!(
            "{host} resolves to {ip} which is not in the policy's destination_ip ranges, \
             connection rejected"
        ));
    }
    if let Some(reason) = cedar_provider_rejection(cedar, host, ip) {
        return Some(reason);
    }
    let private_admitted =
        cedar.names_endpoint() || (!conditions.is_empty() && !cedar.unconstrained_permit());
    if is_internal_ip(ip) && !private_admitted {
        return Some(format!(
            "{host} resolves to internal address {ip}, connection rejected"
        ));
    }
    match cedar.allows(ip) {
        Ok(true) => None,
        Ok(false) => Some(format!(
            "Cedar policy denies {host} at address {ip}, connection rejected"
        )),
        Err(error) => Some(format!(
            "Cedar policy evaluation failed for {host} at address {ip}: {error}"
        )),
    }
}

/// Returns why the `allowed_ips` of a provider endpoint matching a Cedar
/// sandbox's connection to `host` reject resolved address `ip`, or `None`
/// when every such endpoint admits it.
fn cedar_provider_rejection(cedar: &CedarDestination, host: &str, ip: IpAddr) -> Option<String> {
    cedar
        .provider_ranges()
        .iter()
        .find_map(|ranges| match ranges {
            Err(reason) => Some(format!("{host}: {reason}, connection rejected")),
            Ok(ranges) if !ranges.iter().any(|range| range.contains(&ip)) => Some(format!(
                "{host} resolves to {ip} which is not in its provider endpoint's allowed_ips, \
             connection rejected"
            )),
            Ok(_) => None,
        })
}

impl openshell_policy_runtime_interface::ResolvedAddressPolicy for CedarDestination {
    fn rejection(&self, host: &str, ip: IpAddr) -> Option<String> {
        cedar_address_rejection(self, host, ip)
    }
    fn blocks_control_plane(&self, host: &str) -> bool {
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let host = host.strip_suffix('.').unwrap_or(host);
        !self.address_conditions().is_empty()
            || !self.provider_ranges().is_empty()
            || self.names_endpoint()
            || host.parse::<IpAddr>().is_ok()
    }
    fn ip_constrained(&self) -> bool {
        !self.address_conditions().is_empty() || !self.provider_ranges().is_empty()
    }
    fn allows_gateway(&self, ip: IpAddr) -> Result<bool, String> {
        self.allows(ip)
    }
}
