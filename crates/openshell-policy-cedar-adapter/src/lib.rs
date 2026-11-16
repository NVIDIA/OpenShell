// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Adapts Cedar analysis to sandbox policy messages for gateway and runtime composition.

use miette::Result;
use openshell_core::policy_l7::{EffectiveFilesystem, effective_endpoint_ports};
use openshell_core::proto::{FilesystemPolicy, NetworkEndpoint, NetworkTlsMode};
use openshell_policy_cedar::CedarEngine;

pub mod endpoint_status;

/// Derived values consumed by common policy validation without exposing an engine.
pub struct PolicyAnalysis {
    pub filesystem: EffectiveFilesystem,
    pub warnings: Vec<String>,
    pub tls_skip_conflicts: Vec<TlsSkipConflict>,
}

pub struct TlsSkipConflict {
    pub index: usize,
    pub host: String,
    pub port: u16,
}

/// Analyze Cedar source and identify settings that would bypass its inspection.
///
/// # Errors
/// Returns an error if Cedar parsing, schema validation, or analysis fails.
pub fn analyze(source: &str, settings: &[NetworkEndpoint]) -> Result<PolicyAnalysis> {
    let engine =
        CedarEngine::from_policy_str(source).map_err(|error| miette::miette!("{error}"))?;
    Ok(PolicyAnalysis {
        filesystem: engine_filesystem(&engine),
        warnings: engine.warnings().iter().map(ToString::to_string).collect(),
        tls_skip_conflicts: settings
            .iter()
            .enumerate()
            .filter_map(|(index, setting)| {
                let (host, port) = tls_skip_inspected_endpoint(&engine, setting, true)?;
                Some(TlsSkipConflict { index, host, port })
            })
            .collect(),
    })
}

/// Derive filesystem grants from Cedar source.
///
/// # Errors
/// Returns an error if the source cannot be loaded.
pub fn effective_filesystem(source: &str) -> Result<EffectiveFilesystem> {
    let engine =
        CedarEngine::from_policy_str(source).map_err(|error| miette::miette!("{error}"))?;
    Ok(engine_filesystem(&engine))
}

/// Returns the first inspected `host:port` that `endpoint` selects when it
/// sets `tls: skip`.
///
/// The proxy relays a skipped connection without terminating TLS, so the
/// `HttpRequest` policies inspecting it would never run.
///
/// `unparseable_host_selects` decides an endpoint host the host matcher
/// rejects: `true` fails closed for a check that rejects the endpoint, and
/// `false` leaves out an endpoint, such as a host-less provider endpoint,
/// that can select no inspected connection.
#[must_use]
pub fn tls_skip_inspected_endpoint(
    engine: &CedarEngine,
    endpoint: &NetworkEndpoint,
    unparseable_host_selects: bool,
) -> Option<(String, u16)> {
    if endpoint.tls != NetworkTlsMode::Skip as i32 {
        return None;
    }
    let ports = effective_endpoint_ports(endpoint);
    engine
        .configured_l7_endpoints()
        .find(|(host, port, ..)| {
            ports.contains(&u32::from(*port))
                && openshell_core::host_pattern::host_patterns_overlap(&endpoint.host, host)
                    .unwrap_or(unparseable_host_selects)
        })
        .map(|(host, port, _, _)| (host, port))
}

/// The Landlock grants of a loaded Cedar policy; see
/// [`effective_filesystem`].
#[must_use]
pub fn engine_filesystem(engine: &CedarEngine) -> EffectiveFilesystem {
    let grants = engine.filesystem_grants();
    EffectiveFilesystem {
        filesystem: Some(FilesystemPolicy {
            include_workdir: false,
            read_only: grants.read_only.clone(),
            read_write: grants.read_write.clone(),
        }),
        needs_proxy_baseline: engine.has_network_permits(),
    }
}
