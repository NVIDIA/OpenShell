// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Composition of Cedar analysis with common sandbox policy validation.

use crate::{EffectiveFilesystem, PolicyViolation};
use openshell_core::proto::NetworkEndpoint;

pub fn validate(
    source: &str,
    settings: &[NetworkEndpoint],
    violations: &mut Vec<PolicyViolation>,
) -> Vec<String> {
    let analysis = match openshell_policy_cedar_adapter::analyze(source, settings) {
        Ok(analysis) => analysis,
        Err(error) => {
            violations.push(PolicyViolation::InvalidCedarPolicy {
                reason: error.to_string(),
            });
            return Vec::new();
        }
    };
    if let Some(filesystem) = &analysis.filesystem.filesystem
        && let Err(errors) =
            crate::validate_filesystem_paths(&filesystem.read_only, &filesystem.read_write)
    {
        violations.extend(errors);
    }
    for conflict in analysis.tls_skip_conflicts {
        violations.push(PolicyViolation::InvalidEndpointSetting {
            index: conflict.index,
            host: settings[conflict.index].host.clone(),
            reason: format!(
                "tls: skip relays connections without inspection, but HttpRequest \
                 policies inspect {}:{}; remove tls: skip, or narrow its host or \
                 ports so it does not select an inspected endpoint",
                conflict.host, conflict.port
            ),
        });
    }
    analysis.warnings
}

pub fn effective_filesystem(source: &str) -> Result<EffectiveFilesystem, PolicyViolation> {
    openshell_policy_cedar_adapter::effective_filesystem(source).map_err(|error| {
        PolicyViolation::InvalidCedarPolicy {
            reason: error.to_string(),
        }
    })
}
