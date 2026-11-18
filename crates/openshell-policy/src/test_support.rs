// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration fixtures for policy and cross-engine integration tests.

use crate::{to_proto, validate_endpoint_settings, validate_process_identity};
use miette::Result;
use openshell_core::proto::{NetworkEndpoint, ProcessPolicy, SandboxPolicy};
use std::collections::HashMap;

/// Shared policy configuration supplied by a test fixture.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PolicyConfiguration {
    /// Supervisor middleware configs, as in a YAML policy's
    /// `network_middlewares` section.
    pub network_middlewares: HashMap<String, openshell_core::proto::NetworkMiddlewareConfig>,
    /// Endpoint settings for a Cedar policy (see
    /// `SandboxPolicy.endpoint_settings`).
    pub endpoint_settings: Vec<NetworkEndpoint>,
    /// Process identity for a Cedar policy, as in a YAML policy's `process`
    /// section. `None` when the fixture omits it or sets neither field.
    pub process: Option<ProcessPolicy>,
}

fn configured_process(process: Option<&ProcessPolicy>) -> Option<ProcessPolicy> {
    process
        .filter(|process| !process.run_as_user.is_empty() || !process.run_as_group.is_empty())
        .cloned()
}

/// Parses a configuration fixture using the authored policy field mappings.
///
/// # Errors
/// Returns an error for invalid configuration or access-control sections.
pub fn parse_configuration(content: &str) -> Result<PolicyConfiguration> {
    // Parse with the policy parser so the format and validation match the
    // corresponding sections of a YAML policy exactly.
    let raw = openshell_policy_schema::parse_policy(&format!("version: 1\n{content}"))?;
    let parsed = to_proto(raw)?;
    let file = PolicyConfiguration {
        network_middlewares: parsed.network_middlewares.clone(),
        endpoint_settings: parsed.endpoint_settings.clone(),
        process: configured_process(parsed.process.as_ref()),
    };
    let only_file_sections = SandboxPolicy {
        version: 1,
        process: parsed.process.clone(),
        network_middlewares: file.network_middlewares.clone(),
        endpoint_settings: file.endpoint_settings.clone(),
        ..Default::default()
    };
    if parsed != only_file_sections {
        return Err(miette::miette!(
            "expected YAML with only top-level network_middlewares, endpoint_settings, and \
             process sections"
        ));
    }
    let mut violations = validate_endpoint_settings(&file.endpoint_settings);
    if let Some(process) = &file.process {
        violations.extend(validate_process_identity(process));
    }
    if !violations.is_empty() {
        let messages: Vec<String> = violations.iter().map(ToString::to_string).collect();
        return Err(miette::miette!("{}", messages.join("; ")));
    }
    Ok(file)
}
