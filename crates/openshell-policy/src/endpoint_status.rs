// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configured MCP selectors shared by routing and passive endpoint reporting.

use miette::Result;
use openshell_core::proto::{NetworkEndpoint, SandboxPolicy};

/// Collect configured MCP endpoints, without substituting observed hosts for
/// configured globs. Callers validate the policy before installing this inventory.
///
/// # Errors
///
/// Returns an error if the Cedar policy cannot be compiled or Cedar support is
/// unavailable in this build.
pub fn configured_mcp_endpoints(policy: &SandboxPolicy) -> Result<Vec<NetworkEndpoint>> {
    if policy.cedar_policy_source.is_empty() {
        return Ok(policy
            .network_policies
            .values()
            .flat_map(|rule| &rule.endpoints)
            .filter(|endpoint| openshell_core::mcp::is_mcp_protocol(&endpoint.protocol))
            .cloned()
            .collect());
    }
    #[cfg(feature = "cedar")]
    {
        let cedar =
            openshell_policy_cedar::CedarEngine::from_policy_str(&policy.cedar_policy_source)
                .map_err(|error| miette::miette!("{error}"))?;
        Ok(cedar_mcp_endpoints(policy, &cedar))
    }
    #[cfg(not(feature = "cedar"))]
    Err(miette::miette!("Cedar policy support is unavailable"))
}

/// Derive the inventory from the same compiled Cedar policy used for routing.
#[cfg(feature = "cedar")]
#[must_use]
pub fn cedar_mcp_endpoints(
    policy: &SandboxPolicy,
    cedar: &openshell_policy_cedar::CedarEngine,
) -> Vec<NetworkEndpoint> {
    use openshell_policy_cedar::L7Protocol;
    let mut endpoints = Vec::new();
    for (host, port, path, inspection) in cedar.configured_l7_endpoints() {
        if inspection.protocol == L7Protocol::Mcp {
            endpoints.push(NetworkEndpoint {
                host,
                port: u32::from(port),
                path,
                protocol: "mcp".to_string(),
                ..NetworkEndpoint::default()
            });
        }
    }
    // Providers and middleware settings can introduce more specific paths and
    // selectors. Their protocol comes from Cedar, never from a provider rule.
    for endpoint in policy
        .provider_credential_rules
        .values()
        .flat_map(|rule| &rule.endpoints)
        .chain(policy.endpoint_settings.iter())
    {
        let ports = if endpoint.ports.is_empty() {
            vec![endpoint.port]
        } else {
            endpoint.ports.clone()
        };
        let inspected = ports
            .into_iter()
            .filter_map(|port| u16::try_from(port).ok())
            .any(|port| {
                cedar
                    .configured_l7_endpoints()
                    .filter(|(host, declared_port, _, _)| {
                        *declared_port == port
                            && openshell_core::host_pattern::host_patterns_overlap(
                                host,
                                &endpoint.host,
                            )
                            .unwrap_or(false)
                    })
                    .any(|(host, _, _, _)| {
                        // A literal provider selector uses the complete merged
                        // inspection of that host, including more specific REST
                        // paths. For a provider glob, consider every overlapping
                        // configured Cedar selector, including exact hosts.
                        let selecting_host = if endpoint.host.contains('*') {
                            &host
                        } else {
                            &endpoint.host
                        };
                        cedar
                            .l7_endpoints(selecting_host, port)
                            .filter(|(path, _)| {
                                openshell_core::endpoint_path::matches(path, &endpoint.path)
                            })
                            .max_by_key(|(path, _)| {
                                (
                                    path == &endpoint.path,
                                    path.chars().filter(|c| *c != '*').count(),
                                )
                            })
                            .is_some_and(|(_, inspection)| inspection.protocol == L7Protocol::Mcp)
                    })
            });
        if inspected {
            let mut descriptor = endpoint.clone();
            descriptor.protocol = "mcp".to_string();
            endpoints.push(descriptor);
        }
    }
    endpoints
}

#[cfg(all(test, feature = "cedar"))]
mod tests {
    use super::*;
    use openshell_core::endpoint_status::initial_endpoint_status;
    use openshell_core::proto::NetworkPolicyRule;

    #[test]
    fn cedar_inventory_preserves_globs_provider_ports_and_settings_paths() {
        let source = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
@protocol("mcp") @path("/mcp/**")
permit (principal, action == Sandbox::Action::"HttpRequest", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
"#;
        let provider = NetworkEndpoint {
            host: "*.example.com".to_string(),
            ports: vec![8443, 443, 443],
            path: "/mcp/provider/**".to_string(),
            provider_credentialed: true,
            ..Default::default()
        };
        let setting = NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            path: "/mcp/scoped".to_string(),
            ..Default::default()
        };
        let policy = SandboxPolicy {
            cedar_policy_source: source.to_string(),
            provider_credential_rules: std::collections::HashMap::from([(
                "provider".to_string(),
                NetworkPolicyRule {
                    endpoints: vec![provider.clone()],
                    ..Default::default()
                },
            )]),
            endpoint_settings: vec![setting.clone()],
            ..Default::default()
        };
        let descriptors = configured_mcp_endpoints(&policy).expect("descriptors");
        assert_eq!(descriptors.len(), 3);
        let provider_status = initial_endpoint_status(
            descriptors
                .iter()
                .find(|endpoint| endpoint.provider_credentialed)
                .expect("provider"),
        );
        assert_eq!(provider_status, initial_endpoint_status(&provider));
        assert_eq!(provider_status.host, "*.example.com");
        assert_eq!(provider_status.ports, [443, 8443]);
        assert!(
            descriptors
                .iter()
                .any(|endpoint| initial_endpoint_status(endpoint)
                    == initial_endpoint_status(&setting))
        );
        assert!(
            descriptors
                .iter()
                .filter(|endpoint| endpoint.path == "/mcp/**")
                .all(|endpoint| endpoint.host == "*.example.com")
        );
    }

    #[test]
    fn provider_glob_covers_exact_cedar_host_and_rest_override_is_not_mcp() {
        let source = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource);
@protocol("mcp") @path("/mcp/**")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@protocol("rest") @path("/mcp/private/**")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#;
        let mcp = NetworkEndpoint {
            host: "*.example.com".to_string(),
            port: 443,
            path: "/mcp/tools".to_string(),
            provider_credentialed: true,
            ..Default::default()
        };
        let rest = NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            path: "/mcp/private/tools".to_string(),
            provider_credentialed: true,
            ..Default::default()
        };
        let policy = SandboxPolicy {
            cedar_policy_source: source.to_string(),
            provider_credential_rules: std::collections::HashMap::from([(
                "provider".to_string(),
                NetworkPolicyRule {
                    endpoints: vec![mcp.clone(), rest.clone()],
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let descriptors = configured_mcp_endpoints(&policy).expect("descriptors");
        assert!(
            descriptors
                .iter()
                .any(|endpoint| initial_endpoint_status(endpoint) == initial_endpoint_status(&mcp))
        );
        assert!(!descriptors.iter().any(|endpoint| initial_endpoint_status(endpoint) == initial_endpoint_status(&rest)));
    }
}
