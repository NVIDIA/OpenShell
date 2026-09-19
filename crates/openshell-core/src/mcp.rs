// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell`-owned MCP protocol revisions and immutable batch-shape metadata.

use std::collections::BTreeSet;

use crate::proto::{ProviderProfile, policy::McpConfig};

pub use openshell_policy_schema::{
    DEFAULT_MCP_PROTOCOL_VERSION, MAX_MCP_LEGACY_BATCH_MESSAGES, McpProtocolVersion,
    McpWireProfile, ParseMcpProtocolVersionError,
};

/// Return whether a policy protocol name denotes MCP.
///
/// Protocol names are case-insensitive throughout policy validation and
/// execution, so every MCP-specific projection must use the same predicate.
#[must_use]
pub fn is_mcp_protocol(protocol: &str) -> bool {
    protocol.trim().eq_ignore_ascii_case("mcp")
}

/// Normalize only the MCP option fields in a provider profile.
///
/// MCP protocol matching is case-insensitive. Missing or empty version state
/// materializes [`DEFAULT_MCP_PROTOCOL_VERSION`], while a valid explicit
/// allowlist is sorted in [`McpProtocolVersion::ALL`] semantic order. An
/// explicit list containing an unsupported, padded, or duplicate value is
/// left byte-for-byte unchanged so a later validation boundary can reject the
/// original evidence. MCP-shaped data on non-MCP endpoints is also untouched.
pub fn normalize_provider_profile_mcp_fields(profile: &mut ProviderProfile) {
    for endpoint in &mut profile.endpoints {
        if !is_mcp_protocol(&endpoint.protocol) {
            continue;
        }

        let Some(options) = endpoint.mcp.as_mut() else {
            endpoint.mcp = Some(McpConfig {
                versions: vec![DEFAULT_MCP_PROTOCOL_VERSION.as_str().to_string()],
                ..McpConfig::default()
            });
            continue;
        };

        if options.versions.is_empty() {
            options.versions = vec![DEFAULT_MCP_PROTOCOL_VERSION.as_str().to_string()];
            continue;
        }

        // Parse into the shared version type before mutation. Comparing the
        // set size with the input length detects duplicates without erasing
        // the duplicate values that a fail-closed validator must report.
        let Ok(canonical) = options
            .versions
            .iter()
            .map(|version| version.parse::<McpProtocolVersion>())
            .collect::<Result<BTreeSet<_>, _>>()
        else {
            continue;
        };
        if canonical.len() != options.versions.len() {
            continue;
        }

        options.versions = canonical
            .into_iter()
            .map(|version| version.as_str().to_string())
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;
    use prost_types::{FileDescriptorSet, field_descriptor_proto};

    use super::*;

    #[test]
    fn mcp_protocol_version_all_values_are_in_canonical_order() {
        assert_eq!(
            McpProtocolVersion::ALL,
            &[
                McpProtocolVersion::V2025_03_26,
                McpProtocolVersion::V2025_06_18,
                McpProtocolVersion::V2025_11_25,
            ]
        );
        assert!(
            McpProtocolVersion::ALL
                .windows(2)
                .all(|versions| versions[0] < versions[1])
        );
    }

    #[test]
    fn default_mcp_protocol_version_is_pinned_to_the_2025_11_25_profile() {
        assert_eq!(
            DEFAULT_MCP_PROTOCOL_VERSION,
            McpProtocolVersion::V2025_11_25
        );
        assert_eq!(DEFAULT_MCP_PROTOCOL_VERSION.as_str(), "2025-11-25");

        let profile = DEFAULT_MCP_PROTOCOL_VERSION.wire_profile();
        assert_eq!(profile.version(), McpProtocolVersion::V2025_11_25);
        assert!(!profile.allows_json_rpc_batches());
        assert_eq!(profile.max_batch_messages(), None);
    }

    fn provider_profile_with_mcp(protocol: &str, options: Option<McpConfig>) -> ProviderProfile {
        ProviderProfile {
            id: "mcp-profile".to_string(),
            display_name: "MCP profile".to_string(),
            description: "source-owned description".to_string(),
            endpoints: vec![crate::proto::policy::NetworkEndpoint {
                host: "mcp.example.com".to_string(),
                ports: vec![443],
                protocol: protocol.to_string(),
                mcp: options,
                ..crate::proto::policy::NetworkEndpoint::default()
            }],
            ..ProviderProfile::default()
        }
    }

    #[test]
    fn provider_profile_mcp_normalization_materializes_empty_versions() {
        let mut omitted = provider_profile_with_mcp("McP", None);
        normalize_provider_profile_mcp_fields(&mut omitted);
        assert_eq!(
            omitted.endpoints[0]
                .mcp
                .as_ref()
                .expect("omitted MCP options must materialize")
                .versions,
            ["2025-11-25"]
        );

        let mut empty = provider_profile_with_mcp(
            "mcp",
            Some(McpConfig {
                strict_tool_names: Some(false),
                allow_all_known_mcp_methods: Some(true),
                versions: Vec::new(),
                ..McpConfig::default()
            }),
        );
        normalize_provider_profile_mcp_fields(&mut empty);
        assert_eq!(
            empty.endpoints[0]
                .mcp
                .as_ref()
                .expect("explicit MCP options remain present"),
            &McpConfig {
                strict_tool_names: Some(false),
                allow_all_known_mcp_methods: Some(true),
                versions: vec!["2025-11-25".to_string()],
                ..McpConfig::default()
            }
        );
    }

    #[test]
    fn provider_profile_mcp_normalization_canonicalizes_valid_explicit_versions_only() {
        let mut profile = provider_profile_with_mcp(
            "mcp",
            Some(McpConfig {
                strict_tool_names: Some(true),
                versions: vec![
                    "2025-11-25".to_string(),
                    "2025-03-26".to_string(),
                    "2025-06-18".to_string(),
                ],
                ..McpConfig::default()
            }),
        );
        let original = profile.clone();

        normalize_provider_profile_mcp_fields(&mut profile);

        assert_eq!(profile.id, original.id);
        assert_eq!(profile.display_name, original.display_name);
        assert_eq!(profile.description, original.description);
        assert_eq!(profile.endpoints[0].host, original.endpoints[0].host);
        assert_eq!(profile.endpoints[0].ports, original.endpoints[0].ports);
        assert_eq!(
            profile.endpoints[0].protocol,
            original.endpoints[0].protocol
        );
        assert_eq!(
            profile.endpoints[0]
                .mcp
                .as_ref()
                .expect("valid MCP options"),
            &McpConfig {
                strict_tool_names: Some(true),
                versions: vec![
                    "2025-03-26".to_string(),
                    "2025-06-18".to_string(),
                    "2025-11-25".to_string(),
                ],
                ..McpConfig::default()
            }
        );
    }

    #[test]
    fn provider_profile_mcp_normalization_preserves_every_malformed_explicit_list() {
        for versions in [
            vec!["2025-11-25", "2025-11-25"],
            vec![" 2025-11-25"],
            vec!["2025-11-25 "],
            vec!["2026-07-28"],
            vec!["latest"],
            vec!["draft"],
        ] {
            let mut profile = provider_profile_with_mcp(
                "mcp",
                Some(McpConfig {
                    versions: versions.into_iter().map(ToString::to_string).collect(),
                    ..McpConfig::default()
                }),
            );
            let original = profile.clone();

            normalize_provider_profile_mcp_fields(&mut profile);

            assert_eq!(profile, original);
        }
    }

    #[test]
    fn provider_profile_mcp_normalization_ignores_non_mcp_endpoint_evidence() {
        let mut profile = provider_profile_with_mcp(
            "rest",
            Some(McpConfig {
                versions: vec!["latest".to_string()],
                ..McpConfig::default()
            }),
        );
        let original = profile.clone();

        normalize_provider_profile_mcp_fields(&mut profile);

        assert_eq!(profile, original);
    }

    #[test]
    fn mcp_protocol_version_parses_only_exact_supported_values() {
        assert_eq!("2025-03-26".parse(), Ok(McpProtocolVersion::V2025_03_26));
        assert_eq!("2025-06-18".parse(), Ok(McpProtocolVersion::V2025_06_18));
        assert_eq!("2025-11-25".parse(), Ok(McpProtocolVersion::V2025_11_25));

        for unsupported in [
            "",
            "2025-03-26 ",
            " 2025-06-18",
            "2025-11-25\n",
            "2025-11-24",
            "2026-07-28",
            "draft",
            "latest",
        ] {
            let error = unsupported
                .parse::<McpProtocolVersion>()
                .expect_err("unsupported MCP revision must be rejected");
            assert_eq!(error.value(), unsupported);
        }
    }

    #[test]
    fn mcp_protocol_version_display_and_as_str_round_trip() {
        for version in McpProtocolVersion::ALL.iter().copied() {
            assert_eq!(version.to_string(), version.as_str());
            assert_eq!(version.as_str().parse(), Ok(version));
        }
    }

    #[test]
    fn mcp_protocol_version_error_reports_the_rejected_input() {
        let rejected = " 2025-03-26";
        let error = rejected
            .parse::<McpProtocolVersion>()
            .expect_err("padded MCP revision must be rejected");

        assert_eq!(
            error.to_string(),
            format!("unsupported MCP protocol version '{rejected}'")
        );
        assert_eq!(error.value(), rejected);
    }

    #[test]
    fn mcp_protocol_version_wire_profiles_define_batch_metadata() {
        assert_eq!(MAX_MCP_LEGACY_BATCH_MESSAGES, 64);

        let legacy = McpProtocolVersion::V2025_03_26.wire_profile();
        assert_eq!(legacy.version(), McpProtocolVersion::V2025_03_26);
        assert!(legacy.allows_json_rpc_batches());
        assert_eq!(
            legacy.max_batch_messages(),
            Some(MAX_MCP_LEGACY_BATCH_MESSAGES)
        );

        for version in [
            McpProtocolVersion::V2025_06_18,
            McpProtocolVersion::V2025_11_25,
        ] {
            let profile = version.wire_profile();
            assert_eq!(profile.version(), version);
            assert!(!profile.allows_json_rpc_batches());
            assert_eq!(profile.max_batch_messages(), None);
        }
    }

    #[test]
    fn mcp_options_versions_field_number_is_stable() {
        let descriptor_set = FileDescriptorSet::decode(crate::FILE_DESCRIPTOR_SET)
            .expect("OpenShell descriptor set must decode");
        let mcp_options = descriptor_set
            .file
            .iter()
            .find(|file| file.package.as_deref() == Some("openshell.sandbox.v1"))
            .and_then(|file| {
                file.message_type
                    .iter()
                    .find(|message| message.name.as_deref() == Some("McpOptions"))
            })
            .expect("sandbox schema must define McpOptions");
        let versions = mcp_options
            .field
            .iter()
            .find(|field| field.name.as_deref() == Some("versions"))
            .expect("McpOptions must define versions");

        assert_eq!(versions.number, Some(3));
        assert_eq!(versions.label(), field_descriptor_proto::Label::Repeated);
        assert_eq!(versions.r#type(), field_descriptor_proto::Type::String);
    }
}
