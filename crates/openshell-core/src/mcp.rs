// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell`-owned MCP policy revisions, allowlist parsing, and resource limits.

use crate::proto::{McpOptions, ProviderProfile};

pub use openshell_policy_schema::{
    DEFAULT_MCP_PROTOCOL_VERSION, MAX_MCP_LEGACY_BATCH_MESSAGES, McpProtocolVersion,
    ParseMcpProtocolVersionError, ParseMcpVersionsError, canonicalize_mcp_versions,
    parse_mcp_versions,
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
            endpoint.mcp = Some(McpOptions {
                versions: vec![DEFAULT_MCP_PROTOCOL_VERSION.as_str().to_string()],
                ..McpOptions::default()
            });
            continue;
        };

        if options.versions.is_empty() {
            options.versions = vec![DEFAULT_MCP_PROTOCOL_VERSION.as_str().to_string()];
            continue;
        }

        // Validate the explicit list before mutation so malformed values retain
        // their original order and spelling for the checked policy boundary.
        let Ok(versions) = parse_mcp_versions(&options.versions) else {
            continue;
        };

        options.versions = versions
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
                McpProtocolVersion::V2026_07_28,
            ]
        );
        assert!(
            McpProtocolVersion::ALL
                .windows(2)
                .all(|versions| versions[0] < versions[1])
        );
    }

    #[test]
    fn default_mcp_protocol_version_is_pinned_to_the_2025_11_25_revision() {
        assert_eq!(
            DEFAULT_MCP_PROTOCOL_VERSION,
            McpProtocolVersion::V2025_11_25
        );
        assert_eq!(DEFAULT_MCP_PROTOCOL_VERSION.as_str(), "2025-11-25");
    }

    #[test]
    fn parse_mcp_versions_returns_canonical_order_without_mutating_the_authored_list() {
        let values = ["2026-07-28", "2025-03-26", "2025-11-25", "2025-06-18"].map(str::to_string);
        let original = values.clone();

        let versions = parse_mcp_versions(&values).expect("explicit supported revisions");

        assert_eq!(
            versions.into_iter().collect::<Vec<_>>(),
            McpProtocolVersion::ALL
        );
        assert_eq!(values, original);
    }

    #[test]
    fn parse_mcp_versions_reports_the_first_error_without_repairing_input() {
        let duplicate = ParseMcpVersionsError::Duplicate(McpProtocolVersion::V2025_03_26);
        let unsupported = ParseMcpVersionsError::Unsupported(
            " 2025-11-25"
                .parse::<McpProtocolVersion>()
                .expect_err("revision is unsupported"),
        );
        for (values, expected) in [
            (vec![], ParseMcpVersionsError::Empty),
            (vec!["2025-03-26", "2025-03-26", " 2025-11-25"], duplicate),
            (vec![" 2025-11-25", "2025-03-26", "2025-03-26"], unsupported),
        ] {
            let values = values.into_iter().map(str::to_string).collect::<Vec<_>>();
            let original = values.clone();

            assert_eq!(parse_mcp_versions(&values), Err(expected));
            assert_eq!(values, original);
        }
    }

    fn provider_profile_with_mcp(protocol: &str, options: Option<McpOptions>) -> ProviderProfile {
        ProviderProfile {
            id: "mcp-profile".to_string(),
            display_name: "MCP profile".to_string(),
            description: "source-owned description".to_string(),
            endpoints: vec![crate::proto::NetworkEndpoint {
                host: "mcp.example.com".to_string(),
                port: 443,
                protocol: protocol.to_string(),
                mcp: options,
                ..crate::proto::NetworkEndpoint::default()
            }],
            ..ProviderProfile::default()
        }
    }

    #[test]
    fn provider_profile_mcp_normalization_materializes_omitted_and_empty_versions() {
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
            Some(McpOptions {
                strict_tool_names: Some(false),
                allow_all_known_mcp_methods: Some(true),
                versions: Vec::new(),
            }),
        );
        normalize_provider_profile_mcp_fields(&mut empty);
        assert_eq!(
            empty.endpoints[0]
                .mcp
                .as_ref()
                .expect("empty MCP versions must materialize"),
            &McpOptions {
                strict_tool_names: Some(false),
                allow_all_known_mcp_methods: Some(true),
                versions: vec!["2025-11-25".to_string()],
            }
        );
    }

    #[test]
    fn provider_profile_mcp_normalization_canonicalizes_valid_explicit_versions_only() {
        let mut profile = provider_profile_with_mcp(
            "mcp",
            Some(McpOptions {
                strict_tool_names: Some(true),
                versions: vec![
                    "2026-07-28".to_string(),
                    "2025-11-25".to_string(),
                    "2025-03-26".to_string(),
                    "2025-06-18".to_string(),
                ],
                ..McpOptions::default()
            }),
        );
        let original = profile.clone();

        normalize_provider_profile_mcp_fields(&mut profile);

        assert_eq!(profile.id, original.id);
        assert_eq!(profile.display_name, original.display_name);
        assert_eq!(profile.description, original.description);
        assert_eq!(profile.endpoints[0].host, original.endpoints[0].host);
        assert_eq!(profile.endpoints[0].port, original.endpoints[0].port);
        assert_eq!(
            profile.endpoints[0].protocol,
            original.endpoints[0].protocol
        );
        assert_eq!(
            profile.endpoints[0]
                .mcp
                .as_ref()
                .expect("valid MCP options"),
            &McpOptions {
                strict_tool_names: Some(true),
                versions: vec![
                    "2025-03-26".to_string(),
                    "2025-06-18".to_string(),
                    "2025-11-25".to_string(),
                    "2026-07-28".to_string(),
                ],
                ..McpOptions::default()
            }
        );
    }

    #[test]
    fn provider_profile_mcp_normalization_preserves_every_malformed_explicit_list() {
        for versions in [
            vec!["2025-11-25", "2025-11-25"],
            vec!["2026-07-28", "2025-03-26", "2025-03-26", "2025-06-18"],
            vec!["2026-07-28", "latest", "2025-03-26"],
            vec![" 2025-11-25"],
            vec!["2025-11-25 "],
            vec!["2026-07-29"],
            vec!["latest"],
            vec!["draft"],
        ] {
            let mut profile = provider_profile_with_mcp(
                "mcp",
                Some(McpOptions {
                    versions: versions.into_iter().map(ToString::to_string).collect(),
                    ..McpOptions::default()
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
            Some(McpOptions {
                versions: vec!["latest".to_string()],
                ..McpOptions::default()
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
        assert_eq!("2026-07-28".parse(), Ok(McpProtocolVersion::V2026_07_28));

        for unsupported in [
            "",
            "2025-03-26 ",
            " 2025-06-18",
            "2025-11-25\n",
            "2025-11-24",
            "2026-07-28 ",
            "2026-07-29",
            "draft",
            "latest",
        ] {
            let error = unsupported
                .parse::<McpProtocolVersion>()
                .expect_err("unsupported revision must fail");
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
