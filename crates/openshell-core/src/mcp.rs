// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell-owned MCP protocol revisions and immutable batch-shape metadata.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use crate::proto::{McpOptions, ProviderProfile};

/// Fixed `OpenShell` batch-member bound for the MCP `2025-03-26` wire profile.
///
/// The bound is distinct from the separately enforced request-body byte limit.
pub const MAX_MCP_LEGACY_BATCH_MESSAGES: usize = 64;

/// Stable MCP protocol revisions accepted by `OpenShell` policy configuration.
///
/// Variant order is the canonical semantic order used when normalizing policy
/// allowlists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum McpProtocolVersion {
    /// MCP protocol revision `2025-03-26`.
    V2025_03_26,
    /// MCP protocol revision `2025-06-18`.
    V2025_06_18,
    /// MCP protocol revision `2025-11-25`.
    V2025_11_25,
}

/// Pinned MCP protocol revision used when policy authoring omits a revision.
///
/// This value is assigned directly rather than derived from
/// [`McpProtocolVersion::ALL`] or its order. Adding support for a newer
/// revision therefore cannot silently change versionless policies.
pub const DEFAULT_MCP_PROTOCOL_VERSION: McpProtocolVersion = McpProtocolVersion::V2025_11_25;

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
        if !endpoint.protocol.eq_ignore_ascii_case("mcp") {
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

        // Parse into the shared version type before mutation. Comparing the
        // set size with the input length detects duplicates without erasing
        // the duplicate values that a fail-closed validator must report.
        let Ok(versions) = options
            .versions
            .iter()
            .map(|version| version.parse::<McpProtocolVersion>())
            .collect::<Result<BTreeSet<_>, _>>()
        else {
            continue;
        };
        if versions.len() != options.versions.len() {
            continue;
        }

        options.versions = versions
            .into_iter()
            .map(|version| version.as_str().to_string())
            .collect();
    }
}

impl McpProtocolVersion {
    /// Every supported MCP protocol revision in canonical semantic order.
    pub const ALL: &'static [Self] = &[Self::V2025_03_26, Self::V2025_06_18, Self::V2025_11_25];

    /// Return the exact protocol identifier used on the MCP wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2025_03_26 => "2025-03-26",
            Self::V2025_06_18 => "2025-06-18",
            Self::V2025_11_25 => "2025-11-25",
        }
    }

    /// Return the fixed batch-shape metadata for this protocol revision.
    #[must_use]
    pub const fn wire_profile(self) -> McpWireProfile {
        match self {
            Self::V2025_03_26 => McpWireProfile {
                version: self,
                allows_json_rpc_batches: true,
                max_batch_messages: Some(MAX_MCP_LEGACY_BATCH_MESSAGES),
            },
            Self::V2025_06_18 | Self::V2025_11_25 => McpWireProfile {
                version: self,
                allows_json_rpc_batches: false,
                max_batch_messages: None,
            },
        }
    }
}

impl fmt::Display for McpProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for McpProtocolVersion {
    type Err = ParseMcpProtocolVersionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "2025-03-26" => Ok(Self::V2025_03_26),
            "2025-06-18" => Ok(Self::V2025_06_18),
            "2025-11-25" => Ok(Self::V2025_11_25),
            _ => Err(ParseMcpProtocolVersionError {
                value: value.to_string(),
            }),
        }
    }
}

/// Error returned when a string is not an exact supported MCP revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseMcpProtocolVersionError {
    value: String,
}

impl ParseMcpProtocolVersionError {
    /// Return the exact input that failed MCP revision parsing.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for ParseMcpProtocolVersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported MCP protocol version '{}'",
            self.value
        )
    }
}

impl std::error::Error for ParseMcpProtocolVersionError {}

/// Immutable batch-shape metadata for one exact MCP protocol revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct McpWireProfile {
    version: McpProtocolVersion,
    allows_json_rpc_batches: bool,
    max_batch_messages: Option<usize>,
}

impl McpWireProfile {
    /// Return the protocol revision governed by this profile.
    #[must_use]
    pub const fn version(self) -> McpProtocolVersion {
        self.version
    }

    /// Return whether the revision permits a top-level JSON-RPC batch array.
    #[must_use]
    pub const fn allows_json_rpc_batches(self) -> bool {
        self.allows_json_rpc_batches
    }

    /// Return the maximum batch members when batching is permitted.
    ///
    /// `None` means the profile forbids batches; it never represents an
    /// unbounded batch.
    #[must_use]
    pub const fn max_batch_messages(self) -> Option<usize> {
        self.max_batch_messages
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
                ],
                ..McpOptions::default()
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
            let error = unsupported.parse::<McpProtocolVersion>();
            assert_eq!(
                error,
                Err(ParseMcpProtocolVersionError {
                    value: unsupported.to_string(),
                })
            );
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
