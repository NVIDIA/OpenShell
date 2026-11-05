// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generated protocol buffer code.
//!
//! This module re-exports the generated protobuf types and service definitions.

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    unused_imports,
    unused_qualifications,
    rust_2018_idioms
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/openshell.rs"));
}

pub use self::generated::openshell::v1 as openshell;

// Cross-package references from packages nested under `openshell.*.v1` can be
// generated as `super::super::v1::*`. Keep that path available as an alias for
// the root `openshell.v1` package.
#[doc(hidden)]
pub mod v1 {
    pub use super::openshell::*;
}

pub mod datamodel {
    pub use super::generated::openshell::datamodel::v1;
}

pub mod sandbox {
    pub mod backend {
        pub use super::super::generated::openshell::sandbox::backend::v1;
    }
    pub use super::generated::openshell::sandbox::v1;
    pub mod protocol {
        pub use super::super::generated::openshell::sandbox::protocol::v1;
    }
}

pub mod compute {
    pub use super::generated::openshell::compute::v1;
}

pub mod extension {
    pub use super::generated::openshell::extension::v1;
}

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    unused_imports,
    unused_qualifications,
    rust_2018_idioms
)]
pub mod credentials {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/openshell.credentials.v1.rs"));
    }
}

pub mod test {
    pub use super::generated::openshell::test::v1::*;
}

pub mod middleware {
    pub use super::generated::openshell::middleware::v1;
}

#[doc(hidden)]
pub mod pagination {
    pub use super::generated::openshell::internal::pagination::v1;
}

pub mod gateway_interceptor {
    pub use super::generated::openshell::gateway_interceptor::v1;
}

/// Private gateway-to-shared-supervisor assignment protocol.
pub mod supervisor_host {
    pub use super::generated::openshell::supervisor::host::v1;
}

pub use datamodel::v1::*;
pub use gateway_interceptor::v1::*;
pub use middleware::v1::*;
pub use openshell::*;
pub use sandbox::v1::*;
pub use test::ObjectForTest;

impl ProviderCredentialRefreshStrategy {
    /// Canonical registration name, distinct from permissive YAML enum aliases.
    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Static => "static",
            Self::External => "external",
            Self::Oauth2RefreshToken => "oauth2_refresh_token",
            Self::Oauth2ClientCredentials => "oauth2_client_credentials",
            Self::GoogleServiceAccountJwt => "google_service_account_jwt",
            Self::AwsStsAssumeRole => "aws_sts_assume_role",
        }
    }

    /// Resolve new authored/configure inputs without accepting unknown enum
    /// integers, aliases, or unregistered custom names. Legacy decoders must
    /// retain their raw integer instead of calling this validation helper.
    pub fn resolve_input(strategy: i32, name: Option<&str>) -> Result<Self, String> {
        let strategy = Self::try_from(strategy)
            .map_err(|_| format!("unsupported provider refresh strategy enum: {strategy}"))?;
        let Some(name) = name else {
            return Ok(strategy);
        };
        let named = match name {
            "static" => Self::Static,
            "external" => Self::External,
            "oauth2_refresh_token" => Self::Oauth2RefreshToken,
            "oauth2_client_credentials" => Self::Oauth2ClientCredentials,
            "google_service_account_jwt" => Self::GoogleServiceAccountJwt,
            "aws_sts_assume_role" => Self::AwsStsAssumeRole,
            _ => {
                return Err(format!(
                    "unsupported provider refresh strategy name: {name}"
                ));
            }
        };
        if strategy != Self::Unspecified && strategy != named {
            return Err(format!(
                "refresh strategy '{}' conflicts with strategy_name '{name}'",
                strategy.canonical_name()
            ));
        }
        Ok(named)
    }
}

/// Build a selector for one explicitly named workspace.
pub fn workspace_selector(workspace: impl Into<String>) -> WorkspaceSelector {
    WorkspaceSelector {
        selection: Some(workspace_selector::Selection::Workspace(workspace.into())),
    }
}

/// Build a selector for every workspace supported by a cross-workspace request.
pub fn all_workspaces_selector() -> WorkspaceSelector {
    WorkspaceSelector {
        selection: Some(workspace_selector::Selection::AllWorkspaces(
            AllWorkspaces {},
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use prost::Message;

    use super::SandboxPolicy;

    #[test]
    fn refresh_strategy_name_compatibility_is_exact_and_fail_closed() {
        use super::ProviderCredentialRefreshStrategy as Strategy;
        assert_eq!(
            Strategy::resolve_input(0, None).unwrap(),
            Strategy::Unspecified
        );
        for strategy in [
            Strategy::Static,
            Strategy::External,
            Strategy::Oauth2RefreshToken,
            Strategy::Oauth2ClientCredentials,
            Strategy::GoogleServiceAccountJwt,
            Strategy::AwsStsAssumeRole,
        ] {
            let name = strategy.canonical_name();
            assert_eq!(
                Strategy::resolve_input(strategy as i32, None).unwrap(),
                strategy
            );
            assert_eq!(Strategy::resolve_input(0, Some(name)).unwrap(), strategy);
            assert_eq!(
                Strategy::resolve_input(strategy as i32, Some(name)).unwrap(),
                strategy
            );
            for unknown in [-1, i32::MAX] {
                assert!(Strategy::resolve_input(unknown, Some(name)).is_err());
                assert!(Strategy::resolve_input(unknown, None).is_err());
            }
        }
        assert!(
            Strategy::resolve_input(
                Strategy::Oauth2RefreshToken as i32,
                Some("oauth2_client_credentials")
            )
            .is_err()
        );
        for name in [
            "",
            "unspecified",
            "custom:example",
            "OAUTH2_REFRESH_TOKEN",
            "oauth2-refresh-token",
            " oauth2_refresh_token",
        ] {
            assert!(Strategy::resolve_input(0, Some(name)).is_err(), "{name}");
        }
    }

    // SandboxPolicy payload encoded by the pre-0.1.0 schema with
    // NetworkBinary.harness=true. Keep this fixed fixture to prove that the
    // current schema continues to accept the former durable wire format.
    const LEGACY_SANDBOX_POLICY_WITH_HARNESS: &[u8] = &[
        0x2a, 0x1d, 0x0a, 0x06, 0x6c, 0x65, 0x67, 0x61, 0x63, 0x79, 0x12, 0x13, 0x1a, 0x11, 0x0a,
        0x0d, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x63, 0x75, 0x72, 0x6c, 0x10,
        0x01,
    ];

    #[derive(Clone, PartialEq, Message)]
    struct LegacyNetworkBinary {
        #[prost(string, tag = "1")]
        path: String,
        #[prost(bool, tag = "2")]
        harness: bool,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyNetworkPolicyRule {
        #[prost(message, repeated, tag = "3")]
        binaries: Vec<LegacyNetworkBinary>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacySandboxPolicy {
        #[prost(map = "string, message", tag = "5")]
        network_policies: HashMap<String, LegacyNetworkPolicyRule>,
    }

    #[test]
    fn sandbox_policy_ignores_removed_network_binary_harness_wire_field() {
        let legacy = LegacySandboxPolicy {
            network_policies: HashMap::from([(
                "legacy".to_string(),
                LegacyNetworkPolicyRule {
                    binaries: vec![LegacyNetworkBinary {
                        path: "/usr/bin/curl".to_string(),
                        harness: true,
                    }],
                },
            )]),
        };

        assert_eq!(legacy.encode_to_vec(), LEGACY_SANDBOX_POLICY_WITH_HARNESS);

        let decoded = SandboxPolicy::decode(LEGACY_SANDBOX_POLICY_WITH_HARNESS)
            .expect("legacy policy fixture should decode");
        assert_eq!(
            decoded.network_policies["legacy"].binaries[0].path,
            "/usr/bin/curl"
        );

        let round_tripped =
            LegacySandboxPolicy::decode(decoded.encode_to_vec().as_slice()).unwrap();
        assert!(!round_tripped.network_policies["legacy"].binaries[0].harness);
    }

    #[test]
    fn network_binary_reserves_removed_harness_name_and_tag() {
        let descriptor = prost_types::FileDescriptorSet::decode(crate::FILE_DESCRIPTOR_SET)
            .expect("descriptor set should decode");
        let network_binary = descriptor
            .file
            .iter()
            .find(|file| file.package.as_deref() == Some("openshell.sandbox.v1"))
            .and_then(|file| {
                file.message_type
                    .iter()
                    .find(|message| message.name.as_deref() == Some("NetworkBinary"))
            })
            .expect("NetworkBinary descriptor should exist");

        assert!(
            network_binary
                .field
                .iter()
                .all(|field| field.name.as_deref() != Some("harness"))
        );
        assert!(
            network_binary
                .reserved_range
                .iter()
                .any(|range| range.start == Some(2) && range.end == Some(3))
        );
        assert!(
            network_binary
                .reserved_name
                .iter()
                .any(|name| name == "harness")
        );
    }
}
