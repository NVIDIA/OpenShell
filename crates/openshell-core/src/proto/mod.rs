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
    pub use super::generated::openshell::sandbox::v1;
}

pub mod compute {
    pub use super::generated::openshell::compute::v1;
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

pub use datamodel::v1::*;
pub use gateway_interceptor::v1::*;
pub use middleware::v1::*;
pub use openshell::*;
pub use sandbox::v1::*;
pub use test::ObjectForTest;

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

        let decoded = SandboxPolicy::decode(legacy.encode_to_vec().as_slice())
            .expect("legacy policy should decode");
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
