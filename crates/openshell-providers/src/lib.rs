// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider discovery and registry utilities.

mod context;
mod discovery;
#[cfg(test)]
mod environment_tests;
#[cfg(any(test, feature = "example-profiles"))]
pub mod example_profiles;
mod profiles;
#[cfg(test)]
mod test_helpers;

use std::collections::HashMap;

pub use openshell_core::proto::Provider;

/// Legacy Vertex bootstrap material must never become a workload credential.
/// Older stored profiles may still declare this key as an injectable env var.
pub const LEGACY_VERTEX_PRIVATE_KEY_ENV: &str = "GOOGLE_SERVICE_ACCOUNT_KEY";

pub use context::{DiscoveryContext, RealDiscoveryContext};
pub use discovery::discover_from_profile;
pub use profiles::{
    CredentialRefreshProfile, EnvironmentProfile, ProfileError, ProfileValidationDiagnostic,
    ProviderTypeProfile, is_gateway_mintable_strategy, normalize_profile_id, parse_profile_json,
    parse_profile_yaml, profile_to_json, profile_to_yaml, profiles_to_json, profiles_to_yaml,
    strategy_output_env_key, strategy_output_spec, strategy_primary_env_key, validate_profile_set,
};

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("unsupported provider type: {0}")]
    UnsupportedProvider(String),
    #[error(
        "provider profile '{profile_id}' discovery references unknown credential '{credential_name}'"
    )]
    UnknownDiscoveryCredential {
        profile_id: String,
        credential_name: String,
    },
    #[error("required platform adapter 'gcp-metadata' is unavailable in this build")]
    UnavailableGcpMetadataAdapter,
    #[error("unknown required platform adapter")]
    UnknownPlatformAdapter,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveredProvider {
    pub credentials: HashMap<String, String>,
    pub config: HashMap<String, String>,
}

impl DiscoveredProvider {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty() && self.config.is_empty()
    }
}
