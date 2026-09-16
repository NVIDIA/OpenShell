// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider discovery and registry utilities.

mod context;
mod discovery;
#[cfg(any(test, feature = "example-profiles"))]
pub mod example_profiles;
mod profiles;
mod providers;
#[cfg(test)]
mod test_helpers;

use std::collections::HashMap;

pub use openshell_core::proto::Provider;

pub use context::{DiscoveryContext, RealDiscoveryContext};
pub use discovery::{discover_from_profile, discover_with_spec};
pub use profiles::{
    CredentialRefreshProfile, ProfileError, ProfileValidationDiagnostic, ProviderTypeProfile,
    is_gateway_mintable_strategy, normalize_profile_id, parse_profile_json, parse_profile_yaml,
    profile_to_json, profile_to_yaml, profiles_to_json, profiles_to_yaml, strategy_output_env_key,
    strategy_output_spec, strategy_primary_env_key, validate_profile_set,
};

pub const VERTEX_AI_PROJECT_ID_KEY: &str = "VERTEX_AI_PROJECT_ID";
pub const VERTEX_AI_REGION_KEY: &str = "VERTEX_AI_REGION";
pub const VERTEX_AI_CONFIG_KEY_NAMES: &[&str] = &[
    VERTEX_AI_PROJECT_ID_KEY,
    VERTEX_AI_REGION_KEY,
    "GOOGLE_VERTEX_AI_BASE_URL",
    "VERTEX_AI_BASE_URL",
    "VERTEX_AI_PUBLISHER",
];

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

#[derive(Debug, Clone, Copy)]
pub struct ProviderDiscoverySpec {
    pub id: &'static str,
    pub credential_env_vars: &'static [&'static str],
}

trait ProviderPlugin: Send + Sync {
    /// Canonical provider id.
    fn id(&self) -> &'static str;

    /// Inject provider-specific environment variables into the sandbox env.
    ///
    /// Called during sandbox creation to project provider config (project IDs,
    /// regions, SDK flags) into env vars the sandbox process will inherit.
    /// Default is a no-op; GCP and Vertex providers override this.
    fn inject_env(&self, _provider: &Provider, _env: &mut HashMap<String, String>) {}
}

#[derive(Default)]
pub struct ProviderRegistry {
    plugins: HashMap<&'static str, Box<dyn ProviderPlugin>>,
}

impl ProviderRegistry {
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Self::default();
        // Keep only the legacy config projectors required to run existing
        // Google Cloud and Vertex records. Public provider discovery is
        // profile-driven; this registry is an internal compatibility adapter.
        registry.register(providers::google_cloud::GoogleCloudProvider);
        registry.register(providers::vertex::VertexProvider);
        registry
    }

    fn register<P>(&mut self, plugin: P)
    where
        P: ProviderPlugin + 'static,
    {
        self.plugins.insert(plugin.id(), Box::new(plugin));
    }

    #[must_use]
    fn get(&self, id: &str) -> Option<&dyn ProviderPlugin> {
        self.plugins.get(id).map(Box::as_ref)
    }

    /// Inject provider-specific config for a resolved profile ID.
    ///
    /// Plugins are selected by the exact ID of the profile the gateway
    /// resolved. There is no alias table: a profile activates the plugin whose
    /// ID it matches, and nothing else does.
    pub fn inject_env_for_profile_id(
        &self,
        provider: &Provider,
        profile_id: &str,
        env: &mut HashMap<String, String>,
    ) {
        if let Some(plugin) = self.get(profile_id) {
            plugin.inject_env(provider, env);
        }
    }
}
