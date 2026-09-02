// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider discovery and registry utilities.

mod context;
mod discovery;
mod profiles;
mod providers;
#[cfg(test)]
mod test_helpers;

use std::collections::HashMap;
use std::path::Path;

pub use openshell_core::proto::Provider;

pub use context::{DiscoveryContext, RealDiscoveryContext};
pub use discovery::{discover_from_profile, discover_with_spec};
pub use profiles::{
    CredentialRefreshProfile, ProfileError, ProfileValidationDiagnostic, ProviderTypeProfile,
    builtin_profiles, is_gateway_mintable_strategy, normalize_profile_id, parse_profile_json,
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

    /// Inject provider-specific env vars via the registered plugin.
    ///
    /// Normalizes the provider type and delegates to the plugin's `inject_env`.
    /// No-op if the provider type has no registered plugin or the plugin's
    /// default implementation is a no-op.
    pub fn inject_env(&self, provider: &Provider, env: &mut HashMap<String, String>) {
        let normalized = normalize_provider_type(&provider.r#type);
        if let Some(id) = normalized
            && let Some(plugin) = self.get(id)
        {
            plugin.inject_env(provider, env);
        }
    }

    /// Inject config for an already-resolved profile ID without alias
    /// normalization. This prevents an exact custom profile whose ID resembles
    /// a legacy alias from selecting an unrelated built-in compatibility plugin.
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

#[must_use]
pub fn normalize_provider_type(input: &str) -> Option<&'static str> {
    // Inference provider aliases are canonicalized in openshell-core so that
    // openshell-server and openshell-providers agree on the same mapping.
    if let Some(canonical) = openshell_core::inference::normalize_inference_provider_type(input) {
        return Some(canonical);
    }
    let normalized = input.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "claude" | "claude-code" | "claude_code" => Some("claude-code"),
        "codex" => Some("codex"),
        "copilot" => Some("copilot"),
        "gcp" | "google-cloud" => Some("google-cloud"),
        "github" | "gh" => Some("github"),
        _ => None,
    }
}

#[must_use]
pub fn detect_provider_from_command(command: &[String]) -> Option<&'static str> {
    let first = command.first()?;
    let basename = Path::new(first)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(first);
    normalize_provider_type(basename)
}

#[cfg(test)]
mod tests {
    use super::{detect_provider_from_command, normalize_provider_type};

    #[test]
    fn normalizes_known_provider_aliases() {
        assert_eq!(normalize_provider_type("gh"), Some("github"));
        assert_eq!(normalize_provider_type("CLAUDE"), Some("claude-code"));
        assert_eq!(normalize_provider_type("claude-code"), Some("claude-code"));
        for retired in ["generic", "gitlab", "glab", "opencode", "outlook"] {
            assert_eq!(normalize_provider_type(retired), None);
        }
        assert_eq!(normalize_provider_type("openai"), Some("openai"));
        assert_eq!(normalize_provider_type("anthropic"), Some("anthropic"));
        assert_eq!(normalize_provider_type("nvidia"), Some("nvidia"));
        assert_eq!(normalize_provider_type("copilot"), Some("copilot"));
        assert_eq!(
            normalize_provider_type("google-vertex-ai"),
            Some("google-vertex-ai")
        );
        assert_eq!(normalize_provider_type("vertex"), Some("google-vertex-ai"));
        assert_eq!(
            normalize_provider_type("vertex-ai"),
            Some("google-vertex-ai")
        );
        assert_eq!(normalize_provider_type("unknown"), None);
    }

    #[test]
    fn detects_provider_from_command_token() {
        assert_eq!(
            detect_provider_from_command(&["claude".to_string()]),
            Some("claude-code")
        );
        assert_eq!(
            detect_provider_from_command(&["/usr/bin/glab".to_string()]),
            None
        );
        assert_eq!(
            detect_provider_from_command(&["/usr/bin/bash".to_string()]),
            None
        );
        // Copilot standalone binary
        assert_eq!(
            detect_provider_from_command(&["copilot".to_string()]),
            Some("copilot")
        );
        assert_eq!(
            detect_provider_from_command(&["/usr/local/bin/copilot".to_string()]),
            Some("copilot")
        );
        // gh alone still maps to github
        assert_eq!(
            detect_provider_from_command(&["gh".to_string()]),
            Some("github")
        );
    }
}
