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
pub use discovery::discover_with_spec;
pub use profiles::{ProviderTypeProfile, default_profiles, get_default_profile};

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("unsupported provider type: {0}")]
    UnsupportedProvider(String),
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

pub trait ProviderPlugin: Send + Sync {
    /// Canonical provider id (for example: "claude", "gitlab").
    fn id(&self) -> &'static str;

    /// Discover provider credentials and config from the local machine.
    fn discover_existing(&self) -> Result<Option<DiscoveredProvider>, ProviderError>;

    /// Return the known credential environment variable names for this provider type.
    ///
    /// Used by the TUI to label BYO key entry fields and to choose which
    /// env var name to store a manually-entered credential under.
    fn credential_env_vars(&self) -> &'static [&'static str] {
        &[]
    }

    /// Apply provider data to sandbox runtime context.
    ///
    /// Default implementation is a no-op; provider-specific runtime projection
    /// can be layered in incrementally.
    fn apply_to_sandbox(&self, _provider: &Provider) -> Result<(), ProviderError> {
        Ok(())
    }
}

#[derive(Default)]
pub struct ProviderRegistry {
    plugins: HashMap<&'static str, Box<dyn ProviderPlugin>>,
}

impl ProviderRegistry {
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Self::default();
        registry.register(providers::claude::ClaudeProvider);
        registry.register(providers::codex::CodexProvider);
        registry.register(providers::copilot::CopilotProvider);
        registry.register(providers::opencode::OpencodeProvider);
        registry.register(providers::generic::GenericProvider);
        registry.register(providers::openai::OpenaiProvider);
        registry.register(providers::anthropic::AnthropicProvider);
        registry.register(providers::nvidia::NvidiaProvider);
        registry.register(providers::gitlab::GitlabProvider);
        registry.register(providers::github::GithubProvider);
        registry.register(providers::outlook::OutlookProvider);
        registry
    }

    pub fn register<P>(&mut self, plugin: P)
    where
        P: ProviderPlugin + 'static,
    {
        self.plugins.insert(plugin.id(), Box::new(plugin));
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&dyn ProviderPlugin> {
        self.plugins.get(id).map(Box::as_ref)
    }

    pub fn discover_existing(&self, id: &str) -> Result<Option<DiscoveredProvider>, ProviderError> {
        let Some(plugin) = self.get(id) else {
            return Err(ProviderError::UnsupportedProvider(id.to_string()));
        };
        plugin.discover_existing()
    }

    /// Return the known credential env var names for a provider type.
    #[must_use]
    pub fn credential_env_vars(&self, id: &str) -> &'static [&'static str] {
        self.get(id)
            .map_or(&[], ProviderPlugin::credential_env_vars)
    }

    #[must_use]
    pub fn profile(&self, id: &str) -> Option<&'static ProviderTypeProfile> {
        get_default_profile(id)
    }

    #[must_use]
    pub fn profiles(&self) -> Vec<&'static ProviderTypeProfile> {
        default_profiles().iter().collect()
    }

    #[must_use]
    pub fn known_types(&self) -> Vec<&'static str> {
        let mut types = self.plugins.keys().copied().collect::<Vec<_>>();
        types.sort_unstable();
        types
    }
}

#[must_use]
pub fn normalize_provider_type(input: &str) -> Option<&'static str> {
    let normalized = input.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "claude" => Some("claude"),
        "codex" => Some("codex"),
        "copilot" => Some("copilot"),
        "opencode" => Some("opencode"),
        "generic" => Some("generic"),
        "openai" => Some("openai"),
        "anthropic" => Some("anthropic"),
        "nvidia" => Some("nvidia"),
        "gitlab" | "glab" => Some("gitlab"),
        "github" | "gh" => Some("github"),
        "outlook" => Some("outlook"),
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
        assert_eq!(normalize_provider_type("gitlab"), Some("gitlab"));
        assert_eq!(normalize_provider_type("glab"), Some("gitlab"));
        assert_eq!(normalize_provider_type("gh"), Some("github"));
        assert_eq!(normalize_provider_type("CLAUDE"), Some("claude"));
        assert_eq!(normalize_provider_type("generic"), Some("generic"));
        assert_eq!(normalize_provider_type("openai"), Some("openai"));
        assert_eq!(normalize_provider_type("anthropic"), Some("anthropic"));
        assert_eq!(normalize_provider_type("nvidia"), Some("nvidia"));
        assert_eq!(normalize_provider_type("copilot"), Some("copilot"));
        assert_eq!(normalize_provider_type("unknown"), None);
    }

    #[test]
    fn detects_provider_from_command_token() {
        assert_eq!(
            detect_provider_from_command(&["claude".to_string()]),
            Some("claude")
        );
        assert_eq!(
            detect_provider_from_command(&["/usr/bin/glab".to_string()]),
            Some("gitlab")
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
