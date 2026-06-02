// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{DiscoveredProvider, ProviderError, ProviderPlugin};

/// Enclawed: a classification-gated, MCP-attested AI agent gateway.
///
/// Unlike the env-var-discovered providers (Claude Code, Codex, Copilot, ...),
/// Enclawed bootstraps every credential into the operator's OS keyring at
/// install time and never reads them from the environment. There is therefore
/// nothing for OpenShell to discover at provider-discovery time; the matching
/// sandbox image is responsible for running Enclawed's installer at first
/// boot to populate the keyring. Modeled on [`GenericProvider`] for that
/// reason.
pub struct EnclawedProvider;

impl ProviderPlugin for EnclawedProvider {
    fn id(&self) -> &'static str {
        "enclawed"
    }

    fn discover_existing(&self) -> Result<Option<DiscoveredProvider>, ProviderError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::EnclawedProvider;
    use crate::ProviderPlugin;

    #[test]
    fn enclawed_provider_discovery_is_empty_by_default() {
        let provider = EnclawedProvider;
        let discovered = provider.discover_existing().expect("discovery");
        assert!(discovered.is_none());
    }
}
