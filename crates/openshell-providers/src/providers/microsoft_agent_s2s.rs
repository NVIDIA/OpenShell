// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0

use crate::DiscoveryContext;
use crate::{DiscoveredProvider, ProviderError, ProviderPlugin, RealDiscoveryContext};

pub struct MicrosoftAgentS2sProvider;

const CREDENTIAL_ENV_VARS: &[&str] = &["A365_BLUEPRINT_CLIENT_SECRET"];
const CONFIG_ENV_VARS: &[&str] = &[
    "AZURE_TENANT_ID",
    "A365_BLUEPRINT_CLIENT_ID",
    "A365_RUNTIME_AGENT_ID",
    "A365_ALLOWED_AUDIENCES",
    "A365_OBSERVABILITY_RESOURCE",
    "A365_REQUIRED_ROLES",
];

impl ProviderPlugin for MicrosoftAgentS2sProvider {
    fn id(&self) -> &'static str {
        "microsoft-agent-s2s"
    }

    fn discover_existing(&self) -> Result<Option<DiscoveredProvider>, ProviderError> {
        discover_microsoft_agent_s2s(&RealDiscoveryContext)
    }

    fn credential_env_vars(&self) -> &'static [&'static str] {
        CREDENTIAL_ENV_VARS
    }
}

fn discover_microsoft_agent_s2s(
    context: &dyn DiscoveryContext,
) -> Result<Option<DiscoveredProvider>, ProviderError> {
    let mut discovered = DiscoveredProvider::default();

    for key in CREDENTIAL_ENV_VARS {
        if let Some(value) = context.env_var(key)
            && !value.trim().is_empty()
        {
            discovered
                .credentials
                .entry((*key).to_string())
                .or_insert(value);
        }
    }

    for key in CONFIG_ENV_VARS {
        if let Some(value) = context.env_var(key)
            && !value.trim().is_empty()
        {
            discovered.config.entry((*key).to_string()).or_insert(value);
        }
    }

    if discovered.is_empty() {
        Ok(None)
    } else {
        Ok(Some(discovered))
    }
}

#[cfg(test)]
mod tests {
    use super::discover_microsoft_agent_s2s;
    use crate::test_helpers::MockDiscoveryContext;

    #[test]
    fn discovers_microsoft_agent_s2s_env_state() {
        let ctx = MockDiscoveryContext::new()
            .with_env("AZURE_TENANT_ID", "tenant-id")
            .with_env("A365_BLUEPRINT_CLIENT_ID", "blueprint-client-id")
            .with_env("A365_BLUEPRINT_CLIENT_SECRET", "blueprint-secret")
            .with_env("A365_RUNTIME_AGENT_ID", "runtime-agent-id")
            .with_env("A365_ALLOWED_AUDIENCES", "api://aud-a,api://aud-b")
            .with_env("A365_OBSERVABILITY_RESOURCE", "observability-resource")
            .with_env("A365_REQUIRED_ROLES", "Agent365.Observability.OtelWrite");
        let discovered = discover_microsoft_agent_s2s(&ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("A365_BLUEPRINT_CLIENT_SECRET"),
            Some(&"blueprint-secret".to_string())
        );
        assert_eq!(
            discovered.config.get("AZURE_TENANT_ID"),
            Some(&"tenant-id".to_string())
        );
        assert_eq!(
            discovered.config.get("A365_BLUEPRINT_CLIENT_ID"),
            Some(&"blueprint-client-id".to_string())
        );
        assert_eq!(
            discovered.config.get("A365_RUNTIME_AGENT_ID"),
            Some(&"runtime-agent-id".to_string())
        );
        assert_eq!(
            discovered.config.get("A365_ALLOWED_AUDIENCES"),
            Some(&"api://aud-a,api://aud-b".to_string())
        );
        assert_eq!(
            discovered.config.get("A365_OBSERVABILITY_RESOURCE"),
            Some(&"observability-resource".to_string())
        );
        assert_eq!(
            discovered.config.get("A365_REQUIRED_ROLES"),
            Some(&"Agent365.Observability.OtelWrite".to_string())
        );
    }
}
