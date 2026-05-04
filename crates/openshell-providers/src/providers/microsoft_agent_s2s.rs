// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    ProviderDiscoverySpec, ProviderError, ProviderPlugin, RealDiscoveryContext, discover_with_spec,
};

pub struct MicrosoftAgentS2sProvider;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "microsoft-agent-s2s",
    credential_env_vars: &[
        "AZURE_TENANT_ID",
        "A365_BLUEPRINT_CLIENT_ID",
        "A365_BLUEPRINT_CLIENT_SECRET",
        "A365_RUNTIME_AGENT_ID",
        "A365_ALLOWED_AUDIENCES",
        "A365_OBSERVABILITY_RESOURCE",
        "A365_REQUIRED_ROLES",
    ],
};

impl ProviderPlugin for MicrosoftAgentS2sProvider {
    fn id(&self) -> &'static str {
        SPEC.id
    }

    fn discover_existing(&self) -> Result<Option<crate::DiscoveredProvider>, ProviderError> {
        discover_with_spec(&SPEC, &RealDiscoveryContext)
    }

    fn credential_env_vars(&self) -> &'static [&'static str] {
        SPEC.credential_env_vars
    }
}

#[cfg(test)]
mod tests {
    use super::SPEC;
    use crate::discover_with_spec;
    use crate::test_helpers::MockDiscoveryContext;

    #[test]
    fn discovers_microsoft_agent_s2s_env_credentials() {
        let ctx = MockDiscoveryContext::new()
            .with_env("AZURE_TENANT_ID", "tenant-id")
            .with_env("A365_BLUEPRINT_CLIENT_ID", "blueprint-client-id")
            .with_env("A365_BLUEPRINT_CLIENT_SECRET", "blueprint-secret")
            .with_env("A365_RUNTIME_AGENT_ID", "runtime-agent-id")
            .with_env("A365_ALLOWED_AUDIENCES", "api://aud-a,api://aud-b")
            .with_env("A365_OBSERVABILITY_RESOURCE", "observability-resource")
            .with_env("A365_REQUIRED_ROLES", "Agent365.Observability.OtelWrite");
        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("AZURE_TENANT_ID"),
            Some(&"tenant-id".to_string())
        );
        assert_eq!(
            discovered.credentials.get("A365_BLUEPRINT_CLIENT_ID"),
            Some(&"blueprint-client-id".to_string())
        );
        assert_eq!(
            discovered.credentials.get("A365_BLUEPRINT_CLIENT_SECRET"),
            Some(&"blueprint-secret".to_string())
        );
        assert_eq!(
            discovered.credentials.get("A365_RUNTIME_AGENT_ID"),
            Some(&"runtime-agent-id".to_string())
        );
        assert_eq!(
            discovered.credentials.get("A365_ALLOWED_AUDIENCES"),
            Some(&"api://aud-a,api://aud-b".to_string())
        );
        assert_eq!(
            discovered.credentials.get("A365_OBSERVABILITY_RESOURCE"),
            Some(&"observability-resource".to_string())
        );
        assert_eq!(
            discovered.credentials.get("A365_REQUIRED_ROLES"),
            Some(&"Agent365.Observability.OtelWrite".to_string())
        );
    }
}
