// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    DiscoveredProvider, DiscoveryContext, ProviderDiscoverySpec, ProviderError, ProviderPlugin,
    RealDiscoveryContext,
};

pub struct DockerAgentProvider;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "docker-agent",
    credential_env_vars: &["DOCKER_ACCESS_TOKEN"],
};

/// Known locations of the Docker binary.
///
/// Discovery succeeds when any of these paths exists, even without a token,
/// because `DOCKER_ACCESS_TOKEN` is optional (public Docker Hub and the local
/// Model Runner work without one).
const DOCKER_BINARIES: &[&str] = &[
    "/usr/bin/docker",
    "/usr/local/bin/docker",
    "/usr/bin/docker-agent",
    "/usr/local/bin/docker-agent",
];

pub fn discover_docker_agent(
    spec: &ProviderDiscoverySpec,
    context: &dyn DiscoveryContext,
) -> Option<DiscoveredProvider> {
    let mut discovered = DiscoveredProvider::default();

    for key in spec.credential_env_vars {
        if let Some(value) = context.env_var(key)
            && !value.trim().is_empty()
        {
            discovered
                .credentials
                .entry((*key).to_string())
                .or_insert(value);
        }
    }

    // Credentials are optional; treat the provider as discovered whenever a
    // docker binary is present so that the policy always gets applied.
    if !discovered.is_empty() || DOCKER_BINARIES.iter().any(|p| context.path_exists(p)) {
        Some(discovered)
    } else {
        None
    }
}

impl ProviderPlugin for DockerAgentProvider {
    fn id(&self) -> &'static str {
        SPEC.id
    }

    fn discover_existing(&self) -> Result<Option<DiscoveredProvider>, ProviderError> {
        Ok(discover_docker_agent(&SPEC, &RealDiscoveryContext))
    }

    fn credential_env_vars(&self) -> &'static [&'static str] {
        SPEC.credential_env_vars
    }
}

#[cfg(test)]
mod tests {
    use super::{DOCKER_BINARIES, SPEC, discover_docker_agent};
    use crate::test_helpers::MockDiscoveryContext;

    #[test]
    fn discovers_docker_agent_hub_token() {
        let ctx =
            MockDiscoveryContext::new().with_env("DOCKER_ACCESS_TOKEN", "dckr_pat_test_token");
        let discovered = discover_docker_agent(&SPEC, &ctx).expect("provider");
        assert_eq!(
            discovered.credentials.get("DOCKER_ACCESS_TOKEN"),
            Some(&"dckr_pat_test_token".to_string())
        );
    }

    #[test]
    fn discovers_docker_agent_without_token_when_binary_present() {
        // No DOCKER_ACCESS_TOKEN set, but docker binary exists.
        let ctx = MockDiscoveryContext::new().with_path(DOCKER_BINARIES[0]);
        let discovered = discover_docker_agent(&SPEC, &ctx)
            .expect("provider should be found when binary present");
        assert!(
            discovered.credentials.is_empty(),
            "no credentials expected when token is absent"
        );
    }

    #[test]
    fn no_discovery_without_token_or_binary() {
        let ctx = MockDiscoveryContext::new();
        assert!(
            discover_docker_agent(&SPEC, &ctx).is_none(),
            "should not discover when neither token nor binary is present"
        );
    }
}
