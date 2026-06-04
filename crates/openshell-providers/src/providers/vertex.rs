// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use openshell_core::google_cloud;
use openshell_core::inference;

use crate::{
    DiscoveredProvider, Provider, ProviderDiscoverySpec, ProviderError, ProviderPlugin,
    RealDiscoveryContext, discover_with_spec,
};

pub struct VertexProvider;

const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "google-vertex-ai",
    credential_env_vars: inference::VERTEX_AI_CREDENTIAL_KEY_NAMES,
};

impl ProviderPlugin for VertexProvider {
    fn id(&self) -> &'static str {
        SPEC.id
    }

    fn discover_existing(&self) -> Result<Option<DiscoveredProvider>, ProviderError> {
        let mut discovered = discover_with_spec(&SPEC, &RealDiscoveryContext)?.unwrap_or_default();

        for key in inference::VERTEX_AI_CONFIG_KEY_NAMES {
            if let Ok(val) = std::env::var(key)
                && !val.trim().is_empty()
            {
                discovered.config.entry(key.to_string()).or_insert(val);
            }
        }

        if discovered.is_empty() {
            Ok(None)
        } else {
            Ok(Some(discovered))
        }
    }

    fn credential_env_vars(&self) -> &'static [&'static str] {
        SPEC.credential_env_vars
    }

    fn inject_env(&self, provider: &Provider, env: &mut HashMap<String, String>) {
        if let Some(project) = provider
            .config
            .get(inference::VERTEX_AI_PROJECT_ID_KEY)
            .filter(|v| !v.trim().is_empty())
        {
            let trimmed = project.trim().to_string();
            for var in google_cloud::PROJECT_ID_ENV_VARS {
                env.entry((*var).to_string())
                    .or_insert_with(|| trimmed.clone());
            }
            env.entry(google_cloud::ANTHROPIC_VERTEX_PROJECT_ID_ENV_VAR.to_string())
                .or_insert_with(|| trimmed.clone());
        }

        if let Some(region) = provider
            .config
            .get(inference::VERTEX_AI_REGION_KEY)
            .filter(|v| !v.trim().is_empty())
        {
            let trimmed = region.trim().to_string();
            for var in google_cloud::REGION_ENV_VARS {
                env.entry((*var).to_string())
                    .or_insert_with(|| trimmed.clone());
            }
            env.entry(google_cloud::VERTEX_LOCATION_ENV_VAR.to_string())
                .or_insert_with(|| trimmed.clone());
        }

        env.entry(google_cloud::GOOSE_PROVIDER_ENV_VAR.to_string())
            .or_insert_with(|| "gcp_vertex_ai".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_provider(config: HashMap<String, String>) -> Provider {
        Provider {
            config,
            r#type: "google-vertex-ai".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn injects_project_id_and_anthropic_alias() {
        let provider = make_provider(HashMap::from([(
            "VERTEX_AI_PROJECT_ID".to_string(),
            "my-vertex-project".to_string(),
        )]));
        let mut env = HashMap::new();
        VertexProvider.inject_env(&provider, &mut env);

        assert_eq!(
            env.get("GCP_PROJECT_ID").map(String::as_str),
            Some("my-vertex-project")
        );
        assert_eq!(
            env.get("GOOGLE_CLOUD_PROJECT").map(String::as_str),
            Some("my-vertex-project")
        );
        assert_eq!(
            env.get("ANTHROPIC_VERTEX_PROJECT_ID").map(String::as_str),
            Some("my-vertex-project")
        );
    }

    #[test]
    fn injects_region_and_vertex_location() {
        let provider = make_provider(HashMap::from([(
            "VERTEX_AI_REGION".to_string(),
            "us-east4".to_string(),
        )]));
        let mut env = HashMap::new();
        VertexProvider.inject_env(&provider, &mut env);

        assert_eq!(
            env.get("CLOUD_ML_REGION").map(String::as_str),
            Some("us-east4")
        );
        assert_eq!(
            env.get("GCP_LOCATION").map(String::as_str),
            Some("us-east4")
        );
        assert_eq!(
            env.get("VERTEX_LOCATION").map(String::as_str),
            Some("us-east4")
        );
    }

    #[test]
    fn injects_inference_flags() {
        let provider = make_provider(HashMap::new());
        let mut env = HashMap::new();
        VertexProvider.inject_env(&provider, &mut env);

        assert!(!env.contains_key("CLAUDE_CODE_USE_VERTEX"));
        assert_eq!(
            env.get("GOOSE_PROVIDER").map(String::as_str),
            Some("gcp_vertex_ai")
        );
    }

    #[test]
    fn does_not_overwrite_existing_env() {
        let provider = make_provider(HashMap::from([(
            "VERTEX_AI_PROJECT_ID".to_string(),
            "new".to_string(),
        )]));
        let mut env = HashMap::from([("GCP_PROJECT_ID".to_string(), "existing".to_string())]);
        VertexProvider.inject_env(&provider, &mut env);

        assert_eq!(
            env.get("GCP_PROJECT_ID").map(String::as_str),
            Some("existing")
        );
    }

    #[test]
    fn skips_empty_config_values() {
        let provider = make_provider(HashMap::from([(
            "VERTEX_AI_PROJECT_ID".to_string(),
            "  ".to_string(),
        )]));
        let mut env = HashMap::new();
        VertexProvider.inject_env(&provider, &mut env);

        assert!(!env.contains_key("GCP_PROJECT_ID"));
        assert!(!env.contains_key("ANTHROPIC_VERTEX_PROJECT_ID"));
    }
}
