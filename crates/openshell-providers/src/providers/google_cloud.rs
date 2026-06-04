// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use openshell_core::google_cloud;

use crate::{
    DiscoveredProvider, Provider, ProviderDiscoverySpec, ProviderError, ProviderPlugin,
    RealDiscoveryContext, discover_with_spec,
};

pub struct GoogleCloudProvider;

const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "google-cloud",
    credential_env_vars: google_cloud::TOKEN_ENV_KEYS,
};

impl ProviderPlugin for GoogleCloudProvider {
    fn id(&self) -> &'static str {
        SPEC.id
    }

    fn discover_existing(&self) -> Result<Option<DiscoveredProvider>, ProviderError> {
        discover_with_spec(&SPEC, &RealDiscoveryContext)
    }

    fn credential_env_vars(&self) -> &'static [&'static str] {
        SPEC.credential_env_vars
    }

    fn inject_env(&self, provider: &Provider, env: &mut HashMap<String, String>) {
        if let Some(project) = provider
            .config
            .get(google_cloud::GCP_PROJECT_ID_CONFIG_KEY)
            .filter(|v| !v.trim().is_empty())
        {
            for var in google_cloud::PROJECT_ID_ENV_VARS {
                env.entry((*var).to_string())
                    .or_insert_with(|| project.trim().to_string());
            }
        }

        if let Some(region) = provider
            .config
            .get(google_cloud::GCP_REGION_CONFIG_KEY)
            .filter(|v| !v.trim().is_empty())
        {
            for var in google_cloud::REGION_ENV_VARS {
                env.entry((*var).to_string())
                    .or_insert_with(|| region.trim().to_string());
            }
        }

        env.entry("GCE_METADATA_HOST".to_string())
            .or_insert_with(|| google_cloud::METADATA_HOST.to_string());

        if let Some(email) = provider
            .config
            .get(google_cloud::GCP_SERVICE_ACCOUNT_EMAIL_CONFIG_KEY)
            .filter(|v| !v.trim().is_empty())
        {
            for var in google_cloud::SERVICE_ACCOUNT_EMAIL_ENV_VARS {
                env.entry((*var).to_string())
                    .or_insert_with(|| email.trim().to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_provider(config: HashMap<String, String>) -> Provider {
        Provider {
            config,
            r#type: "google-cloud".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn injects_project_id_aliases() {
        let provider = make_provider(HashMap::from([(
            "project_id".to_string(),
            "my-project".to_string(),
        )]));
        let mut env = HashMap::new();
        GoogleCloudProvider.inject_env(&provider, &mut env);

        assert_eq!(
            env.get("GCP_PROJECT_ID").map(String::as_str),
            Some("my-project")
        );
        assert_eq!(
            env.get("GOOGLE_CLOUD_PROJECT").map(String::as_str),
            Some("my-project")
        );
    }

    #[test]
    fn injects_region_aliases() {
        let provider = make_provider(HashMap::from([(
            "region".to_string(),
            "us-central1".to_string(),
        )]));
        let mut env = HashMap::new();
        GoogleCloudProvider.inject_env(&provider, &mut env);

        assert_eq!(
            env.get("CLOUD_ML_REGION").map(String::as_str),
            Some("us-central1")
        );
        assert_eq!(
            env.get("GCP_LOCATION").map(String::as_str),
            Some("us-central1")
        );
    }

    #[test]
    fn injects_metadata_host() {
        let provider = make_provider(HashMap::new());
        let mut env = HashMap::new();
        GoogleCloudProvider.inject_env(&provider, &mut env);

        assert_eq!(
            env.get("GCE_METADATA_HOST").map(String::as_str),
            Some(google_cloud::METADATA_HOST)
        );
    }

    #[test]
    fn injects_service_account_email() {
        let provider = make_provider(HashMap::from([(
            "service_account_email".to_string(),
            "sa@project.iam.gserviceaccount.com".to_string(),
        )]));
        let mut env = HashMap::new();
        GoogleCloudProvider.inject_env(&provider, &mut env);

        assert_eq!(
            env.get("GCP_SERVICE_ACCOUNT_EMAIL").map(String::as_str),
            Some("sa@project.iam.gserviceaccount.com")
        );
    }

    #[test]
    fn does_not_overwrite_existing_env() {
        let provider = make_provider(HashMap::from([(
            "project_id".to_string(),
            "new-project".to_string(),
        )]));
        let mut env =
            HashMap::from([("GCP_PROJECT_ID".to_string(), "existing-project".to_string())]);
        GoogleCloudProvider.inject_env(&provider, &mut env);

        assert_eq!(
            env.get("GCP_PROJECT_ID").map(String::as_str),
            Some("existing-project"),
            "should not overwrite existing env"
        );
    }

    #[test]
    fn skips_empty_config_values() {
        let provider = make_provider(HashMap::from([(
            "project_id".to_string(),
            "  ".to_string(),
        )]));
        let mut env = HashMap::new();
        GoogleCloudProvider.inject_env(&provider, &mut env);

        assert!(!env.contains_key("GCP_PROJECT_ID"));
    }
}
