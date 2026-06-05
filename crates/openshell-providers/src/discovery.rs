// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    DiscoveredProvider, DiscoveryContext, ProviderDiscoverySpec, ProviderError, ProviderTypeProfile,
};
use std::collections::HashSet;

pub fn discover_with_spec(
    spec: &ProviderDiscoverySpec,
    context: &dyn DiscoveryContext,
) -> Result<Option<DiscoveredProvider>, ProviderError> {
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

    if discovered.is_empty() {
        Ok(None)
    } else {
        Ok(Some(discovered))
    }
}

pub fn discover_from_profile(
    profile: &ProviderTypeProfile,
    context: &dyn DiscoveryContext,
) -> Result<Option<DiscoveredProvider>, ProviderError> {
    let mut discovered = DiscoveredProvider::default();
    let mut scanned_env_vars = HashSet::new();

    for credential_name in &profile.discovery.credentials {
        let credential_name = credential_name.trim();
        let Some(credential) = profile
            .credentials
            .iter()
            .find(|credential| credential.name.trim() == credential_name)
        else {
            return Err(ProviderError::UnknownDiscoveryCredential {
                profile_id: profile.id.clone(),
                credential_name: credential_name.to_string(),
            });
        };

        for env_var in &credential.env_vars {
            let env_var = env_var.trim();
            if env_var.is_empty() || !scanned_env_vars.insert(env_var.to_string()) {
                continue;
            }
            if let Some(value) = context.env_var(env_var)
                && !value.trim().is_empty()
            {
                discovered
                    .credentials
                    .entry(env_var.to_string())
                    .or_insert(value);
            }
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
    use super::discover_from_profile;
    use crate::profiles::{CredentialProfile, DiscoveryProfile};
    use crate::test_helpers::MockDiscoveryContext;
    use crate::{ProviderError, ProviderTypeProfile};

    fn profile() -> ProviderTypeProfile {
        ProviderTypeProfile {
            id: "custom".to_string(),
            display_name: "Custom".to_string(),
            description: String::new(),
            category: openshell_core::proto::ProviderProfileCategory::Other,
            credentials: vec![
                CredentialProfile {
                    name: "api_key".to_string(),
                    env_vars: vec!["CUSTOM_API_KEY".to_string(), "CUSTOM_API_TOKEN".to_string()],
                    required: true,
                    description: String::new(),
                    auth_style: String::new(),
                    header_name: String::new(),
                    query_param: String::new(),
                    refresh: None,
                    path_template: String::new(),
                    token_grant: None,
                },
                CredentialProfile {
                    name: "secondary".to_string(),
                    env_vars: vec!["CUSTOM_API_KEY".to_string()],
                    required: false,
                    description: String::new(),
                    auth_style: String::new(),
                    header_name: String::new(),
                    query_param: String::new(),
                    refresh: None,
                    path_template: String::new(),
                    token_grant: None,
                },
            ],
            endpoints: Vec::new(),
            binaries: Vec::new(),
            inference_capable: false,
            discovery: DiscoveryProfile {
                credentials: vec!["api_key".to_string(), "secondary".to_string()],
            },
        }
    }

    #[test]
    fn profile_discovery_scans_referenced_credential_env_vars() {
        let ctx = MockDiscoveryContext::new().with_env("CUSTOM_API_TOKEN", "secret-token");

        let discovered = discover_from_profile(&profile(), &ctx)
            .expect("discovery should succeed")
            .expect("provider should be discovered");

        assert_eq!(
            discovered.credentials.get("CUSTOM_API_TOKEN"),
            Some(&"secret-token".to_string())
        );
        assert!(!discovered.credentials.contains_key("CUSTOM_API_KEY"));
    }

    #[test]
    fn profile_discovery_ignores_empty_values_and_returns_none_when_empty() {
        let ctx = MockDiscoveryContext::new().with_env("CUSTOM_API_KEY", "   ");

        let discovered = discover_from_profile(&profile(), &ctx).expect("discovery should succeed");

        assert!(discovered.is_none());
    }

    #[test]
    fn profile_discovery_rejects_unknown_credential_references() {
        let mut profile = profile();
        profile.discovery.credentials = vec!["missing".to_string()];

        let err = discover_from_profile(&profile, &MockDiscoveryContext::new())
            .expect_err("unknown discovery credential should fail");

        assert!(matches!(
            err,
            ProviderError::UnknownDiscoveryCredential {
                profile_id,
                credential_name
            } if profile_id == "custom" && credential_name == "missing"
        ));
    }
}
