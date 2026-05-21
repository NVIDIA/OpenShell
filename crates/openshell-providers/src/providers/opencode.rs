// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::{
    DiscoveredProvider, ProviderDiscoverySpec, ProviderError, ProviderPlugin, RealDiscoveryContext,
    discover_with_spec,
};

pub struct OpencodeProvider;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "opencode",
    credential_env_vars: &["OPENCODE_API_KEY", "OPENROUTER_API_KEY", "OPENAI_API_KEY"],
};

/// Return the path to the opencode config file, respecting `XDG_CONFIG_HOME`.
fn opencode_config_path() -> Option<PathBuf> {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".config"))
        })?;
    Some(config_home.join("opencode").join("opencode.json"))
}

/// Extract API key credentials from the contents of an opencode config file.
///
/// opencode stores per-provider API keys at `provider.<name>.options.apiKey`.
/// Each key is surfaced as `<NAME_UPPERCASE>_API_KEY` so that it can be injected
/// as an environment variable into the sandbox and picked up by opencode at runtime.
fn extract_credentials_from_opencode_config(content: &str) -> HashMap<String, String> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
        return HashMap::new();
    };
    let Some(providers) = json.get("provider").and_then(|p| p.as_object()) else {
        return HashMap::new();
    };

    let mut creds = HashMap::new();
    for (provider_name, provider_cfg) in providers {
        if let Some(api_key) = provider_cfg
            .get("options")
            .and_then(|o| o.get("apiKey"))
            .and_then(|k| k.as_str())
            .filter(|k| !k.trim().is_empty())
        {
            let env_var = format!("{}_API_KEY", provider_name.to_ascii_uppercase());
            creds.insert(env_var, api_key.to_string());
        }
    }
    creds
}

/// Read opencode credentials from `path`, returning `None` if the file is absent or unreadable.
fn read_opencode_config_file(path: &Path) -> Option<HashMap<String, String>> {
    let content = std::fs::read_to_string(path).ok()?;
    let creds = extract_credentials_from_opencode_config(&content);
    if creds.is_empty() { None } else { Some(creds) }
}

impl ProviderPlugin for OpencodeProvider {
    fn id(&self) -> &'static str {
        SPEC.id
    }

    fn discover_existing(&self) -> Result<Option<DiscoveredProvider>, ProviderError> {
        let mut discovered = discover_with_spec(&SPEC, &RealDiscoveryContext)?.unwrap_or_default();

        // Supplement env-var discovery with credentials stored in the opencode config file.
        // opencode's native config lives at $XDG_CONFIG_HOME/opencode/opencode.json and stores
        // API keys under `provider.<name>.options.apiKey`.  If the user configured opencode
        // normally (i.e. no env vars set), this is the only place the keys exist.
        if let Some(path) = opencode_config_path()
            && let Some(file_creds) = read_opencode_config_file(&path)
        {
            for (key, value) in file_creds {
                // Env vars already set take priority; config file fills the gaps.
                discovered.credentials.entry(key).or_insert(value);
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
}

#[cfg(test)]
mod tests {
    use super::{SPEC, extract_credentials_from_opencode_config};
    use crate::discover_with_spec;
    use crate::test_helpers::MockDiscoveryContext;

    #[test]
    fn discovers_opencode_env_credentials() {
        let ctx = MockDiscoveryContext::new().with_env("OPENCODE_API_KEY", "op-key");
        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("OPENCODE_API_KEY"),
            Some(&"op-key".to_string())
        );
    }

    #[test]
    fn extracts_credentials_from_config_file() {
        let config = r#"{
            "provider": {
                "anthropic": { "options": { "apiKey": "sk-ant-key" } },
                "openai":    { "options": { "apiKey": "sk-openai-key" } }
            }
        }"#;
        let creds = extract_credentials_from_opencode_config(config);
        assert_eq!(
            creds.get("ANTHROPIC_API_KEY"),
            Some(&"sk-ant-key".to_string())
        );
        assert_eq!(
            creds.get("OPENAI_API_KEY"),
            Some(&"sk-openai-key".to_string())
        );
    }

    #[test]
    fn skips_providers_without_api_key() {
        let config = r#"{
            "provider": {
                "ollama": { "options": { "baseUrl": "http://localhost:11434" } }
            }
        }"#;
        let creds = extract_credentials_from_opencode_config(config);
        assert!(
            creds.is_empty(),
            "no credentials expected for keyless provider"
        );
    }

    #[test]
    fn skips_empty_api_keys() {
        let config = r#"{
            "provider": {
                "anthropic": { "options": { "apiKey": "" } }
            }
        }"#;
        let creds = extract_credentials_from_opencode_config(config);
        assert!(creds.is_empty());
    }

    #[test]
    fn tolerates_malformed_json() {
        let creds = extract_credentials_from_opencode_config("not json at all");
        assert!(creds.is_empty());
    }

    #[test]
    fn tolerates_missing_provider_section() {
        let config = r#"{ "theme": "dark" }"#;
        let creds = extract_credentials_from_opencode_config(config);
        assert!(creds.is_empty());
    }
}
