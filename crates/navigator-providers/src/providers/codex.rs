use crate::{
    ProviderDiscoverySpec, ProviderError, ProviderPlugin, RealDiscoveryContext, discover_with_spec,
};

pub struct CodexProvider;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "codex",
    credential_env_vars: &["OPENAI_API_KEY"],
    config_paths: &[
        "~/.config/codex/config.json",
        "~/.codex/config.json",
        "~/.config/openai/config.json",
    ],
};

impl ProviderPlugin for CodexProvider {
    fn id(&self) -> &'static str {
        SPEC.id
    }

    fn discover_existing(&self) -> Result<Option<crate::DiscoveredProvider>, ProviderError> {
        discover_with_spec(&SPEC, &RealDiscoveryContext)
    }
}

#[cfg(test)]
mod tests {
    use super::SPEC;
    use crate::discover_with_spec;
    use crate::test_helpers::{MockDiscoveryContext, home_join};

    #[test]
    fn discovers_codex_env_credentials() {
        let ctx = MockDiscoveryContext::new().with_env("OPENAI_API_KEY", "openai-key");
        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("OPENAI_API_KEY"),
            Some(&"openai-key".to_string())
        );
    }

    #[test]
    fn discovers_codex_json_file_credentials_only() {
        let home = "/mock/home";
        let config_path = home_join(home, ".config/codex/config.json");
        let ctx = MockDiscoveryContext::new().with_home(home).with_file(
            config_path,
            r#"{"token":"tok","base_url":"https://api.example.com"}"#,
        );

        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("token"),
            Some(&"tok".to_string())
        );
        assert!(discovered.config.is_empty());
    }
}
