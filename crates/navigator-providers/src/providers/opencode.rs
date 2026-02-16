use crate::{
    ProviderDiscoverySpec, ProviderError, ProviderPlugin, RealDiscoveryContext, discover_with_spec,
};

pub struct OpencodeProvider;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "opencode",
    credential_env_vars: &["OPENCODE_API_KEY", "OPENROUTER_API_KEY", "OPENAI_API_KEY"],
    config_paths: &["~/.config/opencode/config.json", "~/.opencode/config.json"],
};

impl ProviderPlugin for OpencodeProvider {
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
    fn discovers_opencode_json_file_credentials_only() {
        let home = "/mock/home";
        let config_path = home_join(home, ".config/opencode/config.json");
        let ctx = MockDiscoveryContext::new()
            .with_home(home)
            .with_file(config_path, r#"{"openrouter_token":"rtr","model":"x"}"#);

        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("openrouter_token"),
            Some(&"rtr".to_string())
        );
        assert!(discovered.config.is_empty());
    }
}
