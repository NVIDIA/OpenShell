use crate::{
    ProviderDiscoverySpec, ProviderError, ProviderPlugin, RealDiscoveryContext, discover_with_spec,
};

pub struct OpenclawProvider;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "openclaw",
    credential_env_vars: &["OPENCLAW_API_KEY", "OPENAI_API_KEY"],
    config_paths: &["~/.config/openclaw/config.json", "~/.openclaw/config.json"],
};

impl ProviderPlugin for OpenclawProvider {
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
    fn discovers_openclaw_env_credentials() {
        let ctx = MockDiscoveryContext::new().with_env("OPENCLAW_API_KEY", "claw-key");
        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("OPENCLAW_API_KEY"),
            Some(&"claw-key".to_string())
        );
    }

    #[test]
    fn discovers_openclaw_json_file_credentials_only() {
        let home = "/mock/home";
        let config_path = home_join(home, ".config/openclaw/config.json");
        let ctx = MockDiscoveryContext::new()
            .with_home(home)
            .with_file(config_path, r#"{"api_key":"key","org":"team"}"#);

        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("api_key"),
            Some(&"key".to_string())
        );
        assert!(discovered.config.is_empty());
    }
}
