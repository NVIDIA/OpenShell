use crate::{
    ProviderDiscoverySpec, ProviderError, ProviderPlugin, RealDiscoveryContext, discover_with_spec,
};

pub struct GithubProvider;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "github",
    credential_env_vars: &["GITHUB_TOKEN", "GH_TOKEN"],
    config_paths: &["~/.config/gh/hosts.yml"],
};

impl ProviderPlugin for GithubProvider {
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
    fn discovers_github_env_credentials() {
        let ctx = MockDiscoveryContext::new().with_env("GH_TOKEN", "gh-token");
        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("GH_TOKEN"),
            Some(&"gh-token".to_string())
        );
    }

    #[test]
    fn config_path_existence_alone_does_not_produce_discovery() {
        let home = "/mock/home";
        let path = home_join(home, ".config/gh/hosts.yml");
        let ctx = MockDiscoveryContext::new()
            .with_home(home)
            .with_existing_path(path);
        let discovered = discover_with_spec(&SPEC, &ctx).expect("discovery");
        assert!(discovered.is_none());
    }
}
