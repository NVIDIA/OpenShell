use crate::{
    ProviderDiscoverySpec, ProviderError, ProviderPlugin, RealDiscoveryContext, discover_with_spec,
};

pub struct GitlabProvider;

pub const SPEC: ProviderDiscoverySpec = ProviderDiscoverySpec {
    id: "gitlab",
    credential_env_vars: &["GITLAB_TOKEN", "GLAB_TOKEN", "CI_JOB_TOKEN"],
    config_paths: &["~/.config/glab-cli/config.yml"],
};

impl ProviderPlugin for GitlabProvider {
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
    fn discovers_gitlab_env_credentials() {
        let ctx = MockDiscoveryContext::new().with_env("GLAB_TOKEN", "glab-token");
        let discovered = discover_with_spec(&SPEC, &ctx)
            .expect("discovery")
            .expect("provider");
        assert_eq!(
            discovered.credentials.get("GLAB_TOKEN"),
            Some(&"glab-token".to_string())
        );
    }

    #[test]
    fn config_path_existence_alone_does_not_produce_discovery() {
        let home = "/mock/home";
        let path = home_join(home, ".config/glab-cli/config.yml");
        let ctx = MockDiscoveryContext::new()
            .with_home(home)
            .with_existing_path(path);
        let discovered = discover_with_spec(&SPEC, &ctx).expect("discovery");
        assert!(discovered.is_none());
    }
}
