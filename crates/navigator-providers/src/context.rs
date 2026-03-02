pub trait DiscoveryContext {
    fn env_var(&self, key: &str) -> Option<String>;
}

pub struct RealDiscoveryContext;

impl DiscoveryContext for RealDiscoveryContext {
    fn env_var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}
