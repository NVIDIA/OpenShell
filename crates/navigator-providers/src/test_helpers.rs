use crate::DiscoveryContext;
use std::collections::HashMap;

#[derive(Default)]
pub struct MockDiscoveryContext {
    env: HashMap<String, String>,
}

impl MockDiscoveryContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.insert(key.to_string(), value.to_string());
        self
    }
}

impl DiscoveryContext for MockDiscoveryContext {
    fn env_var(&self, key: &str) -> Option<String> {
        self.env.get(key).cloned()
    }
}
