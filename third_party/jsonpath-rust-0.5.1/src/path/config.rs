pub mod cache;

use crate::path::config::cache::RegexCache;

/// Configuration to adjust the jsonpath search
#[derive(Clone, Default)]
pub struct JsonPathConfig {
    /// cache to provide
    pub regex_cache: RegexCache,
}

impl JsonPathConfig {
    pub fn new(regex_cache: RegexCache) -> Self {
        Self { regex_cache }
    }
}
