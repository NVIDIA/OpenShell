use std::path::{Path, PathBuf};

pub trait DiscoveryContext {
    fn env_var(&self, key: &str) -> Option<String>;
    fn expand_home(&self, path: &str) -> Option<PathBuf>;
    fn path_exists(&self, path: &Path) -> bool;
    fn read_to_string(&self, path: &Path) -> Option<String>;
}

pub struct RealDiscoveryContext;

impl DiscoveryContext for RealDiscoveryContext {
    fn env_var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn expand_home(&self, path: &str) -> Option<PathBuf> {
        if let Some(stripped) = path.strip_prefix("~/") {
            return std::env::var("HOME")
                .ok()
                .map(PathBuf::from)
                .map(|home| home.join(stripped));
        }
        Some(PathBuf::from(path))
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn read_to_string(&self, path: &Path) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }
}
