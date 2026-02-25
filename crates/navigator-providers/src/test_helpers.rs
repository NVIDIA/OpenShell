use crate::DiscoveryContext;
use crate::context::expand_home_relative;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct MockDiscoveryContext {
    env: HashMap<String, String>,
    files: HashMap<PathBuf, String>,
    exists: HashSet<PathBuf>,
    home: Option<PathBuf>,
}

impl MockDiscoveryContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_file(mut self, path: impl Into<PathBuf>, contents: &str) -> Self {
        let path = path.into();
        self.exists.insert(path.clone());
        self.files.insert(path, contents.to_string());
        self
    }

    pub fn with_existing_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.exists.insert(path.into());
        self
    }
}

impl DiscoveryContext for MockDiscoveryContext {
    fn env_var(&self, key: &str) -> Option<String> {
        self.env.get(key).cloned()
    }

    fn expand_home(&self, path: &str) -> Option<PathBuf> {
        if let Some(stripped) = path.strip_prefix("~/") {
            let home = self.home.as_deref()?;
            return expand_home_relative(home, stripped);
        }
        Some(PathBuf::from(path))
    }

    fn path_exists(&self, path: &Path) -> bool {
        self.exists.contains(path)
    }

    fn read_to_string(&self, path: &Path) -> Option<String> {
        self.files.get(path).cloned()
    }
}

pub fn home_join(home: &str, rel: &str) -> PathBuf {
    PathBuf::from(home).join(rel)
}
