use std::path::{Component, Path, PathBuf};

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
            let home = std::env::var("HOME").ok()?;
            return expand_home_relative(Path::new(&home), stripped);
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

pub(crate) fn expand_home_relative(home: &Path, stripped: &str) -> Option<PathBuf> {
    let relative = Path::new(stripped);
    for component in relative.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(home.join(relative))
}

#[cfg(test)]
mod tests {
    use super::expand_home_relative;
    use std::path::{Path, PathBuf};

    #[test]
    fn rejects_parent_dir_escape_when_expanding_home() {
        assert_eq!(
            expand_home_relative(Path::new("/home/tester"), "../etc/passwd"),
            None
        );
    }

    #[test]
    fn expands_safe_relative_home_path() {
        assert_eq!(
            expand_home_relative(Path::new("/home/tester"), ".config/codex/config.json"),
            Some(PathBuf::from("/home/tester/.config/codex/config.json"))
        );
    }
}
