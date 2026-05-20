// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime defaults for local gateway installs.

use miette::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTlsPaths {
    pub ca: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
}

impl LocalTlsPaths {
    fn resolve(dir: &Path) -> Self {
        Self {
            ca: dir.join("ca.crt"),
            server_cert: dir.join("server").join("tls.crt"),
            server_key: dir.join("server").join("tls.key"),
            client_cert: dir.join("client").join("tls.crt"),
            client_key: dir.join("client").join("tls.key"),
        }
    }

    fn files(&self) -> [&Path; 5] {
        [
            &self.ca,
            &self.server_cert,
            &self.server_key,
            &self.client_cert,
            &self.client_key,
        ]
    }
}

pub fn default_gateway_config_path() -> Result<PathBuf> {
    Ok(openshell_core::paths::openshell_config_dir()?.join("gateway.toml"))
}

pub fn default_database_url() -> Result<String> {
    let path = openshell_core::paths::openshell_state_dir()?
        .join("gateway")
        .join("openshell.db");
    openshell_core::paths::ensure_parent_dir_restricted(&path)?;
    Ok(format!("sqlite:{}", path.display()))
}

fn default_local_tls_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("OPENSHELL_LOCAL_TLS_DIR") {
        return Ok(PathBuf::from(path));
    }
    Ok(openshell_core::paths::openshell_state_dir()?.join("tls"))
}

pub fn complete_local_tls_paths() -> Result<Option<LocalTlsPaths>> {
    let dir = default_local_tls_dir()?;
    let paths = LocalTlsPaths::resolve(&dir);
    let present = paths.files().iter().filter(|path| path.is_file()).count();
    match present {
        0 => Ok(None),
        5 => Ok(Some(paths)),
        _ => Err(miette::miette!(
            "partial local TLS state in {}: expected ca.crt, server/tls.crt, server/tls.key, client/tls.crt, and client/tls.key",
            dir.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{LazyLock, Mutex};

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    struct EnvVarGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvVarGuard {
        #[allow(unsafe_code)]
        fn set(key: &'static str, value: &Path) -> Self {
            let original = std::env::var(key).ok();
            // SAFETY: tests serialize environment mutation with ENV_LOCK.
            unsafe { std::env::set_var(key, value) };
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            match self.original.as_deref() {
                // SAFETY: tests serialize environment mutation with ENV_LOCK.
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                // SAFETY: tests serialize environment mutation with ENV_LOCK.
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn complete_local_tls_paths_returns_none_when_bundle_absent() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvVarGuard::set("OPENSHELL_LOCAL_TLS_DIR", tmp.path());

        assert!(complete_local_tls_paths().unwrap().is_none());
    }

    #[test]
    fn complete_local_tls_paths_rejects_partial_bundle() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvVarGuard::set("OPENSHELL_LOCAL_TLS_DIR", tmp.path());
        std::fs::write(tmp.path().join("ca.crt"), "ca").unwrap();

        let err = complete_local_tls_paths().unwrap_err();
        assert!(err.to_string().contains("partial local TLS state"));
    }

    #[test]
    fn complete_local_tls_paths_returns_full_bundle() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvVarGuard::set("OPENSHELL_LOCAL_TLS_DIR", tmp.path());
        std::fs::create_dir_all(tmp.path().join("server")).unwrap();
        std::fs::create_dir_all(tmp.path().join("client")).unwrap();
        for rel in [
            "ca.crt",
            "server/tls.crt",
            "server/tls.key",
            "client/tls.crt",
            "client/tls.key",
        ] {
            std::fs::write(tmp.path().join(rel), "pem").unwrap();
        }

        let paths = complete_local_tls_paths().unwrap().unwrap();
        assert_eq!(paths.ca, tmp.path().join("ca.crt"));
        assert_eq!(paths.server_cert, tmp.path().join("server/tls.crt"));
        assert_eq!(paths.client_key, tmp.path().join("client/tls.key"));
    }
}
