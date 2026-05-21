// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime defaults for local gateway installs.

use miette::Result;
use openshell_core::GatewayJwtConfig;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalJwtPaths {
    pub signing_key: PathBuf,
    pub public_key: PathBuf,
    pub kid: PathBuf,
}

impl LocalJwtPaths {
    fn resolve(dir: &Path) -> Self {
        let jwt = dir.join("jwt");
        Self {
            signing_key: jwt.join("signing.pem"),
            public_key: jwt.join("public.pem"),
            kid: jwt.join("kid"),
        }
    }

    fn files(&self) -> [&Path; 3] {
        [&self.signing_key, &self.public_key, &self.kid]
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

pub fn complete_local_jwt_config() -> Result<Option<GatewayJwtConfig>> {
    let dir = default_local_tls_dir()?;
    let paths = LocalJwtPaths::resolve(&dir);
    let present = paths.files().iter().filter(|path| path.is_file()).count();
    match present {
        0 => Ok(None),
        3 => Ok(Some(GatewayJwtConfig {
            signing_key_path: paths.signing_key,
            public_key_path: paths.public_key,
            kid_path: paths.kid,
            gateway_id: "openshell".to_string(),
            ttl_secs: 3_600,
        })),
        _ => Err(miette::miette!(
            "partial local sandbox JWT state in {}: expected jwt/signing.pem, jwt/public.pem, and jwt/kid",
            dir.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TEST_ENV_LOCK as ENV_LOCK;

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

    #[test]
    fn complete_local_jwt_config_returns_none_when_bundle_absent() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvVarGuard::set("OPENSHELL_LOCAL_TLS_DIR", tmp.path());

        assert!(complete_local_jwt_config().unwrap().is_none());
    }

    #[test]
    fn complete_local_jwt_config_rejects_partial_bundle() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvVarGuard::set("OPENSHELL_LOCAL_TLS_DIR", tmp.path());
        std::fs::create_dir_all(tmp.path().join("jwt")).unwrap();
        std::fs::write(tmp.path().join("jwt/signing.pem"), "key").unwrap();

        let err = complete_local_jwt_config().unwrap_err();
        assert!(err.to_string().contains("partial local sandbox JWT state"));
    }

    #[test]
    fn complete_local_jwt_config_returns_full_bundle() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvVarGuard::set("OPENSHELL_LOCAL_TLS_DIR", tmp.path());
        std::fs::create_dir_all(tmp.path().join("jwt")).unwrap();
        for rel in ["jwt/signing.pem", "jwt/public.pem", "jwt/kid"] {
            std::fs::write(tmp.path().join(rel), "pem").unwrap();
        }

        let config = complete_local_jwt_config().unwrap().unwrap();

        assert_eq!(config.signing_key_path, tmp.path().join("jwt/signing.pem"));
        assert_eq!(config.public_key_path, tmp.path().join("jwt/public.pem"));
        assert_eq!(config.kid_path, tmp.path().join("jwt/kid"));
        assert_eq!(config.gateway_id, "openshell");
        assert_eq!(config.ttl_secs, 3_600);
    }
}
