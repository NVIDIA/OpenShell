// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Selected compute-driver config construction.
//!
//! This module owns loading the selected driver config from TOML and applying
//! gateway startup defaults and endpoint overrides. It does not acquire,
//! connect to, or start compute drivers.

use crate::config_file;
use crate::defaults::LocalTlsPaths;
use openshell_core::{Error, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestTlsPaths {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

impl GuestTlsPaths {
    pub(crate) fn as_paths(&self) -> (&std::path::Path, &std::path::Path, &std::path::Path) {
        (&self.ca, &self.cert, &self.key)
    }
}

impl GuestTlsPaths {
    fn configured_paths(
        gateway: &config_file::GatewayFileSection,
    ) -> (Option<&PathBuf>, Option<&PathBuf>, Option<&PathBuf>) {
        (
            gateway.guest_tls_ca.as_ref(),
            gateway.guest_tls_cert.as_ref(),
            gateway.guest_tls_key.as_ref(),
        )
    }

    /// Validate guest TLS relationships without reading certificate files.
    pub(crate) fn validate_configuration(
        gateway: Option<&config_file::GatewayFileSection>,
        tls_disabled: bool,
    ) -> std::result::Result<(), String> {
        let configured = gateway.map(Self::configured_paths);
        let provided = configured
            .is_some_and(|(ca, cert, key)| ca.is_some() || cert.is_some() || key.is_some());
        if tls_disabled && provided {
            return Err(
                "guest_tls_ca, guest_tls_cert, and guest_tls_key require gateway TLS; remove them or omit --disable-tls"
                    .to_string(),
            );
        }
        if let Some((ca, cert, key)) = configured
            && (ca.is_some() || cert.is_some() || key.is_some())
            && (ca.is_none() || cert.is_none() || key.is_none())
        {
            return Err(
                "guest TLS requires one complete bundle: guest_tls_ca, guest_tls_cert, and guest_tls_key"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Resolve gateway-owned guest TLS inputs. Explicit TOML values take
    /// precedence over the package-managed local bundle; partial bundles are
    /// rejected before any driver is deserialized or constructed.
    pub(crate) fn resolve(
        gateway: Option<&config_file::GatewayFileSection>,
        local: Option<&LocalTlsPaths>,
        tls_disabled: bool,
    ) -> std::result::Result<Option<Self>, String> {
        Self::validate_configuration(gateway, tls_disabled)?;
        if tls_disabled {
            return Ok(None);
        }

        if let Some((Some(ca), Some(cert), Some(key))) = gateway.map(Self::configured_paths) {
            for (field, path) in [
                ("guest_tls_ca", ca),
                ("guest_tls_cert", cert),
                ("guest_tls_key", key),
            ] {
                if !path.is_file() {
                    return Err(format!(
                        "{field} '{}' does not exist or is not a file",
                        path.display()
                    ));
                }
            }
            return Ok(Some(Self {
                ca: ca.clone(),
                cert: cert.clone(),
                key: key.clone(),
            }));
        }

        Ok(local.map(|paths| Self {
            ca: paths.ca.clone(),
            cert: paths.client_cert.clone(),
            key: paths.client_key.clone(),
        }))
    }
}

#[derive(Clone, Copy)]
pub struct DriverStartupContext<'a> {
    pub file: Option<&'a config_file::ConfigFile>,
    pub guest_tls: Option<&'a GuestTlsPaths>,
    pub gateway_port: u16,
    pub gateway_tls_enabled: bool,
    pub endpoint_overrides: &'a BTreeMap<String, PathBuf>,
}

pub fn remote_driver_config_from_context(
    context: DriverStartupContext<'_>,
    name: &str,
) -> Result<RemoteDriverConfig> {
    let mut cfg = RemoteDriverConfig::default();
    if let Some(file) = context.file {
        let merged = config_file::driver_table(
            name,
            &file.openshell.gateway,
            file.openshell.drivers.get(name),
        );
        reject_driver_owned_guest_tls_fields(&merged)?;
        if let Some(socket_path) = merged.get("socket_path").and_then(toml::Value::as_str) {
            cfg.socket_path = PathBuf::from(socket_path);
        }
    }
    apply_remote_driver_overrides(&mut cfg, context, name);
    validate_remote_driver_config(&cfg, name)?;
    Ok(cfg)
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct RemoteDriverConfig {
    #[serde(default)]
    pub socket_path: PathBuf,
}

pub fn driver_config_from_context<T>(
    context: DriverStartupContext<'_>,
    driver_name: &str,
    inherited_config_keys: &[&str],
) -> Result<T>
where
    T: Default + serde::de::DeserializeOwned,
{
    driver_config_from_file(context.file, driver_name, inherited_config_keys)
}

fn driver_config_from_file<T>(
    file: Option<&config_file::ConfigFile>,
    driver_name: &str,
    inherited_config_keys: &[&str],
) -> Result<T>
where
    T: Default + serde::de::DeserializeOwned,
{
    let Some(file) = file else {
        return Ok(T::default());
    };
    let merged = config_file::driver_table_with_inherited_keys(
        driver_name,
        &file.openshell.gateway,
        file.openshell.drivers.get(driver_name),
        inherited_config_keys,
    );
    reject_driver_owned_guest_tls_fields(&merged)?;
    merged.try_into().map_err(|e| {
        Error::config(format!(
            "invalid [openshell.drivers.{driver_name}] table: {e}"
        ))
    })
}

/// Reject TLS paths in gateway driver tables. These credentials are gateway
/// inputs and are injected only into the selected local driver after the
/// gateway has validated the complete bundle.
fn reject_driver_owned_guest_tls_fields(table: &toml::Value) -> Result<()> {
    let Some(table) = table.as_table() else {
        return Ok(());
    };
    for field in ["guest_tls_ca", "guest_tls_cert", "guest_tls_key"] {
        if table.contains_key(field) {
            return Err(Error::config(format!(
                "{field} belongs in [openshell.gateway], not a [openshell.drivers.*] table"
            )));
        }
    }
    Ok(())
}

fn apply_remote_driver_overrides(
    cfg: &mut RemoteDriverConfig,
    context: DriverStartupContext<'_>,
    name: &str,
) {
    if let Some(socket_path) = context.endpoint_overrides.get(name) {
        cfg.socket_path.clone_from(socket_path);
    }
}

fn validate_remote_driver_config(cfg: &RemoteDriverConfig, name: &str) -> Result<()> {
    if !cfg.socket_path.as_os_str().is_empty() {
        return Ok(());
    }
    Err(Error::config(format!(
        "remote compute driver '{name}' requires socket_path"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::Path;

    fn test_context(file: Option<&config_file::ConfigFile>) -> DriverStartupContext<'_> {
        static EMPTY_ENDPOINT_OVERRIDES: std::sync::LazyLock<BTreeMap<String, PathBuf>> =
            std::sync::LazyLock::new(BTreeMap::new);
        test_context_with_endpoint_overrides(file, &EMPTY_ENDPOINT_OVERRIDES)
    }

    fn test_context_with_endpoint_overrides<'a>(
        file: Option<&'a config_file::ConfigFile>,
        endpoint_overrides: &'a BTreeMap<String, PathBuf>,
    ) -> DriverStartupContext<'a> {
        DriverStartupContext {
            file,
            guest_tls: None,
            gateway_port: openshell_core::config::DEFAULT_SERVER_PORT,
            gateway_tls_enabled: false,
            endpoint_overrides,
        }
    }

    #[test]
    fn gateway_guest_tls_resolves_explicit_complete_bundle() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ca = dir.path().join("ca.pem");
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        for path in [&ca, &cert, &key] {
            std::fs::write(path, b"test").expect("write TLS fixture");
        }
        let gateway = config_file::GatewayFileSection {
            guest_tls_ca: Some(ca.clone()),
            guest_tls_cert: Some(cert.clone()),
            guest_tls_key: Some(key.clone()),
            ..Default::default()
        };

        let resolved = GuestTlsPaths::resolve(Some(&gateway), None, false)
            .expect("complete guest TLS should resolve")
            .expect("guest TLS bundle");

        assert_eq!(
            resolved.as_paths(),
            (ca.as_path(), cert.as_path(), key.as_path())
        );
    }

    #[test]
    fn gateway_guest_tls_rejects_every_partial_bundle() {
        let path = PathBuf::from("/tmp/guest-tls.pem");
        for (ca, cert, key) in [
            (Some(path.clone()), None, None),
            (None, Some(path.clone()), None),
            (None, None, Some(path.clone())),
            (Some(path.clone()), Some(path.clone()), None),
            (Some(path.clone()), None, Some(path.clone())),
            (None, Some(path.clone()), Some(path)),
        ] {
            let gateway = config_file::GatewayFileSection {
                guest_tls_ca: ca,
                guest_tls_cert: cert,
                guest_tls_key: key,
                ..Default::default()
            };
            let error = GuestTlsPaths::resolve(Some(&gateway), None, false)
                .expect_err("partial guest TLS must fail");
            assert!(error.contains("one complete bundle"));
        }
    }

    #[test]
    fn gateway_guest_tls_rejects_missing_explicit_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let gateway = config_file::GatewayFileSection {
            guest_tls_ca: Some(dir.path().join("missing-ca.pem")),
            guest_tls_cert: Some(dir.path().join("missing-cert.pem")),
            guest_tls_key: Some(dir.path().join("missing-key.pem")),
            ..Default::default()
        };
        let error = GuestTlsPaths::resolve(Some(&gateway), None, false)
            .expect_err("missing explicit file must fail");
        assert!(error.contains("guest_tls_ca"));
        assert!(error.contains("does not exist"));
    }

    #[test]
    fn gateway_guest_tls_uses_package_managed_bundle() {
        let local = LocalTlsPaths {
            ca: PathBuf::from("/managed/ca.pem"),
            server_cert: PathBuf::from("/managed/server-cert.pem"),
            server_key: PathBuf::from("/managed/server-key.pem"),
            client_cert: PathBuf::from("/managed/client-cert.pem"),
            client_key: PathBuf::from("/managed/client-key.pem"),
        };
        let resolved = GuestTlsPaths::resolve(None, Some(&local), false)
            .expect("managed bundle should resolve")
            .expect("guest TLS bundle");
        assert_eq!(
            resolved.as_paths(),
            (
                Path::new("/managed/ca.pem"),
                Path::new("/managed/client-cert.pem"),
                Path::new("/managed/client-key.pem"),
            )
        );
    }

    #[test]
    fn gateway_guest_tls_can_be_absent() {
        assert!(GuestTlsPaths::resolve(None, None, false).unwrap().is_none());
        assert!(GuestTlsPaths::resolve(None, None, true).unwrap().is_none());
    }

    #[test]
    fn gateway_guest_tls_rejects_plaintext_gateway() {
        let gateway = config_file::GatewayFileSection {
            guest_tls_ca: Some(PathBuf::from("/tmp/ca.pem")),
            guest_tls_cert: Some(PathBuf::from("/tmp/cert.pem")),
            guest_tls_key: Some(PathBuf::from("/tmp/key.pem")),
            ..Default::default()
        };
        let error = GuestTlsPaths::resolve(Some(&gateway), None, true)
            .expect_err("guest TLS and plaintext gateway conflict");
        assert!(error.contains("require gateway TLS"));
    }

    #[derive(Debug, Default, Deserialize)]
    struct EmptyDriverConfig {}

    #[test]
    fn driver_owned_guest_tls_fields_are_rejected_for_local_and_remote_drivers() {
        for field in ["guest_tls_ca", "guest_tls_cert", "guest_tls_key"] {
            let source = format!(
                r#"
[openshell]
version = 2

[openshell.drivers.kyma]
socket_path = "/run/openshell/kyma.sock"
{field} = "/run/openshell/guest.pem"
"#
            );
            let file: config_file::ConfigFile = toml::from_str(&source).expect("valid TOML");

            let local_error =
                driver_config_from_context::<EmptyDriverConfig>(test_context(Some(&file)), "kyma")
                    .expect_err("local driver TLS field must be rejected");
            assert!(local_error.to_string().contains(field));
            assert!(local_error.to_string().contains("[openshell.gateway]"));

            let remote_error = remote_driver_config_from_context(test_context(Some(&file)), "kyma")
                .expect_err("remote driver TLS field must be rejected");
            assert!(remote_error.to_string().contains(field));
            assert!(remote_error.to_string().contains("[openshell.gateway]"));
        }
    }

    #[test]
    fn explicit_gateway_guest_tls_takes_precedence_over_package_bundle() {
        let dir = tempfile::tempdir().expect("temp dir");
        let explicit = [
            dir.path().join("explicit-ca.pem"),
            dir.path().join("explicit-cert.pem"),
            dir.path().join("explicit-key.pem"),
        ];
        for path in &explicit {
            std::fs::write(path, b"explicit").expect("write explicit TLS fixture");
        }
        let gateway = config_file::GatewayFileSection {
            guest_tls_ca: Some(explicit[0].clone()),
            guest_tls_cert: Some(explicit[1].clone()),
            guest_tls_key: Some(explicit[2].clone()),
            ..Default::default()
        };
        let package = LocalTlsPaths {
            ca: PathBuf::from("/managed/ca.pem"),
            server_cert: PathBuf::from("/managed/server-cert.pem"),
            server_key: PathBuf::from("/managed/server-key.pem"),
            client_cert: PathBuf::from("/managed/client-cert.pem"),
            client_key: PathBuf::from("/managed/client-key.pem"),
        };

        let resolved = GuestTlsPaths::resolve(Some(&gateway), Some(&package), false)
            .expect("explicit bundle resolves")
            .expect("guest bundle");
        assert_eq!(
            resolved.as_paths(),
            (
                explicit[0].as_path(),
                explicit[1].as_path(),
                explicit[2].as_path()
            )
        );
    }

    #[test]
    fn gateway_guest_tls_rejects_directories_for_every_bundle_member() {
        let dir = tempfile::tempdir().expect("temp dir");
        let files = [
            dir.path().join("ca.pem"),
            dir.path().join("cert.pem"),
            dir.path().join("key.pem"),
        ];
        for path in &files {
            std::fs::write(path, b"fixture").expect("write TLS fixture");
        }

        for index in 0..files.len() {
            let mut paths = files.clone();
            paths[index] = dir.path().to_path_buf();
            let gateway = config_file::GatewayFileSection {
                guest_tls_ca: Some(paths[0].clone()),
                guest_tls_cert: Some(paths[1].clone()),
                guest_tls_key: Some(paths[2].clone()),
                ..Default::default()
            };
            let error = GuestTlsPaths::resolve(Some(&gateway), None, false)
                .expect_err("directory TLS input must be rejected");
            assert!(error.contains("not a file"), "{error}");
        }
    }

    #[test]
    fn remote_driver_config_reads_socket_path_from_named_table() {
        let file: config_file::ConfigFile = toml::from_str(
            r#"
[openshell.drivers.kyma]
socket_path = "/run/openshell/kyma.sock"
"#,
        )
        .expect("valid config");

        let cfg = remote_driver_config_from_context(test_context(Some(&file)), "kyma")
            .expect("remote config");

        assert_eq!(cfg.socket_path, PathBuf::from("/run/openshell/kyma.sock"));
    }

    #[test]
    fn remote_driver_config_reads_only_socket_path() {
        let file: config_file::ConfigFile = toml::from_str(
            r#"
[openshell]
version = 2

[openshell.drivers.kubernetes]
socket_path = "/run/openshell/kubernetes.sock"
workspace_mode = "shared"
service_account_name = "sandbox-sa"
"#,
        )
        .expect("valid config");

        let cfg = remote_driver_config_from_context(test_context(Some(&file)), "kubernetes")
            .expect("remote config");
        assert_eq!(
            cfg.socket_path,
            PathBuf::from("/run/openshell/kubernetes.sock")
        );
    }

    #[test]
    fn remote_driver_config_uses_endpoint_override_without_file() {
        let endpoint_overrides =
            BTreeMap::from([("kyma".to_string(), PathBuf::from("/tmp/kyma.sock"))]);

        let cfg = remote_driver_config_from_context(
            test_context_with_endpoint_overrides(None, &endpoint_overrides),
            "kyma",
        )
        .expect("remote config");

        assert_eq!(cfg.socket_path, PathBuf::from("/tmp/kyma.sock"));
    }

    #[test]
    fn remote_driver_config_endpoint_override_wins_over_file() {
        let file: config_file::ConfigFile = toml::from_str(
            r#"
[openshell.drivers.kyma]
socket_path = "/run/openshell/kyma.sock"
"#,
        )
        .expect("valid config");
        let endpoint_overrides =
            BTreeMap::from([("kyma".to_string(), PathBuf::from("/tmp/kyma.sock"))]);

        let cfg = remote_driver_config_from_context(
            test_context_with_endpoint_overrides(Some(&file), &endpoint_overrides),
            "kyma",
        )
        .expect("remote config");

        assert_eq!(cfg.socket_path, PathBuf::from("/tmp/kyma.sock"));
    }

    #[test]
    fn remote_driver_config_rejects_missing_socket_path() {
        let err = remote_driver_config_from_context(test_context(None), "kyma").unwrap_err();

        assert!(
            err.to_string()
                .contains("remote compute driver 'kyma' requires socket_path")
        );
    }
}
