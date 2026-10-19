// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The gateway under test, found the same way the `openshell` CLI finds it:
//!
//! 1. `OPENSHELL_GATEWAY_ENDPOINT`: a gateway URL. Plaintext, or TLS without
//!    a client certificate.
//! 2. `OPENSHELL_GATEWAY`: the name of a gateway registered with the CLI.
//! 3. The CLI's active gateway, set by `openshell gateway select`.
//!
//! A registered gateway's endpoint and auth mode come from its
//! `metadata.json`. For mTLS, the CA and client certificate come from its
//! `mtls/` directory. `OPENSHELL_WORKSPACE` selects the workspace.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use openshell_bootstrap::GatewayMetadata;
use openshell_sdk::{ClientConfig, EdgeAuthInterceptor, Health, OpenShellClient, ServiceStatus};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use crate::error::{Error, Result, ResultExt};

pub const ENDPOINT_ENV: &str = "OPENSHELL_GATEWAY_ENDPOINT";
pub const GATEWAY_ENV: &str = "OPENSHELL_GATEWAY";
pub const WORKSPACE_ENV: &str = "OPENSHELL_WORKSPACE";
const DEFAULT_WORKSPACE: &str = "default";

// Mirrors the SDK's endpoint settings for channels testkit builds itself.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const READY_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
pub struct Gateway {
    /// The registered name, or `None` for a raw endpoint.
    pub name: Option<String>,
    pub endpoint: String,
    pub workspace: String,
    /// The directory holding `ca.crt`, `tls.crt`, and `tls.key` for mTLS.
    mtls_dir: Option<PathBuf>,
}

impl Gateway {
    /// Find the gateway from the environment, as the CLI does.
    pub fn from_env() -> Result<Self> {
        let workspace = env(WORKSPACE_ENV).unwrap_or_else(|| DEFAULT_WORKSPACE.to_string());
        if let Some(endpoint) = env(ENDPOINT_ENV) {
            return Ok(Self::from_endpoint(endpoint, workspace));
        }
        let name = env(GATEWAY_ENV)
            .or_else(openshell_bootstrap::load_active_gateway)
            .ok_or_else(|| {
                Error::msg(format!(
                    "no gateway selected; set {GATEWAY_ENV} to a registered gateway, \
                     {ENDPOINT_ENV} to a gateway URL, or select one with \
                     `openshell gateway select`"
                ))
            })?;
        let metadata = openshell_bootstrap::load_gateway_metadata(&name)
            .map_err(Error::from_display)
            .context(format!("load gateway {name}"))?;
        let mtls_dir = openshell_core::paths::openshell_config_dir()
            .map_err(Error::from_display)?
            .join("gateways")
            .join(&name)
            .join("mtls");
        Self::from_metadata(name, &metadata, mtls_dir, workspace)
    }

    fn from_endpoint(endpoint: String, workspace: String) -> Self {
        Self {
            name: None,
            endpoint,
            workspace,
            mtls_dir: None,
        }
    }

    fn from_metadata(
        name: String,
        metadata: &GatewayMetadata,
        mtls_dir: PathBuf,
        workspace: String,
    ) -> Result<Self> {
        let endpoint = metadata.gateway_endpoint.clone();
        let mtls_dir = match metadata.auth_mode.as_deref() {
            None | Some("mtls") if endpoint.starts_with("https://") => Some(mtls_dir),
            None | Some("mtls" | "plaintext") => None,
            Some(mode) => {
                return Err(Error::msg(format!(
                    "gateway {name} uses {mode} auth; testkit supports plaintext and mTLS gateways"
                )));
            }
        };
        Ok(Self {
            name: Some(name),
            endpoint,
            workspace,
            mtls_dir,
        })
    }

    #[cfg(test)]
    pub(crate) fn named_for_test(name: &str) -> Self {
        Self {
            name: Some(name.to_string()),
            endpoint: "https://127.0.0.1:1".to_string(),
            workspace: DEFAULT_WORKSPACE.to_string(),
            mtls_dir: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn endpoint_for_test(endpoint: &str) -> Self {
        Self::from_endpoint(endpoint.to_string(), DEFAULT_WORKSPACE.to_string())
    }

    /// One line naming the gateway, for test logs.
    pub fn describe(&self) -> String {
        let auth = match (&self.mtls_dir, self.endpoint.starts_with("https://")) {
            (Some(dir), _) => format!("mTLS from {}", dir.display()),
            (None, true) => "TLS".to_string(),
            (None, false) => "plaintext".to_string(),
        };
        let name = self
            .name
            .as_deref()
            .map_or_else(|| format!("from {ENDPOINT_ENV}"), |name| name.to_string());
        format!(
            "gateway {name} at {} ({auth}), workspace {}",
            self.endpoint, self.workspace
        )
    }

    /// Connect to the gateway.
    pub async fn connect(&self) -> Result<OpenShellClient> {
        let Some(dir) = &self.mtls_dir else {
            return OpenShellClient::connect(ClientConfig::new(self.endpoint.clone()))
                .await
                .context(format!("connect to {}", self.endpoint));
        };

        // The SDK does not speak mTLS, so build the channel here and hand it
        // to the SDK. Every SDK call, including exec, uses this channel.
        let ca = Certificate::from_pem(read(&dir.join("ca.crt"))?);
        let identity = Identity::from_pem(read(&dir.join("tls.crt"))?, read(&dir.join("tls.key"))?);
        let channel = Endpoint::from_shared(self.endpoint.clone())
            .map_err(|error| Error::from_error(&error))?
            .connect_timeout(CONNECT_TIMEOUT)
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(KEEP_ALIVE_INTERVAL)
            .keep_alive_while_idle(true)
            .tls_config(ClientTlsConfig::new().ca_certificate(ca).identity(identity))
            .map_err(|error| Error::from_error(&error))
            .context("configure mTLS")?
            .connect()
            .await
            .map_err(|error| Error::from_error(&error))
            .context(format!("connect to {} with mTLS", self.endpoint))?;
        let interceptor = EdgeAuthInterceptor::new(None, None)?;
        Ok(OpenShellClient::from_parts(channel, interceptor))
    }

    /// Wait until the gateway accepts a connection and reports itself
    /// healthy, retrying until `timeout`.
    ///
    /// This is a readiness check for whoever brings the environment up, run
    /// once before its tests. Tests themselves connect once and fail fast.
    pub async fn wait_ready(&self, timeout: Duration) -> Result<Health> {
        let started = Instant::now();
        loop {
            let error = match self.check_health().await {
                Ok(health) => return Ok(health),
                Err(error) => error,
            };
            if started.elapsed() >= timeout {
                return Err(error.context(format!(
                    "gateway at {} not ready after {}s",
                    self.endpoint,
                    timeout.as_secs()
                )));
            }
            tokio::time::sleep(READY_INTERVAL).await;
        }
    }

    async fn check_health(&self) -> Result<Health> {
        let health = self.connect().await?.health().await.context("health")?;
        crate::ensure!(
            health.status == ServiceStatus::Healthy,
            "gateway reports {:?}",
            health.status
        );
        Ok(health)
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path)
        .map_err(Error::from_display)
        .context(format!("read {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(endpoint: &str, auth_mode: Option<&str>) -> GatewayMetadata {
        serde_json::from_value(serde_json::json!({
            "name": "gw",
            "gateway_endpoint": endpoint,
            "is_remote": false,
            "gateway_port": 0,
            "auth_mode": auth_mode,
        }))
        .unwrap()
    }

    fn from_metadata(endpoint: &str, auth_mode: Option<&str>) -> Result<Gateway> {
        Gateway::from_metadata(
            "gw".to_string(),
            &metadata(endpoint, auth_mode),
            PathBuf::from("/config/gateways/gw/mtls"),
            "default".to_string(),
        )
    }

    #[test]
    fn https_gateway_uses_mtls_by_default() {
        for mode in [None, Some("mtls")] {
            let gateway = from_metadata("https://127.0.0.1:17670", mode).unwrap();
            assert_eq!(
                gateway.mtls_dir,
                Some(PathBuf::from("/config/gateways/gw/mtls"))
            );
            assert_eq!(
                gateway.describe(),
                "gateway gw at https://127.0.0.1:17670 (mTLS from /config/gateways/gw/mtls), workspace default"
            );
        }
    }

    #[test]
    fn plaintext_gateway_has_no_mtls() {
        for (endpoint, mode) in [
            ("http://127.0.0.1:18080", Some("plaintext")),
            ("http://127.0.0.1:18080", None),
        ] {
            let gateway = from_metadata(endpoint, mode).unwrap();
            assert_eq!(gateway.mtls_dir, None);
            assert!(gateway.describe().contains("(plaintext)"));
        }
    }

    #[test]
    fn rejects_unsupported_auth_modes() {
        let err = from_metadata("https://gw.example.com", Some("cloudflare_jwt")).unwrap_err();
        assert!(
            err.to_string().contains("uses cloudflare_jwt auth"),
            "{err}"
        );
    }

    #[test]
    fn raw_endpoint_has_no_name() {
        let gateway = Gateway::from_endpoint("http://127.0.0.1:1".to_string(), "ws".to_string());
        assert_eq!(
            gateway.describe(),
            "gateway from OPENSHELL_GATEWAY_ENDPOINT at http://127.0.0.1:1 (plaintext), workspace ws"
        );
    }

    #[tokio::test]
    async fn wait_ready_reports_the_last_error_after_timeout() {
        // Nothing listens on a port bound and then released.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let gateway =
            Gateway::from_endpoint(format!("http://127.0.0.1:{port}"), "default".to_string());
        let err = gateway.wait_ready(Duration::ZERO).await.unwrap_err();
        let message = err.to_string();
        assert!(
            message.starts_with(&format!(
                "gateway at http://127.0.0.1:{port} not ready after 0s: "
            )),
            "{message}"
        );
    }
}
