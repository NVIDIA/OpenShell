// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The gateway under test, found the same way the `openshell` CLI finds it:
//!
//! 1. `OPENSHELL_GATEWAY_ENDPOINT`: a gateway URL. Its credentials come from
//!    the gateway named by `OPENSHELL_GATEWAY`, or else the registered gateway
//!    with that endpoint. A URL no gateway is registered for is used as is:
//!    plaintext, or TLS without a client certificate.
//! 2. `OPENSHELL_GATEWAY`: the name of a gateway registered with the CLI.
//! 3. The CLI's active gateway, set by `openshell gateway select`.
//!
//! A registered gateway's endpoint and auth mode come from its
//! `metadata.json`. For mTLS, the CA and client certificate come from its
//! `mtls/` directory. `OPENSHELL_WORKSPACE` selects the workspace.

use std::path::{Path, PathBuf};
use std::time::Duration;

use openshell_sdk::{ClientConfig, ClientIdentity, Health, OpenShellClient, ServiceStatus};

use crate::error::{Error, Result, ResultExt};

pub const ENDPOINT_ENV: &str = "OPENSHELL_GATEWAY_ENDPOINT";
pub const GATEWAY_ENV: &str = "OPENSHELL_GATEWAY";
pub const WORKSPACE_ENV: &str = "OPENSHELL_WORKSPACE";
const DEFAULT_WORKSPACE: &str = "default";

// Mirrors the SDK's endpoint settings for channels testkit builds itself.
const READY_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
pub struct Gateway {
    /// The registered name, or `None` for an unregistered endpoint.
    pub name: Option<String>,
    pub endpoint: String,
    pub workspace: String,
    /// The directory holding `ca.crt`, `tls.crt`, and `tls.key` for mTLS.
    mtls_dir: Option<PathBuf>,
    /// The endpoint came from [`ENDPOINT_ENV`], so the CLI must get it too.
    pub(crate) endpoint_from_env: bool,
}

impl Gateway {
    /// Find the gateway from the environment, as the CLI does.
    pub fn from_env() -> Result<Self> {
        let workspace = env(WORKSPACE_ENV).unwrap_or_else(|| DEFAULT_WORKSPACE.to_string());
        if let Some(endpoint) = env(ENDPOINT_ENV) {
            let Some(name) = env(GATEWAY_ENV).or_else(|| find_registered(&endpoint)) else {
                return Ok(Self::from_endpoint(endpoint, workspace));
            };
            // Like the CLI, a named gateway need not be registered yet.
            let auth_mode = openshell_bootstrap::get_gateway_metadata(&name)
                .and_then(|metadata| metadata.auth_mode);
            let mtls_dir = mtls_dir(&name)?;
            return Self::registered(
                name,
                endpoint,
                auth_mode.as_deref(),
                mtls_dir,
                workspace,
                true,
            );
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
        let mtls_dir = mtls_dir(&name)?;
        Self::registered(
            name,
            metadata.gateway_endpoint,
            metadata.auth_mode.as_deref(),
            mtls_dir,
            workspace,
            false,
        )
    }

    fn from_endpoint(endpoint: String, workspace: String) -> Self {
        Self {
            name: None,
            endpoint,
            workspace,
            mtls_dir: None,
            endpoint_from_env: true,
        }
    }

    fn registered(
        name: String,
        endpoint: String,
        auth_mode: Option<&str>,
        mtls_dir: PathBuf,
        workspace: String,
        endpoint_from_env: bool,
    ) -> Result<Self> {
        let mtls_dir = match auth_mode {
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
            endpoint_from_env,
        })
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
    ///
    /// The registered gateway's CA and client certificate are read from its
    /// CLI config directory and handed to the SDK, which owns the transport
    /// (TLS, connect timeout, keep-alive).
    pub async fn connect(&self) -> Result<OpenShellClient> {
        let mut config = ClientConfig::new(self.endpoint.clone());
        if let Some(dir) = &self.mtls_dir {
            config.ca_cert = Some(read(&dir.join("ca.crt"))?);
            config.client_identity = Some(ClientIdentity::new(
                read(&dir.join("tls.crt"))?,
                read(&dir.join("tls.key"))?,
            ));
        }
        OpenShellClient::connect(config)
            .await
            .context(format!("connect to {}", self.endpoint))
    }

    /// Wait until the gateway accepts a connection and reports itself
    /// healthy, retrying until `timeout`.
    ///
    /// The whole wait, including each connect and health call, is bounded by
    /// `timeout`, so a gateway that accepts connections but never answers
    /// cannot hang it.
    ///
    /// This is a readiness check for whoever brings the environment up, run
    /// once before its tests. Tests themselves connect once and fail fast.
    pub async fn wait_ready(&self, timeout: Duration) -> Result<Health> {
        let mut last_error = None;
        let outcome = tokio::time::timeout(timeout, async {
            loop {
                match self.check_health().await {
                    Ok(health) => return health,
                    Err(error) => last_error = Some(error),
                }
                tokio::time::sleep(READY_INTERVAL).await;
            }
        })
        .await;
        outcome.map_err(|_| {
            let message = format!(
                "gateway at {} not ready after {}s",
                self.endpoint,
                timeout.as_secs()
            );
            match last_error.take() {
                Some(error) => error.context(message),
                None => Error::msg(message),
            }
        })
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

fn mtls_dir(name: &str) -> Result<PathBuf> {
    Ok(openshell_core::paths::openshell_config_dir()
        .map_err(Error::from_display)?
        .join("gateways")
        .join(name)
        .join("mtls"))
}

/// The registered gateway with `endpoint`, preferring the active one, as the
/// CLI does.
fn find_registered(endpoint: &str) -> Option<String> {
    let active = openshell_bootstrap::load_active_gateway()
        .and_then(|name| openshell_bootstrap::get_gateway_metadata(&name));
    let all = openshell_bootstrap::list_gateways().unwrap_or_default();
    let endpoint = endpoint.trim_end_matches('/');
    active
        .into_iter()
        .chain(all)
        .find(|metadata| metadata.gateway_endpoint.trim_end_matches('/') == endpoint)
        .map(|metadata| metadata.name)
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
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    use super::Gateway;

    /// A peer that accepts connections and never answers must not hang the
    /// readiness wait: the timeout covers the connect and health calls too.
    #[tokio::test]
    async fn wait_ready_gives_up_on_a_gateway_that_never_answers() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        std::thread::spawn(move || {
            // Hold every connection open without reading or replying.
            let held: Vec<_> = listener.incoming().flatten().collect();
            drop(held);
        });

        let gateway = Gateway::from_endpoint(endpoint, "default".to_string());
        let started = Instant::now();
        let error = gateway
            .wait_ready(Duration::from_secs(1))
            .await
            .expect_err("an unresponsive gateway is not ready");

        assert!(started.elapsed() < Duration::from_secs(5), "{error}");
        assert!(error.to_string().contains("not ready after 1s"), "{error}");
    }
}
