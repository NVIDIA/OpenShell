// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The target: how tests reach the system under test.
//!
//! An environment writes a target file; tests find it through
//! [`TARGET_ENV`]. Relative paths in the file resolve against its directory.
//!
//! ```yaml
//! gateway:
//!   endpoint: https://127.0.0.1:17670
//!   tls:
//!     ca: ca.crt
//!     client_cert: client.crt
//!     client_key: client.key
//! cli:
//!   binary: /usr/bin/openshell   # default: `openshell` on PATH
//!   gateway: tmachine            # the name the gateway is registered under
//! workspace: default
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use openshell_sdk::{
    AuthConfig, ClientConfig, EdgeAuthInterceptor, Health, OpenShellClient, ServiceStatus,
};
use serde::Deserialize;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use crate::cli::Cli;
use crate::error::{Error, Result, ResultExt};

/// Environment variable naming the target file.
pub const TARGET_ENV: &str = "OPENSHELL_TEST_TARGET";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub gateway: Gateway,
    /// The CLI the environment installed. Every environment provides one;
    /// it is optional here only so SDK-only suites can run against a
    /// hand-written target.
    #[serde(default)]
    pub cli: Option<CliTarget>,
    #[serde(default = "default_workspace")]
    pub workspace: String,
    #[serde(skip)]
    base_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    /// Gateway URL; the scheme selects plaintext (`http`) or TLS (`https`).
    pub endpoint: String,
    #[serde(default)]
    pub tls: Option<Tls>,
    #[serde(default)]
    pub auth: Option<Auth>,
}

/// TLS material. A client certificate and key together select mTLS.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub ca: Option<PathBuf>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
}

/// The installed `openshell` CLI, configured for the target's gateway.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliTarget {
    /// A path, resolved like other target paths, or a name found on PATH.
    #[serde(default = "default_cli_binary")]
    pub binary: PathBuf,
    /// The gateway name to select. Omit to use the CLI's active gateway.
    #[serde(default)]
    pub gateway: Option<String>,
}

fn default_cli_binary() -> PathBuf {
    PathBuf::from("openshell")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub bearer_token_file: PathBuf,
}

fn default_workspace() -> String {
    "default".to_string()
}

// Mirrors the SDK's endpoint settings for channels testkit builds itself.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const READY_INTERVAL: Duration = Duration::from_secs(1);

impl Target {
    /// Load the target named by [`TARGET_ENV`].
    pub fn from_env() -> Result<Self> {
        let path = std::env::var_os(TARGET_ENV).ok_or_else(|| {
            Error::msg(format!(
                "{TARGET_ENV} is not set; it must name the target file for the system under test"
            ))
        })?;
        Self::from_path(Path::new(&path))
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let yaml = std::fs::read_to_string(path)
            .map_err(Error::from_display)
            .context(format!("read target file {}", path.display()))?;
        let base_dir = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Self::parse(&yaml, base_dir).context(format!("load target file {}", path.display()))
    }

    /// Parse a target, resolving relative paths against `base_dir`.
    pub fn parse(yaml: &str, base_dir: PathBuf) -> Result<Self> {
        let mut target: Self = serde_yml::from_str(yaml).map_err(Error::from_display)?;
        target.base_dir = base_dir;
        target.validate()?;
        Ok(target)
    }

    fn validate(&self) -> Result {
        let gateway = &self.gateway;
        let Some(tls) = &gateway.tls else {
            return Ok(());
        };
        if tls.client_cert.is_some() != tls.client_key.is_some() {
            return Err(Error::msg(
                "gateway.tls.client_cert and gateway.tls.client_key must be set together",
            ));
        }
        if !gateway.endpoint.starts_with("https://") {
            return Err(Error::msg(format!(
                "gateway.tls is set but gateway.endpoint {:?} is not https",
                gateway.endpoint
            )));
        }
        Ok(())
    }

    fn resolve(&self, path: &Path) -> PathBuf {
        self.base_dir.join(path)
    }

    /// The target's CLI. Fails if the target file has no `cli` section.
    pub fn cli(&self) -> Result<Cli> {
        let cli = self.cli.as_ref().ok_or_else(|| {
            Error::msg("the target file has no `cli` section; the environment must provide its CLI")
        })?;
        // A bare name is looked up on PATH; anything with a separator is a
        // path relative to the target file.
        let binary = if cli.binary.components().count() > 1 {
            self.resolve(&cli.binary)
        } else {
            cli.binary.clone()
        };
        Ok(Cli::new(cli, binary))
    }

    /// Check that the target's CLI reaches the gateway: `openshell status`
    /// must report it connected.
    pub async fn check_cli(&self) -> Result {
        let output = self
            .cli()?
            .run(["status", "--output", "json"])
            .await?
            .success()?;
        let status: serde_json::Value = output.json()?;
        crate::ensure!(
            status["status"] == "connected",
            "`{}` reports {}",
            output.command,
            status
        );
        Ok(())
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>> {
        let path = self.resolve(path);
        std::fs::read(&path)
            .map_err(Error::from_display)
            .context(format!("read {}", path.display()))
    }

    /// Connect to the target's gateway.
    pub async fn connect(&self) -> Result<OpenShellClient> {
        let gateway = &self.gateway;
        let tls = gateway.tls.as_ref();
        let ca = tls
            .and_then(|tls| tls.ca.as_deref())
            .map(|path| self.read(path))
            .transpose()?;
        let token = gateway
            .auth
            .as_ref()
            .map(|auth| {
                self.read(&auth.bearer_token_file)
                    .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_string())
            })
            .transpose()?;

        let identity = match tls.map(|tls| (&tls.client_cert, &tls.client_key)) {
            Some((Some(cert), Some(key))) => {
                Some(Identity::from_pem(self.read(cert)?, self.read(key)?))
            }
            _ => None,
        };

        let Some(identity) = identity else {
            let mut config = ClientConfig::new(gateway.endpoint.clone());
            config.ca_cert = ca;
            config.auth = token.map(AuthConfig::oidc);
            return OpenShellClient::connect(config)
                .await
                .context(format!("connect to {}", gateway.endpoint));
        };

        // The SDK does not speak mTLS, so build the channel here and hand it
        // to the SDK. Every SDK call, including exec, uses this channel.
        let tls_config = ca.map_or_else(
            || ClientTlsConfig::new().with_enabled_roots(),
            |ca| ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca)),
        );
        let channel = Endpoint::from_shared(gateway.endpoint.clone())
            .map_err(|error| Error::from_error(&error))?
            .connect_timeout(CONNECT_TIMEOUT)
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(KEEP_ALIVE_INTERVAL)
            .keep_alive_while_idle(true)
            .tls_config(tls_config.identity(identity))
            .map_err(|error| Error::from_error(&error))
            .context("configure mTLS")?
            .connect()
            .await
            .map_err(|error| Error::from_error(&error))
            .context(format!("connect to {} with mTLS", gateway.endpoint))?;
        let interceptor = EdgeAuthInterceptor::new(token.as_deref(), None)?;
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
                    self.gateway.endpoint,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<Target> {
        Target::parse(yaml, PathBuf::from("/targets/vm"))
    }

    #[test]
    fn parses_mtls_target_and_resolves_relative_paths() {
        let target = parse(
            "gateway:\n  endpoint: https://127.0.0.1:17670\n  tls:\n    ca: ca.crt\n    client_cert: client.crt\n    client_key: /abs/client.key\n",
        )
        .unwrap();
        let tls = target.gateway.tls.as_ref().unwrap();
        assert_eq!(target.workspace, "default");
        assert_eq!(
            target.resolve(tls.ca.as_deref().unwrap()),
            PathBuf::from("/targets/vm/ca.crt")
        );
        assert_eq!(
            target.resolve(tls.client_key.as_deref().unwrap()),
            PathBuf::from("/abs/client.key")
        );
    }

    #[test]
    fn parses_plaintext_target() {
        let target = parse("gateway:\n  endpoint: http://127.0.0.1:17670\n").unwrap();
        assert!(target.gateway.tls.is_none());
    }

    #[test]
    fn parses_cli_section() {
        let target = parse(
            "gateway:\n  endpoint: http://x\ncli:\n  binary: bin/openshell\n  gateway: tmachine\n",
        )
        .unwrap();
        let cli = target.cli.as_ref().unwrap();
        assert_eq!(cli.gateway.as_deref(), Some("tmachine"));
        assert!(target.cli().is_ok());

        let target = parse("gateway:\n  endpoint: http://x\ncli: {}\n").unwrap();
        assert_eq!(
            target.cli.as_ref().unwrap().binary,
            PathBuf::from("openshell")
        );

        let err = parse("gateway:\n  endpoint: http://x\n")
            .unwrap()
            .cli()
            .unwrap_err();
        assert!(err.to_string().contains("no `cli` section"), "{err}");
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = parse("gateway:\n  endpoint: http://x\n  endpiont: http://y\n").unwrap_err();
        assert!(err.to_string().contains("endpiont"), "{err}");
    }

    #[test]
    fn rejects_half_configured_client_identity() {
        let err = parse("gateway:\n  endpoint: https://x\n  tls:\n    client_cert: client.crt\n")
            .unwrap_err();
        assert!(err.to_string().contains("set together"), "{err}");
    }

    #[test]
    fn rejects_tls_on_plaintext_endpoint() {
        let err = parse("gateway:\n  endpoint: http://x\n  tls:\n    ca: ca.crt\n").unwrap_err();
        assert!(err.to_string().contains("not https"), "{err}");
    }

    #[tokio::test]
    async fn wait_ready_reports_the_last_error_after_timeout() {
        // Nothing listens on a port bound and then released.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let target = parse(&format!("gateway:\n  endpoint: http://127.0.0.1:{port}\n")).unwrap();
        let err = target.wait_ready(Duration::ZERO).await.unwrap_err();
        let message = err.to_string();
        assert!(
            message.starts_with(&format!(
                "gateway at http://127.0.0.1:{port} not ready after 0s: "
            )),
            "{message}"
        );
    }
}
