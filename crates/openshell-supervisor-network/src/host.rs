// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side proxy startup for compute drivers that do not run the Linux
//! in-sandbox supervisor.
//!
//! MXC uses this on Windows: MXC's `network.proxy` redirects sandbox egress to a
//! per-sandbox loopback listener in the gateway process, and this module starts
//! the existing OpenShell CONNECT proxy against the trimmed network-only
//! `SandboxPolicy`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use miette::Result;
use openshell_core::activity::ActivitySender;
use openshell_core::denial::DenialEvent;
use openshell_core::policy::ProxyPolicy;
use openshell_core::proposals::AgentProposals;
use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;
use openshell_core::provider_credentials::ProviderCredentialState;
use tokio::sync::mpsc::UnboundedSender;

use crate::opa::OpaEngine;
use crate::policy_local::PolicyLocalContext;
use crate::proxy::{ProxyHandle, ProxyIdentityMode};

/// Configuration for a host-side OpenShell CONNECT proxy.
pub struct HostProxyConfig {
    /// Exact socket the compute driver will redirect sandbox egress to.
    pub bind_addr: SocketAddr,
    /// Network-only policy produced by the compute driver's policy split.
    pub policy: ProtoSandboxPolicy,
    /// Static process identity used when the platform cannot recover the
    /// socket-owning sandbox process. Policy binaries must match this path for
    /// L4/L7 allow rules to pass.
    pub binary_path: PathBuf,
    pub sandbox_id: Option<String>,
    pub sandbox_name: Option<String>,
    pub openshell_endpoint: Option<String>,
    pub inference_routes: Option<String>,
    pub provider_credentials: Option<ProviderCredentialState>,
    /// Shared feature state for the policy.local agent proposal surface.
    pub agent_proposals: AgentProposals,
    pub denial_tx: Option<UnboundedSender<DenialEvent>>,
    pub activity_tx: Option<ActivitySender>,
}

/// RAII handle for a host-side proxy. Dropping it aborts the proxy accept loop.
pub struct HostProxyHandle {
    proxy: ProxyHandle,
    pub policy_local_ctx: Arc<PolicyLocalContext>,
}

impl HostProxyHandle {
    #[must_use]
    pub const fn http_addr(&self) -> Option<SocketAddr> {
        self.proxy.http_addr()
    }
}

/// Start a host-side proxy for one sandbox.
///
/// Linux supervisor mode should continue to use `run::run_networking`; this API
/// is for host-side compute-driver integrations such as Windows MXC.
pub async fn start_host_proxy(config: HostProxyConfig) -> Result<HostProxyHandle> {
    if !config.bind_addr.ip().is_loopback() {
        return Err(miette::miette!(
            "host proxy bind address must be loopback-only: {}",
            config.bind_addr
        ));
    }

    let engine = Arc::new(OpaEngine::from_proto(&config.policy)?);
    let (_workspace_tx, workspace_rx) = tokio::sync::watch::channel(String::new());
    let policy_local_ctx = Arc::new(PolicyLocalContext::new(
        Some(config.policy.clone()),
        config.openshell_endpoint.clone(),
        config
            .sandbox_name
            .clone()
            .or_else(|| config.sandbox_id.clone()),
        config.agent_proposals,
        workspace_rx,
    ));
    let inference_ctx = crate::inference_routes::build_inference_context(
        config.sandbox_id.as_deref(),
        config.openshell_endpoint.as_deref(),
        config.inference_routes.as_deref(),
    )
    .await?;

    let (_ready_tx, ready_rx) = tokio::sync::watch::channel(true);
    let proxy_policy = ProxyPolicy {
        http_addr: Some(config.bind_addr),
    };
    let upstream_proxy_args = crate::upstream_proxy::UpstreamProxyArgs::default();
    let proxy = ProxyHandle::start_with_bind_addr(
        &proxy_policy,
        Some(config.bind_addr),
        engine,
        Arc::new(ProxyIdentityMode::static_binary(config.binary_path)?),
        // Host mode does not install a CA into the sandbox yet; L4 policy and
        // plaintext/forward-proxy L7 paths are active, while HTTPS MITM is a
        // follow-up once MXC has a trust-bootstrap story.
        None,
        inference_ctx,
        config.provider_credentials,
        Some(policy_local_ctx.clone()),
        config.denial_tx,
        config.activity_tx,
        ready_rx,
        &upstream_proxy_args,
    )
    .await?;

    Ok(HostProxyHandle {
        proxy,
        policy_local_ctx,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use openshell_core::proposals::AgentProposals;
    use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;

    fn test_config(bind_addr: SocketAddr, binary_path: PathBuf) -> HostProxyConfig {
        HostProxyConfig {
            bind_addr,
            policy: ProtoSandboxPolicy {
                version: 1,
                ..Default::default()
            },
            binary_path,
            sandbox_id: Some("sandbox-123".to_string()),
            sandbox_name: Some("agent-box".to_string()),
            openshell_endpoint: None,
            inference_routes: None,
            provider_credentials: None,
            agent_proposals: AgentProposals::new(true),
            denial_tx: None,
            activity_tx: None,
        }
    }

    #[tokio::test]
    async fn rejects_non_loopback_bind_addr() {
        let result = start_host_proxy(test_config(
            ([192, 0, 2, 1], 0).into(),
            PathBuf::from("missing-agent.exe"),
        ))
        .await;

        let Err(err) = result else {
            panic!("host proxy should reject non-loopback bind addresses");
        };
        assert!(
            err.to_string().contains("loopback-only"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn starts_loopback_proxy_and_serves_policy_local() {
        let binary = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(binary.path(), b"agent").unwrap();

        let handle = start_host_proxy(test_config(
            ([127, 0, 0, 1], 0).into(),
            binary.path().to_path_buf(),
        ))
        .await
        .unwrap();

        let addr = handle.http_addr().expect("proxy should report bound addr");
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0);

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                b"GET http://policy.local/v1/policy/current HTTP/1.1\r\n\
                  Host: policy.local\r\n\
                  Connection: close\r\n\
                  \r\n",
            )
            .await
            .unwrap();

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();

        let response = String::from_utf8(response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "unexpected response: {response}"
        );
        let (_, body) = response.split_once("\r\n\r\n").expect("response body");
        let body: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(body["format"], "yaml");
        assert!(
            body["policy_yaml"]
                .as_str()
                .unwrap_or_default()
                .contains("version: 1"),
            "unexpected policy payload: {body}"
        );
    }
}
