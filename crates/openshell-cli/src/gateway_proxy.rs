// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Local browser proxy for remote gateway service domains.

use std::sync::Arc;

use miette::{IntoDiagnostic, Result};
use openshell_bootstrap::GatewayMetadata;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::tls::{TlsOptions, build_rustls_config, require_tls_materials};

trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub async fn run(metadata: GatewayMetadata, tls: TlsOptions) -> Result<()> {
    let upstream = Upstream::from_endpoint(&metadata.gateway_endpoint)?;
    if !metadata.is_remote && upstream.is_local_endpoint() {
        return Err(miette::miette!(
            "gateway proxy requires a remote gateway; '{}' points at local endpoint {}",
            metadata.name,
            metadata.gateway_endpoint
        ));
    }

    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .into_diagnostic()?;
    let local_addr = listener.local_addr().into_diagnostic()?;
    let example = local_service_url_pattern(&metadata.name, local_addr.port());

    eprintln!("✓ Gateway proxy listening");
    eprintln!("  Gateway: {}", metadata.name);
    eprintln!("  Upstream: {}", metadata.gateway_endpoint);
    eprintln!("  Local: http://127.0.0.1:{}", local_addr.port());
    eprintln!("  Services: {example}");
    eprintln!();
    eprintln!("Press Ctrl-C to stop.");

    let tls = Arc::new(tls);
    let upstream = Arc::new(upstream);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (client, peer) = accepted.into_diagnostic()?;
                let upstream = Arc::clone(&upstream);
                let tls = Arc::clone(&tls);
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(client, upstream, tls).await {
                        warn!(peer = %peer, error = %err, "gateway proxy connection failed");
                    }
                });
            }
            signal = tokio::signal::ctrl_c() => {
                signal.into_diagnostic()?;
                break;
            }
        }
    }

    Ok(())
}

fn local_service_url_pattern(gateway_name: &str, port: u16) -> String {
    format!("http://<sandbox>--<service>.{gateway_name}.openshell.localhost:{port}/")
}

async fn handle_connection(
    mut client: TcpStream,
    upstream: Arc<Upstream>,
    tls: Arc<TlsOptions>,
) -> Result<()> {
    client.set_nodelay(true).into_diagnostic()?;
    let mut upstream = connect_upstream(&upstream, &tls).await?;
    debug!("gateway proxy connected upstream");
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

async fn connect_upstream(upstream: &Upstream, tls: &TlsOptions) -> Result<Box<dyn ProxyStream>> {
    if tls.is_bearer_auth() {
        let token = tls
            .edge_token
            .as_deref()
            .ok_or_else(|| miette::miette!("edge token required for gateway proxy"))?;
        let proxy = crate::edge_tunnel::start_tunnel_proxy(&upstream.endpoint, token).await?;
        let stream = TcpStream::connect(proxy.local_addr)
            .await
            .into_diagnostic()?;
        stream.set_nodelay(true).into_diagnostic()?;
        return Ok(Box::new(stream));
    }

    let stream = TcpStream::connect((upstream.host.as_str(), upstream.port))
        .await
        .into_diagnostic()?;
    stream.set_nodelay(true).into_diagnostic()?;

    if upstream.scheme == "https" {
        let materials = require_tls_materials(&upstream.endpoint, tls)?;
        let config = build_rustls_config(&materials)?;
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(upstream.host.clone())
            .map_err(|_| miette::miette!("invalid gateway host: {}", upstream.host))?;
        let stream = connector
            .connect(server_name, stream)
            .await
            .into_diagnostic()?;
        Ok(Box::new(stream))
    } else {
        Ok(Box::new(stream))
    }
}

#[derive(Debug)]
struct Upstream {
    endpoint: String,
    scheme: String,
    host: String,
    port: u16,
}

impl Upstream {
    fn from_endpoint(endpoint: &str) -> Result<Self> {
        let url = url::Url::parse(endpoint).into_diagnostic()?;
        let scheme = url.scheme();
        if !matches!(scheme, "http" | "https") {
            return Err(miette::miette!(
                "gateway proxy only supports http/https endpoints"
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| miette::miette!("gateway endpoint is missing a host"))?
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| miette::miette!("gateway endpoint is missing a port"))?;
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            scheme: scheme.to_string(),
            host,
            port,
        })
    }

    fn is_local_endpoint(&self) -> bool {
        if self.host.eq_ignore_ascii_case("localhost") {
            return true;
        }
        self.host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|addr| addr.is_loopback() || addr.is_unspecified())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_url_pattern_uses_gateway_name_and_proxy_port() {
        assert_eq!(
            local_service_url_pattern("navigator", 32123),
            "http://<sandbox>--<service>.navigator.openshell.localhost:32123/"
        );
    }

    #[test]
    fn parses_https_upstream_default_port() {
        let upstream = Upstream::from_endpoint("https://my.gateway.example.com").unwrap();
        assert_eq!(upstream.scheme, "https");
        assert_eq!(upstream.host, "my.gateway.example.com");
        assert_eq!(upstream.port, 443);
    }

    #[test]
    fn parses_http_upstream_explicit_port() {
        let upstream = Upstream::from_endpoint("http://10.0.0.5:31886").unwrap();
        assert_eq!(upstream.scheme, "http");
        assert_eq!(upstream.host, "10.0.0.5");
        assert_eq!(upstream.port, 31886);
    }

    #[test]
    fn tailscale_hostname_is_not_local_endpoint() {
        let upstream = Upstream::from_endpoint("http://spark.kiko-cordylus.ts.net:39284").unwrap();
        assert!(!upstream.is_local_endpoint());
    }

    #[test]
    fn loopback_endpoint_is_local_endpoint() {
        let upstream = Upstream::from_endpoint("https://127.0.0.1:31886").unwrap();
        assert!(upstream.is_local_endpoint());
    }
}
