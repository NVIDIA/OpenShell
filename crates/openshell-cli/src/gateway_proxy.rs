// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Local browser proxy for remote gateway service domains.

use std::net::SocketAddr;
use std::sync::Arc;

use miette::{IntoDiagnostic, Result};
use openshell_bootstrap::GatewayMetadata;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
                    if let Err(err) = handle_connection(client, peer, upstream, tls).await {
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
    client: TcpStream,
    peer: SocketAddr,
    upstream: Arc<Upstream>,
    tls: Arc<TlsOptions>,
) -> Result<()> {
    client.set_nodelay(true).into_diagnostic()?;
    let endpoint_label = upstream.endpoint_label();
    let transport_label = upstream.transport_label(&tls);
    let upstream = connect_upstream(&upstream, &tls).await?;
    debug!(peer = %peer, "gateway proxy connected upstream");
    eprintln!(
        "→ proxy {peer} -> {} via {}",
        endpoint_label, transport_label
    );

    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream);

    let request = relay_with_logging(
        &mut client_reader,
        &mut upstream_writer,
        ProxyDirection::Request,
        peer,
    );
    let response = relay_with_logging(
        &mut upstream_reader,
        &mut client_writer,
        ProxyDirection::Response,
        peer,
    );
    let (request_result, response_result) = tokio::join!(request, response);
    if let Err(err) = request_result {
        warn!(peer = %peer, error = %err, "gateway proxy request relay failed");
    }
    if let Err(err) = response_result {
        warn!(peer = %peer, error = %err, "gateway proxy response relay failed");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ProxyDirection {
    Request,
    Response,
}

async fn relay_with_logging<R, W>(
    reader: &mut R,
    writer: &mut W,
    direction: ProxyDirection,
    peer: SocketAddr,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0;
    let mut logged = false;
    let mut buffer = [0_u8; 16 * 1024];

    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }
        if !logged {
            log_first_proxy_chunk(direction, peer, &buffer[..read]);
            logged = true;
        }
        writer.write_all(&buffer[..read]).await?;
        total += u64::try_from(read).unwrap_or(0);
    }
}

fn log_first_proxy_chunk(direction: ProxyDirection, peer: SocketAddr, bytes: &[u8]) {
    match direction {
        ProxyDirection::Request => {
            let (line, host) = request_line_and_host(bytes);
            eprintln!(
                "  request {peer}: {} host={}",
                line.unwrap_or("<non-http>"),
                host.unwrap_or("<missing>")
            );
        }
        ProxyDirection::Response => {
            if let Some(line) = first_line(bytes).filter(|line| line.starts_with("HTTP/")) {
                eprintln!("  response {peer}: {line}");
            } else {
                eprintln!(
                    "  response {peer}: non-http first bytes [{}] ascii={}",
                    hex_preview(bytes),
                    ascii_preview(bytes)
                );
            }
        }
    }
}

fn request_line_and_host(bytes: &[u8]) -> (Option<&str>, Option<&str>) {
    let text = std::str::from_utf8(bytes).ok();
    let line = first_line(bytes);
    let host = text.and_then(|text| {
        text.split("\r\n")
            .find_map(|line| line.strip_prefix("Host:").map(str::trim))
            .or_else(|| {
                text.split('\n')
                    .find_map(|line| line.strip_prefix("Host:").map(str::trim))
            })
    });
    (line, host)
}

fn first_line(bytes: &[u8]) -> Option<&str> {
    let end = bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .or_else(|| bytes.iter().position(|byte| *byte == b'\n'))?;
    std::str::from_utf8(&bytes[..end]).ok()
}

fn hex_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(32)
        .map(|byte| match byte {
            0x20..=0x7e => char::from(*byte),
            _ => '.',
        })
        .collect()
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

    fn endpoint_label(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.host, self.port)
    }

    fn transport_label(&self, tls: &TlsOptions) -> &'static str {
        if tls.is_bearer_auth() {
            "edge tunnel"
        } else if self.scheme == "https" {
            "mTLS"
        } else {
            "plain HTTP"
        }
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

    #[test]
    fn parses_request_line_and_host() {
        let (line, host) = request_line_and_host(
            b"GET / HTTP/1.1\r\nHost: luscious-sawfish--openclaw.spark.openshell.localhost:53068\r\n\r\n",
        );

        assert_eq!(line, Some("GET / HTTP/1.1"));
        assert_eq!(
            host,
            Some("luscious-sawfish--openclaw.spark.openshell.localhost:53068")
        );
    }
}
