// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! Verifies application bearer authorization behavior through an exposed
//! `Ryno` service.

use std::fs::File;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::http1;
use hyper::{Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use ryno_e2e::harness::binary::ryno_cmd;
use ryno_e2e::harness::sandbox::{E2E_WORKLOAD_IMAGE, SandboxGuard};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;
use url::Position;

const SERVICE_PORT: &str = "4500";
const BEARER_TOKEN: &str = "Bearer ryno-e2e-application-token";
const READY_TIMEOUT: Duration = Duration::from_secs(60);
const HEADER_ECHO_SERVER: &str = r#"
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.headers.get("Authorization", "").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass

ThreadingHTTPServer(("127.0.0.1", 4500), Handler).serve_forever()
"#;

async fn run_cli(args: &[&str]) -> Result<std::process::Output, String> {
    let mut command = ryno_cmd();
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
        .output()
        .await
        .map_err(|error| format!("failed to run ryno: {error}"))
}

enum ServiceTransport {
    Http,
    Https {
        connector: TlsConnector,
        server_name: ServerName<'static>,
    },
}

struct ServiceTarget {
    port: u16,
    authority: String,
    path: String,
    transport: ServiceTransport,
}

impl ServiceTarget {
    fn from_url(url: &str) -> Result<Self, String> {
        let url = url::Url::parse(url).map_err(|error| format!("invalid service URL: {error}"))?;
        let host = url
            .host_str()
            .ok_or_else(|| "service URL omitted its host".to_string())?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| "service URL omitted its port".to_string())?;
        let transport = match url.scheme() {
            "http" => ServiceTransport::Http,
            "https" => ServiceTransport::Https {
                connector: e2e_tls_connector()?,
                server_name: ServerName::try_from(host.to_string())
                    .map_err(|error| format!("invalid service TLS server name: {error}"))?,
            },
            scheme => return Err(format!("unsupported service URL scheme {scheme:?}")),
        };
        let authority = url[Position::BeforeHost..Position::AfterPort].to_string();
        let path = url.query().map_or_else(
            || url.path().to_string(),
            |query| format!("{}?{query}", url.path()),
        );

        Ok(Self {
            port,
            authority,
            path,
            transport,
        })
    }
}

fn e2e_mtls_dir() -> Result<PathBuf, String> {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .ok_or_else(|| "XDG_CONFIG_HOME is required for an HTTPS service URL".to_string())?;
    let gateway = std::env::var("RYNO_GATEWAY")
        .map_err(|_| "RYNO_GATEWAY is required for an HTTPS service URL".to_string())?;
    Ok(PathBuf::from(config_home)
        .join("ryno/gateways")
        .join(gateway)
        .join("mtls"))
}

fn load_certificates(
    path: &Path,
    description: &str,
) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = File::open(path)
        .map_err(|error| format!("open {description} '{}': {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("parse {description} '{}': {error}", path.display()))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let file = File::open(path)
        .map_err(|error| format!("open client TLS key '{}': {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| format!("parse client TLS key '{}': {error}", path.display()))?
        .ok_or_else(|| format!("client TLS key '{}' is empty", path.display()))
}

fn e2e_tls_connector() -> Result<TlsConnector, String> {
    let mtls_dir = e2e_mtls_dir()?;
    let ca_path = mtls_dir.join("ca.crt");
    let mut roots = RootCertStore::empty();
    for certificate in load_certificates(&ca_path, "gateway CA certificate")? {
        roots.add(certificate).map_err(|error| {
            format!(
                "add gateway CA certificate '{}': {error}",
                ca_path.display()
            )
        })?;
    }
    let client_certificates =
        load_certificates(&mtls_dir.join("tls.crt"), "client TLS certificate")?;
    let client_key = load_private_key(&mtls_dir.join("tls.key"))?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certificates, client_key)
        .map_err(|error| format!("build e2e mTLS client configuration: {error}"))?;
    Ok(TlsConnector::from(Arc::new(config)))
}

async fn request_over_stream<S>(
    stream: S,
    target: &ServiceTarget,
    authorization: &str,
) -> Result<(StatusCode, String), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| format!("start HTTP connection: {error}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = Request::builder()
        .uri(&target.path)
        .header(header::HOST, &target.authority)
        .header(header::AUTHORIZATION, authorization)
        .body(Empty::<Bytes>::new())
        .map_err(|error| format!("build service request: {error}"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| format!("send service request: {error}"))?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|error| format!("read service response: {error}"))?
        .to_bytes();
    let body = String::from_utf8(body.to_vec())
        .map_err(|error| format!("service returned non-UTF-8 data: {error}"))?;
    Ok((status, body))
}

async fn request_service(
    target: &ServiceTarget,
    authorization: &str,
) -> Result<(StatusCode, String), String> {
    // The service hostname is a virtual routing authority. Dial the loopback
    // gateway directly so the test does not depend on the host resolver
    // recognizing arbitrary subdomains of `.localhost`.
    let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, target.port))
        .await
        .map_err(|error| format!("connect to loopback service gateway: {error}"))?;
    let _ = stream.set_nodelay(true);
    match &target.transport {
        ServiceTransport::Http => request_over_stream(stream, target, authorization).await,
        ServiceTransport::Https {
            connector,
            server_name,
        } => {
            let stream = connector
                .connect(server_name.clone(), stream)
                .await
                .map_err(|error| format!("start service TLS connection: {error}"))?;
            request_over_stream(stream, target, authorization).await
        }
    }
}

async fn wait_for_authorization(url: &str, expected: &str) -> Result<(), String> {
    // Parse the URL and load TLS material before the retry loop so permanent
    // test-configuration errors fail immediately instead of looking like
    // service-readiness timeouts.
    let target = ServiceTarget::from_url(url)?;
    let mut last_observation = "no request attempted".to_string();
    let result = timeout(READY_TIMEOUT, async {
        loop {
            match request_service(&target, BEARER_TOKEN).await {
                Ok((StatusCode::OK, body)) if body == expected => return Ok(()),
                Ok((StatusCode::OK, body)) => {
                    return Err(format!(
                        "service received unexpected Authorization value: {body:?}"
                    ));
                }
                Ok((status, body))
                    if matches!(
                        status,
                        StatusCode::BAD_GATEWAY
                            | StatusCode::PRECONDITION_FAILED
                            | StatusCode::SERVICE_UNAVAILABLE
                    ) =>
                {
                    last_observation =
                        format!("service returned retryable status {status} with body {body:?}");
                    sleep(Duration::from_millis(250)).await;
                }
                Err(error) => {
                    last_observation = error;
                    sleep(Duration::from_millis(250)).await;
                }
                Ok((status, body)) => {
                    return Err(format!(
                        "service returned unexpected status {status} with body {body:?}"
                    ));
                }
            }
        }
    })
    .await;

    match result {
        Ok(result) => result,
        Err(_) => Err(format!(
            "timed out waiting for the exposed service; last observation: {last_observation}"
        )),
    }
}

#[tokio::test]
async fn service_bearer_passthrough_preserves_authorization_header() {
    let sandbox_name = format!("svc-auth-{}", std::process::id());
    let create = run_cli(&[
        "sandbox",
        "create",
        "--name",
        &sandbox_name,
        "--from",
        E2E_WORKLOAD_IMAGE,
        "--expose",
        SERVICE_PORT,
        "--output",
        "json",
        "--detach",
        "--no-tty",
        "--",
        "python3",
        "-c",
        HEADER_ECHO_SERVER,
    ])
    .await
    .expect("run sandbox create");
    assert!(
        create.status.success(),
        "sandbox create failed with exit {:?}: {}",
        create.status.code(),
        String::from_utf8_lossy(&create.stderr)
    );
    let mut sandbox = SandboxGuard::manage_existing(sandbox_name.clone());

    let created: Value = serde_json::from_slice(&create.stdout).expect("parse sandbox create JSON");
    let service_url = created
        .get("service_urls")
        .and_then(|urls| urls.get(""))
        .and_then(Value::as_str)
        .expect("unnamed service URL in create response");

    wait_for_authorization(service_url, "")
        .await
        .expect("default mode should strip Authorization");

    let expose = run_cli(&[
        "service",
        "expose",
        &sandbox_name,
        SERVICE_PORT,
        "--authorization-mode",
        "bearer-passthrough",
    ])
    .await
    .expect("run service re-expose");
    assert!(
        expose.status.success(),
        "service re-expose failed with exit {:?}: {}",
        expose.status.code(),
        String::from_utf8_lossy(&expose.stderr)
    );

    wait_for_authorization(service_url, BEARER_TOKEN)
        .await
        .expect("passthrough mode should preserve Authorization");

    sandbox.cleanup().await;
}
