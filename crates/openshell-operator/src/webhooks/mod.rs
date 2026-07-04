// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Admission webhook server for `SandboxRuntime` CRDs.
//!
//! Implements validating and mutating admission webhooks served over HTTPS,
//! using axum for HTTP routing and `tokio-rustls` for TLS.

pub mod mutate;
pub mod validate;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::post;
use axum::Router;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::info;

use crate::config::OperatorConfig;

/// Run the webhook HTTPS server.
///
/// Serves validating and mutating webhook endpoints over TLS.
pub async fn run_webhook_server(config: OperatorConfig) -> anyhow::Result<()> {
    let cert_path = config
        .tls_cert_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("TLS cert path required for webhook server"))?;
    let key_path = config
        .tls_key_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("TLS key path required for webhook server"))?;

    // Load TLS config.
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let app = Router::new()
        .route("/validate", post(validate::handle_validate))
        .route("/mutate", post(mutate::handle_mutate));

    let addr: SocketAddr = config.webhook_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "webhook server listening");

    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper_util::service::TowerToHyperService::new(app);
                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, service)
                    .await
                    {
                        tracing::warn!(error = %e, "webhook connection error");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "TLS handshake failed");
                }
            }
        });
    }
}

fn load_certs(path: &str) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {path}"))?;
    Ok(key)
}
