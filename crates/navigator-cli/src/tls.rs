// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{IntoDiagnostic, Result, WrapErr};
use navigator_core::proto::inference_client::InferenceClient;
use navigator_core::proto::navigator_client::NavigatorClient;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::io::Cursor;
use std::path::PathBuf;
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

#[derive(Clone, Debug, Default)]
pub struct TlsOptions {
    ca: Option<PathBuf>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    /// Cluster name for resolving default cert directory.
    cluster_name: Option<String>,
}

impl TlsOptions {
    pub fn new(ca: Option<PathBuf>, cert: Option<PathBuf>, key: Option<PathBuf>) -> Self {
        Self {
            ca,
            cert,
            key,
            cluster_name: None,
        }
    }

    pub fn has_any(&self) -> bool {
        self.ca.is_some() || self.cert.is_some() || self.key.is_some()
    }

    /// Return the cluster name, if set.
    pub fn cluster_name(&self) -> Option<&str> {
        self.cluster_name.as_deref()
    }

    /// Set the cluster name for cert directory resolution.
    #[must_use]
    pub fn with_cluster_name(&self, name: &str) -> Self {
        Self {
            ca: self.ca.clone(),
            cert: self.cert.clone(),
            key: self.key.clone(),
            cluster_name: Some(name.to_string()),
        }
    }

    #[must_use]
    pub fn with_default_paths(&self, server: &str) -> Self {
        let base = self
            .cluster_name
            .as_deref()
            .and_then(tls_dir_for_cluster)
            .or_else(|| default_tls_dir(server));
        Self {
            ca: self
                .ca
                .clone()
                .or_else(|| base.as_ref().map(|dir| dir.join("ca.crt"))),
            cert: self
                .cert
                .clone()
                .or_else(|| base.as_ref().map(|dir| dir.join("tls.crt"))),
            key: self
                .key
                .clone()
                .or_else(|| base.as_ref().map(|dir| dir.join("tls.key"))),
            cluster_name: self.cluster_name.clone(),
        }
    }
}

pub struct TlsMaterials {
    ca: Vec<u8>,
    cert: Vec<u8>,
    key: Vec<u8>,
}

/// Resolve the TLS cert directory for a known cluster name.
fn tls_dir_for_cluster(name: &str) -> Option<PathBuf> {
    let safe_name = sanitize_name(name);
    let base = xdg_config_dir().ok()?.join("navigator").join("clusters");
    Some(base.join(safe_name).join("mtls"))
}

/// Fallback TLS directory resolution from a server URL.
///
/// Used when no cluster name is set (e.g., `SshProxy` which receives a raw URL).
fn default_tls_dir(server: &str) -> Option<PathBuf> {
    let mut name = std::env::var("NAVIGATOR_CLUSTER_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty());

    if name.is_none()
        && let Ok(uri) = server.parse::<hyper::Uri>()
        && let Some(host) = uri.host()
    {
        name = Some(
            if host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost") {
                "navigator".to_string()
            } else {
                host.to_string()
            },
        );
    }

    let name = name.unwrap_or_else(|| "navigator".to_string());
    let safe_name = sanitize_name(&name);
    let base = xdg_config_dir().ok()?.join("navigator").join("clusters");
    Some(base.join(safe_name).join("mtls"))
}

fn sanitize_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn xdg_config_dir() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config"))
}

pub fn require_tls_materials(server: &str, tls: &TlsOptions) -> Result<TlsMaterials> {
    let resolved = tls.with_default_paths(server);
    let default_hint = default_tls_dir(server).map_or_else(String::new, |dir| {
        format!(" or place certs in {}", dir.display())
    });
    let ca_path = resolved
        .ca
        .as_ref()
        .ok_or_else(|| miette::miette!("TLS CA is required for https endpoints{default_hint}"))?;
    let cert_path = resolved.cert.as_ref().ok_or_else(|| {
        miette::miette!("TLS client cert is required for https endpoints{default_hint}")
    })?;
    let key_path = resolved.key.as_ref().ok_or_else(|| {
        miette::miette!("TLS client key is required for https endpoints{default_hint}")
    })?;

    let ca = std::fs::read(ca_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read TLS CA from {}", ca_path.display()))?;
    let cert = std::fs::read(cert_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read TLS cert from {}", cert_path.display()))?;
    let key = std::fs::read(key_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read TLS key from {}", key_path.display()))?;

    Ok(TlsMaterials { ca, cert, key })
}

fn load_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = Cursor::new(pem);
    let key = rustls_pemfile::private_key(&mut cursor)
        .into_diagnostic()?
        .ok_or_else(|| miette::miette!("no private key found in TLS key PEM"))?;
    Ok(key)
}

pub fn build_rustls_config(materials: &TlsMaterials) -> Result<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    let mut ca_cursor = Cursor::new(&materials.ca);
    let ca_certs = rustls_pemfile::certs(&mut ca_cursor)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .into_diagnostic()?;
    for cert in ca_certs {
        roots.add(cert).into_diagnostic()?;
    }

    let mut cert_cursor = Cursor::new(&materials.cert);
    let cert_chain = rustls_pemfile::certs(&mut cert_cursor)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .into_diagnostic()?;
    let key = load_private_key(&materials.key)?;

    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .into_diagnostic()
}

pub fn build_tonic_tls_config(materials: &TlsMaterials) -> ClientTlsConfig {
    let ca_cert = Certificate::from_pem(materials.ca.clone());
    let identity = Identity::from_pem(materials.cert.clone(), materials.key.clone());
    ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .identity(identity)
}

pub async fn build_channel(server: &str, tls: &TlsOptions) -> Result<Channel> {
    let mut endpoint = Endpoint::from_shared(server.to_string())
        .into_diagnostic()?
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_while_idle(true);
    let materials = require_tls_materials(server, tls)?;
    let tls_config = build_tonic_tls_config(&materials);
    endpoint = endpoint.tls_config(tls_config).into_diagnostic()?;
    endpoint.connect().await.into_diagnostic()
}

pub async fn grpc_client(server: &str, tls: &TlsOptions) -> Result<NavigatorClient<Channel>> {
    let channel = build_channel(server, tls).await?;
    Ok(NavigatorClient::new(channel))
}

pub async fn grpc_inference_client(
    server: &str,
    tls: &TlsOptions,
) -> Result<InferenceClient<Channel>> {
    let mut endpoint = Endpoint::from_shared(server.to_string())
        .into_diagnostic()?
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_while_idle(true);
    let materials = require_tls_materials(server, tls)?;
    let tls_config = build_tonic_tls_config(&materials);
    endpoint = endpoint.tls_config(tls_config).into_diagnostic()?;
    let channel = endpoint.connect().await.into_diagnostic()?;
    Ok(InferenceClient::new(channel))
}
