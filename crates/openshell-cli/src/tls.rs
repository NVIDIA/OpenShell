// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_sdk::{AuthConfig, ClientConfig, ClientIdentity, OpenShellClient};
use rustls::{
    RootCertStore,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use std::io::Cursor;
use std::path::PathBuf;
use tonic::metadata::AsciiMetadataValue;
use tonic::transport::Channel;

/// Concrete gRPC client type used by all commands.
pub type GrpcClient = openshell_sdk::raw::AuthedGrpcClient;

#[derive(Clone, Debug, Default)]
pub struct TlsOptions {
    ca: Option<PathBuf>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    /// Gateway name for resolving default cert directory.
    gateway_name: Option<String>,
    /// Edge auth bearer token — when set, disables mTLS client certs and
    /// injects authentication headers on every gRPC request instead.
    pub edge_token: Option<String>,
    /// OIDC bearer token — when set, injects `authorization: Bearer <token>`
    /// on every gRPC request. Takes precedence over `edge_token`.
    pub oidc_token: Option<String>,
    /// Skip TLS certificate verification for gateway connections.
    pub gateway_insecure: bool,
}

impl TlsOptions {
    pub fn new(ca: Option<PathBuf>, cert: Option<PathBuf>, key: Option<PathBuf>) -> Self {
        Self {
            ca,
            cert,
            key,
            gateway_name: None,
            edge_token: None,
            oidc_token: None,
            gateway_insecure: false,
        }
    }

    pub fn has_any(&self) -> bool {
        self.ca.is_some() || self.cert.is_some() || self.key.is_some()
    }

    /// Return the gateway name, if set.
    pub fn gateway_name(&self) -> Option<&str> {
        self.gateway_name.as_deref()
    }

    /// Set the gateway name for cert directory resolution.
    #[must_use]
    pub fn with_gateway_name(&self, name: &str) -> Self {
        Self {
            gateway_name: Some(name.to_string()),
            ..self.clone()
        }
    }

    #[must_use]
    pub fn with_default_paths(&self, server: &str) -> Self {
        let base = self
            .gateway_name
            .as_deref()
            .and_then(tls_dir_for_gateway)
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
            gateway_name: self.gateway_name.clone(),
            ..self.clone()
        }
    }

    /// Returns `true` when using bearer token auth.
    pub fn is_bearer_auth(&self) -> bool {
        self.edge_token.is_some() || self.oidc_token.is_some()
    }
}

pub struct TlsMaterials {
    ca: Vec<u8>,
    cert: Vec<u8>,
    key: Vec<u8>,
}

/// Resolve the TLS cert directory for a known gateway name.
fn tls_dir_for_gateway(name: &str) -> Option<PathBuf> {
    let safe_name = sanitize_name(name);
    let base = xdg_config_dir().ok()?.join("openshell").join("gateways");
    Some(base.join(safe_name).join("mtls"))
}

/// Fallback TLS directory resolution from a server URL.
///
/// Used when no gateway name is set (e.g., `SshProxy` which receives a raw URL).
fn default_tls_dir(server: &str) -> Option<PathBuf> {
    let mut name = std::env::var("OPENSHELL_GATEWAY")
        .ok()
        .filter(|value| !value.trim().is_empty());

    if name.is_none()
        && let Ok(uri) = server.parse::<hyper::Uri>()
        && let Some(host) = uri.host()
    {
        name = Some(
            if host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost") {
                "openshell".to_string()
            } else {
                host.to_string()
            },
        );
    }

    let name = name.unwrap_or_else(|| "openshell".to_string());
    let safe_name = sanitize_name(&name);
    let base = xdg_config_dir().ok()?.join("openshell").join("gateways");
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
    openshell_core::paths::xdg_config_dir()
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

    openshell_crypto::tls::client_builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .into_diagnostic()
}

#[derive(Debug)]
struct InsecureServerCertVerifier;

impl ServerCertVerifier for InsecureServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        openshell_crypto::tls::configuration_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn build_insecure_rustls_config() -> Result<rustls::ClientConfig> {
    let config = openshell_crypto::tls::client_builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(InsecureServerCertVerifier))
        .with_no_client_auth();
    Ok(config)
}

fn sdk_client_config(server: &str, tls: &TlsOptions) -> Result<ClientConfig> {
    let mut config = ClientConfig::new(server);
    config.insecure_skip_verify = tls.gateway_insecure;
    let uses_edge_tunnel = tls.oidc_token.is_none() && tls.edge_token.is_some();
    config.auth = tls
        .oidc_token
        .as_deref()
        .map(AuthConfig::oidc)
        .or_else(|| tls.edge_token.clone().map(AuthConfig::EdgeJwt));

    // Plaintext, the edge tunnel, and insecure TLS do not consume certificate
    // material. For verified HTTPS, preserve the CLI's existing behavior:
    // mTLS is required without bearer auth and optional with OIDC.
    if server.starts_with("https://") && !tls.gateway_insecure && !uses_edge_tunnel {
        if tls.oidc_token.is_some() {
            if let Ok(materials) = require_tls_materials(server, tls) {
                config.ca_cert = Some(materials.ca);
                config.client_identity = Some(ClientIdentity::new(materials.cert, materials.key));
            } else {
                let resolved = tls.with_default_paths(server);
                config.ca_cert = resolved
                    .ca
                    .as_ref()
                    .and_then(|ca_path| std::fs::read(ca_path).ok());
            }
        } else {
            let materials = require_tls_materials(server, tls)?;
            config.ca_cert = Some(materials.ca);
            config.client_identity = Some(ClientIdentity::new(materials.cert, materials.key));
        }
    }

    Ok(config)
}

/// Build a gateway channel through `openshell-sdk` while retaining the CLI's
/// filesystem-aware certificate discovery.
pub async fn build_channel(server: &str, tls: &TlsOptions) -> Result<Channel> {
    let config = sdk_client_config(server, tls)?;
    openshell_sdk::transport::build_channel(&config)
        .await
        .into_diagnostic()
}

/// Build the SDK client and return its raw gRPC escape hatch.
///
/// When `tls.edge_token` is set, the returned client is wrapped with an
/// interceptor that injects authentication headers on every request.
/// Otherwise, standard mTLS is used (interceptor is a no-op).
pub async fn grpc_client(server: &str, tls: &TlsOptions) -> Result<GrpcClient> {
    let config = sdk_client_config(server, tls)?;
    // Keep the SDK's transport state machine out of every command future.
    // Most CLI commands compose this helper into larger async operations.
    let client = Box::pin(OpenShellClient::connect(config))
        .await
        .into_diagnostic()?;
    Ok(client.raw_grpc())
}

/// Gateway replica that owns the sandbox named in `response`, when it says.
pub fn owner_replica<T>(response: &tonic::Response<T>) -> Option<AsciiMetadataValue> {
    response
        .metadata()
        .get(openshell_core::replica_routing::OWNER_REPLICA_HEADER)
        .cloned()
}

pub fn with_owner_hint<T>(message: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request.metadata_mut().insert(
        openshell_core::replica_routing::OWNER_REQUEST_HEADER,
        AsciiMetadataValue::from_static("1"),
    );
    request
}

/// Wrap `message` so the edge proxy can route it straight to `replica`.
pub fn routed_to<T>(message: T, replica: Option<&AsciiMetadataValue>) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    if let Some(replica) = replica {
        request.metadata_mut().insert(
            openshell_core::replica_routing::ROUTE_REPLICA_HEADER,
            replica.clone(),
        );
    }
    request
}

/// A routed call is retried once without routing only when no gateway
/// received it.
///
/// Envoy Gateway answers a replica route whose Service has no ready endpoints
/// with `grpc-status: 14` and no `grpc-message`, while gateway errors and
/// mid-request resets always carry a message.
pub fn retry_unrouted(replica: Option<&AsciiMetadataValue>, status: &tonic::Status) -> bool {
    let message = status.message();
    replica.is_some()
        && status.code() == tonic::Code::Unavailable
        && (message.is_empty()
            || message.contains("no healthy upstream")
            || message.contains("connection failure"))
}

#[cfg(test)]
mod tests {
    use super::{
        TlsOptions, owner_replica, retry_unrouted, routed_to, sdk_client_config, with_owner_hint,
    };
    use openshell_core::replica_routing::{
        OWNER_REPLICA_HEADER, OWNER_REQUEST_HEADER, ROUTE_REPLICA_HEADER,
    };
    use openshell_sdk::AuthConfig;
    use std::io::Write;

    #[test]
    fn owner_hint_is_requested_explicitly() {
        assert!(
            with_owner_hint(())
                .metadata()
                .contains_key(OWNER_REQUEST_HEADER)
        );
    }

    #[test]
    fn owner_replica_is_carried_to_the_routed_request() {
        let mut response = tonic::Response::new(());
        response
            .metadata_mut()
            .insert(OWNER_REPLICA_HEADER, "openshell-1".parse().unwrap());
        let replica = owner_replica(&response);
        let request = routed_to((), replica.as_ref());
        assert_eq!(
            request.metadata().get(ROUTE_REPLICA_HEADER).unwrap(),
            "openshell-1"
        );
    }

    #[test]
    fn requests_without_a_known_owner_are_not_routed() {
        let replica = owner_replica(&tonic::Response::new(()));
        assert!(replica.is_none());
        let request = routed_to((), replica.as_ref());
        assert!(request.metadata().get(ROUTE_REPLICA_HEADER).is_none());
    }

    #[test]
    fn only_unavailable_routed_calls_are_retried() {
        let replica = "openshell-1".parse().unwrap();
        let unavailable = tonic::Status::unavailable("no healthy upstream");
        assert!(retry_unrouted(Some(&replica), &unavailable));
        assert!(!retry_unrouted(None, &unavailable));
        assert!(!retry_unrouted(
            Some(&replica),
            &tonic::Status::permission_denied("denied")
        ));
    }

    #[test]
    fn calls_are_retried_only_when_no_gateway_received_them() {
        let replica = "openshell-1".parse().unwrap();
        for never_arrived in [
            "",
            "no healthy upstream",
            "upstream connect error or disconnect/reset before headers. reset reason: connection failure, transport failure reason: delayed connect error: Connection refused",
        ] {
            assert!(retry_unrouted(
                Some(&replica),
                &tonic::Status::unavailable(never_arrived)
            ));
        }
        for may_have_started in [
            "supervisor session not connected",
            "upstream connect error or disconnect/reset before headers. reset reason: connection termination",
        ] {
            assert!(!retry_unrouted(
                Some(&replica),
                &tonic::Status::unavailable(may_have_started)
            ));
        }
        assert!(!retry_unrouted(
            None,
            &tonic::Status::unavailable("no healthy upstream")
        ));
    }

    #[test]
    fn sdk_config_carries_cli_mtls_materials() {
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        let mut cert = tempfile::NamedTempFile::new().unwrap();
        let mut key = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(b"ca pem").unwrap();
        cert.write_all(b"cert pem").unwrap();
        key.write_all(b"key pem").unwrap();

        let tls = TlsOptions::new(
            Some(ca.path().to_path_buf()),
            Some(cert.path().to_path_buf()),
            Some(key.path().to_path_buf()),
        );
        let config = sdk_client_config("https://gateway.example", &tls).unwrap();

        assert_eq!(config.ca_cert.as_deref(), Some(b"ca pem".as_slice()));
        let identity = config.client_identity.unwrap();
        assert_eq!(identity.certificate, b"cert pem");
        assert_eq!(identity.private_key, b"key pem");
    }

    #[test]
    fn sdk_config_maps_oidc_without_requiring_mtls() {
        let tls = TlsOptions {
            oidc_token: Some("access-token".to_string()),
            ..Default::default()
        };

        let config = sdk_client_config("https://gateway.example", &tls).unwrap();

        assert!(matches!(config.auth, Some(AuthConfig::Oidc { .. })));
        assert!(config.client_identity.is_none());
    }

    #[test]
    fn sdk_config_ignores_certificates_for_plaintext() {
        let config = sdk_client_config("http://127.0.0.1:8080", &TlsOptions::default()).unwrap();
        assert!(config.ca_cert.is_none());
        assert!(config.client_identity.is_none());
    }
}
