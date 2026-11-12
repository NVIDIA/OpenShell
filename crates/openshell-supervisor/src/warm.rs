// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A dedicated supervisor parks one authenticated runtime until its gateway
//! registration stream returns its committed claim. Only public runtime
//! coordinates exist before the claim.

use std::path::Path;
use std::time::Duration;

use miette::{IntoDiagnostic as _, Result};
use openshell_sandbox_backend::runtime_routed::RuntimeRouter;
use openshell_supervisor::backend_setup::{BackendSetup, RoutedBackendSetup};
use openshell_supervisor_control::{
    MAX_LAUNCH_MATERIAL_BYTES, PreparedRuntimeRegistration, SandboxInstanceRegistration,
};

pub fn proxy_tls(
    ca: &openshell_supervisor_control::ProxyCaMaterial,
    directory: &Path,
) -> Result<openshell_supervisor_network::run::ProxyTlsFiles> {
    use std::io::Write as _;
    let certificate = directory.join("proxy-ca.crt");
    let key = directory.join("proxy-ca.key");
    for (path, bytes) in [
        (&certificate, ca.certificate_pem.as_bytes()),
        (&key, ca.private_key_pem.expose_secret().as_bytes()),
    ] {
        let mut file = tempfile::NamedTempFile::new_in(directory).into_diagnostic()?;
        file.write_all(bytes).into_diagnostic()?;
        file.persist_noclobber(path)
            .map_err(|_| miette::miette!("cannot persist claim TLS material"))?;
    }
    Ok(openshell_supervisor_network::run::ProxyTlsFiles {
        ca_certificate: Some(certificate),
        ca_private_key: Some(key),
        ..openshell_supervisor_network::run::ProxyTlsFiles::from_environment()
    })
}

fn read_bounded(path: &Path) -> Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(miette::miette!("cannot read warm supervisor material")),
    };
    let mut bytes = Vec::new();
    file.take(MAX_LAUNCH_MATERIAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .into_diagnostic()?;
    if bytes.len() > MAX_LAUNCH_MATERIAL_BYTES {
        return Err(miette::miette!(
            "warm supervisor material exceeds its size limit"
        ));
    }
    Ok(Some(bytes))
}

pub async fn wait_for_claim(
    args: &mut crate::Args,
) -> Result<(Box<dyn BackendSetup>, SandboxInstanceRegistration)> {
    let prepared_path = args
        .warm_prepared_file
        .as_deref()
        .expect("checked by caller");
    let listen = args
        .runtime_listen
        .ok_or_else(|| miette::miette!("--runtime-listen is required for a warm supervisor"))?;
    let prepared: PreparedRuntimeRegistration = serde_json::from_slice(
        &read_bounded(prepared_path)?
            .ok_or_else(|| miette::miette!("warm preparation is missing"))?,
    )
    .map_err(|_| miette::miette!("invalid warm preparation"))?;
    prepared
        .validate()
        .map_err(|_| miette::miette!("invalid warm preparation"))?;
    let endpoint = args
        .openshell_endpoint
        .clone()
        .ok_or_else(|| miette::miette!("warm supervisor requires a gateway endpoint"))?;
    let token_path =
        std::env::var(openshell_core::sandbox_env::K8S_SA_TOKEN_FILE).into_diagnostic()?;
    park_until_claim(
        args,
        prepared,
        register(&endpoint, Path::new(&token_path)),
        listen,
    )
    .await
}

async fn register(endpoint: &str, token_path: &Path) -> Result<Vec<u8>> {
    use openshell_core::proto::supervisor_host::v1::{
        RegisterSupervisorRequest, supervisor_host_client::SupervisorHostClient,
    };
    if !endpoint.starts_with("https://") {
        return Err(miette::miette!(
            "warm supervisor registration requires gateway TLS"
        ));
    }
    let mut delay = Duration::from_millis(200);
    loop {
        let attempt = async {
            let channel = openshell_core::grpc_client::connect_gateway_channel(endpoint)
                .await
                .map_err(|_| tonic::Status::unavailable("gateway connection unavailable"))?;
            // Re-read the projected SA token after a real disconnect or expiry.
            let token = std::fs::read_to_string(token_path)
                .map_err(|_| tonic::Status::unavailable("bootstrap credential unavailable"))?;
            let mut request = tonic::Request::new(RegisterSupervisorRequest {});
            request.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", token.trim())
                    .parse()
                    .map_err(|_| tonic::Status::unauthenticated("invalid bootstrap credential"))?,
            );
            let mut stream = SupervisorHostClient::new(channel)
                .max_decoding_message_size(MAX_LAUNCH_MATERIAL_BYTES + 1024)
                .register_supervisor(request)
                .await?
                .into_inner();
            // No deadline or retry while an unclaimed registration is pending.
            stream
                .message()
                .await?
                .map(|message| message.launch_material)
                .ok_or_else(|| tonic::Status::unavailable("registration stream closed"))
        }
        .await;
        match attempt {
            Ok(material) => return Ok(material),
            Err(status)
                if matches!(
                    status.code(),
                    tonic::Code::Unavailable
                        | tonic::Code::Cancelled
                        | tonic::Code::DeadlineExceeded
                        | tonic::Code::Unauthenticated
                ) =>
            {
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(10));
            }
            Err(_) => {
                return Err(miette::miette!(
                    "gateway refused warm supervisor registration"
                ));
            }
        }
    }
}

async fn park_until_claim(
    args: &mut crate::Args,
    prepared: PreparedRuntimeRegistration,
    claim: impl Future<Output = Result<Vec<u8>>>,
    listen: std::net::SocketAddr,
) -> Result<(Box<dyn BackendSetup>, SandboxInstanceRegistration)> {
    tokio::pin!(claim);
    let router = RuntimeRouter::bind(listen).map_err(|e| miette::miette!(e.to_string()))?;
    let route = router
        .register(&prepared.route, &prepared.runtime_descriptor.tls)
        .map_err(|e| miette::miette!(e.to_string()))?;
    let mut health = None;
    let mut connected = false;
    loop {
        // The startup probe records that a pinned TLS connection is parked, not
        // merely that this process has bound its listening socket.
        if route.has_parked_connection() {
            connected = true;
            if health.is_none()
                && let Some(port) = args.warm_health_port
            {
                health = Some(
                    tokio::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
                        .await
                        .into_diagnostic()?,
                );
            }
        } else if connected {
            // Kubernetes latches a successful startup probe until this process
            // exits. Never keep that verdict alive after losing the runtime:
            // the driver excludes terminated/restarted supervisors and replaces
            // the spare. Normal supervision owns reconnection after a claim.
            return Err(miette::miette!(
                "prepared runtime disconnected before its claim"
            ));
        }
        tokio::select! {
            bytes = &mut claim => {
            let bytes = bytes?;
            if bytes.len() > MAX_LAUNCH_MATERIAL_BYTES { return Err(miette::miette!("warm launch material exceeds its size limit")); }
            let registration: SandboxInstanceRegistration = serde_json::from_slice(&bytes)
                .map_err(|_| miette::miette!("invalid warm launch material"))?;
            prepared
                .validate_activation(&registration)
                .map_err(|_| miette::miette!("warm claim does not match the prepared runtime"))?;
            // Close warm readiness before normal dedicated startup begins. Its
            // health listener opens only once supervision is ready.
            drop(health);
            args.sandbox_id = Some(registration.sandbox_id.clone());
            args.sandbox = Some(registration.sandbox_name.clone());
            args.workdir.clone_from(&registration.workdir);
            let setup = RoutedBackendSetup::new(router, prepared.route).with_prepared_route(route);
            return Ok((Box::new(setup), registration));
        }
            () = tokio::time::sleep(Duration::from_millis(100)) => {}
            () = async {
                match &health {
                    Some(listener) => { let _ = listener.accept().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use openshell_sandbox_backend::boundary_protocol::generate_sandbox_tls_material;
    use openshell_sandbox_backend::runtime_routed::{RouteReply, negotiate_route};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};

    #[tokio::test]
    async fn dedicated_wait_keeps_the_authenticated_connection_until_claim() {
        dedicated_wait(false).await;
    }

    #[tokio::test]
    async fn dedicated_wait_exits_when_the_authenticated_runtime_disconnects() {
        dedicated_wait(true).await;
    }

    // BackendSetup is local to the dedicated supervisor's runtime; both callers
    // use Tokio's current-thread test runtime.
    #[allow(clippy::future_not_send)]
    async fn dedicated_wait(disconnect: bool) {
        let root = tempfile::tempdir().unwrap();
        let session = openshell_core::SandboxSessionId::new();
        let tls = generate_sandbox_tls_material(session).unwrap();
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        drop(socket);
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let health = socket.local_addr().unwrap();
        drop(socket);
        let prepared: PreparedRuntimeRegistration = serde_json::from_value(serde_json::json!({
            "route": "rt-dedicated-0123456789",
            "runtime_descriptor": {
                "boundary_id": "", "generation": "generation-1", "session_id": session,
                "workload_identity": {"uid": 1000, "gid": 1000, "supplementary_gids": [],
                    "source": "test", "resource_digest": "a".repeat(64)},
                "transport": {"kind": "runtime-initiated-routed", "authority": address.to_string(), "route": "rt-dedicated-0123456789"},
                "tls": {"server_name": tls.server_name, "trust_anchor_pem": tls.trust_anchor_pem},
                "resource_claims": {"kubernetes.workload_pod_uid": "pod-1", "kubernetes.supervisor_pod_uid": "supervisor-1"},
                "provisioning_evidence": {"generation": "generation-1", "evidence_digest": "a".repeat(64)}
            }
        })).unwrap();
        let mut descriptor = prepared.runtime_descriptor.clone();
        descriptor.boundary_id = "claimed-sandbox".into();
        let claim: SandboxInstanceRegistration = serde_json::from_value(serde_json::json!({
            "route": prepared.route, "sandbox_id": "claimed-sandbox", "sandbox_name": "claimed",
            "runtime_descriptor": descriptor,
            "auth": {"session_id": session, "runtime_generation": "generation-1", "session_rotation": 1, "auth_epoch": 1,
                "gateway_token": "gateway-test", "gateway_expires_at": 0, "sandbox_token": "sandbox-test", "sandbox_expires_at": 0},
            "main_process_spec": serde_json::to_string(&openshell_core::sandbox_env::MainProcessConfig::scratch()).unwrap(),
            "proxy_ca": {"certificate_pem": "test-ca", "private_key_pem": "test-key"}
        })).unwrap();
        let prepared_path = root.path().join("prepared.json");
        let (claim_tx, claim_rx) = tokio::sync::oneshot::channel();
        std::fs::write(&prepared_path, serde_json::to_vec(&prepared).unwrap()).unwrap();
        let mut args = crate::Args::parse_from([
            "openshell-supervisor",
            "--warm-prepared-file",
            prepared_path.to_str().unwrap(),
            "--runtime-listen",
            &address.to_string(),
            "--warm-health-port",
            &health.port().to_string(),
        ]);
        let peer = async {
            let socket = loop {
                if let Ok(socket) =
                    openshell_core::net::connect_tcp_nodelay_best_effort(address).await
                {
                    break socket;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            };
            let mut socket = socket;
            assert!(matches!(
                negotiate_route(&mut socket, &prepared.route).await.unwrap(),
                RouteReply::Accept(_)
            ));
            let certs = CertificateDer::pem_slice_iter(tls.certificate_chain_pem.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            let key = PrivateKeyDer::from_pem_slice(tls.private_key_pem.as_bytes()).unwrap();
            let config = openshell_crypto::tls::try_server_builder()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
                .accept(socket)
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if openshell_core::net::connect_tcp_nodelay_best_effort(health)
                        .await
                        .is_ok()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            if disconnect {
                drop(stream);
                // Retain the sender so the pending registration cannot end the
                // wait. Only losing the authenticated runtime should do so.
                return (None, Some(claim_tx));
            }
            claim_tx.send(serde_json::to_vec(&claim).unwrap()).unwrap();
            (Some(stream), None)
        };
        let (result, stream) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(
                park_until_claim(
                    &mut args,
                    prepared.clone(),
                    async { Ok(claim_rx.await.unwrap()) },
                    address
                ),
                peer
            )
        })
        .await
        .unwrap();
        if disconnect {
            let error = result.err().expect("disconnected spare must terminate");
            assert!(error.to_string().contains("prepared runtime disconnected"));
            assert!(args.sandbox_id.is_none());
            assert!(
                openshell_core::net::connect_tcp_nodelay_best_effort(health)
                    .await
                    .is_err()
            );
            return;
        }
        let (setup, registration) = result.unwrap();
        assert_eq!(args.sandbox_id.as_deref(), Some("claimed-sandbox"));
        // Decoding adopts the parked route; registering it again would fail.
        let descriptor = registration
            .runtime_descriptor
            .backend_descriptor()
            .unwrap();
        let (identity, _backend) = setup.decode(&descriptor.payload).unwrap();
        assert_eq!(identity.sandbox_id, "claimed-sandbox");
        assert!(
            openshell_core::net::connect_tcp_nodelay_best_effort(health)
                .await
                .is_err()
        );
        drop(stream);
    }

    #[test]
    fn launch_reader_distinguishes_absence_from_invalid_material() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("launch");
        assert!(read_bounded(&path).unwrap().is_none());
        std::fs::write(&path, vec![0; MAX_LAUNCH_MATERIAL_BYTES + 1]).unwrap();
        assert!(read_bounded(&path).is_err());
        assert!(read_bounded(root.path()).is_err());
    }
}
