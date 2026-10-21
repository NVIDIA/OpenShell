// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor shared by the sandboxes of one gateway.
//!
//! A compute driver registers each sandbox instance, one running generation
//! of a stable Sandbox resource, over the session-control API, which accepts
//! only mutually authenticated TLS clients holding the admission certificate.
//! A registration carries exactly the gateway-issued credentials of that
//! generation; the host never acts with any other identity. This module only
//! validates registrations and turns them into launch material: the
//! [`SandboxInstanceHost`] registry admits, runs, and removes each instance,
//! whose runtime connections arrive through one routed listener. Removing a
//! registration stops only that instance.

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use miette::Result;
use openshell_sandbox_backend::runtime_routed::RuntimeRouter;
use openshell_sandbox_backend::session_control::{
    MAX_REGISTRATION_BYTES, SESSIONS_PATH, SandboxInstanceList, SandboxInstancePhaseReport,
    SandboxInstanceRegistration, SandboxInstanceStatusReport,
};

use crate::sandbox_instance_host::{
    SandboxInstanceAdmission, SandboxInstanceAdmitted, SandboxInstanceBody, SandboxInstanceHost,
    SandboxInstanceHostError, SandboxInstancePhase, SandboxInstanceStatus,
};

/// Concurrent session-control connections; the only client is the gateway,
/// whose removals hold a connection while a workload stops.
const MAX_CONTROL_CONNECTIONS: usize = 64;
/// Bound on a TLS handshake and on reading one request.
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Process-level inputs of a shared supervisor.
pub struct SharedHostConfig {
    /// Gateway gRPC endpoint every sandbox instance uses with its own
    /// credentials.
    pub gateway_endpoint: String,
    /// Private directory for per-instance files (`--session-root`).
    pub instance_root: PathBuf,
    /// Listener for runtime-initiated Sandbox Protocol connections.
    pub runtime_listen: SocketAddr,
    /// Time a removed sandbox instance may take to stop its workload.
    pub removal_grace: Duration,
}

/// Session-control adapter over the sandbox instance registry and the
/// routed runtime listener its instances claim routes on.
pub struct SharedHost {
    host: SandboxInstanceHost,
    router: Arc<RuntimeRouter>,
    gateway_endpoint: String,
    removal_grace: Duration,
}

/// A rejected session-control request.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("{0}")]
    Invalid(String),
    #[error("route is already registered with different launch material")]
    Conflict,
    #[error("route is still being removed")]
    Removing,
    #[error("{0}")]
    Unavailable(String),
}

impl From<SandboxInstanceHostError> for ControlError {
    fn from(error: SandboxInstanceHostError) -> Self {
        match error {
            SandboxInstanceHostError::InvalidKey => Self::Invalid(error.to_string()),
            SandboxInstanceHostError::Conflict => Self::Conflict,
            SandboxInstanceHostError::Removing => Self::Removing,
            SandboxInstanceHostError::Files(_) | SandboxInstanceHostError::Thread(_) => {
                Self::Unavailable(error.to_string())
            }
        }
    }
}

impl SharedHost {
    /// Bind the routed runtime listener and prepare the instance root.
    pub fn start(config: SharedHostConfig) -> Result<Arc<Self>> {
        let host = SandboxInstanceHost::new(config.instance_root)?;
        let router = RuntimeRouter::bind(config.runtime_listen)
            .map_err(|error| miette::miette!("{error}"))?;
        Ok(Arc::new(Self {
            host,
            router,
            gateway_endpoint: config.gateway_endpoint,
            removal_grace: config.removal_grace,
        }))
    }

    /// Address of the routed runtime listener.
    #[must_use]
    pub fn runtime_addr(&self) -> SocketAddr {
        self.router.local_addr()
    }

    /// Start a sandbox instance for `registration`, or confirm an identical
    /// one.
    pub fn register(
        &self,
        registration: SandboxInstanceRegistration,
    ) -> Result<SandboxInstanceAdmitted, ControlError> {
        registration
            .validate()
            .map_err(|error| ControlError::Invalid(error.to_string()))?;
        let admission = SandboxInstanceAdmission {
            key: registration.route.clone(),
            fingerprint: registration_digest(&registration)?,
            sandbox_id: registration.sandbox_id.clone(),
        };
        self.host
            .admit(admission, |dir| self.instance_launch(registration, dir))
    }

    /// Status of one registered sandbox instance.
    #[must_use]
    pub fn status(&self, route: &str) -> Option<SandboxInstanceStatusReport> {
        self.host
            .status(route)
            .map(|status| status_report(route, status))
    }

    /// Status of every registered sandbox instance.
    #[must_use]
    pub fn list(&self) -> SandboxInstanceList {
        SandboxInstanceList {
            sessions: self
                .host
                .list()
                .into_iter()
                .map(|(route, status)| status_report(&route, status))
                .collect(),
        }
    }

    /// Stop one sandbox instance, delete its private files, and forget it.
    pub async fn remove(&self, route: &str) -> Option<SandboxInstanceStatusReport> {
        self.host
            .remove(route, self.removal_grace)
            .await
            .map(|status| status_report(route, status))
    }

    /// Stop every sandbox instance, for process shutdown.
    pub async fn remove_all(&self) {
        self.host.remove_all(self.removal_grace).await;
    }

    /// Launch material of `registration` with its private files in `dir`.
    fn instance_launch(
        &self,
        registration: SandboxInstanceRegistration,
        dir: &Path,
    ) -> Result<(crate::SandboxInstanceBindings, SandboxInstanceBody), ControlError> {
        let failure = |error: miette::Report| ControlError::Unavailable(error.to_string());
        let main_process =
            openshell_core::sandbox_env::MainProcessConfig::decode(&registration.main_process_spec)
                .map_err(ControlError::Invalid)?;
        let descriptor = registration
            .runtime_descriptor
            .backend_descriptor()
            .map_err(|error| ControlError::Invalid(error.to_string()))?;
        let ca_certificate = dir.join("proxy-ca.crt");
        let ca_private_key = dir.join("proxy-ca.key");
        write_private_file(
            &ca_certificate,
            registration.proxy_ca.certificate_pem.as_bytes(),
        )
        .map_err(failure)?;
        write_private_file(
            &ca_private_key,
            registration
                .proxy_ca
                .private_key_pem
                .expose_secret()
                .as_bytes(),
        )
        .map_err(failure)?;
        let trust_dir = dir.join("trust");
        crate::sandbox_instance_host::prepare_private_dir(&trust_dir).map_err(failure)?;
        let ssh_socket = dir.join("ssh.sock");
        let config = crate::SandboxInstanceConfig {
            command: main_process.command,
            workdir: registration.workdir,
            timeout_secs: 0,
            interactive: main_process.tty,
            await_main_process_attachment: main_process.await_main_process_attachment,
            sandbox_id: Some(registration.sandbox_id),
            sandbox: Some(registration.sandbox_name),
            container_image: registration.container_image,
            openshell_endpoint: Some(self.gateway_endpoint.clone()),
            policy_rules: None,
            policy_data: None,
            ssh_socket_path: Some(ssh_socket.to_string_lossy().into_owned()),
            shared_ssh_socket: false,
            // The Kubernetes driver refuses the gateway topology when an
            // upstream proxy or provider workload identity is configured,
            // and it configures no extra CA for dedicated supervisors.
            upstream_proxy_args:
                openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs::default(),
            additional_ca_bundle: None,
            backend_descriptor: descriptor,
            auth_bundle: registration.auth,
            admitted_isolation_backend: Some(openshell_sandbox_backend::BACKEND_NAME.to_string()),
            main_exit_marker: None,
            trace_context: registration
                .trace_context
                .map(|context| crate::TraceContext {
                    traceparent: context.traceparent,
                    tracestate: context.tracestate,
                }),
            // One process cannot hold a per-sandbox workload identity, so
            // providers that need one fail closed.
            provider_workload_api_socket: None,
            proxy_tls: openshell_supervisor_network::run::ProxyTlsFiles {
                ca_certificate: Some(ca_certificate),
                ca_private_key: Some(ca_private_key),
                directory: Some(trust_dir),
            },
        };
        crate::sandbox_instance_host::sandbox_instance_launch(
            Box::new(crate::backend_setup::RoutedBackendSetup::new(
                self.router.clone(),
                registration.route,
            )),
            config,
            dir,
        )
        .map_err(failure)
    }
}

fn registration_digest(
    registration: &SandboxInstanceRegistration,
) -> Result<[u8; 32], ControlError> {
    let encoded = serde_json::to_vec(registration)
        .map_err(|error| ControlError::Invalid(format!("encode registration: {error}")))?;
    openshell_crypto::sha256(&encoded).map_err(|error| ControlError::Unavailable(error.to_string()))
}

fn status_report(route: &str, status: SandboxInstanceStatus) -> SandboxInstanceStatusReport {
    SandboxInstanceStatusReport {
        route: route.to_string(),
        sandbox_id: status.sandbox_id,
        phase: match status.phase {
            SandboxInstancePhase::Starting => SandboxInstancePhaseReport::Starting,
            SandboxInstancePhase::Supervising => SandboxInstancePhaseReport::Supervising,
            SandboxInstancePhase::Stopping => SandboxInstancePhaseReport::Stopping,
            SandboxInstancePhase::Exited(exit_code) => {
                SandboxInstancePhaseReport::Exited { exit_code }
            }
            SandboxInstancePhase::Failed(error) => SandboxInstancePhaseReport::Failed { error },
        },
        ready: status.ready,
    }
}

#[cfg(unix)]
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    use miette::{IntoDiagnostic as _, WrapErr as _};
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("create {}", path.display()))?;
    file.write_all(contents).into_diagnostic()?;
    file.sync_all().into_diagnostic()
}

#[cfg(not(unix))]
fn write_private_file(_path: &Path, _contents: &[u8]) -> Result<()> {
    Err(miette::miette!("shared supervision requires a Unix host"))
}

type ControlResponse = http::Response<Full<Bytes>>;

fn json_response(status: http::StatusCode, body: &impl serde::Serialize) -> ControlResponse {
    let body = serde_json::to_vec(body).unwrap_or_default();
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_default()
}

fn error_response(status: http::StatusCode, message: &str) -> ControlResponse {
    json_response(status, &serde_json::json!({ "error": message }))
}

async fn handle_control(
    host: Arc<SharedHost>,
    request: http::Request<hyper::body::Incoming>,
) -> ControlResponse {
    let path = request.uri().path().to_string();
    let route = path
        .strip_prefix(SESSIONS_PATH)
        .and_then(|rest| rest.strip_prefix('/'))
        .filter(|route| !route.is_empty() && !route.contains('/'));
    match (request.method().clone(), route) {
        (http::Method::GET, None) if path == SESSIONS_PATH => {
            json_response(http::StatusCode::OK, &host.list())
        }
        (http::Method::GET, Some(route)) => host.status(route).map_or_else(
            || {
                error_response(
                    http::StatusCode::NOT_FOUND,
                    "sandbox instance is not registered",
                )
            },
            |status| json_response(http::StatusCode::OK, &status),
        ),
        (http::Method::PUT, Some(route)) => {
            let route = route.to_string();
            let body = match tokio::time::timeout(
                CONTROL_IO_TIMEOUT,
                Limited::new(request.into_body(), MAX_REGISTRATION_BYTES).collect(),
            )
            .await
            {
                Ok(Ok(body)) => body.to_bytes(),
                _ => {
                    return error_response(
                        http::StatusCode::PAYLOAD_TOO_LARGE,
                        "registration body is invalid or too large",
                    );
                }
            };
            let registration = match serde_json::from_slice::<SandboxInstanceRegistration>(&body) {
                Ok(registration) if registration.route == route => registration,
                Ok(_) => {
                    return error_response(
                        http::StatusCode::BAD_REQUEST,
                        "registration route does not match the request path",
                    );
                }
                // Decoder errors can quote field values, including credentials.
                Err(_) => {
                    return error_response(
                        http::StatusCode::BAD_REQUEST,
                        "registration body is not a valid sandbox instance registration",
                    );
                }
            };
            match host.register(registration) {
                Ok(outcome) => {
                    let status = if outcome == SandboxInstanceAdmitted::Created {
                        http::StatusCode::CREATED
                    } else {
                        http::StatusCode::OK
                    };
                    host.status(&route).map_or_else(
                        || {
                            error_response(
                                http::StatusCode::CONFLICT,
                                "sandbox instance was removed",
                            )
                        },
                        |report| json_response(status, &report),
                    )
                }
                Err(error @ ControlError::Invalid(_)) => {
                    error_response(http::StatusCode::BAD_REQUEST, &error.to_string())
                }
                Err(error @ (ControlError::Conflict | ControlError::Removing)) => {
                    error_response(http::StatusCode::CONFLICT, &error.to_string())
                }
                Err(error @ ControlError::Unavailable(_)) => {
                    error_response(http::StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
                }
            }
        }
        (http::Method::DELETE, Some(route)) => host.remove(route).await.map_or_else(
            || {
                error_response(
                    http::StatusCode::NOT_FOUND,
                    "sandbox instance is not registered",
                )
            },
            |status| json_response(http::StatusCode::OK, &status),
        ),
        _ => error_response(http::StatusCode::NOT_FOUND, "unknown session-control route"),
    }
}

/// Serve the session-control API until `shutdown` completes. Every
/// connection must complete mutually authenticated TLS before any request.
pub async fn serve_session_control(
    host: Arc<SharedHost>,
    listener: tokio::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
    shutdown: impl Future<Output = ()>,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONTROL_CONNECTIONS));
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    continue;
                };
                openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                let acceptor = acceptor.clone();
                let host = host.clone();
                connections.spawn(async move {
                    let _slot = slot;
                    let Ok(Ok(stream)) =
                        tokio::time::timeout(CONTROL_IO_TIMEOUT, acceptor.accept(stream)).await
                    else {
                        tracing::debug!("rejected session-control connection without admission TLS");
                        return;
                    };
                    let service = hyper::service::service_fn(move |request| {
                        let host = host.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(handle_control(host, request).await)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(CONTROL_IO_TIMEOUT)
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}
