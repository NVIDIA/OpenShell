// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor shared by the sandboxes of one gateway.
//!
//! A compute driver registers each runtime generation over the
//! session-control API, which accepts only mutually authenticated TLS clients
//! holding the admission certificate. A registration carries exactly the
//! gateway-issued credentials of that generation; the host never acts with
//! any other identity. Each registration becomes a [`SessionHost`] session
//! whose runtime connections arrive through one routed listener. Removing a
//! registration stops only that session.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_sandbox_backend::runtime_routed::RuntimeRouter;
use openshell_sandbox_backend::session_control::{
    MAX_REGISTRATION_BYTES, SESSIONS_PATH, SessionList, SessionPhaseReport, SessionRegistration,
    SessionStatusReport,
};
use tokio::sync::watch;

use crate::session_host::{HostedSessionSpec, SessionHost, SessionPhase, SessionStatus};

/// Concurrent session-control connections; the only client is the gateway,
/// whose removals hold a connection while a workload stops.
const MAX_CONTROL_CONNECTIONS: usize = 64;
/// Bound on a TLS handshake and on reading one request.
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Process-level inputs of a shared supervisor.
pub struct SharedHostConfig {
    /// Gateway gRPC endpoint every session uses with its own credentials.
    pub gateway_endpoint: String,
    /// Private directory for per-session files.
    pub session_root: PathBuf,
    /// Listener for runtime-initiated Sandbox Protocol connections.
    pub runtime_listen: SocketAddr,
    /// Time a removed session may take to stop its workload.
    pub removal_grace: Duration,
}

struct Registered {
    /// Distinguishes this registration from a later one of the same route.
    serial: u64,
    digest: [u8; 32],
    sandbox_id: String,
    /// Final status of the removal in progress, shared by every remover.
    removal: Option<watch::Receiver<Option<SessionStatusReport>>>,
}

type Registrations = Mutex<HashMap<String, Registered>>;

fn lock(registrations: &Registrations) -> MutexGuard<'_, HashMap<String, Registered>> {
    registrations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Registered sessions, their runtime router, and their private files.
pub struct SharedHost {
    host: SessionHost,
    router: Arc<RuntimeRouter>,
    registrations: Registrations,
    next_serial: AtomicU64,
    config: SharedHostConfig,
}

/// Outcome of a registration request.
#[derive(Debug, PartialEq, Eq)]
pub enum RegisterOutcome {
    Created,
    /// The identical registration already exists.
    Unchanged,
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

impl SharedHost {
    /// Bind the routed runtime listener and prepare the session root.
    pub fn start(config: SharedHostConfig) -> Result<Arc<Self>> {
        prepare_private_dir(&config.session_root)?;
        let router = RuntimeRouter::bind(config.runtime_listen)
            .map_err(|error| miette::miette!("{error}"))?;
        Ok(Arc::new(Self {
            host: SessionHost::new(),
            router,
            registrations: Mutex::default(),
            next_serial: AtomicU64::new(0),
            config,
        }))
    }

    /// Address of the routed runtime listener.
    #[must_use]
    pub fn runtime_addr(&self) -> SocketAddr {
        self.router.local_addr()
    }

    /// Start a session for `registration`, or confirm an identical one.
    pub fn register(
        &self,
        registration: SessionRegistration,
    ) -> Result<RegisterOutcome, ControlError> {
        registration
            .validate()
            .map_err(|error| ControlError::Invalid(error.to_string()))?;
        let digest = registration_digest(&registration)?;
        let route = registration.route.clone();
        let sandbox_id = registration.sandbox_id.clone();
        self.admit(&route, digest, sandbox_id, |session_dir| {
            let spec = self.session_spec(registration, session_dir)?;
            self.host
                .start_supervisor_session(spec)
                .map_err(|error| ControlError::Unavailable(error.to_string()))
        })
    }

    /// Reserve `route` and run `start` with the session's private directory.
    fn admit(
        &self,
        route: &str,
        digest: [u8; 32],
        sandbox_id: String,
        start: impl FnOnce(&Path) -> Result<(), ControlError>,
    ) -> Result<RegisterOutcome, ControlError> {
        let mut registrations = lock(&self.registrations);
        if let Some(existing) = registrations.get(route) {
            return if existing.removal.is_some() {
                Err(ControlError::Removing)
            } else if existing.digest == digest {
                Ok(RegisterOutcome::Unchanged)
            } else {
                Err(ControlError::Conflict)
            };
        }
        let session_dir = self.config.session_root.join(route);
        if let Err(error) = start(&session_dir) {
            let _ = std::fs::remove_dir_all(&session_dir);
            return Err(error);
        }
        registrations.insert(
            route.to_string(),
            Registered {
                serial: self.next_serial.fetch_add(1, Ordering::Relaxed),
                digest,
                sandbox_id,
                removal: None,
            },
        );
        Ok(RegisterOutcome::Created)
    }

    /// Status of one registered session.
    #[must_use]
    pub fn status(&self, route: &str) -> Option<SessionStatusReport> {
        let sandbox_id = lock(&self.registrations).get(route)?.sandbox_id.clone();
        let status = self.host.status(route)?;
        Some(status_report(route, sandbox_id, &status))
    }

    /// Status of every registered session.
    #[must_use]
    pub fn list(&self) -> SessionList {
        let routes = lock(&self.registrations)
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        SessionList {
            sessions: routes
                .iter()
                .filter_map(|route| self.status(route))
                .collect(),
        }
    }

    /// Stop one session, delete its private files, and forget it.
    ///
    /// Removal runs on a task the host owns, so it completes even when the
    /// caller disconnects, and concurrent callers share its result. The
    /// route stays reserved until the session has ended and its files are
    /// gone, so a new registration of the route can never meet them.
    pub async fn remove(self: &Arc<Self>, route: &str) -> Option<SessionStatusReport> {
        let mut removed = self.begin_removal(route)?;
        removed
            .wait_for(Option::is_some)
            .await
            .ok()
            .and_then(|report| report.clone())
    }

    fn begin_removal(
        self: &Arc<Self>,
        route: &str,
    ) -> Option<watch::Receiver<Option<SessionStatusReport>>> {
        let mut registrations = lock(&self.registrations);
        let registered = registrations.get_mut(route)?;
        if let Some(removed) = &registered.removal {
            return Some(removed.clone());
        }
        let (report, removed) = watch::channel(None);
        registered.removal = Some(removed.clone());
        let serial = registered.serial;
        let sandbox_id = registered.sandbox_id.clone();
        let shared = Arc::clone(self);
        let route = route.to_string();
        tokio::spawn(async move {
            let status = shared
                .host
                .remove(&route, shared.config.removal_grace)
                .await
                .unwrap_or_else(|| SessionStatus {
                    phase: SessionPhase::Failed("session was not running".to_string()),
                    ready: false,
                });
            let session_dir = shared.config.session_root.join(&route);
            let _ =
                tokio::task::spawn_blocking(move || match std::fs::remove_dir_all(&session_dir) {
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                        tracing::warn!(%error, "could not delete removed session files");
                    }
                    _ => {}
                })
                .await;
            {
                let mut registrations = lock(&shared.registrations);
                if registrations
                    .get(&route)
                    .is_some_and(|registered| registered.serial == serial)
                {
                    registrations.remove(&route);
                }
            }
            report.send_replace(Some(status_report(&route, sandbox_id, &status)));
        });
        Some(removed)
    }

    /// Stop every session, for process shutdown.
    pub async fn remove_all(self: &Arc<Self>) {
        let routes = lock(&self.registrations)
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        futures::future::join_all(routes.iter().map(|route| self.remove(route))).await;
    }

    fn session_spec(
        &self,
        registration: SessionRegistration,
        session_dir: &Path,
    ) -> Result<HostedSessionSpec, ControlError> {
        let failure = |error: miette::Report| ControlError::Unavailable(error.to_string());
        let main_process =
            openshell_core::sandbox_env::MainProcessConfig::decode(&registration.main_process_spec)
                .map_err(ControlError::Invalid)?;
        let descriptor = registration
            .runtime_descriptor
            .backend_descriptor()
            .map_err(|error| ControlError::Invalid(error.to_string()))?;
        if session_dir.exists() {
            std::fs::remove_dir_all(session_dir)
                .into_diagnostic()
                .map_err(failure)?;
        }
        prepare_private_dir(session_dir).map_err(failure)?;
        let ca_certificate = session_dir.join("proxy-ca.crt");
        let ca_private_key = session_dir.join("proxy-ca.key");
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
        let trust_dir = session_dir.join("trust");
        prepare_private_dir(&trust_dir).map_err(failure)?;
        let ssh_socket = session_dir.join("ssh.sock");
        Ok(HostedSessionSpec {
            key: registration.route.clone(),
            backend_setup: Box::new(crate::backend_setup::RoutedBackendSetup::new(
                self.router.clone(),
                registration.route,
            )),
            config: crate::SessionConfig {
                command: main_process.command,
                workdir: registration.workdir,
                timeout_secs: 0,
                interactive: main_process.tty,
                await_main_process_attachment: main_process.await_main_process_attachment,
                sandbox_id: Some(registration.sandbox_id),
                sandbox: Some(registration.sandbox_name),
                openshell_endpoint: Some(self.config.gateway_endpoint.clone()),
                policy_rules: None,
                policy_data: None,
                ssh_socket_path: Some(ssh_socket.to_string_lossy().into_owned()),
                shared_ssh_socket: false,
                ocsf_json: openshell_ocsf::OcsfJsonSettings::default(),
                // The Kubernetes driver refuses the gateway topology when an
                // upstream proxy or provider workload identity is configured,
                // and it configures no extra CA for dedicated supervisors.
                upstream_proxy_args:
                    openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs::default(),
                additional_ca_bundle: None,
                backend_descriptor: descriptor,
                auth_bundle: registration.auth,
                gateway_credentials: None,
                admitted_isolation_backend: Some(
                    openshell_sandbox_backend::BACKEND_NAME.to_string(),
                ),
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
                denial_log: openshell_supervisor_network::policy_local::DenialLogSource::default(),
            },
            container_image: registration.container_image,
        })
    }
}

fn registration_digest(registration: &SessionRegistration) -> Result<[u8; 32], ControlError> {
    let encoded = serde_json::to_vec(registration)
        .map_err(|error| ControlError::Invalid(format!("encode registration: {error}")))?;
    openshell_crypto::sha256(&encoded).map_err(|error| ControlError::Unavailable(error.to_string()))
}

fn status_report(route: &str, sandbox_id: String, status: &SessionStatus) -> SessionStatusReport {
    SessionStatusReport {
        route: route.to_string(),
        sandbox_id,
        phase: match &status.phase {
            SessionPhase::Starting => SessionPhaseReport::Starting,
            SessionPhase::Supervising => SessionPhaseReport::Supervising,
            SessionPhase::Stopping => SessionPhaseReport::Stopping,
            SessionPhase::Exited(code) => SessionPhaseReport::Exited { exit_code: *code },
            SessionPhase::Failed(error) => SessionPhaseReport::Failed {
                error: error.clone(),
            },
        },
        ready: status.ready,
    }
}

#[cfg(unix)]
fn prepare_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path).into_diagnostic()?;
            if !metadata.is_dir() {
                return Err(miette::miette!(
                    "session path is not a directory: {}",
                    path.display()
                ));
            }
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .into_diagnostic()?;
        }
        Err(error) => {
            return Err(error)
                .into_diagnostic()
                .wrap_err_with(|| format!("create private directory {}", path.display()));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_private_dir(_path: &Path) -> Result<()> {
    Err(miette::miette!("shared supervision requires a Unix host"))
}

#[cfg(unix)]
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
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
            || error_response(http::StatusCode::NOT_FOUND, "session is not registered"),
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
            let registration = match serde_json::from_slice::<SessionRegistration>(&body) {
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
                        "registration body is not a valid session registration",
                    );
                }
            };
            match host.register(registration) {
                Ok(outcome) => {
                    let status = if outcome == RegisterOutcome::Created {
                        http::StatusCode::CREATED
                    } else {
                        http::StatusCode::OK
                    };
                    host.status(&route).map_or_else(
                        || error_response(http::StatusCode::CONFLICT, "session was removed"),
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
            || error_response(http::StatusCode::NOT_FOUND, "session is not registered"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_host::{SessionBinding, SessionBody};

    fn shared_host(root: &Path) -> Arc<SharedHost> {
        SharedHost::start(SharedHostConfig {
            gateway_endpoint: "http://127.0.0.1:9".to_string(),
            session_root: root.to_path_buf(),
            runtime_listen: "127.0.0.1:0".parse().unwrap(),
            removal_grace: Duration::from_secs(10),
        })
        .unwrap()
    }

    /// Admit a session that keeps a private file and takes a while to stop.
    fn admit(host: &SharedHost, route: &str, launch: u8) -> Result<RegisterOutcome, ControlError> {
        host.admit(route, [launch; 32], format!("sandbox-{launch}"), |dir| {
            let unavailable = |error: miette::Report| ControlError::Unavailable(error.to_string());
            prepare_private_dir(dir).map_err(unavailable)?;
            write_private_file(&dir.join("launch"), &[launch]).map_err(unavailable)?;
            let body: SessionBody = Box::new(|controls| {
                Box::pin(async move {
                    controls.readiness.send_replace(true);
                    controls.shutdown.await;
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    Ok(0)
                })
            });
            let binding = SessionBinding {
                event_context: Arc::new(crate::session_event_context(None, None, String::new())),
                ocsf_json: openshell_ocsf::OcsfJsonSettings::default(),
                log_sink: None,
                denial_log: openshell_supervisor_network::policy_local::SessionDenialLog::default(),
            };
            host.host
                .start(route, binding, None, body)
                .map_err(|error| ControlError::Unavailable(error.to_string()))
        })
    }

    async fn wait_ready(host: &SharedHost, route: &str) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !host.status(route).is_some_and(|status| status.ready) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("session becomes ready");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_route_stays_reserved_until_its_single_removal_finishes() {
        let root = tempfile::tempdir().unwrap();
        let host = shared_host(root.path());
        let route = "route-a";
        assert_eq!(admit(&host, route, 1).unwrap(), RegisterOutcome::Created);
        assert_eq!(admit(&host, route, 1).unwrap(), RegisterOutcome::Unchanged);
        assert!(matches!(
            admit(&host, route, 2),
            Err(ControlError::Conflict)
        ));
        wait_ready(&host, route).await;

        // A disconnected caller still removes the session.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), host.remove(route))
                .await
                .is_err()
        );
        assert!(matches!(
            admit(&host, route, 1),
            Err(ControlError::Removing)
        ));
        let removers = [(); 2].map(|()| {
            let host = host.clone();
            tokio::spawn(async move { host.remove(route).await })
        });
        for remover in removers {
            let report = remover.await.unwrap().expect("route was registered");
            assert_eq!(report.sandbox_id, "sandbox-1");
            assert_eq!(report.phase, SessionPhaseReport::Exited { exit_code: 0 });
        }
        assert!(host.status(route).is_none());
        assert!(!root.path().join(route).exists());

        // Nothing from the removed session reaches the route's next owner.
        assert_eq!(admit(&host, route, 3).unwrap(), RegisterOutcome::Created);
        wait_ready(&host, route).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::fs::read(root.path().join(route).join("launch")).unwrap(),
            [3]
        );
        assert_eq!(host.status(route).unwrap().sandbox_id, "sandbox-3");
        host.remove_all().await;
        assert!(host.list().sessions.is_empty());
    }
}
