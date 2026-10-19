// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Several supervisor sessions in one process.
//!
//! Each session runs on its own Tokio runtime. Every thread that runtime
//! starts, and the thread driving it, is bound to the session's OCSF context,
//! OCSF JSON settings, log sink, and denial log, so tasks, callbacks,
//! reconnects, and credential renewal that the session spawns inherit its
//! identity. Unbound threads carry no sandbox identity and push no logs.
//! Gateway credentials are never bound to threads; each session passes its
//! own explicitly. Stopping a session shuts down only its runtime and revokes
//! its gateway credentials.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use miette::Result;
use openshell_core::grpc_client::GatewayCredentials;
use openshell_ocsf::{EventContext, OcsfJsonSettings};
use openshell_supervisor_network::policy_local::SessionDenialLog;
use openshell_supervisor_process::log_push::LogSink;
use tokio::sync::watch;

use crate::SessionControls;

/// Worker threads in each session runtime.
const SESSION_WORKER_THREADS: usize = 2;
/// Bound on joining a session thread after its runtime is told to stop.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-session values bound to every thread of the session's runtime.
#[derive(Clone)]
pub struct SessionBinding {
    pub event_context: Arc<EventContext>,
    pub ocsf_json: OcsfJsonSettings,
    pub log_sink: Option<LogSink>,
    pub denial_log: SessionDenialLog,
}

impl SessionBinding {
    fn bind(&self) {
        openshell_ocsf::ctx::bind_thread_ctx(Some(self.event_context.clone()));
        openshell_ocsf::bind_thread_json_settings(Some(self.ocsf_json.clone()));
        openshell_supervisor_process::log_push::bind_thread_sink(self.log_sink.clone());
        bind_thread_denial_log(Some(self.denial_log.clone()));
    }

    fn unbind() {
        openshell_ocsf::ctx::bind_thread_ctx(None);
        openshell_ocsf::bind_thread_json_settings(None);
        openshell_supervisor_process::log_push::bind_thread_sink(None);
        bind_thread_denial_log(None);
    }
}

std::thread_local! {
    static THREAD_DENIAL_LOG: std::cell::RefCell<Option<SessionDenialLog>> =
        const { std::cell::RefCell::new(None) };
}

fn bind_thread_denial_log(log: Option<SessionDenialLog>) {
    THREAD_DENIAL_LOG.with(|current| *current.borrow_mut() = log);
}

/// Shorthand-log destination for hosted sessions' recent denials.
///
/// Each line goes to the denial log of the session bound to the emitting
/// thread. Lines from unbound threads are dropped, so no session can read
/// another's denials through `policy.local`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SessionDenialWriter;

impl std::io::Write for SessionDenialWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        THREAD_DENIAL_LOG.with(|log| {
            if let Some(log) = log.borrow().as_ref() {
                for line in String::from_utf8_lossy(bytes).lines() {
                    log.record(line);
                }
            }
        });
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Observable lifecycle of one hosted session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionPhase {
    /// Startup has not yet produced an accepted gateway session.
    Starting,
    /// The workload started and the gateway accepted supervision at least once.
    Supervising,
    /// The owner asked the session to stop.
    Stopping,
    /// Supervision ended with the workload's exit status.
    Exited(i32),
    /// Startup or supervision failed; the workload is no longer supervised.
    Failed(String),
}

impl SessionPhase {
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Exited(_) | Self::Failed(_))
    }
}

/// Current state of one hosted session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStatus {
    pub phase: SessionPhase,
    /// Gateway supervision is currently accepted for this session.
    pub ready: bool,
}

/// Body of a hosted session, constructed on its own runtime.
pub type SessionBody =
    Box<dyn FnOnce(SessionControls) -> Pin<Box<dyn Future<Output = Result<i32>>>> + Send + 'static>;

/// The hosted-session registration was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionHostError {
    #[error("a session with this key is already hosted")]
    Duplicate,
    #[error("start session thread: {0}")]
    Thread(String),
}

struct HostedSession {
    /// Distinguishes this session from a later one that reuses its key.
    serial: u64,
    stop: watch::Sender<bool>,
    abort: watch::Sender<bool>,
    phase: watch::Receiver<SessionPhase>,
    ready: watch::Receiver<bool>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// Final status of the removal in progress, shared by every remover.
    removal: Option<watch::Receiver<Option<SessionStatus>>>,
}

impl HostedSession {
    fn status(&self) -> SessionStatus {
        let phase = self.phase.borrow().clone();
        // The runner always reports a terminal phase, even while unwinding;
        // a closed channel without one still means supervision has ended.
        if !phase.is_terminal() && self.phase.has_changed().is_err() {
            return SessionStatus {
                phase: SessionPhase::Failed("session thread ended unexpectedly".to_string()),
                ready: false,
            };
        }
        SessionStatus {
            phase,
            ready: *self.ready.borrow(),
        }
    }
}

type Sessions = Arc<Mutex<HashMap<String, HostedSession>>>;

fn lock(sessions: &Sessions) -> MutexGuard<'_, HashMap<String, HostedSession>> {
    sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Runs and stops supervisor sessions, each on its own bound runtime.
#[derive(Default)]
pub struct SessionHost {
    sessions: Sessions,
    next_serial: AtomicU64,
}

impl SessionHost {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Start `body` on a new runtime bound to `binding`.
    ///
    /// `credentials`, when present, are revoked once the session's runtime has
    /// stopped, so nothing can reuse them after the session ends.
    ///
    /// # Errors
    ///
    /// Returns [`SessionHostError::Duplicate`] when `key` is already hosted,
    /// including a session that ended but has not been removed.
    pub fn start(
        &self,
        key: &str,
        binding: SessionBinding,
        credentials: Option<GatewayCredentials>,
        body: SessionBody,
    ) -> std::result::Result<(), SessionHostError> {
        let mut sessions = lock(&self.sessions);
        if sessions.contains_key(key) {
            return Err(SessionHostError::Duplicate);
        }
        let (stop, stop_requested) = watch::channel(false);
        let (abort, abort_requested) = watch::channel(false);
        let (phase_tx, phase) = watch::channel(SessionPhase::Starting);
        let (ready_tx, ready) = watch::channel(false);
        let thread = std::thread::Builder::new()
            .name("openshell-session".to_string())
            .spawn(move || {
                run_hosted_session(
                    &binding,
                    credentials,
                    body,
                    SessionSignals {
                        stop_requested,
                        abort_requested,
                        phase: phase_tx,
                        ready: ready_tx,
                    },
                );
            })
            .map_err(|error| SessionHostError::Thread(error.to_string()))?;
        sessions.insert(
            key.to_string(),
            HostedSession {
                serial: self.next_serial.fetch_add(1, Ordering::Relaxed),
                stop,
                abort,
                phase,
                ready,
                thread: Some(thread),
                removal: None,
            },
        );
        Ok(())
    }

    /// Status of a hosted session, including one that ended but has not been
    /// removed.
    #[must_use]
    pub fn status(&self, key: &str) -> Option<SessionStatus> {
        lock(&self.sessions).get(key).map(HostedSession::status)
    }

    /// Keys of every hosted session.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        lock(&self.sessions).keys().cloned().collect()
    }

    /// Stop one session and forget it. Other sessions keep running.
    ///
    /// A supervising session terminates its workload gracefully within
    /// `grace`; one still starting is cancelled at once, because startup has
    /// no safe intermediate state to wind down. Removal runs on its own task,
    /// so it completes even when the caller stops waiting, and concurrent
    /// callers share it and its result. The key stays registered until the
    /// session's thread has finished, so the same key cannot start a second
    /// owner while this one is stopping. Returns the final status, or `None`
    /// when `key` is not hosted.
    pub async fn remove(&self, key: &str, grace: Duration) -> Option<SessionStatus> {
        let (mut removed, phase) = self.begin_removal(key, grace)?;
        // The removal task ends without a report only with its runtime.
        removed
            .wait_for(Option::is_some)
            .await
            .map_or_else(|_| Some(terminal_status(&phase)), |status| status.clone())
    }

    fn begin_removal(
        &self,
        key: &str,
        grace: Duration,
    ) -> Option<(
        watch::Receiver<Option<SessionStatus>>,
        watch::Receiver<SessionPhase>,
    )> {
        let mut sessions = lock(&self.sessions);
        let session = sessions.get_mut(key)?;
        if let Some(removed) = &session.removal {
            return Some((removed.clone(), session.phase.clone()));
        }
        session.stop.send_replace(true);
        if *session.phase.borrow() == SessionPhase::Starting {
            session.abort.send_replace(true);
        }
        let (report, removed) = watch::channel(None);
        session.removal = Some(removed.clone());
        tokio::spawn(
            Removal {
                sessions: self.sessions.clone(),
                key: key.to_string(),
                serial: session.serial,
                phase: session.phase.clone(),
                thread: session.thread.take(),
                grace,
                report,
            }
            .run(),
        );
        Some((removed, session.phase.clone()))
    }
}

fn terminal_status(phase: &watch::Receiver<SessionPhase>) -> SessionStatus {
    SessionStatus {
        phase: phase.borrow().clone(),
        ready: false,
    }
}

/// The single owner of one session's removal.
struct Removal {
    sessions: Sessions,
    key: String,
    serial: u64,
    phase: watch::Receiver<SessionPhase>,
    thread: Option<std::thread::JoinHandle<()>>,
    grace: Duration,
    report: watch::Sender<Option<SessionStatus>>,
}

impl Removal {
    async fn run(mut self) {
        let finished =
            tokio::time::timeout(self.grace, self.phase.wait_for(SessionPhase::is_terminal))
                .await
                .is_ok();
        if !finished
            && let Some(session) = lock(&self.sessions)
                .get(&self.key)
                .filter(|session| session.serial == self.serial)
        {
            session.abort.send_replace(true);
        }
        if let Some(thread) = self.thread.take() {
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
        }
        let removed = {
            let mut sessions = lock(&self.sessions);
            match sessions.get(&self.key) {
                Some(session) if session.serial == self.serial => sessions.remove(&self.key),
                _ => None,
            }
        };
        let status =
            removed.map_or_else(|| terminal_status(&self.phase), |session| session.status());
        self.report.send_replace(Some(status));
    }
}

struct SessionSignals {
    stop_requested: watch::Receiver<bool>,
    abort_requested: watch::Receiver<bool>,
    phase: watch::Sender<SessionPhase>,
    ready: watch::Sender<bool>,
}

/// Reports a hosted session's end and revokes its credentials, including when
/// the session thread unwinds.
struct SessionExit {
    credentials: Option<GatewayCredentials>,
    phase: watch::Sender<SessionPhase>,
    ready: watch::Sender<bool>,
    outcome: Option<SessionPhase>,
}

impl Drop for SessionExit {
    fn drop(&mut self) {
        if let Some(credentials) = self.credentials.take() {
            credentials.revoke();
        }
        self.ready.send_replace(false);
        let outcome = self.outcome.take().unwrap_or_else(|| {
            SessionPhase::Failed("session thread ended without reporting a result".to_string())
        });
        self.phase.send_replace(outcome);
        SessionBinding::unbind();
    }
}

fn run_hosted_session(
    binding: &SessionBinding,
    credentials: Option<GatewayCredentials>,
    body: SessionBody,
    signals: SessionSignals,
) {
    let SessionSignals {
        stop_requested,
        mut abort_requested,
        phase,
        ready,
    } = signals;
    let mut exit = SessionExit {
        credentials,
        phase: phase.clone(),
        ready: ready.clone(),
        outcome: None,
    };
    binding.bind();
    let thread_binding = binding.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(SESSION_WORKER_THREADS)
        .thread_name("openshell-session-worker")
        .enable_all()
        .on_thread_start(move || thread_binding.bind())
        .on_thread_stop(SessionBinding::unbind)
        .build();
    let outcome = match runtime {
        Ok(runtime) => {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                runtime.block_on(async {
                    let (readiness, mut accepted) = watch::channel(false);
                    let mirror_phase = phase.clone();
                    let mirror_ready = ready.clone();
                    let mirror = tokio::spawn(async move {
                        loop {
                            let is_ready = *accepted.borrow_and_update();
                            mirror_ready.send_replace(is_ready);
                            if is_ready {
                                mirror_phase.send_if_modified(|current| {
                                    let promote = *current == SessionPhase::Starting;
                                    if promote {
                                        *current = SessionPhase::Supervising;
                                    }
                                    promote
                                });
                            }
                            if accepted.changed().await.is_err() {
                                mirror_ready.send_replace(false);
                                return;
                            }
                        }
                    });
                    let mut stop = stop_requested.clone();
                    let stop_phase = phase.clone();
                    let shutdown = Box::pin(async move {
                        let _ = stop.wait_for(|requested| *requested).await;
                        stop_phase.send_replace(SessionPhase::Stopping);
                    });
                    let session = body(SessionControls {
                        shutdown,
                        readiness,
                    });
                    let outcome = tokio::select! {
                        result = session => result,
                        _ = abort_requested.wait_for(|requested| *requested) => {
                            Err(miette::miette!("session was cancelled before it finished"))
                        }
                    };
                    mirror.abort();
                    outcome
                })
            }));
            runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
            outcome.unwrap_or_else(|_| Err(miette::miette!("session panicked")))
        }
        Err(error) => Err(miette::miette!("build session runtime: {error}")),
    };
    exit.outcome = Some(match outcome {
        Ok(code) => SessionPhase::Exited(code),
        Err(error) => SessionPhase::Failed(error.to_string()),
    });
}

/// Trusted inputs for one supervisor session hosted with others.
pub struct HostedSessionSpec {
    /// Unique key for this generation within the host.
    pub key: String,
    pub backend_setup: Box<dyn crate::backend_setup::BackendSetup + Send>,
    pub config: crate::SessionConfig,
    /// Workload image recorded in this session's OCSF events.
    pub container_image: String,
}

impl SessionHost {
    /// Start a supervisor session with its own OCSF identity, OCSF JSON
    /// settings, log push stream, denial log, and gateway credentials.
    ///
    /// # Errors
    ///
    /// Fails when the launch credentials are invalid or the key is hosted.
    pub fn start_supervisor_session(&self, spec: HostedSessionSpec) -> Result<()> {
        let HostedSessionSpec {
            key,
            backend_setup,
            mut config,
            container_image,
        } = spec;
        let credentials = GatewayCredentials::from_auth_bundle(&config.auth_bundle)?;
        // Sessions must never share proxy trust files; give one a private
        // directory that lives exactly as long as the session.
        let private_tls_dir = if config.proxy_tls.directory.is_none() {
            let prepared = crate::prepare_network_proxy_tls_dir(None)?;
            config.proxy_tls.directory = Some(prepared.path.clone());
            Some(prepared)
        } else {
            None
        };
        let gateway = config.openshell_endpoint.as_deref().map(|endpoint| {
            openshell_core::grpc_client::GatewayEndpoint::new(endpoint, credentials.clone())
        });
        let (log_tx, log_rx) = tokio::sync::mpsc::channel(
            openshell_supervisor_process::log_push::LOG_PUSH_QUEUE_LINES,
        );
        let log_push = config.sandbox_id.clone().zip(gateway);
        let binding = SessionBinding {
            event_context: Arc::new(crate::session_event_context(
                config.sandbox_id.as_deref(),
                config.sandbox.as_deref(),
                container_image,
            )),
            ocsf_json: OcsfJsonSettings::default(),
            log_sink: log_push
                .as_ref()
                .map(|(sandbox_id, _)| LogSink::new(sandbox_id.as_str(), log_tx)),
            denial_log: SessionDenialLog::default(),
        };
        config.gateway_credentials = Some(credentials.clone());
        config.ocsf_json = binding.ocsf_json.clone();
        config.denial_log = openshell_supervisor_network::policy_local::DenialLogSource::Session(
            binding.denial_log.clone(),
        );
        let body: SessionBody = Box::new(move |controls| {
            Box::pin(async move {
                let _private_tls_dir = private_tls_dir;
                let _log_push = log_push.map(|(sandbox_id, gateway)| {
                    openshell_supervisor_process::log_push::start_log_push(
                        gateway, sandbox_id, log_rx,
                    )
                });
                Box::pin(crate::run_session(backend_setup.as_ref(), config, controls)).await
            })
        });
        self.start(&key, binding, Some(credentials), body)
            .map_err(|error| miette::miette!("{error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;
    use openshell_core::grpc_client::GatewayEndpoint;
    use openshell_core::proto::SandboxLogLine;
    use tokio::sync::mpsc;
    use tracing_subscriber::layer::SubscriberExt as _;

    type Captured = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// Records each gRPC request's bearer and body, then answers `UNIMPLEMENTED`.
    async fn capture_gateway() -> (String, Captured) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let captured = Captured::default();
        let sink = captured.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let sink = sink.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |request: http::Request<hyper::body::Incoming>| {
                            let sink = sink.clone();
                            async move {
                                let authorization = request
                                    .headers()
                                    .get("authorization")
                                    .and_then(|value| value.to_str().ok())
                                    .unwrap_or_default()
                                    .to_string();
                                let body = request
                                    .into_body()
                                    .collect()
                                    .await
                                    .map(|body| body.to_bytes().to_vec())
                                    .unwrap_or_default();
                                sink.lock().unwrap().push((authorization, body));
                                http::Response::builder()
                                    .header("content-type", "application/grpc")
                                    .header("grpc-status", "12")
                                    .body(http_body_util::Empty::<bytes::Bytes>::new())
                            }
                        },
                    );
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
                });
            }
        });
        (format!("http://{address}"), captured)
    }

    fn bearers_for(captured: &Captured, sandbox: &str) -> Vec<String> {
        captured
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, body)| {
                body.windows(sandbox.len())
                    .any(|bytes| bytes == sandbox.as_bytes())
            })
            .map(|(authorization, _)| authorization.clone())
            .collect()
    }

    struct Session {
        identity: tokio::sync::oneshot::Receiver<String>,
        logs: mpsc::Receiver<SandboxLogLine>,
        call_again: mpsc::Sender<()>,
        alive: mpsc::Receiver<()>,
        credentials: GatewayCredentials,
    }

    fn start_session(host: &SessionHost, gateway_url: &str, sandbox: &'static str) -> Session {
        let credentials =
            GatewayCredentials::from_gateway_token(&format!("token-{sandbox}")).unwrap();
        let gateway = GatewayEndpoint::new(gateway_url, credentials.clone());
        let (log_tx, logs) = mpsc::channel(16);
        let binding = SessionBinding {
            event_context: Arc::new(crate::session_event_context(
                Some(sandbox),
                Some(sandbox),
                String::new(),
            )),
            ocsf_json: OcsfJsonSettings::default(),
            log_sink: Some(LogSink::new(sandbox, log_tx)),
            denial_log: SessionDenialLog::default(),
        };
        let (identity_tx, identity) = tokio::sync::oneshot::channel();
        let (call_again, mut calls) = mpsc::channel(1);
        let (alive_tx, alive) = mpsc::channel::<()>(1);
        let body: SessionBody = Box::new(move |controls| {
            Box::pin(async move {
                let SessionControls {
                    shutdown,
                    readiness,
                } = controls;
                // Nested tasks and the blocking pool inherit the session identity.
                let observed = tokio::spawn(async {
                    tokio::task::spawn_blocking(|| openshell_ocsf::ctx::ctx().sandbox_id.clone())
                        .await
                        .unwrap()
                })
                .await
                .unwrap();
                let _ = identity_tx.send(observed);
                let _ =
                    openshell_core::grpc_client::fetch_settings_snapshot(&gateway, sandbox).await;
                let dispatch = tracing::Dispatch::new(
                    tracing_subscriber::registry()
                        .with(openshell_supervisor_process::log_push::LogPushLayer::thread_bound()),
                );
                tokio::spawn(async move {
                    tracing::dispatcher::with_default(&dispatch, || {
                        tracing::info!(target: "session_test", "emitted by {sandbox}");
                    });
                })
                .await
                .unwrap();
                // A long-lived task the session never stops itself.
                tokio::spawn(async move {
                    let _alive = alive_tx;
                    std::future::pending::<()>().await;
                });
                readiness.send_replace(true);
                tokio::pin!(shutdown);
                loop {
                    tokio::select! {
                        () = &mut shutdown => return Ok(0),
                        Some(()) = calls.recv() => {
                            let _ = openshell_core::grpc_client::fetch_settings_snapshot(
                                &gateway, sandbox,
                            )
                            .await;
                        }
                    }
                }
            })
        });
        host.start(sandbox, binding, Some(credentials.clone()), body)
            .unwrap();
        Session {
            identity,
            logs,
            call_again,
            alive,
            credentials,
        }
    }

    async fn wait_supervising(host: &SessionHost, key: &str) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while host.status(key).map(|status| status.phase) != Some(SessionPhase::Supervising) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("session reaches supervision");
    }

    fn unbound() -> SessionBinding {
        SessionBinding {
            event_context: Arc::new(crate::session_event_context(None, None, String::new())),
            ocsf_json: OcsfJsonSettings::default(),
            log_sink: None,
            denial_log: SessionDenialLog::default(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stopping_and_panicking_sessions_keep_their_key_and_fail_closed() {
        let host = Arc::new(SessionHost::new());
        let body: SessionBody = Box::new(|controls| {
            Box::pin(async move {
                controls.readiness.send_replace(true);
                controls.shutdown.await;
                // Winding down takes time; the key must stay taken meanwhile.
                tokio::time::sleep(Duration::from_millis(300)).await;
                Ok(0)
            })
        });
        host.start("generation", unbound(), None, body).unwrap();
        wait_supervising(&host, "generation").await;
        let removal = tokio::spawn({
            let host = host.clone();
            async move { host.remove("generation", Duration::from_secs(10)).await }
        });
        tokio::time::timeout(Duration::from_secs(10), async {
            while host.status("generation").map(|status| status.phase)
                != Some(SessionPhase::Stopping)
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("session observes the stop request");
        let replacement: SessionBody = Box::new(|_| Box::pin(async { Ok(0) }));
        assert_eq!(
            host.start("generation", unbound(), None, replacement),
            Err(SessionHostError::Duplicate)
        );
        let stopped = removal.await.unwrap().expect("session was hosted");
        assert_eq!(stopped.phase, SessionPhase::Exited(0));
        assert!(host.status("generation").is_none());

        let credentials = GatewayCredentials::from_gateway_token("panicking-token").unwrap();
        let panicking: SessionBody = Box::new(|controls| {
            Box::pin(async move {
                controls.readiness.send_replace(true);
                tokio::task::yield_now().await;
                panic!("hosted session failure");
            })
        });
        host.start("panicking", unbound(), Some(credentials.clone()), panicking)
            .unwrap();
        let status = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = host.status("panicking")
                    && status.phase.is_terminal()
                {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("panicking session reports an end");
        assert_eq!(
            status,
            SessionStatus {
                phase: SessionPhase::Failed("session panicked".to_string()),
                ready: false,
            }
        );
        let revoked = GatewayEndpoint::new("http://127.0.0.1:9", credentials);
        let error = openshell_core::grpc_client::fetch_settings_snapshot(&revoked, "panicking")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("revoked"), "{error}");
        assert!(
            host.remove("panicking", Duration::from_secs(1))
                .await
                .is_some()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn removal_outlives_its_caller_and_reports_to_every_remover() {
        let host = Arc::new(SessionHost::new());
        let winding_down = |code| -> SessionBody {
            Box::new(move |controls| {
                Box::pin(async move {
                    controls.readiness.send_replace(true);
                    controls.shutdown.await;
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    Ok(code)
                })
            })
        };
        host.start("generation", unbound(), None, winding_down(3))
            .unwrap();
        wait_supervising(&host, "generation").await;
        // A caller that gives up, such as an expired RPC, strands nothing.
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                host.remove("generation", Duration::from_secs(10))
            )
            .await
            .is_err()
        );
        let removers = [(); 2].map(|()| {
            let host = host.clone();
            tokio::spawn(async move { host.remove("generation", Duration::from_secs(10)).await })
        });
        for remover in removers {
            let status = remover.await.unwrap().expect("session was hosted");
            assert_eq!(status.phase, SessionPhase::Exited(3));
        }
        assert!(host.status("generation").is_none());

        // The key is free again, and the earlier removal cannot touch its new owner.
        host.start("generation", unbound(), None, winding_down(4))
            .unwrap();
        wait_supervising(&host, "generation").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            host.status("generation").map(|status| status.phase),
            Some(SessionPhase::Supervising)
        );
        let status = host.remove("generation", Duration::from_secs(10)).await;
        assert_eq!(
            status.map(|status| status.phase),
            Some(SessionPhase::Exited(4))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hosted_sessions_keep_identity_credentials_and_lifecycle_separate() {
        let (gateway_url, captured) = capture_gateway().await;
        let host = SessionHost::new();
        let mut alpha = start_session(&host, &gateway_url, "sandbox-alpha");
        let mut beta = start_session(&host, &gateway_url, "sandbox-beta");
        wait_supervising(&host, "sandbox-alpha").await;
        wait_supervising(&host, "sandbox-beta").await;
        assert!(matches!(
            host.start(
                "sandbox-alpha",
                SessionBinding {
                    event_context: Arc::new(crate::session_event_context(
                        None,
                        None,
                        String::new()
                    )),
                    ocsf_json: OcsfJsonSettings::default(),
                    log_sink: None,
                    denial_log: SessionDenialLog::default(),
                },
                None,
                Box::new(|_| Box::pin(async { Ok(0) })),
            ),
            Err(SessionHostError::Duplicate)
        ));

        assert_eq!((&mut alpha.identity).await.unwrap(), "sandbox-alpha");
        assert_eq!((&mut beta.identity).await.unwrap(), "sandbox-beta");
        // Other tests in this process may set the process-wide context; a
        // thread outside every session must still carry no session identity.
        let outside = openshell_ocsf::ctx::ctx().sandbox_id.clone();
        assert!(!["sandbox-alpha", "sandbox-beta"].contains(&outside.as_str()));
        assert_eq!(
            bearers_for(&captured, "sandbox-alpha"),
            ["Bearer token-sandbox-alpha"]
        );
        assert_eq!(
            bearers_for(&captured, "sandbox-beta"),
            ["Bearer token-sandbox-beta"]
        );
        for (session, sandbox) in [(&mut alpha, "sandbox-alpha"), (&mut beta, "sandbox-beta")] {
            let line = session.logs.try_recv().expect("session log line");
            assert_eq!(line.sandbox_id, sandbox);
            assert_eq!(line.message, format!("emitted by {sandbox}"));
            assert!(session.logs.try_recv().is_err());
        }

        let stopped = host
            .remove("sandbox-alpha", Duration::from_secs(10))
            .await
            .expect("alpha was hosted");
        assert_eq!(stopped.phase, SessionPhase::Exited(0));
        assert!(!stopped.ready);
        assert!(host.status("sandbox-alpha").is_none());
        assert_eq!(alpha.alive.recv().await, None, "alpha's tasks stopped");
        let revoked = GatewayEndpoint::new(gateway_url.as_str(), alpha.credentials.clone());
        let error = openshell_core::grpc_client::fetch_settings_snapshot(&revoked, "sandbox-alpha")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("revoked"), "{error}");

        beta.call_again.send(()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while bearers_for(&captured, "sandbox-beta").len() < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("beta keeps calling the gateway");
        assert_eq!(
            bearers_for(&captured, "sandbox-beta"),
            ["Bearer token-sandbox-beta", "Bearer token-sandbox-beta"]
        );
        assert_eq!(
            host.status("sandbox-beta").map(|status| status.phase),
            Some(SessionPhase::Supervising)
        );
        assert!(
            beta.alive
                .try_recv()
                .is_err_and(|error| error == mpsc::error::TryRecvError::Empty)
        );

        let stopped = host.remove("sandbox-beta", Duration::from_secs(10)).await;
        assert_eq!(
            stopped.map(|status| status.phase),
            Some(SessionPhase::Exited(0))
        );
    }
}
