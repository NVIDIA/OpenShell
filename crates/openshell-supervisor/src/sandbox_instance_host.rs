// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Several sandbox instances in one supervisor process.
//!
//! A sandbox instance is one running generation of a stable Sandbox
//! resource. Gateway transport connections, and the gateway supervisor
//! sessions carried over them, may reconnect within one instance without
//! creating another.
//!
//! Each instance runs on its own Tokio runtime. Every thread that runtime
//! starts, and the thread driving it, is bound to the instance's
//! [`SandboxInstanceBindings`]: OCSF context, OCSF JSON settings, log sink, and
//! denial log, so tasks, callbacks, reconnects, and credential renewal that the
//! instance spawns inherit its identity. Unbound threads carry no sandbox
//! identity and push no logs. Gateway credentials are never bound to threads;
//! each instance passes its own explicitly. Stopping an instance shuts down
//! only its runtime and revokes its gateway credentials.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use miette::Result;
use openshell_core::grpc_client::GatewayCredentials;
use openshell_ocsf::OcsfJsonSettings;
use openshell_supervisor_network::policy_local::{DenialLogSource, SandboxInstanceDenialLog};
use openshell_supervisor_process::log_push::LogSink;
use tokio::sync::watch;

use crate::{SandboxInstanceBindings, SandboxInstanceControls};

/// Worker threads in each sandbox instance runtime.
const INSTANCE_WORKER_THREADS: usize = 2;
/// Bound on joining an instance thread after its runtime is told to stop.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Bind the calling thread to one instance's bindings.
fn bind_thread(bindings: &SandboxInstanceBindings) {
    openshell_ocsf::ctx::bind_thread_ctx(Some(bindings.event_context.clone()));
    openshell_ocsf::bind_thread_json_settings(Some(bindings.ocsf_json.clone()));
    openshell_supervisor_process::log_push::bind_thread_sink(bindings.log_sink.clone());
    bind_thread_denial_log(match &bindings.denial_log {
        DenialLogSource::SandboxInstance(log) => Some(log.clone()),
        DenialLogSource::ShorthandFiles(_) => None,
    });
}

fn unbind_thread() {
    openshell_ocsf::ctx::bind_thread_ctx(None);
    openshell_ocsf::bind_thread_json_settings(None);
    openshell_supervisor_process::log_push::bind_thread_sink(None);
    bind_thread_denial_log(None);
}

std::thread_local! {
    static THREAD_DENIAL_LOG: std::cell::RefCell<Option<SandboxInstanceDenialLog>> =
        const { std::cell::RefCell::new(None) };
}

fn bind_thread_denial_log(log: Option<SandboxInstanceDenialLog>) {
    THREAD_DENIAL_LOG.with(|current| *current.borrow_mut() = log);
}

/// Shorthand-log destination for hosted sandbox instances' recent denials.
///
/// Each line goes to the denial log of the instance bound to the emitting
/// thread. Lines from unbound threads are dropped, so no instance can read
/// another's denials through `policy.local`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SandboxInstanceDenialWriter;

impl std::io::Write for SandboxInstanceDenialWriter {
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

/// Observable lifecycle of one hosted sandbox instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SandboxInstancePhase {
    /// Startup has not yet produced an accepted gateway session.
    Starting,
    /// The workload started and the gateway accepted supervision at least once.
    Supervising,
    /// The owner asked the instance to stop.
    Stopping,
    /// Supervision ended with the workload's exit status.
    Exited(i32),
    /// Startup or supervision failed; the workload is no longer supervised.
    Failed(String),
}

impl SandboxInstancePhase {
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Exited(_) | Self::Failed(_))
    }
}

/// Current state of one hosted sandbox instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxInstanceStatus {
    pub phase: SandboxInstancePhase,
    /// Gateway supervision is currently accepted for this instance.
    pub ready: bool,
}

/// Body of a hosted sandbox instance, constructed on its own runtime.
pub type SandboxInstanceBody = Box<
    dyn FnOnce(SandboxInstanceControls) -> Pin<Box<dyn Future<Output = Result<i32>>>>
        + Send
        + 'static,
>;

/// The hosted sandbox instance registration was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SandboxInstanceHostError {
    #[error("a sandbox instance with this key is already hosted")]
    Duplicate,
    #[error("start sandbox instance thread: {0}")]
    Thread(String),
}

struct HostedSandboxInstance {
    /// Distinguishes this instance from a later one that reuses its key.
    serial: u64,
    stop: watch::Sender<bool>,
    abort: watch::Sender<bool>,
    phase: watch::Receiver<SandboxInstancePhase>,
    ready: watch::Receiver<bool>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// Final status of the removal in progress, shared by every remover.
    removal: Option<watch::Receiver<Option<SandboxInstanceStatus>>>,
}

impl HostedSandboxInstance {
    fn status(&self) -> SandboxInstanceStatus {
        let phase = self.phase.borrow().clone();
        // The runner always reports a terminal phase, even while unwinding;
        // a closed channel without one still means supervision has ended.
        if !phase.is_terminal() && self.phase.has_changed().is_err() {
            return SandboxInstanceStatus {
                phase: SandboxInstancePhase::Failed(
                    "sandbox instance thread ended unexpectedly".to_string(),
                ),
                ready: false,
            };
        }
        SandboxInstanceStatus {
            phase,
            ready: *self.ready.borrow(),
        }
    }
}

type Instances = Arc<Mutex<HashMap<String, HostedSandboxInstance>>>;

fn lock(instances: &Instances) -> MutexGuard<'_, HashMap<String, HostedSandboxInstance>> {
    instances
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Runs and stops sandbox instances, each on its own bound runtime.
#[derive(Default)]
pub struct SandboxInstanceHost {
    instances: Instances,
    next_serial: AtomicU64,
}

impl SandboxInstanceHost {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Start `body` on a new runtime bound to `bindings`.
    ///
    /// The bindings' gateway credentials are revoked once the instance's
    /// runtime has stopped, so nothing can reuse them after the instance ends.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxInstanceHostError::Duplicate`] when `key` is already hosted,
    /// including an instance that ended but has not been removed.
    pub fn start(
        &self,
        key: &str,
        bindings: SandboxInstanceBindings,
        body: SandboxInstanceBody,
    ) -> std::result::Result<(), SandboxInstanceHostError> {
        let mut instances = lock(&self.instances);
        if instances.contains_key(key) {
            return Err(SandboxInstanceHostError::Duplicate);
        }
        let (stop, stop_requested) = watch::channel(false);
        let (abort, abort_requested) = watch::channel(false);
        let (phase_tx, phase) = watch::channel(SandboxInstancePhase::Starting);
        let (ready_tx, ready) = watch::channel(false);
        let thread = std::thread::Builder::new()
            .name("openshell-instance".to_string())
            .spawn(move || {
                run_hosted_sandbox_instance(
                    &bindings,
                    body,
                    SandboxInstanceSignals {
                        stop_requested,
                        abort_requested,
                        phase: phase_tx,
                        ready: ready_tx,
                    },
                );
            })
            .map_err(|error| SandboxInstanceHostError::Thread(error.to_string()))?;
        instances.insert(
            key.to_string(),
            HostedSandboxInstance {
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

    /// Status of a hosted sandbox instance, including one that ended but has
    /// not been removed.
    #[must_use]
    pub fn status(&self, key: &str) -> Option<SandboxInstanceStatus> {
        lock(&self.instances)
            .get(key)
            .map(HostedSandboxInstance::status)
    }

    /// Keys of every hosted sandbox instance.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        lock(&self.instances).keys().cloned().collect()
    }

    /// Stop one sandbox instance and forget it. Other instances keep running.
    ///
    /// A supervising instance terminates its workload gracefully within
    /// `grace`; one still starting is cancelled at once, because startup has
    /// no safe intermediate state to wind down. Removal runs on its own task,
    /// so it completes even when the caller stops waiting, and concurrent
    /// callers share it and its result. The key stays registered until the
    /// instance's thread has finished, so the same key cannot start a second
    /// owner while this one is stopping. Returns the final status, or `None`
    /// when `key` is not hosted.
    pub async fn remove(&self, key: &str, grace: Duration) -> Option<SandboxInstanceStatus> {
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
        watch::Receiver<Option<SandboxInstanceStatus>>,
        watch::Receiver<SandboxInstancePhase>,
    )> {
        let mut instances = lock(&self.instances);
        let instance = instances.get_mut(key)?;
        if let Some(removed) = &instance.removal {
            return Some((removed.clone(), instance.phase.clone()));
        }
        instance.stop.send_replace(true);
        if *instance.phase.borrow() == SandboxInstancePhase::Starting {
            instance.abort.send_replace(true);
        }
        let (report, removed) = watch::channel(None);
        instance.removal = Some(removed.clone());
        tokio::spawn(
            Removal {
                instances: self.instances.clone(),
                key: key.to_string(),
                serial: instance.serial,
                phase: instance.phase.clone(),
                thread: instance.thread.take(),
                grace,
                report,
            }
            .run(),
        );
        Some((removed, instance.phase.clone()))
    }
}

fn terminal_status(phase: &watch::Receiver<SandboxInstancePhase>) -> SandboxInstanceStatus {
    SandboxInstanceStatus {
        phase: phase.borrow().clone(),
        ready: false,
    }
}

/// The single owner of one sandbox instance's removal.
struct Removal {
    instances: Instances,
    key: String,
    serial: u64,
    phase: watch::Receiver<SandboxInstancePhase>,
    thread: Option<std::thread::JoinHandle<()>>,
    grace: Duration,
    report: watch::Sender<Option<SandboxInstanceStatus>>,
}

impl Removal {
    async fn run(mut self) {
        let finished = tokio::time::timeout(
            self.grace,
            self.phase.wait_for(SandboxInstancePhase::is_terminal),
        )
        .await
        .is_ok();
        if !finished
            && let Some(instance) = lock(&self.instances)
                .get(&self.key)
                .filter(|instance| instance.serial == self.serial)
        {
            instance.abort.send_replace(true);
        }
        if let Some(thread) = self.thread.take() {
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
        }
        let removed = {
            let mut instances = lock(&self.instances);
            match instances.get(&self.key) {
                Some(instance) if instance.serial == self.serial => instances.remove(&self.key),
                _ => None,
            }
        };
        let status = removed.map_or_else(
            || terminal_status(&self.phase),
            |instance| instance.status(),
        );
        self.report.send_replace(Some(status));
    }
}

struct SandboxInstanceSignals {
    stop_requested: watch::Receiver<bool>,
    abort_requested: watch::Receiver<bool>,
    phase: watch::Sender<SandboxInstancePhase>,
    ready: watch::Sender<bool>,
}

/// Reports a hosted sandbox instance's end and revokes its credentials,
/// including when the instance thread unwinds.
struct SandboxInstanceExit {
    credentials: GatewayCredentials,
    phase: watch::Sender<SandboxInstancePhase>,
    ready: watch::Sender<bool>,
    outcome: Option<SandboxInstancePhase>,
}

impl Drop for SandboxInstanceExit {
    fn drop(&mut self) {
        self.credentials.revoke();
        self.ready.send_replace(false);
        let outcome = self.outcome.take().unwrap_or_else(|| {
            SandboxInstancePhase::Failed(
                "sandbox instance thread ended without reporting a result".to_string(),
            )
        });
        self.phase.send_replace(outcome);
        unbind_thread();
    }
}

fn run_hosted_sandbox_instance(
    bindings: &SandboxInstanceBindings,
    body: SandboxInstanceBody,
    signals: SandboxInstanceSignals,
) {
    let SandboxInstanceSignals {
        stop_requested,
        mut abort_requested,
        phase,
        ready,
    } = signals;
    let mut exit = SandboxInstanceExit {
        credentials: bindings.gateway_credentials.clone(),
        phase: phase.clone(),
        ready: ready.clone(),
        outcome: None,
    };
    bind_thread(bindings);
    let thread_bindings = bindings.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(INSTANCE_WORKER_THREADS)
        .thread_name("openshell-instance-worker")
        .enable_all()
        .on_thread_start(move || bind_thread(&thread_bindings))
        .on_thread_stop(unbind_thread)
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
                                    let promote = *current == SandboxInstancePhase::Starting;
                                    if promote {
                                        *current = SandboxInstancePhase::Supervising;
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
                        stop_phase.send_replace(SandboxInstancePhase::Stopping);
                    });
                    let instance = body(SandboxInstanceControls {
                        shutdown,
                        readiness,
                    });
                    let outcome = tokio::select! {
                        result = instance => result,
                        _ = abort_requested.wait_for(|requested| *requested) => {
                            Err(miette::miette!("sandbox instance was cancelled before it finished"))
                        }
                    };
                    mirror.abort();
                    outcome
                })
            }));
            runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
            outcome.unwrap_or_else(|_| Err(miette::miette!("sandbox instance panicked")))
        }
        Err(error) => Err(miette::miette!("build sandbox instance runtime: {error}")),
    };
    exit.outcome = Some(match outcome {
        Ok(code) => SandboxInstancePhase::Exited(code),
        Err(error) => SandboxInstancePhase::Failed(error.to_string()),
    });
}

/// Trusted inputs for one sandbox instance hosted with others.
pub struct SandboxInstanceSpec {
    /// Unique key for this generation within the host.
    pub key: String,
    pub backend_setup: Box<dyn crate::backend_setup::BackendSetup + Send>,
    pub config: crate::SandboxInstanceConfig,
}

impl SandboxInstanceHost {
    /// Start a sandbox instance with its own OCSF identity, OCSF JSON
    /// settings, log push stream, denial log, and gateway credentials.
    ///
    /// # Errors
    ///
    /// Fails when the launch credentials are invalid or the key is hosted.
    pub fn start_sandbox_instance(&self, spec: SandboxInstanceSpec) -> Result<()> {
        let SandboxInstanceSpec {
            key,
            backend_setup,
            mut config,
        } = spec;
        // Instances must never share proxy trust files; give one a private
        // directory that lives exactly as long as the instance.
        let private_tls_dir = if config.proxy_tls.directory.is_none() {
            let prepared = crate::prepare_network_proxy_tls_dir(None)?;
            config.proxy_tls.directory = Some(prepared.path.clone());
            Some(prepared)
        } else {
            None
        };
        // Log push, supervision, and renewal share these credentials.
        let gateway_credentials = GatewayCredentials::from_auth_bundle(&config.auth_bundle)?;
        let log_push = config
            .sandbox_id
            .clone()
            .zip(config.openshell_endpoint.as_deref().map(|endpoint| {
                openshell_core::grpc_client::GatewayEndpoint::new(
                    endpoint,
                    gateway_credentials.clone(),
                )
            }));
        let (log_tx, log_rx) = tokio::sync::mpsc::channel(
            openshell_supervisor_process::log_push::LOG_PUSH_QUEUE_LINES,
        );
        let bindings = SandboxInstanceBindings {
            gateway_credentials,
            event_context: Arc::new(config.event_context()),
            ocsf_json: OcsfJsonSettings::default(),
            log_sink: log_push
                .as_ref()
                .map(|(sandbox_id, _)| LogSink::new(sandbox_id.as_str(), log_tx)),
            denial_log: DenialLogSource::SandboxInstance(SandboxInstanceDenialLog::default()),
        };
        let instance_bindings = bindings.clone();
        let body: SandboxInstanceBody = Box::new(move |controls| {
            Box::pin(async move {
                let _private_tls_dir = private_tls_dir;
                let _log_push = log_push.map(|(sandbox_id, gateway)| {
                    openshell_supervisor_process::log_push::start_log_push(
                        gateway, sandbox_id, log_rx,
                    )
                });
                Box::pin(crate::run_sandbox_instance(
                    backend_setup.as_ref(),
                    config,
                    instance_bindings,
                    controls,
                ))
                .await
            })
        });
        self.start(&key, bindings, body)
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

    struct Instance {
        identity: tokio::sync::oneshot::Receiver<String>,
        logs: mpsc::Receiver<SandboxLogLine>,
        call_again: mpsc::Sender<()>,
        alive: mpsc::Receiver<()>,
        credentials: GatewayCredentials,
    }

    fn start_instance(
        host: &SandboxInstanceHost,
        gateway_url: &str,
        sandbox: &'static str,
    ) -> Instance {
        let credentials =
            GatewayCredentials::from_gateway_token(&format!("token-{sandbox}")).unwrap();
        let gateway = GatewayEndpoint::new(gateway_url, credentials.clone());
        let (log_tx, logs) = mpsc::channel(16);
        let bindings = SandboxInstanceBindings {
            gateway_credentials: credentials.clone(),
            event_context: Arc::new(crate::sandbox_instance_event_context(
                Some(sandbox),
                Some(sandbox),
                String::new(),
            )),
            ocsf_json: OcsfJsonSettings::default(),
            log_sink: Some(LogSink::new(sandbox, log_tx)),
            denial_log: DenialLogSource::SandboxInstance(SandboxInstanceDenialLog::default()),
        };
        let (identity_tx, identity) = tokio::sync::oneshot::channel();
        let (call_again, mut calls) = mpsc::channel(1);
        let (alive_tx, alive) = mpsc::channel::<()>(1);
        let body: SandboxInstanceBody = Box::new(move |controls| {
            Box::pin(async move {
                let SandboxInstanceControls {
                    shutdown,
                    readiness,
                } = controls;
                // Nested tasks and the blocking pool inherit the instance identity.
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
                        tracing::info!(target: "instance_test", "emitted by {sandbox}");
                    });
                })
                .await
                .unwrap();
                // A long-lived task the instance never stops itself.
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
        host.start(sandbox, bindings, body).unwrap();
        Instance {
            identity,
            logs,
            call_again,
            alive,
            credentials,
        }
    }

    async fn wait_supervising(host: &SandboxInstanceHost, key: &str) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while host.status(key).map(|status| status.phase)
                != Some(SandboxInstancePhase::Supervising)
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("instance reaches supervision");
    }

    fn unbound() -> SandboxInstanceBindings {
        SandboxInstanceBindings {
            gateway_credentials: GatewayCredentials::from_gateway_token("unbound-token").unwrap(),
            event_context: Arc::new(crate::sandbox_instance_event_context(
                None,
                None,
                String::new(),
            )),
            ocsf_json: OcsfJsonSettings::default(),
            log_sink: None,
            denial_log: DenialLogSource::SandboxInstance(SandboxInstanceDenialLog::default()),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stopping_and_panicking_instances_keep_their_key_and_fail_closed() {
        let host = Arc::new(SandboxInstanceHost::new());
        let body: SandboxInstanceBody = Box::new(|controls| {
            Box::pin(async move {
                controls.readiness.send_replace(true);
                controls.shutdown.await;
                // Winding down takes time; the key must stay taken meanwhile.
                tokio::time::sleep(Duration::from_millis(300)).await;
                Ok(0)
            })
        });
        host.start("generation", unbound(), body).unwrap();
        wait_supervising(&host, "generation").await;
        let removal = tokio::spawn({
            let host = host.clone();
            async move { host.remove("generation", Duration::from_secs(10)).await }
        });
        tokio::time::timeout(Duration::from_secs(10), async {
            while host.status("generation").map(|status| status.phase)
                != Some(SandboxInstancePhase::Stopping)
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("instance observes the stop request");
        let replacement: SandboxInstanceBody = Box::new(|_| Box::pin(async { Ok(0) }));
        assert_eq!(
            host.start("generation", unbound(), replacement),
            Err(SandboxInstanceHostError::Duplicate)
        );
        let stopped = removal.await.unwrap().expect("instance was hosted");
        assert_eq!(stopped.phase, SandboxInstancePhase::Exited(0));
        assert!(host.status("generation").is_none());

        let credentials = GatewayCredentials::from_gateway_token("panicking-token").unwrap();
        let panicking: SandboxInstanceBody = Box::new(|controls| {
            Box::pin(async move {
                controls.readiness.send_replace(true);
                tokio::task::yield_now().await;
                panic!("hosted sandbox instance failure");
            })
        });
        host.start(
            "panicking",
            SandboxInstanceBindings {
                gateway_credentials: credentials.clone(),
                ..unbound()
            },
            panicking,
        )
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
        .expect("panicking instance reports an end");
        assert_eq!(
            status,
            SandboxInstanceStatus {
                phase: SandboxInstancePhase::Failed("sandbox instance panicked".to_string()),
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
        let host = Arc::new(SandboxInstanceHost::new());
        let winding_down = |code| -> SandboxInstanceBody {
            Box::new(move |controls| {
                Box::pin(async move {
                    controls.readiness.send_replace(true);
                    controls.shutdown.await;
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    Ok(code)
                })
            })
        };
        host.start("generation", unbound(), winding_down(3))
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
            let status = remover.await.unwrap().expect("instance was hosted");
            assert_eq!(status.phase, SandboxInstancePhase::Exited(3));
        }
        assert!(host.status("generation").is_none());

        // The key is free again, and the earlier removal cannot touch its new owner.
        host.start("generation", unbound(), winding_down(4))
            .unwrap();
        wait_supervising(&host, "generation").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            host.status("generation").map(|status| status.phase),
            Some(SandboxInstancePhase::Supervising)
        );
        let status = host.remove("generation", Duration::from_secs(10)).await;
        assert_eq!(
            status.map(|status| status.phase),
            Some(SandboxInstancePhase::Exited(4))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hosted_instances_keep_identity_credentials_and_lifecycle_separate() {
        let (gateway_url, captured) = capture_gateway().await;
        let host = SandboxInstanceHost::new();
        let mut alpha = start_instance(&host, &gateway_url, "sandbox-alpha");
        let mut beta = start_instance(&host, &gateway_url, "sandbox-beta");
        wait_supervising(&host, "sandbox-alpha").await;
        wait_supervising(&host, "sandbox-beta").await;
        assert!(matches!(
            host.start(
                "sandbox-alpha",
                unbound(),
                Box::new(|_| Box::pin(async { Ok(0) })),
            ),
            Err(SandboxInstanceHostError::Duplicate)
        ));

        assert_eq!((&mut alpha.identity).await.unwrap(), "sandbox-alpha");
        assert_eq!((&mut beta.identity).await.unwrap(), "sandbox-beta");
        // Other tests in this process may set the process-wide context; a
        // thread outside every instance must still carry no instance identity.
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
        for (instance, sandbox) in [(&mut alpha, "sandbox-alpha"), (&mut beta, "sandbox-beta")] {
            let line = instance.logs.try_recv().expect("instance log line");
            assert_eq!(line.sandbox_id, sandbox);
            assert_eq!(line.message, format!("emitted by {sandbox}"));
            assert!(instance.logs.try_recv().is_err());
        }

        let stopped = host
            .remove("sandbox-alpha", Duration::from_secs(10))
            .await
            .expect("alpha was hosted");
        assert_eq!(stopped.phase, SandboxInstancePhase::Exited(0));
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
            Some(SandboxInstancePhase::Supervising)
        );
        assert!(
            beta.alive
                .try_recv()
                .is_err_and(|error| error == mpsc::error::TryRecvError::Empty)
        );

        let stopped = host.remove("sandbox-beta", Duration::from_secs(10)).await;
        assert_eq!(
            stopped.map(|status| status.phase),
            Some(SandboxInstancePhase::Exited(0))
        );
    }
}
