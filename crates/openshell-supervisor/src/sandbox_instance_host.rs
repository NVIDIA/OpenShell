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
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use miette::{IntoDiagnostic as _, Result, WrapErr as _};
use openshell_core::grpc_client::GatewayCredentials;
use openshell_ocsf::OcsfJsonSettings;
use openshell_supervisor_control::{SandboxInstancePhaseReport, SandboxInstanceStatusReport};
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

/// Body of a hosted sandbox instance, constructed on its own runtime.
pub type SandboxInstanceBody = Box<
    dyn FnOnce(SandboxInstanceControls) -> Pin<Box<dyn Future<Output = Result<i32>>>>
        + Send
        + 'static,
>;

/// Trusted identity of one sandbox instance asking to be hosted.
pub struct SandboxInstanceAdmission {
    /// Unique key for this generation within the host. It also names the
    /// instance's private directory, so it must be one path component.
    pub key: String,
    /// Digest of the launch material. Admitting the same digest under an
    /// occupied key again is idempotent.
    pub fingerprint: [u8; 32],
    pub sandbox_id: String,
}

/// Outcome of an accepted admission.
#[derive(Debug, PartialEq, Eq)]
pub enum SandboxInstanceAdmitted {
    Created,
    /// The identical admission is already hosted.
    Unchanged,
}

/// The hosted sandbox instance admission was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SandboxInstanceHostError {
    #[error("sandbox instance key must be a single path component")]
    InvalidKey,
    #[error("key is already hosted with different launch material")]
    Conflict,
    #[error("key is still being removed")]
    Removing,
    #[error("prepare sandbox instance files: {0}")]
    Files(String),
    #[error("start sandbox instance thread: {0}")]
    Thread(String),
}

/// Final status of one removal, shared by every remover.
type RemovalReport = watch::Receiver<Option<SandboxInstanceStatusReport>>;

struct HostedSandboxInstance {
    /// Distinguishes this instance from a later one that reuses its key.
    serial: u64,
    fingerprint: [u8; 32],
    sandbox_id: String,
    stop: watch::Sender<bool>,
    abort: watch::Sender<bool>,
    phase: watch::Receiver<SandboxInstancePhaseReport>,
    ready: watch::Receiver<bool>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// The removal in progress, or the report of one that could not delete
    /// the instance's private files and so kept its key.
    removal: Option<RemovalReport>,
}

impl HostedSandboxInstance {
    /// Status of the instance hosted under `key`, which is its route.
    fn status(&self, key: &str) -> SandboxInstanceStatusReport {
        if let Some(reported) = self
            .removal
            .as_ref()
            .and_then(|report| report.borrow().clone())
        {
            return reported;
        }
        let phase = self.phase.borrow().clone();
        // The runner always reports a terminal phase, even while unwinding;
        // a closed channel without one still means supervision has ended.
        if !phase.is_terminal() && self.phase.has_changed().is_err() {
            return SandboxInstanceStatusReport {
                route: key.to_string(),
                sandbox_id: self.sandbox_id.clone(),
                phase: SandboxInstancePhaseReport::Failed {
                    error: "sandbox instance thread ended unexpectedly".to_string(),
                },
                ready: false,
            };
        }
        SandboxInstanceStatusReport {
            route: key.to_string(),
            sandbox_id: self.sandbox_id.clone(),
            phase,
            ready: *self.ready.borrow(),
        }
    }
}

type Instances = Arc<Mutex<HashMap<String, HostedSandboxInstance>>>;

/// Wakes observers of the registry whenever any instance's status changes.
#[derive(Clone)]
struct ChangeNotifier(Arc<watch::Sender<u64>>);

impl ChangeNotifier {
    fn notify(&self) {
        self.0.send_modify(|changes| *changes += 1);
    }
}

fn lock(instances: &Instances) -> MutexGuard<'_, HashMap<String, HostedSandboxInstance>> {
    instances
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The one registry of hosted sandbox instances.
///
/// Each entry owns its admission fingerprint and sandbox identity, its
/// runtime thread, phase, and stop signals, and a private directory under the
/// host root. Everything else an instance owns, including its gateway
/// credentials and runtime route, lives on its runtime and ends with it. A
/// key stays reserved from admission until one removal has stopped the
/// runtime, revoked its credentials, and deleted its private directory.
pub struct SandboxInstanceHost {
    instances: Instances,
    next_serial: AtomicU64,
    root: PathBuf,
    changes: ChangeNotifier,
}

impl SandboxInstanceHost {
    /// Host instances whose private directories live under `root`.
    ///
    /// # Errors
    ///
    /// Fails when `root` cannot be prepared as a private directory.
    pub fn new(root: PathBuf) -> Result<Self> {
        prepare_private_dir(&root)?;
        Ok(Self {
            instances: Arc::default(),
            next_serial: AtomicU64::new(0),
            root,
            changes: ChangeNotifier(Arc::new(watch::Sender::new(0))),
        })
    }

    /// Notified whenever an instance is admitted, changes phase or readiness,
    /// or is removed. The value only counts changes.
    #[must_use]
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changes.0.subscribe()
    }

    /// Admit a sandbox instance and start the runtime `launch` prepares in
    /// the instance's new, empty private directory.
    ///
    /// The bindings' gateway credentials are revoked once the instance's
    /// runtime has stopped, so nothing can reuse them after the instance ends.
    /// `launch` runs while the registry is locked, so concurrent admissions
    /// of one key cannot both start; it must not call back into the host.
    ///
    /// # Errors
    ///
    /// Rejects an occupied key with different launch material or one still
    /// being removed, and fails when the instance cannot be prepared or
    /// started. A failed admission leaves no instance and no private files.
    pub fn admit<E: From<SandboxInstanceHostError>>(
        &self,
        admission: SandboxInstanceAdmission,
        launch: impl FnOnce(
            &Path,
        )
            -> std::result::Result<(SandboxInstanceBindings, SandboxInstanceBody), E>,
    ) -> std::result::Result<SandboxInstanceAdmitted, E> {
        let SandboxInstanceAdmission {
            key,
            fingerprint,
            sandbox_id,
        } = admission;
        if !matches!(
            Path::new(&key).components().collect::<Vec<_>>().as_slice(),
            [std::path::Component::Normal(name)] if *name == key.as_str()
        ) {
            return Err(SandboxInstanceHostError::InvalidKey.into());
        }
        let mut instances = lock(&self.instances);
        if let Some(existing) = instances.get(&key) {
            return if existing.removal.is_some() {
                Err(SandboxInstanceHostError::Removing.into())
            } else if existing.fingerprint == fingerprint {
                Ok(SandboxInstanceAdmitted::Unchanged)
            } else {
                Err(SandboxInstanceHostError::Conflict.into())
            };
        }
        let dir = self.root.join(&key);
        let started = prepare_instance_dir(&dir)
            .map_err(|error| E::from(SandboxInstanceHostError::Files(error.to_string())))
            .and_then(|()| launch(&dir))
            .and_then(|(bindings, body)| {
                spawn_instance(bindings, body, self.changes.clone()).map_err(E::from)
            });
        let running = match started {
            Ok(running) => running,
            Err(error) => {
                let _ = remove_instance_dir(&dir);
                return Err(error);
            }
        };
        instances.insert(
            key,
            HostedSandboxInstance {
                serial: self.next_serial.fetch_add(1, Ordering::Relaxed),
                fingerprint,
                sandbox_id,
                stop: running.stop,
                abort: running.abort,
                phase: running.phase,
                ready: running.ready,
                thread: Some(running.thread),
                removal: None,
            },
        );
        self.changes.notify();
        Ok(SandboxInstanceAdmitted::Created)
    }

    /// Status of a hosted sandbox instance, including one that ended but has
    /// not been removed. The report's route is the instance's key.
    #[must_use]
    pub fn status(&self, key: &str) -> Option<SandboxInstanceStatusReport> {
        lock(&self.instances)
            .get(key)
            .map(|instance| instance.status(key))
    }

    /// Status of every hosted sandbox instance.
    #[must_use]
    pub fn list(&self) -> Vec<SandboxInstanceStatusReport> {
        lock(&self.instances)
            .iter()
            .map(|(key, instance)| instance.status(key))
            .collect()
    }

    /// Stop one sandbox instance, delete its private files, and forget it.
    /// Other instances keep running.
    ///
    /// A supervising instance terminates its workload gracefully within
    /// `grace`; one still starting is cancelled at once, because startup has
    /// no safe intermediate state to wind down. Removal runs on its own task,
    /// so it completes even when the caller stops waiting, and concurrent
    /// callers share it and its result. The key stays reserved until the
    /// instance's thread has finished and its private directory is gone; if
    /// the directory cannot be deleted, the key stays reserved and the next
    /// removal tries again. Returns the final status, or `None` when `key` is
    /// not hosted.
    pub async fn remove(&self, key: &str, grace: Duration) -> Option<SandboxInstanceStatusReport> {
        let (mut removed, sandbox_id) = self.begin_removal(key, grace)?;
        // The removal task ends without a report only with its runtime.
        let reported = removed
            .wait_for(Option::is_some)
            .await
            .ok()
            .and_then(|status| status.clone());
        Some(reported.unwrap_or_else(|| SandboxInstanceStatusReport {
            route: key.to_string(),
            sandbox_id,
            phase: SandboxInstancePhaseReport::Failed {
                error: "sandbox instance removal did not finish".to_string(),
            },
            ready: false,
        }))
    }

    /// Stop every sandbox instance, for process shutdown.
    pub async fn remove_all(&self, grace: Duration) {
        let keys = lock(&self.instances).keys().cloned().collect::<Vec<_>>();
        futures::future::join_all(keys.iter().map(|key| self.remove(key, grace))).await;
    }

    fn begin_removal(&self, key: &str, grace: Duration) -> Option<(RemovalReport, String)> {
        let mut instances = lock(&self.instances);
        let instance = instances.get_mut(key)?;
        // Join a removal in progress; retry one that kept the key.
        if let Some(removed) = &instance.removal
            && removed.borrow().is_none()
        {
            return Some((removed.clone(), instance.sandbox_id.clone()));
        }
        instance.stop.send_replace(true);
        if *instance.phase.borrow() == SandboxInstancePhaseReport::Starting {
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
                dir: self.root.join(key),
                grace,
                report,
                changes: self.changes.clone(),
            }
            .run(),
        );
        self.changes.notify();
        Some((removed, instance.sandbox_id.clone()))
    }
}

/// The single owner of one sandbox instance's removal.
struct Removal {
    instances: Instances,
    key: String,
    serial: u64,
    phase: watch::Receiver<SandboxInstancePhaseReport>,
    thread: Option<std::thread::JoinHandle<()>>,
    dir: PathBuf,
    grace: Duration,
    report: watch::Sender<Option<SandboxInstanceStatusReport>>,
    changes: ChangeNotifier,
}

impl Removal {
    async fn run(mut self) {
        let finished = tokio::time::timeout(
            self.grace,
            self.phase.wait_for(SandboxInstancePhaseReport::is_terminal),
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
        // Once the thread ends, the runtime, its route, and every task are
        // gone and the credentials are revoked.
        if let Some(thread) = self.thread.take() {
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
        }
        let dir = self.dir.clone();
        let cleanup = match tokio::task::spawn_blocking(move || remove_instance_dir(&dir)).await {
            Ok(result) => result.map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
        };
        let mut instances = lock(&self.instances);
        let Some(instance) = instances
            .get(&self.key)
            .filter(|instance| instance.serial == self.serial)
        else {
            return;
        };
        let mut status = instance.status(&self.key);
        status.ready = false;
        match cleanup {
            Ok(()) => {
                instances.remove(&self.key);
            }
            Err(error) => {
                tracing::warn!(%error, "could not delete removed sandbox instance files; keeping its key reserved");
                status.phase = SandboxInstancePhaseReport::Failed {
                    error: format!(
                        "sandbox instance stopped, but its private files remain: {error}"
                    ),
                };
            }
        }
        self.report.send_replace(Some(status));
        self.changes.notify();
    }
}

/// Signals and thread of one started instance runtime.
struct RunningInstance {
    stop: watch::Sender<bool>,
    abort: watch::Sender<bool>,
    phase: watch::Receiver<SandboxInstancePhaseReport>,
    ready: watch::Receiver<bool>,
    thread: std::thread::JoinHandle<()>,
}

fn spawn_instance(
    bindings: SandboxInstanceBindings,
    body: SandboxInstanceBody,
    changes: ChangeNotifier,
) -> std::result::Result<RunningInstance, SandboxInstanceHostError> {
    let (stop, stop_requested) = watch::channel(false);
    let (abort, abort_requested) = watch::channel(false);
    let (phase_tx, phase) = watch::channel(SandboxInstancePhaseReport::Starting);
    let (ready_tx, ready) = watch::channel(false);
    let credentials = bindings.gateway_credentials.clone();
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
                    changes,
                },
            );
        })
        .map_err(|error| {
            credentials.revoke();
            SandboxInstanceHostError::Thread(error.to_string())
        })?;
    Ok(RunningInstance {
        stop,
        abort,
        phase,
        ready,
        thread,
    })
}

struct SandboxInstanceSignals {
    stop_requested: watch::Receiver<bool>,
    abort_requested: watch::Receiver<bool>,
    phase: watch::Sender<SandboxInstancePhaseReport>,
    ready: watch::Sender<bool>,
    changes: ChangeNotifier,
}

/// Reports a hosted sandbox instance's end and revokes its credentials,
/// including when the instance thread unwinds.
struct SandboxInstanceExit {
    credentials: GatewayCredentials,
    phase: watch::Sender<SandboxInstancePhaseReport>,
    ready: watch::Sender<bool>,
    outcome: Option<SandboxInstancePhaseReport>,
    changes: ChangeNotifier,
}

impl Drop for SandboxInstanceExit {
    fn drop(&mut self) {
        self.credentials.revoke();
        self.ready.send_replace(false);
        let outcome = self
            .outcome
            .take()
            .unwrap_or_else(|| SandboxInstancePhaseReport::Failed {
                error: "sandbox instance thread ended without reporting a result".to_string(),
            });
        self.phase.send_replace(outcome);
        self.changes.notify();
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
        changes,
    } = signals;
    let mut exit = SandboxInstanceExit {
        credentials: bindings.gateway_credentials.clone(),
        phase: phase.clone(),
        ready: ready.clone(),
        outcome: None,
        changes: changes.clone(),
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
                    let mirror_changes = changes.clone();
                    let mirror = tokio::spawn(async move {
                        loop {
                            let is_ready = *accepted.borrow_and_update();
                            let changed = mirror_ready.send_replace(is_ready) != is_ready;
                            let promoted = is_ready
                                && mirror_phase.send_if_modified(|current| {
                                    let promote =
                                        *current == SandboxInstancePhaseReport::Starting;
                                    if promote {
                                        *current = SandboxInstancePhaseReport::Supervising;
                                    }
                                    promote
                                });
                            if changed || promoted {
                                mirror_changes.notify();
                            }
                            if accepted.changed().await.is_err() {
                                if mirror_ready.send_replace(false) {
                                    mirror_changes.notify();
                                }
                                return;
                            }
                        }
                    });
                    let mut stop = stop_requested.clone();
                    let stop_phase = phase.clone();
                    let stop_changes = changes.clone();
                    let shutdown = Box::pin(async move {
                        let _ = stop.wait_for(|requested| *requested).await;
                        stop_phase.send_replace(SandboxInstancePhaseReport::Stopping);
                        stop_changes.notify();
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
        Ok(exit_code) => SandboxInstancePhaseReport::Exited { exit_code },
        Err(error) => SandboxInstancePhaseReport::Failed {
            error: error.to_string(),
        },
    });
}

/// Prepare a hosted sandbox instance of `config` whose private files live in
/// `dir`: bindings with its own gateway credentials, log push stream, and
/// denial log, and a body that supervises it.
///
/// # Errors
///
/// Fails when the launch credentials are invalid.
pub fn sandbox_instance_launch(
    backend_setup: Box<dyn crate::backend_setup::BackendSetup + Send>,
    mut config: crate::SandboxInstanceConfig,
    dir: &Path,
) -> Result<(SandboxInstanceBindings, SandboxInstanceBody)> {
    // Instances must never share proxy trust files.
    config
        .proxy_tls
        .directory
        .get_or_insert_with(|| dir.to_path_buf());
    // Log push, supervision, and renewal share these credentials.
    let gateway_credentials = GatewayCredentials::from_auth_bundle(&config.auth_bundle)?;
    let log_push = config
        .sandbox_id
        .clone()
        .zip(config.openshell_endpoint.as_deref().map(|endpoint| {
            openshell_core::grpc_client::GatewayEndpoint::new(endpoint, gateway_credentials.clone())
        }));
    let (log_tx, log_rx) =
        tokio::sync::mpsc::channel(openshell_supervisor_process::log_push::LOG_PUSH_QUEUE_LINES);
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
            let _log_push = log_push.map(|(sandbox_id, gateway)| {
                openshell_supervisor_process::log_push::start_log_push(gateway, sandbox_id, log_rx)
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
    Ok((bindings, body))
}

/// Create `dir` as an empty private directory, replacing files a previous
/// process left behind.
fn prepare_instance_dir(dir: &Path) -> Result<()> {
    remove_instance_dir(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("delete stale sandbox instance files {}", dir.display()))?;
    prepare_private_dir(dir)
}

fn remove_instance_dir(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

#[cfg(unix)]
pub(crate) fn prepare_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path).into_diagnostic()?;
            if !metadata.is_dir() {
                return Err(miette::miette!(
                    "sandbox instance path is not a directory: {}",
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
pub(crate) fn prepare_private_dir(_path: &Path) -> Result<()> {
    Err(miette::miette!(
        "hosted sandbox instances require a Unix host"
    ))
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
        assert_eq!(
            admit(host, sandbox, sandbox, 0, bindings, body),
            Ok(SandboxInstanceAdmitted::Created)
        );
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
                != Some(SandboxInstancePhaseReport::Supervising)
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

    /// Admit `body` under `key`, recording `launch` in its private directory.
    fn admit(
        host: &SandboxInstanceHost,
        key: &str,
        sandbox_id: &str,
        launch: u8,
        bindings: SandboxInstanceBindings,
        body: SandboxInstanceBody,
    ) -> std::result::Result<SandboxInstanceAdmitted, SandboxInstanceHostError> {
        host.admit(
            SandboxInstanceAdmission {
                key: key.to_string(),
                fingerprint: [launch; 32],
                sandbox_id: sandbox_id.to_string(),
            },
            |dir| {
                std::fs::write(dir.join("launch"), [launch])
                    .map_err(|error| SandboxInstanceHostError::Files(error.to_string()))?;
                Ok((bindings, body))
            },
        )
    }

    fn private_host() -> (tempfile::TempDir, Arc<SandboxInstanceHost>) {
        let root = tempfile::tempdir().unwrap();
        let host = SandboxInstanceHost::new(root.path().join("instances")).unwrap();
        (root, Arc::new(host))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_removal_holds_an_idempotent_admission_until_its_files_are_gone() {
        let (root, host) = private_host();
        let dir = root.path().join("instances").join("generation");
        let winding_down = |code| -> SandboxInstanceBody {
            Box::new(move |controls| {
                Box::pin(async move {
                    controls.readiness.send_replace(true);
                    controls.shutdown.await;
                    // Winding down takes time; the key must stay taken meanwhile.
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    Ok(code)
                })
            })
        };
        let admit_launch = |launch, code| {
            admit(
                &host,
                "generation",
                &format!("sandbox-{launch}"),
                launch,
                unbound(),
                winding_down(code),
            )
        };
        assert_eq!(admit_launch(1, 3), Ok(SandboxInstanceAdmitted::Created));
        assert_eq!(admit_launch(1, 3), Ok(SandboxInstanceAdmitted::Unchanged));
        assert_eq!(admit_launch(2, 3), Err(SandboxInstanceHostError::Conflict));
        assert_eq!(
            admit(
                &host,
                "../escape",
                "sandbox-1",
                1,
                unbound(),
                winding_down(0)
            ),
            Err(SandboxInstanceHostError::InvalidKey)
        );
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
        tokio::time::timeout(Duration::from_secs(10), async {
            while host.status("generation").map(|status| status.phase)
                != Some(SandboxInstancePhaseReport::Stopping)
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("instance observes the stop request");
        assert_eq!(admit_launch(1, 3), Err(SandboxInstanceHostError::Removing));
        assert!(dir.join("launch").exists());
        let removers = [(); 2].map(|()| {
            let host = host.clone();
            tokio::spawn(async move { host.remove("generation", Duration::from_secs(10)).await })
        });
        for remover in removers {
            let status = remover.await.unwrap().expect("instance was hosted");
            assert_eq!(status.sandbox_id, "sandbox-1");
            assert_eq!(
                status.phase,
                SandboxInstancePhaseReport::Exited { exit_code: 3 }
            );
        }
        assert!(host.status("generation").is_none());
        assert!(!dir.exists());

        // The key is free again, and the earlier removal cannot touch its new owner.
        assert_eq!(admit_launch(4, 4), Ok(SandboxInstanceAdmitted::Created));
        wait_supervising(&host, "generation").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            host.status("generation").map(|status| status.phase),
            Some(SandboxInstancePhaseReport::Supervising)
        );
        assert_eq!(std::fs::read(dir.join("launch")).unwrap(), [4]);

        // Files that cannot be deleted keep the key reserved until a later
        // removal deletes them. Root ignores the permission this relies on.
        #[cfg(unix)]
        if !nix::unistd::geteuid().is_root() {
            use std::os::unix::fs::PermissionsExt as _;

            let instances = root.path().join("instances");
            std::fs::set_permissions(&instances, std::fs::Permissions::from_mode(0o500)).unwrap();
            let status = host
                .remove("generation", Duration::from_secs(10))
                .await
                .unwrap();
            assert!(
                matches!(&status.phase, SandboxInstancePhaseReport::Failed { error } if error.contains("private files remain")),
                "{status:?}"
            );
            assert_eq!(host.status("generation"), Some(status));
            assert_eq!(admit_launch(5, 5), Err(SandboxInstanceHostError::Removing));
            std::fs::set_permissions(&instances, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let status = host.remove("generation", Duration::from_secs(10)).await;
        assert_eq!(
            status.map(|status| status.phase),
            Some(SandboxInstancePhaseReport::Exited { exit_code: 4 })
        );
        assert!(!dir.exists());
        host.remove_all(Duration::from_secs(10)).await;
        assert!(host.list().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn panicking_instance_fails_closed_and_revokes_its_credentials() {
        let (_root, host) = private_host();
        let credentials = GatewayCredentials::from_gateway_token("panicking-token").unwrap();
        let panicking: SandboxInstanceBody = Box::new(|controls| {
            Box::pin(async move {
                controls.readiness.send_replace(true);
                tokio::task::yield_now().await;
                panic!("hosted sandbox instance failure");
            })
        });
        admit(
            &host,
            "panicking",
            "sandbox-panicking",
            1,
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
            SandboxInstanceStatusReport {
                route: "panicking".to_string(),
                sandbox_id: "sandbox-panicking".to_string(),
                phase: SandboxInstancePhaseReport::Failed {
                    error: "sandbox instance panicked".to_string(),
                },
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
    async fn hosted_instances_keep_identity_credentials_and_lifecycle_separate() {
        let (gateway_url, captured) = capture_gateway().await;
        let (_root, host) = private_host();
        let mut alpha = start_instance(&host, &gateway_url, "sandbox-alpha");
        let mut beta = start_instance(&host, &gateway_url, "sandbox-beta");
        wait_supervising(&host, "sandbox-alpha").await;
        wait_supervising(&host, "sandbox-beta").await;
        assert_eq!(
            admit(
                &host,
                "sandbox-alpha",
                "sandbox-alpha",
                1,
                unbound(),
                Box::new(|_| Box::pin(async { Ok(0) })),
            ),
            Err(SandboxInstanceHostError::Conflict)
        );

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
        assert_eq!(
            stopped.phase,
            SandboxInstancePhaseReport::Exited { exit_code: 0 }
        );
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
            Some(SandboxInstancePhaseReport::Supervising)
        );
        assert!(
            beta.alive
                .try_recv()
                .is_err_and(|error| error == mpsc::error::TryRecvError::Empty)
        );

        let stopped = host.remove("sandbox-beta", Duration::from_secs(10)).await;
        assert_eq!(
            stopped.map(|status| status.phase),
            Some(SandboxInstancePhaseReport::Exited { exit_code: 0 })
        );
    }
}
