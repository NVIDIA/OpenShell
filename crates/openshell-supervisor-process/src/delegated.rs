// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-owned access-plane assembly for a remote sandbox.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use miette::Result;
use openshell_isolation_interface::contract::{
    BackendError, BoundaryDuplexStream, BoundaryExec, BoundaryLoopbackConnector, BoundaryProcess,
    LoopbackTarget,
};
use openshell_ocsf::{ActivityId, AppLifecycleBuilder, SeverityId, StatusId, ocsf_emit};

fn ocsf_ctx() -> &'static openshell_ocsf::EventContext {
    openshell_ocsf::ctx::ctx()
}

/// Supervisor-owned SSH and gateway-session tasks for a running sandbox.
pub struct BoundaryAccess {
    instance_id: String,
    terminating: Arc<AtomicBool>,
    ssh_task: Option<tokio::task::JoinHandle<()>>,
    session_task: Option<tokio::task::JoinHandle<()>>,
    session_readiness: Option<tokio::sync::watch::Receiver<bool>>,
    main_session: Option<Arc<crate::main_session::MainSession>>,
}

#[derive(Default)]
struct DeferredLoopbackConnector {
    connector: tokio::sync::RwLock<Option<Arc<dyn BoundaryLoopbackConnector>>>,
    ready: tokio::sync::Notify,
}

impl DeferredLoopbackConnector {
    async fn install(&self, connector: Arc<dyn BoundaryLoopbackConnector>) {
        *self.connector.write().await = Some(connector);
        self.ready.notify_waiters();
    }
}

#[async_trait::async_trait]
impl BoundaryLoopbackConnector for DeferredLoopbackConnector {
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError> {
        loop {
            let notified = self.ready.notified();
            let connector = self.connector.read().await.clone();
            if let Some(connector) = connector {
                return connector.connect(target).await;
            }
            notified.await;
        }
    }
}

/// A supervisor stream that has reported configuration admission while the
/// boundary remains held in its confirmed, pre-workload state.
pub struct PrestartedSupervisorSession {
    terminating: Arc<AtomicBool>,
    task: Option<tokio::task::JoinHandle<()>>,
    readiness: tokio::sync::watch::Receiver<bool>,
    loopback: Arc<DeferredLoopbackConnector>,
    outbound: tokio::sync::mpsc::Sender<openshell_core::proto::SupervisorMessage>,
    runtime_ready: Arc<AtomicBool>,
}

impl PrestartedSupervisorSession {
    async fn report_runtime_ready(&self) -> Result<()> {
        self.runtime_ready.store(true, Ordering::Release);
        self.outbound
            .send(openshell_core::proto::SupervisorMessage {
                payload: Some(
                    openshell_core::proto::supervisor_message::Payload::RuntimeReady(
                        openshell_core::proto::SupervisorRuntimeReady {},
                    ),
                ),
            })
            .await
            .map_err(|_| miette::miette!("supervisor session ended before runtime readiness"))
    }
}

impl Drop for PrestartedSupervisorSession {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            self.terminating.store(true, Ordering::Release);
            task.abort();
        }
    }
}

/// Resume a prepared supervisor stream and report its bootstrap result before
/// workload activation. Relay requests wait until the running boundary installs
/// its loopback connector.
pub async fn start_prepared_supervisor_session(
    prepared: crate::supervisor_session::PreparedSupervisorSession,
    bootstrap_result: Option<openshell_core::proto::ConfigBootstrapResult>,
    ssh_socket_path: Option<&str>,
    config_apply_tx: tokio::sync::mpsc::Sender<crate::supervisor_session::ConfigApplyRequest>,
    supervisor_session_updates: Option<tokio::sync::watch::Sender<Option<String>>>,
) -> Result<PrestartedSupervisorSession> {
    let terminating = Arc::new(AtomicBool::new(false));
    let loopback = Arc::new(DeferredLoopbackConnector::default());
    let target = ssh_socket_path.map_or_else(
        || std::path::PathBuf::from(openshell_core::container_paths::SSH_SOCKET_PATH),
        std::path::PathBuf::from,
    );
    let (task, mut readiness, outbound, runtime_ready) = crate::supervisor_session::spawn_prepared(
        prepared,
        bootstrap_result,
        target,
        loopback.clone(),
        None,
        terminating.clone(),
        config_apply_tx,
        supervisor_session_updates,
    );
    let ready = tokio::time::timeout(
        crate::supervisor_session::SESSION_PREPARE_TIMEOUT,
        readiness.wait_for(|ready| *ready),
    )
    .await
    .map(|result| result.map(|_| ()));
    match ready {
        Ok(Ok(())) => Ok(PrestartedSupervisorSession {
            terminating,
            task: Some(task),
            readiness,
            loopback,
            outbound,
            runtime_ready,
        }),
        Ok(Err(_)) => {
            task.abort();
            Err(miette::miette!(
                "prepared supervisor session ended before bootstrap acknowledgement"
            ))
        }
        Err(_) => {
            task.abort();
            Err(miette::miette!(
                "prepared supervisor session did not receive accepted configuration admission before the provisioning deadline"
            ))
        }
    }
}

impl BoundaryAccess {
    /// Stable supervisor instance ID used for lifecycle reporting.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Observe whether the gateway has accepted the current supervisor
    /// session. The value returns to false while the session reconnects.
    #[must_use]
    pub fn session_readiness(&self) -> Option<tokio::sync::watch::Receiver<bool>> {
        self.session_readiness.clone()
    }

    /// Publish the canonical process's terminal status to attached clients.
    pub async fn publish_main_exit(&self, exit_code: i32, attachment_expected: bool) {
        let Some(main_session) = self.main_session.as_ref() else {
            return;
        };
        let _ = main_session
            .finish_remote(exit_code, attachment_expected)
            .await;
    }

    /// Release terminal delivery after the gateway acknowledges the exit, then
    /// wait for attached clients to consume the terminal status.
    pub async fn drain_main_terminal_delivery(&self) {
        let Some(main_session) = self.main_session.as_ref() else {
            return;
        };
        main_session.mark_terminal_reported();
        main_session.wait_for_terminal_attachments().await;
    }
}

impl Drop for BoundaryAccess {
    fn drop(&mut self) {
        self.terminating.store(true, Ordering::Release);
        if let Some(task) = self.ssh_task.take() {
            task.abort();
        }
        if let Some(task) = self.session_task.take() {
            task.abort();
        }
    }
}

/// Start the supervisor access plane using sandbox-supplied exec and
/// loopback-forwarding capabilities.
#[allow(clippy::too_many_arguments)]
pub async fn start_boundary_access(
    instance_id: String,
    sandbox_id: Option<&str>,
    openshell_endpoint: Option<&str>,
    ssh_socket_path: Option<&str>,
    shared_ssh_socket: bool,
    ca_file_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    boundary_exec: Arc<dyn BoundaryExec>,
    port_forward: Arc<dyn BoundaryLoopbackConnector>,
    agent: Arc<dyn BoundaryProcess>,
    supervisor_session_updates: Option<tokio::sync::watch::Sender<Option<String>>>,
    mut prestarted_supervisor_session: Option<PrestartedSupervisorSession>,
    config_apply_tx: Option<
        tokio::sync::mpsc::Sender<crate::supervisor_session::ConfigApplyRequest>,
    >,
) -> Result<BoundaryAccess> {
    if let Some(prestarted) = prestarted_supervisor_session.as_ref() {
        prestarted.loopback.install(port_forward.clone()).await;
    }
    let terminating = prestarted_supervisor_session.as_ref().map_or_else(
        || Arc::new(AtomicBool::new(false)),
        |prestarted| prestarted.terminating.clone(),
    );
    let Some(ssh_socket_path) = ssh_socket_path.map(std::path::PathBuf::from) else {
        if let Some(prestarted) = prestarted_supervisor_session.as_ref() {
            prestarted.report_runtime_ready().await?;
        }
        let (session_task, session_readiness) = match prestarted_supervisor_session.as_mut() {
            Some(prestarted) => (prestarted.task.take(), Some(prestarted.readiness.clone())),
            None => (None, None),
        };
        return Ok(BoundaryAccess {
            instance_id,
            terminating,
            ssh_task: None,
            session_task,
            session_readiness,
            main_session: None,
        });
    };

    let attachment = agent
        .attach()
        .await
        .map_err(|error| miette::miette!(error.to_string()))?;
    let main_session = crate::main_session::MainSession::from_boundary(attachment, agent);

    let (ssh_ready_tx, ssh_ready_rx) = tokio::sync::oneshot::channel();
    let listen_path = ssh_socket_path.clone();
    let ssh_port_forward = port_forward.clone();
    let ssh_main_session = main_session.clone();
    let ssh_task = tokio::spawn(async move {
        if let Err(error) = crate::ssh::run_ssh_server(
            listen_path,
            ssh_ready_tx,
            ca_file_paths,
            shared_ssh_socket,
            ssh_port_forward,
            boundary_exec,
            Some(ssh_main_session),
        )
        .await
        {
            ocsf_emit!(
                AppLifecycleBuilder::new(ocsf_ctx())
                    .activity(ActivityId::Fail)
                    .severity(SeverityId::Critical)
                    .status(StatusId::Failure)
                    .message(format!("SSH server failed: {error}"))
                    .build()
            );
        }
    });

    match tokio::time::timeout(Duration::from_secs(10), ssh_ready_rx).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            ssh_task.abort();
            return Err(error.context("SSH server failed during startup"));
        }
        Ok(Err(_)) => {
            ssh_task.abort();
            return Err(miette::miette!(
                "SSH server task ended before signaling readiness"
            ));
        }
        Err(_) => {
            ssh_task.abort();
            return Err(miette::miette!(
                "SSH server did not start within 10 seconds"
            ));
        }
    }

    let (session_task, session_readiness) = match prestarted_supervisor_session.as_mut() {
        Some(prestarted) => (prestarted.task.take(), Some(prestarted.readiness.clone())),
        None => match (openshell_endpoint, sandbox_id) {
            (Some(endpoint), Some(id)) => {
                let (task, mut accepted) = crate::supervisor_session::spawn_with_readiness(
                    endpoint.to_string(),
                    id.to_string(),
                    ssh_socket_path,
                    port_forward,
                    None,
                    terminating.clone(),
                    crate::supervisor_session::SessionRuntimeContext {
                        instance_id: instance_id.clone(),
                        session_id_updates: supervisor_session_updates,
                        config_apply_tx,
                    },
                );
                let accepted_result = tokio::time::timeout(
                    Duration::from_secs(10),
                    accepted.wait_for(|ready| *ready),
                )
                .await
                .map(|result| result.map(|_| ()));
                match accepted_result {
                    Ok(Ok(())) => (Some(task), Some(accepted)),
                    Ok(Err(_)) => {
                        task.abort();
                        return Err(miette::miette!(
                            "supervisor session ended before gateway acceptance"
                        ));
                    }
                    Err(_) => {
                        task.abort();
                        return Err(miette::miette!(
                            "gateway did not accept supervisor session within 10 seconds"
                        ));
                    }
                }
            }
            _ => (None, None),
        },
    };

    if let Some(prestarted) = prestarted_supervisor_session.as_ref() {
        prestarted.report_runtime_ready().await?;
    }

    Ok(BoundaryAccess {
        instance_id,
        terminating,
        ssh_task: Some(ssh_task),
        session_task,
        session_readiness,
        main_session: Some(main_session),
    })
}

/// Report the canonical process exit until the gateway acknowledges it.
pub async fn report_main_process_exit(
    endpoint: &str,
    sandbox_id: &str,
    instance_id: &str,
    exit_code: i32,
) {
    let mut delay = Duration::from_millis(250);
    loop {
        match crate::supervisor_session::report_main_process_exit(
            endpoint,
            sandbox_id,
            instance_id,
            exit_code,
        )
        .await
        {
            Ok(()) => break,
            Err(error) => {
                tracing::warn!(%error, "main-process exit report failed; retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(2));
            }
        }
    }
}

/// Finalize canonical process terminal delivery until acknowledged.
pub async fn finalize_main_process_exit(endpoint: &str, sandbox_id: &str, instance_id: &str) {
    let mut delay = Duration::from_millis(250);
    loop {
        match crate::supervisor_session::finalize_main_process_exit(
            endpoint,
            sandbox_id,
            instance_id,
        )
        .await
        {
            Ok(()) => break,
            Err(error) => {
                tracing::warn!(%error, "main-process finalization failed; retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(2));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expected_post_exit_attachment_is_preserved_for_remote_main() {
        let main_session = crate::main_session::MainSession::inert();
        let access = BoundaryAccess {
            instance_id: "instance".to_string(),
            terminating: Arc::new(AtomicBool::new(false)),
            ssh_task: None,
            session_task: None,
            session_readiness: None,
            main_session: Some(main_session.clone()),
        };

        access.publish_main_exit(7, true).await;

        main_session
            .begin_terminal_attachment()
            .expect("declared CLI attachment must remain valid after a fast remote main exits");
        main_session.end_terminal_attachment();
    }
}
