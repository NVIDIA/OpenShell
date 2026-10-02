// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-owned access-plane assembly for a remote sandbox.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use miette::Result;
use openshell_isolation_interface::contract::{
    BoundaryExec, BoundaryLoopbackConnector, BoundaryProcess,
};
#[cfg(unix)]
use openshell_ocsf::{ActivityId, AppLifecycleBuilder, SeverityId, StatusId, ocsf_emit};

#[cfg(unix)]
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
    sandbox_id: Option<&str>,
    openshell_endpoint: Option<&str>,
    ssh_socket_path: Option<&str>,
    shared_ssh_socket: bool,
    ca_file_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    boundary_exec: Arc<dyn BoundaryExec>,
    port_forward: Arc<dyn BoundaryLoopbackConnector>,
    agent: Arc<dyn BoundaryProcess>,
    supervisor_session_updates: Option<tokio::sync::watch::Sender<Option<String>>>,
) -> Result<BoundaryAccess> {
    let instance_id = uuid::Uuid::new_v4().to_string();
    let terminating = Arc::new(AtomicBool::new(false));
    let attachment = agent
        .attach()
        .await
        .map_err(|error| miette::miette!(error.to_string()))?;
    let main_session = crate::main_session::MainSession::from_boundary(attachment, agent);
    let ssh_socket_path = ssh_socket_path.map(std::path::PathBuf::from);
    let ssh_task = start_optional_ssh(
        ssh_socket_path.clone(),
        shared_ssh_socket,
        ca_file_paths,
        boundary_exec,
        port_forward.clone(),
        main_session.clone(),
    )
    .await?;

    // Gateway authentication, forwarding, and readiness do not depend on SSH
    // or the host OS. Acceptance remains false until the gateway authenticates
    // this supervisor, and reconnects retain main's retry behavior.
    let (session_task, session_readiness) = match (openshell_endpoint, sandbox_id) {
        (Some(endpoint), Some(id)) => {
            let (task, accepted) = crate::supervisor_session::spawn_with_readiness(
                endpoint.to_string(),
                id.to_string(),
                ssh_socket_path.unwrap_or_default(),
                port_forward,
                None,
                terminating.clone(),
                crate::supervisor_session::SessionRuntimeContext {
                    instance_id: instance_id.clone(),
                    session_id_updates: supervisor_session_updates,
                },
            );
            (Some(task), Some(accepted))
        }
        _ => (None, None),
    };
    Ok(BoundaryAccess {
        instance_id,
        terminating,
        ssh_task,
        session_task,
        session_readiness,
        main_session: Some(main_session),
    })
}

/// The optional SSH adapter is the only platform-specific access component.
#[cfg(unix)]
async fn start_optional_ssh(
    socket_path: Option<std::path::PathBuf>,
    shared_socket: bool,
    ca_file_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    boundary_exec: Arc<dyn BoundaryExec>,
    port_forward: Arc<dyn BoundaryLoopbackConnector>,
    main_session: Arc<crate::main_session::MainSession>,
) -> Result<Option<tokio::task::JoinHandle<()>>> {
    let Some(socket_path) = socket_path else {
        return Ok(None);
    };
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        if let Err(error) = crate::ssh::run_ssh_server(
            socket_path,
            ready_tx,
            ca_file_paths,
            shared_socket,
            port_forward,
            boundary_exec,
            Some(main_session),
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
    match tokio::time::timeout(Duration::from_secs(10), ready_rx).await {
        Ok(Ok(Ok(()))) => Ok(Some(task)),
        result => {
            task.abort();
            match result {
                Ok(Ok(Err(error))) => Err(error.context("SSH server failed during startup")),
                Ok(Err(_)) => Err(miette::miette!(
                    "SSH server task ended before signaling readiness"
                )),
                Err(_) => Err(miette::miette!(
                    "SSH server did not start within 10 seconds"
                )),
                Ok(Ok(Ok(()))) => unreachable!(),
            }
        }
    }
}

#[cfg(not(unix))]
async fn start_optional_ssh(
    socket_path: Option<std::path::PathBuf>,
    _shared_socket: bool,
    _ca_file_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    _boundary_exec: Arc<dyn BoundaryExec>,
    _port_forward: Arc<dyn BoundaryLoopbackConnector>,
    _main_session: Arc<crate::main_session::MainSession>,
) -> Result<Option<tokio::task::JoinHandle<()>>> {
    if socket_path.is_some() {
        return Err(miette::miette!(
            "SSH access sockets are unsupported on this host"
        ));
    }
    Ok(None)
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

    // Unit-only boundary fixture: these tests exercise access-plane composition,
    // not isolation enforcement or E2E qualification.
    struct AccessBoundary;

    #[async_trait::async_trait]
    impl BoundaryProcess for AccessBoundary {
        async fn attach(
            &self,
        ) -> std::result::Result<
            openshell_isolation_interface::contract::ProcessAttachment,
            openshell_isolation_interface::contract::BackendError,
        > {
            Ok(openshell_isolation_interface::contract::ProcessAttachment {
                stdin: Box::new(tokio::io::sink()),
                stdout: Box::new(tokio::io::empty()),
                stderr: Some(Box::new(tokio::io::empty())),
                terminal: None,
            })
        }
        async fn wait(
            &self,
        ) -> std::result::Result<
            openshell_isolation_interface::contract::BoundaryExitStatus,
            openshell_isolation_interface::contract::BackendError,
        > {
            Ok(openshell_isolation_interface::contract::BoundaryExitStatus::Exited(7))
        }
        async fn signal(
            &self,
            _: openshell_isolation_interface::contract::BoundarySignal,
        ) -> std::result::Result<(), openshell_isolation_interface::contract::BackendError>
        {
            Ok(())
        }
        async fn terminate(
            &self,
        ) -> std::result::Result<(), openshell_isolation_interface::contract::BackendError>
        {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl BoundaryExec for AccessBoundary {
        async fn exec(
            &self,
            _: openshell_isolation_interface::contract::ExecSpec,
        ) -> std::result::Result<
            openshell_isolation_interface::contract::ExecSession,
            openshell_isolation_interface::contract::BackendError,
        > {
            Err(
                openshell_isolation_interface::contract::BackendError::Unsupported(
                    "unit fixture has no exec".into(),
                ),
            )
        }
    }

    #[async_trait::async_trait]
    impl BoundaryLoopbackConnector for AccessBoundary {
        async fn connect(
            &self,
            _: openshell_isolation_interface::contract::LoopbackTarget,
        ) -> std::result::Result<
            openshell_isolation_interface::contract::BoundaryDuplexStream,
            openshell_isolation_interface::contract::BackendError,
        > {
            Err(
                openshell_isolation_interface::contract::BackendError::Unsupported(
                    "unit fixture has no forwarding".into(),
                ),
            )
        }
    }

    #[tokio::test]
    async fn no_ssh_access_retains_main_attachment_and_session_readiness() {
        let boundary = Arc::new(AccessBoundary);
        let access = start_boundary_access(
            Some("sandbox"),
            Some("http://127.0.0.1:1"),
            None,
            false,
            None,
            boundary.clone(),
            boundary.clone(),
            boundary,
            None,
        )
        .await
        .expect("access without SSH is portable");
        assert!(access.ssh_task.is_none());
        assert!(access.session_task.is_some());
        assert!(
            !*access
                .session_readiness()
                .expect("readiness exists")
                .borrow()
        );
        let main = access
            .main_session
            .as_ref()
            .expect("main attachment retained");
        access.publish_main_exit(7, true).await;
        main.begin_terminal_attachment()
            .expect("fast-exit attachment survives without SSH");
        main.end_terminal_attachment();
        let terminating = access.terminating.clone();
        drop(access);
        assert!(terminating.load(Ordering::Acquire));
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn explicit_unix_ssh_socket_is_rejected() {
        let boundary = Arc::new(AccessBoundary);
        let result = start_boundary_access(
            None,
            None,
            Some("health.sock"),
            false,
            None,
            boundary.clone(),
            boundary.clone(),
            boundary,
            None,
        )
        .await;
        assert!(
            result
                .err()
                .expect("Unix SSH unsupported")
                .to_string()
                .contains("unsupported")
        );
    }

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
