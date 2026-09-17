// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-owned access-plane assembly for a remote sandbox.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use miette::Result;
use openshell_isolation_interface::contract::{
    BoundaryExec, BoundaryLoopbackConnector, BoundaryProcess,
};
use openshell_ocsf::{ActivityId, AppLifecycleBuilder, SeverityId, StatusId, ocsf_emit};

use crate::otlp::RelayLifecycle;
use crate::supervisor_session::{DrainRequest, SessionRuntimeContext, TelemetryRelay};

fn ocsf_ctx() -> &'static openshell_ocsf::EventContext {
    openshell_ocsf::ctx::ctx()
}

/// Upper bound on the final OTLP relay drain before the exit is reported, so
/// an unreachable gateway cannot delay the exit report.
pub const OTEL_FINAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(3);

/// Supervisor-owned SSH and gateway-session tasks for a running sandbox.
pub struct BoundaryAccess {
    instance_id: String,
    terminating: Arc<AtomicBool>,
    ssh_task: Option<tokio::task::JoinHandle<()>>,
    session_task: Option<tokio::task::JoinHandle<()>>,
    session_readiness: Option<tokio::sync::watch::Receiver<bool>>,
    main_session: Option<Arc<crate::main_session::MainSession>>,
    /// Sends the one-shot final drain request to the session task.
    telemetry_drain: Mutex<Option<tokio::sync::oneshot::Sender<DrainRequest>>>,
}

impl BoundaryAccess {
    /// Stable supervisor instance ID used for lifecycle reporting.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Ask the session to stop the OTLP receiver and flush buffered telemetry
    /// onto its stream. Returns when the session acks or `deadline` elapses.
    /// A boundary without a relay or session returns at once. Only the first
    /// call sends a request.
    pub async fn drain_telemetry(&self, deadline: Duration) {
        let request_tx = self
            .telemetry_drain
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(request_tx) = request_tx else {
            return;
        };
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        if request_tx.send(done_tx).is_err() {
            tracing::debug!("OTEL relay drain skipped: session task is gone");
            return;
        }
        if tokio::time::timeout(deadline, done_rx).await.is_err() {
            tracing::warn!(
                ?deadline,
                "OTEL relay final drain did not complete within deadline"
            );
        }
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
    telemetry: Option<RelayLifecycle>,
) -> Result<BoundaryAccess> {
    let instance_id = uuid::Uuid::new_v4().to_string();
    let terminating = Arc::new(AtomicBool::new(false));
    // Without a gateway session the relay has nowhere to forward; dropping
    // it here leaves the connection server accepting into a closed buffer,
    // which counts drops and never blocks the workload.
    let Some(ssh_socket_path) = ssh_socket_path.map(std::path::PathBuf::from) else {
        return Ok(BoundaryAccess {
            instance_id,
            terminating,
            ssh_task: None,
            session_task: None,
            session_readiness: None,
            main_session: None,
            telemetry_drain: Mutex::new(None),
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

    let (session_task, session_readiness, telemetry_drain) = match (openshell_endpoint, sandbox_id)
    {
        (Some(endpoint), Some(id)) => {
            let (telemetry, drain_tx) = telemetry.map_or((None, None), |relay| {
                let (drain_tx, drain_rx) = tokio::sync::oneshot::channel();
                (Some(TelemetryRelay { relay, drain_rx }), Some(drain_tx))
            });
            let (task, mut accepted) = crate::supervisor_session::spawn_with_readiness(
                endpoint.to_string(),
                id.to_string(),
                ssh_socket_path,
                port_forward,
                None,
                terminating.clone(),
                SessionRuntimeContext {
                    instance_id: instance_id.clone(),
                    session_id_updates: supervisor_session_updates,
                    telemetry,
                },
            );
            let accepted_result =
                tokio::time::timeout(Duration::from_secs(10), accepted.wait_for(|ready| *ready))
                    .await
                    .map(|result| result.map(|_| ()));
            match accepted_result {
                Ok(Ok(())) => (Some(task), Some(accepted), drain_tx),
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
        _ => (None, None, None),
    };

    Ok(BoundaryAccess {
        instance_id,
        terminating,
        ssh_task: Some(ssh_task),
        session_task,
        session_readiness,
        main_session: Some(main_session),
        telemetry_drain: Mutex::new(telemetry_drain),
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

    fn access_with_drain(
        drain: Option<tokio::sync::oneshot::Sender<DrainRequest>>,
    ) -> BoundaryAccess {
        BoundaryAccess {
            instance_id: "instance".to_string(),
            terminating: Arc::new(AtomicBool::new(false)),
            ssh_task: None,
            session_task: None,
            session_readiness: None,
            main_session: None,
            telemetry_drain: Mutex::new(drain),
        }
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
            telemetry_drain: Mutex::new(None),
        };

        access.publish_main_exit(7, true).await;

        main_session
            .begin_terminal_attachment()
            .expect("declared CLI attachment must remain valid after a fast remote main exits");
        main_session.end_terminal_attachment();
    }

    #[tokio::test]
    async fn drain_telemetry_returns_at_once_without_a_relay() {
        let access = access_with_drain(None);
        tokio::time::timeout(
            Duration::from_millis(100),
            access.drain_telemetry(Duration::from_secs(5)),
        )
        .await
        .expect("no relay means nothing to wait for");
    }

    #[tokio::test]
    async fn drain_telemetry_returns_at_once_when_the_session_is_gone() {
        let (drain_tx, drain_rx) = tokio::sync::oneshot::channel::<DrainRequest>();
        drop(drain_rx);
        let access = access_with_drain(Some(drain_tx));
        tokio::time::timeout(
            Duration::from_millis(100),
            access.drain_telemetry(Duration::from_secs(5)),
        )
        .await
        .expect("a dropped session receiver must not stall the exit path");
    }

    #[tokio::test]
    async fn drain_telemetry_waits_for_the_session_ack_and_sends_once() {
        let (drain_tx, drain_rx) = tokio::sync::oneshot::channel::<DrainRequest>();
        let access = access_with_drain(Some(drain_tx));

        let session = tokio::spawn(async move {
            let done_tx = drain_rx.await.expect("drain request arrives");
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = done_tx.send(());
        });

        let started = std::time::Instant::now();
        access.drain_telemetry(Duration::from_secs(5)).await;
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "drain waits for the session's ack"
        );
        session.await.unwrap();

        // Second call finds the request already sent and returns immediately.
        tokio::time::timeout(
            Duration::from_millis(100),
            access.drain_telemetry(Duration::from_secs(5)),
        )
        .await
        .expect("only the first call sends a request");
    }

    #[tokio::test]
    async fn drain_telemetry_gives_up_at_the_deadline() {
        let (drain_tx, drain_rx) = tokio::sync::oneshot::channel::<DrainRequest>();
        let access = access_with_drain(Some(drain_tx));
        // Hold the request open and never ack.
        let held = tokio::spawn(async move {
            let done_tx = drain_rx.await.expect("drain request arrives");
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(done_tx);
        });

        let started = std::time::Instant::now();
        access.drain_telemetry(Duration::from_millis(100)).await;
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100) && elapsed < Duration::from_secs(2),
            "drain returns at the deadline, got {elapsed:?}"
        );
        held.abort();
    }
}
