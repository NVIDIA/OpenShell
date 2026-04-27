// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Maps Podman container events to the compute-driver watch protocol.

use crate::client::{
    ContainerInspect, ContainerListEntry, ContainerState, HealthState, PodmanApiError,
    PodmanClient, PodmanEvent,
};
use crate::container::{LABEL_MANAGED_FILTER, LABEL_SANDBOX_ID, LABEL_SANDBOX_NAME, short_id};
use futures::Stream;
use openshell_core::ComputeDriverError;
use openshell_core::proto::compute::v1::{
    DriverCondition, DriverSandbox, DriverSandboxStatus, WatchSandboxesDeletedEvent,
    WatchSandboxesEvent, WatchSandboxesSandboxEvent, watch_sandboxes_event,
};
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, warn};

// Condition reason constants shared across event-building paths.
const CONDITION_RUNNING: &str = "ContainerRunning";
const CONDITION_STARTING: &str = "ContainerStarting";
const CONDITION_EXITED: &str = "ContainerExited";
const CONDITION_STOPPED: &str = "ContainerStopped";

pub type WatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, ComputeDriverError>> + Send>>;

/// Build a `WatchSandboxesEvent` carrying a sandbox snapshot.
fn sandbox_event(sandbox: DriverSandbox) -> WatchSandboxesEvent {
    WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::Sandbox(
            WatchSandboxesSandboxEvent {
                sandbox: Some(sandbox),
            },
        )),
    }
}

/// Build a `WatchSandboxesEvent` for a deleted sandbox.
fn deleted_event(sandbox_id: String) -> WatchSandboxesEvent {
    WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::Deleted(
            WatchSandboxesDeletedEvent { sandbox_id },
        )),
    }
}

/// Start a watch stream that emits current state and live events.
///
/// The stream first emits a snapshot of all currently-running managed
/// sandboxes (initial state sync), then delivers live container events
/// as they arrive from the Podman event stream.
///
/// # Reconnection contract
///
/// The returned stream is **single-use**.  When the Podman event connection
/// drops (daemon restart, socket error, or clean shutdown), the stream
/// terminates with a final error item and stops producing events.
///
/// Callers are responsible for reconnecting by calling [`start_watch`] again.
/// The server's `ComputeRuntime::watch_loop` in `openshell-server` provides
/// this behaviour with a 2-second backoff: when the stream terminates with an
/// error, `watch_loop` sleeps and then calls `watch_sandboxes()` again, which
/// ultimately calls `start_watch()` again and re-syncs state.
///
/// **Do not add reconnection logic inside this function.**  A local reconnect
/// would race with `watch_loop`'s retry and produce duplicate initial-sync
/// events that corrupt the server's sandbox index.
pub async fn start_watch(client: PodmanClient) -> Result<WatchStream, PodmanApiError> {
    let (tx, rx) = mpsc::channel::<Result<WatchSandboxesEvent, ComputeDriverError>>(256);

    // 1. Subscribe to events first so we don't miss any during the list.
    let mut event_rx = client.events_stream(LABEL_MANAGED_FILTER).await?;

    // 2. List existing containers for initial state sync.
    let existing = client.list_containers(LABEL_MANAGED_FILTER).await?;

    for entry in &existing {
        // For running containers, use inspect to get full state including
        // health check status — matching the same condition derivation used
        // for live events.
        if entry.state == "running" {
            match client.inspect_container(&entry.id).await {
                Ok(inspect) => {
                    if let Some(sandbox) = driver_sandbox_from_inspect(&inspect) {
                        if tx.send(Ok(sandbox_event(sandbox))).await.is_err() {
                            return Err(PodmanApiError::Connection(
                                "watch receiver dropped during initial sync".into(),
                            ));
                        }
                        continue;
                    }
                }
                Err(e) => {
                    warn!(
                        container_id = %entry.id,
                        error = %e,
                        "Failed to inspect running container during initial sync, falling back to list entry"
                    );
                }
            }
        }
        if let Some(event) = driver_sandbox_from_list_entry(entry).map(sandbox_event) {
            if tx.send(Ok(event)).await.is_err() {
                return Err(PodmanApiError::Connection(
                    "watch receiver dropped during initial sync".into(),
                ));
            }
        }
    }

    // 3. Stream live events (buffered during the list operation above).

    tokio::spawn(async move {
        while let Some(result) = event_rx.recv().await {
            match result {
                Ok(event) => {
                    if let Some(we) = map_podman_event(&event, &client).await {
                        if tx.send(Ok(we)).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    if tx
                        .send(Err(ComputeDriverError::Message(e.to_string())))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
        // The Podman event stream has ended — either because the Podman
        // daemon restarted, the Unix socket was closed, or the connection
        // dropped.  We do NOT reconnect here; see the doc-comment on
        // start_watch() for the full reconnection contract.
        //
        // Sending this error terminates the WatchStream seen by the caller.
        // The server's watch_loop detects the terminal error, waits 2 seconds,
        // then calls watch_sandboxes() → start_watch() again, which re-lists
        // all containers and re-subscribes to events.  This ensures a full
        // state resync after any Podman daemon interruption.
        warn!("podman event stream ended unexpectedly; watch_loop will reconnect");
        let _ = tx
            .send(Err(ComputeDriverError::Message(
                "podman event stream ended unexpectedly".to_string(),
            )))
            .await;
    });

    Ok(Box::pin(ReceiverStream::new(rx)))
}

/// Map a Podman event to an optional watch event.
///
/// Some events (like `remove`) produce a deletion event. State-change events
/// trigger a container inspect to build a full snapshot.
async fn map_podman_event(
    event: &PodmanEvent,
    client: &PodmanClient,
) -> Option<WatchSandboxesEvent> {
    let container_id = &event.actor.id;
    let sandbox_id = event
        .actor
        .attributes
        .get(LABEL_SANDBOX_ID)
        .cloned()
        .unwrap_or_default();

    if sandbox_id.is_empty() {
        debug!(
            container_id = %container_id,
            action = %event.action,
            "Ignoring event for container without sandbox-id label"
        );
        return None;
    }

    match event.action.as_str() {
        "remove" => Some(deleted_event(sandbox_id.clone())),
        "create" | "start" | "stop" | "die" | "health_status" => {
            // Inspect the container to get current state.
            match client.inspect_container(container_id).await {
                Ok(inspect) => driver_sandbox_from_inspect(&inspect).map(sandbox_event),
                Err(PodmanApiError::NotFound(_)) => {
                    // The container is already gone by the time we inspected
                    // it. This is a normal race between the `die`/`stop` event
                    // and the subsequent `remove` event: Podman fires `die`
                    // first, but the container may be fully removed before we
                    // can inspect it. Treat this as a deletion so the server
                    // does not see a spurious phase regression.
                    info!(
                        container_id = %container_id,
                        action = %event.action,
                        "Container already removed when inspecting after event, emitting deleted event"
                    );
                    Some(deleted_event(sandbox_id.clone()))
                }
                Err(e) => {
                    warn!(
                        container_id = %container_id,
                        error = %e,
                        "Failed to inspect container after event"
                    );
                    // Emit a synthetic event with the info we have so the
                    // server knows something happened.
                    let sandbox_name = event
                        .actor
                        .attributes
                        .get(LABEL_SANDBOX_NAME)
                        .cloned()
                        .unwrap_or_default();
                    Some(sandbox_event(build_driver_sandbox(
                        sandbox_id.clone(),
                        sandbox_name,
                        String::new(),
                        short_id(container_id),
                        DriverCondition {
                            r#type: "Ready".to_string(),
                            status: "Unknown".to_string(),
                            reason: "InspectFailed".to_string(),
                            message: format!("Container inspect failed: {e}"),
                            last_transition_time: String::new(),
                        },
                        false,
                    )))
                }
            }
        }
        _ => {
            debug!(action = %event.action, "Ignoring unhandled Podman event");
            None
        }
    }
}

/// Construct a `DriverSandbox` from common fields.
///
/// Centralises the boilerplate that every event/inspect/list path shares:
/// `namespace`, `spec`, `agent_fd`, and `sandbox_fd` are always empty in
/// the Podman driver.
fn build_driver_sandbox(
    sandbox_id: String,
    sandbox_name: String,
    instance_name: String,
    instance_id: String,
    condition: DriverCondition,
    deleting: bool,
) -> DriverSandbox {
    DriverSandbox {
        id: sandbox_id,
        name: sandbox_name,
        namespace: String::new(),
        spec: None,
        status: Some(DriverSandboxStatus {
            sandbox_name: instance_name,
            instance_id,
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![condition],
            deleting,
        }),
    }
}

/// Build a `DriverSandbox` from a container inspection result.
pub fn driver_sandbox_from_inspect(inspect: &ContainerInspect) -> Option<DriverSandbox> {
    let sandbox_id = inspect.config.labels.get(LABEL_SANDBOX_ID)?.clone();
    let sandbox_name = inspect
        .config
        .labels
        .get(LABEL_SANDBOX_NAME)
        .cloned()
        .unwrap_or_default();

    let condition = condition_from_state(&inspect.state);
    let deleting = inspect.state.status == "removing";

    Some(build_driver_sandbox(
        sandbox_id,
        sandbox_name,
        inspect.name.trim_start_matches('/').to_string(),
        short_id(&inspect.id),
        condition,
        deleting,
    ))
}

/// Build a `DriverSandbox` from a container list entry (no inspect needed).
pub(crate) fn driver_sandbox_from_list_entry(entry: &ContainerListEntry) -> Option<DriverSandbox> {
    let sandbox_id = entry.labels.get(LABEL_SANDBOX_ID)?.clone();
    let sandbox_name = entry
        .labels
        .get(LABEL_SANDBOX_NAME)
        .cloned()
        .unwrap_or_default();

    let (reason, status_str, message) = match entry.state.as_str() {
        "running" => (
            CONDITION_RUNNING,
            "True",
            "Container is running".to_string(),
        ),
        "created" => ("ContainerCreated", "False", String::new()),
        "exited" => (CONDITION_EXITED, "False", String::new()),
        "stopped" => (CONDITION_STOPPED, "False", String::new()),
        "removing" => ("ContainerRemoving", "False", String::new()),
        _ => ("Unknown", "Unknown", String::new()),
    };

    Some(build_driver_sandbox(
        sandbox_id,
        sandbox_name,
        entry.names.first().cloned().unwrap_or_default(),
        short_id(&entry.id),
        DriverCondition {
            r#type: "Ready".to_string(),
            status: status_str.to_string(),
            reason: reason.to_string(),
            message,
            last_transition_time: String::new(),
        },
        entry.state == "removing",
    ))
}

/// Derive a `DriverCondition` from Podman container state.
fn condition_from_state(state: &ContainerState) -> DriverCondition {
    let (status_val, reason, message) = match state.status.as_str() {
        "running" => match &state.health {
            Some(HealthState { status }) if status == "healthy" => {
                ("True", "HealthCheckPassed", String::new())
            }
            Some(HealthState { status }) if status == "unhealthy" => {
                ("False", "HealthCheckFailed", String::new())
            }
            Some(HealthState { status }) if status == "starting" => {
                ("False", "HealthCheckStarting", String::new())
            }
            _ => ("False", CONDITION_STARTING, String::new()),
        },
        "created" => ("False", "ContainerCreated", String::new()),
        "exited" | "stopped" => {
            let msg = if state.oom_killed {
                "Container was killed by the OOM killer".to_string()
            } else {
                format!("Container exited with code {}", state.exit_code)
            };
            let reason = if state.oom_killed {
                "OOMKilled"
            } else {
                CONDITION_EXITED
            };
            ("False", reason, msg)
        }
        other => (
            "Unknown",
            "Unknown",
            format!("Unknown container state: {other}"),
        ),
    };

    // Use Podman's state timestamps for last_transition_time:
    // - Running/healthy states use started_at
    // - Stopped/exited states use finished_at
    let last_transition_time = match state.status.as_str() {
        "running" => state.started_at.clone().unwrap_or_default(),
        "exited" | "stopped" => state.finished_at.clone().unwrap_or_default(),
        _ => String::new(),
    };

    DriverCondition {
        r#type: "Ready".to_string(),
        status: status_val.to_string(),
        reason: reason.to_string(),
        message,
        last_transition_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn condition_healthy_container() {
        let state = ContainerState {
            status: "running".to_string(),
            running: true,
            exit_code: 0,
            oom_killed: false,
            health: Some(HealthState {
                status: "healthy".to_string(),
            }),
            started_at: Some("2026-04-14T10:00:00Z".to_string()),
            finished_at: None,
        };
        let cond = condition_from_state(&state);
        assert_eq!(cond.r#type, "Ready");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "HealthCheckPassed");
        assert_eq!(cond.last_transition_time, "2026-04-14T10:00:00Z");
    }

    #[test]
    fn condition_oom_killed() {
        let state = ContainerState {
            status: "exited".to_string(),
            running: false,
            exit_code: 137,
            oom_killed: true,
            health: None,
            started_at: None,
            finished_at: Some("2026-04-14T11:00:00Z".to_string()),
        };
        let cond = condition_from_state(&state);
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "OOMKilled");
        assert_eq!(cond.last_transition_time, "2026-04-14T11:00:00Z");
    }

    #[test]
    fn condition_normal_exit() {
        let state = ContainerState {
            status: "exited".to_string(),
            running: false,
            exit_code: 1,
            oom_killed: false,
            health: None,
            started_at: None,
            finished_at: Some("2026-04-14T12:00:00Z".to_string()),
        };
        let cond = condition_from_state(&state);
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "ContainerExited");
        assert!(cond.message.contains("code 1"));
    }

    #[test]
    fn short_id_truncates() {
        assert_eq!(short_id("abc123def456789"), "abc123def456");
        assert_eq!(short_id("short"), "short");
    }

    #[test]
    fn sandbox_event_from_list_entry_running() {
        let mut labels = std::collections::HashMap::new();
        labels.insert(LABEL_SANDBOX_ID.to_string(), "test-id".to_string());
        labels.insert(LABEL_SANDBOX_NAME.to_string(), "test-name".to_string());

        let entry = ContainerListEntry {
            id: "abc123def456789".to_string(),
            names: vec!["openshell-sandbox-test-name".to_string()],
            state: "running".to_string(),
            labels,
            ports: None,
            networks: None,
            exit_code: 0,
        };

        let sandbox = driver_sandbox_from_list_entry(&entry).expect("should produce a sandbox");
        let status = sandbox.status.expect("should have status");
        assert_eq!(status.conditions.len(), 1);
        let cond = &status.conditions[0];
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "ContainerRunning");
        assert!(!status.deleting);
    }

    #[test]
    fn synthetic_inspect_failed_event_structure() {
        // Verify the structure of an inspect-failure event by constructing one
        // using the same pattern as the production code.
        let condition = DriverCondition {
            r#type: "Ready".to_string(),
            status: "Unknown".to_string(),
            reason: "InspectFailed".to_string(),
            message: "Container inspect failed: connection refused".to_string(),
            last_transition_time: String::new(),
        };

        let sandbox = DriverSandbox {
            id: "sandbox-123".to_string(),
            name: "test-sandbox".to_string(),
            namespace: String::new(),
            spec: None,
            status: Some(DriverSandboxStatus {
                sandbox_name: String::new(),
                instance_id: short_id("container-id-full"),
                agent_fd: String::new(),
                sandbox_fd: String::new(),
                conditions: vec![condition],
                deleting: false,
            }),
        };

        let event = WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::Sandbox(
                WatchSandboxesSandboxEvent {
                    sandbox: Some(sandbox),
                },
            )),
        };

        let payload = event.payload.unwrap();
        let sandbox_event = match payload {
            watch_sandboxes_event::Payload::Sandbox(s) => s,
            _ => panic!("expected Sandbox payload"),
        };
        let status = sandbox_event.sandbox.unwrap().status.unwrap();
        assert_eq!(status.conditions.len(), 1);
        let cond = &status.conditions[0];
        assert_eq!(cond.reason, "InspectFailed");
        assert_eq!(cond.status, "Unknown");
        assert!(cond.message.contains("inspect failed"));
    }

    #[test]
    fn not_found_inspect_produces_deleted_event() {
        // When inspect_container returns NotFound (404) after a `die` or
        // `stop` event, the container is already gone. The watcher should emit
        // a deleted_event rather than a synthetic InspectFailed sandbox event,
        // preventing the server from regressing the sandbox phase back to
        // Provisioning.
        //
        // We verify the shape of a deleted_event directly since
        // map_podman_event is async and requires a live Podman client. The
        // production code path is:
        //   Err(PodmanApiError::NotFound(_)) => Some(deleted_event(sandbox_id))
        let sandbox_id = "sandbox-abc-123".to_string();
        let event = deleted_event(sandbox_id.clone());

        let payload = event.payload.expect("deleted event must have a payload");
        match payload {
            watch_sandboxes_event::Payload::Deleted(d) => {
                assert_eq!(d.sandbox_id, sandbox_id);
            }
            other => {
                panic!(
                    "expected Deleted payload, got {other:?} — a NotFound inspect must not produce a sandbox or platform event"
                );
            }
        }
    }
}
