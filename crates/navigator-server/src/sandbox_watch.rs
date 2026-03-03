// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-memory buses to support sandbox watch streaming.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::Event as KubeEventObj;
use kube::Client;
use kube::api::Api;
use kube::runtime::watcher::{self, Event};
use navigator_core::proto::{PlatformEvent, SandboxStreamEvent};
use tokio::sync::broadcast;
use tonic::Status;
use tracing::{debug, warn};

use crate::ServerState;

/// Broadcast bus of sandbox updates keyed by sandbox id.
///
/// Producers call [`SandboxWatchBus::notify`] whenever the persisted sandbox record changes.
/// Consumers can subscribe per-id to drive streaming updates without polling.
#[derive(Debug, Clone)]
pub struct SandboxWatchBus {
    inner: Arc<Mutex<HashMap<String, broadcast::Sender<()>>>>,
}

impl SandboxWatchBus {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn sender_for(&self, sandbox_id: &str) -> broadcast::Sender<()> {
        let mut inner = self.inner.lock().expect("sandbox watch bus lock poisoned");
        inner
            .entry(sandbox_id.to_string())
            .or_insert_with(|| {
                // Small buffer; lag is handled best-effort by the stream.
                let (tx, _rx) = broadcast::channel(128);
                tx
            })
            .clone()
    }

    /// Notify watchers that the sandbox record has changed.
    pub fn notify(&self, sandbox_id: &str) {
        let tx = self.sender_for(sandbox_id);
        let _ = tx.send(());
    }

    /// Subscribe to sandbox updates.
    pub fn subscribe(&self, sandbox_id: &str) -> broadcast::Receiver<()> {
        self.sender_for(sandbox_id).subscribe()
    }
}

/// Spawn a background Kubernetes Event tailer.
///
/// This tailer publishes platform events (sourced from Kubernetes) into per-sandbox broadcast streams.
pub fn spawn_kube_event_tailer(state: Arc<ServerState>) {
    tokio::spawn(async move {
        let client = match Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "Failed to create kube client for event tailer");
                return;
            }
        };

        let ns = state.config.sandbox_namespace.clone();
        let api: Api<KubeEventObj> = Api::namespaced(client, &ns);

        // We don't have a stable label to select Events by sandbox id.
        // Instead, we watch all Events in the namespace and dispatch using the in-memory index.
        // This is best-effort and efficient enough for typical sandbox counts.
        let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();

        loop {
            match stream.try_next().await {
                Ok(Some(Event::Applied(obj))) => {
                    if let Some((sandbox_id, evt)) = map_kube_event_to_platform(&state, &obj) {
                        state
                            .tracing_log_bus
                            .platform_event_bus
                            .publish(&sandbox_id, evt);
                    }
                }
                Ok(Some(Event::Deleted(_))) => {}
                Ok(Some(Event::Restarted(_))) => {
                    debug!(namespace = %ns, "Kubernetes event watcher restarted");
                }
                Ok(None) => {
                    warn!(namespace = %ns, "Kubernetes event watcher stream ended");
                    break;
                }
                Err(err) => {
                    warn!(namespace = %ns, error = %err, "Kubernetes event watcher error");
                }
            }
        }
    });
}

fn map_kube_event_to_platform(
    state: &ServerState,
    obj: &KubeEventObj,
) -> Option<(String, SandboxStreamEvent)> {
    let involved = obj.involved_object.clone();
    let involved_kind = involved.kind.unwrap_or_default();
    let involved_name = involved.name.unwrap_or_default();

    let sandbox_id = match involved_kind.as_str() {
        "Sandbox" => state
            .sandbox_index
            .sandbox_id_for_sandbox_name(&involved_name)?,
        "Pod" => state
            .sandbox_index
            .sandbox_id_for_agent_pod(&involved_name)?,
        _ => return None,
    };

    let ts = obj
        .last_timestamp
        .as_ref()
        .or(obj.first_timestamp.as_ref())
        .map_or(0, |t| t.0.timestamp_millis());

    // Build metadata map with Kubernetes-specific details
    let mut metadata = HashMap::new();
    metadata.insert("involved_kind".to_string(), involved_kind);
    metadata.insert("involved_name".to_string(), involved_name);
    if let Some(ns) = &obj.involved_object.namespace {
        metadata.insert("namespace".to_string(), ns.clone());
    }
    if let Some(count) = obj.count {
        metadata.insert("count".to_string(), count.to_string());
    }

    let evt = PlatformEvent {
        timestamp_ms: ts,
        source: "kubernetes".to_string(),
        r#type: obj.type_.clone().unwrap_or_default(),
        reason: obj.reason.clone().unwrap_or_default(),
        message: obj.message.clone().unwrap_or_default(),
        metadata,
    };

    Some((
        sandbox_id,
        SandboxStreamEvent {
            payload: Some(navigator_core::proto::sandbox_stream_event::Payload::Event(
                evt,
            )),
        },
    ))
}

/// Helper to translate broadcast lag into a gRPC status.
pub fn broadcast_to_status(err: broadcast::error::RecvError) -> Status {
    match err {
        broadcast::error::RecvError::Closed => Status::cancelled("stream closed"),
        broadcast::error::RecvError::Lagged(n) => {
            Status::resource_exhausted(format!("watch stream lagged; dropped {n} messages"))
        }
    }
}
