// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pending supervisor pod registrations for warm-pool activation.
//!
//! Cold pods already bound to a sandbox are activated immediately by the
//! `RegisterSupervisorPod` handler. Warm pods can register before claim
//! assignment; the future claim controller will activate the stored stream once
//! it binds the exact pod UID to a sandbox.

use crate::auth::principal::RegisteredPodIdentity;
use openshell_core::proto::PodActivationMessage;
use std::collections::HashMap;
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tracing::{debug, info, warn};

#[derive(Debug, Default)]
pub struct SupervisorPodRegistrationRegistry {
    inner: Mutex<Inner>,
    next_session_id: AtomicU64,
}

#[derive(Debug, Default)]
struct Inner {
    pending_by_pod_uid: HashMap<String, PendingRegistration>,
}

#[derive(Debug)]
struct PendingRegistration {
    identity: RegisteredPodIdentity,
    sender: mpsc::Sender<StdResult<PodActivationMessage, Status>>,
    session_id: u64,
    registered_at: Instant,
}

impl SupervisorPodRegistrationRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::result_large_err)]
    pub fn register_pending(
        self: &Arc<Self>,
        identity: RegisteredPodIdentity,
    ) -> Result<PendingRegistrationStream, Status> {
        if identity.pod_uid.is_empty() {
            return Err(Status::permission_denied("registered pod UID is required"));
        }

        let (sender, receiver) = mpsc::channel(1);
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let pod_uid = identity.pod_uid.clone();
        let pod_name = identity.pod_name.clone();
        let sandbox_owner = identity.sandbox_owner_name.clone();

        let replaced = {
            let mut inner = self.inner.lock().expect("pending pod registry poisoned");
            inner
                .pending_by_pod_uid
                .insert(
                    pod_uid.clone(),
                    PendingRegistration {
                        identity,
                        sender,
                        session_id,
                        registered_at: Instant::now(),
                    },
                )
                .is_some()
        };

        if replaced {
            info!(
                pod = %pod_name,
                pod_uid = %pod_uid,
                sandbox_owner = %sandbox_owner,
                "replaced duplicate pending supervisor pod registration"
            );
        } else {
            info!(
                pod = %pod_name,
                pod_uid = %pod_uid,
                sandbox_owner = %sandbox_owner,
                "registered warm supervisor pod pending activation"
            );
        }

        Ok(PendingRegistrationStream {
            registry: self.clone(),
            pod_uid,
            session_id,
            inner: ReceiverStream::new(receiver),
        })
    }

    #[allow(clippy::result_large_err)]
    #[allow(dead_code)]
    pub fn activate(
        &self,
        pod_uid: &str,
        activation: PodActivationMessage,
    ) -> Result<bool, Status> {
        let pending = {
            let mut inner = self.inner.lock().expect("pending pod registry poisoned");
            inner.pending_by_pod_uid.remove(pod_uid)
        };

        let Some(pending) = pending else {
            debug!(pod_uid = %pod_uid, "no pending supervisor pod registration to activate");
            return Ok(false);
        };

        let pod_name = pending.identity.pod_name.clone();
        pending.sender.try_send(Ok(activation)).map_err(|_| {
            warn!(
                pod = %pod_name,
                pod_uid = %pod_uid,
                "pending supervisor pod registration stream closed before activation"
            );
            Status::unavailable("registered pod stream closed before activation")
        })?;
        info!(
            pod = %pod_name,
            pod_uid = %pod_uid,
            pending_ms = pending.registered_at.elapsed().as_millis(),
            "activated pending supervisor pod registration"
        );
        Ok(true)
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn pending_count(&self) -> usize {
        self.inner
            .lock()
            .expect("pending pod registry poisoned")
            .pending_by_pod_uid
            .len()
    }

    fn remove_if_session(&self, pod_uid: &str, session_id: u64) {
        let removed = {
            let mut inner = self.inner.lock().expect("pending pod registry poisoned");
            if inner
                .pending_by_pod_uid
                .get(pod_uid)
                .is_some_and(|pending| pending.session_id == session_id)
            {
                inner.pending_by_pod_uid.remove(pod_uid)
            } else {
                None
            }
        };

        if let Some(pending) = removed {
            debug!(
                pod = %pending.identity.pod_name,
                pod_uid = %pod_uid,
                pending_ms = pending.registered_at.elapsed().as_millis(),
                "removed pending supervisor pod registration"
            );
        }
    }
}

pub struct PendingRegistrationStream {
    registry: Arc<SupervisorPodRegistrationRegistry>,
    pod_uid: String,
    session_id: u64,
    inner: ReceiverStream<StdResult<PodActivationMessage, Status>>,
}

impl Stream for PendingRegistrationStream {
    type Item = StdResult<PodActivationMessage, Status>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_next(cx)
    }
}

impl Drop for PendingRegistrationStream {
    fn drop(&mut self) {
        self.registry
            .remove_if_session(&self.pod_uid, self.session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio_stream::StreamExt;

    fn pod_identity(pod_uid: &str) -> RegisteredPodIdentity {
        RegisteredPodIdentity {
            pod_name: "warm-pod-a".to_string(),
            pod_uid: pod_uid.to_string(),
            sandbox_id: None,
            sandbox_owner_name: "sandbox-owner-a".to_string(),
            sandbox_owner_uid: "owner-uid-a".to_string(),
        }
    }

    #[test]
    fn dropping_stream_removes_pending_registration() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        let stream = registry
            .register_pending(pod_identity("pod-uid-a"))
            .expect("register pending");
        assert_eq!(registry.pending_count(), 1);
        drop(stream);
        assert_eq!(registry.pending_count(), 0);
    }

    #[test]
    fn duplicate_registration_replaces_prior_stream() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        let old = registry
            .register_pending(pod_identity("pod-uid-a"))
            .expect("register old");
        let new = registry
            .register_pending(pod_identity("pod-uid-a"))
            .expect("register new");

        assert_eq!(registry.pending_count(), 1);
        drop(old);
        assert_eq!(
            registry.pending_count(),
            1,
            "old stream drop must not remove replacement"
        );
        drop(new);
        assert_eq!(registry.pending_count(), 0);
    }

    #[tokio::test]
    async fn activation_sends_message_and_removes_pending_registration() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        let mut stream = registry
            .register_pending(pod_identity("pod-uid-a"))
            .expect("register pending");

        let activation = PodActivationMessage {
            sandbox_id: "sandbox-a".to_string(),
            sandbox_name: "sandbox-a".to_string(),
            token: "token-a".to_string(),
            token_expires_at_ms: 123,
            startup_metadata: HashMap::default(),
        };
        assert!(
            registry
                .activate("pod-uid-a", activation)
                .expect("activate")
        );
        assert_eq!(registry.pending_count(), 0);

        let received = stream
            .next()
            .await
            .expect("activation message")
            .expect("activation OK");
        assert_eq!(received.sandbox_id, "sandbox-a");
        assert!(stream.next().await.is_none());
    }
}
