// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pending supervisor pod registrations for warm-pool activation.
//!
//! Cold pods already bound to a sandbox are activated immediately by the
//! `RegisterSupervisorPod` handler. Warm pods can register before claim
//! assignment; the future claim controller will activate the stored stream once
//! it binds the exact pod UID to a sandbox.

use openshell_core::proto::PodActivationMessage;
use openshell_core::supervisor_bootstrap::SupervisorBootstrapIdentity;
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
    pending_by_instance_id: HashMap<String, PendingRegistration>,
    activated_instance_id: HashMap<String, Instant>,
}

#[derive(Debug)]
struct PendingRegistration {
    identity: SupervisorBootstrapIdentity,
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
        identity: SupervisorBootstrapIdentity,
    ) -> Result<PendingRegistrationStream, Status> {
        if identity.instance_id.is_empty() {
            return Err(Status::permission_denied(
                "registered supervisor instance ID is required",
            ));
        }

        let (sender, receiver) = mpsc::channel(1);
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let instance_id = identity.instance_id.clone();
        let instance_name = identity.instance_name.clone();
        let owner_name = identity.owner_name.clone();
        let driver = identity.driver.clone();

        let replaced = {
            let mut inner = self.inner.lock().expect("pending pod registry poisoned");
            if inner.activated_instance_id.contains_key(&instance_id) {
                return Err(Status::already_exists(
                    "supervisor instance has already been activated",
                ));
            }
            inner
                .pending_by_instance_id
                .insert(
                    instance_id.clone(),
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
                driver = %driver,
                instance = %instance_name,
                instance_id = %instance_id,
                owner = %owner_name,
                "replaced duplicate pending supervisor registration"
            );
        } else {
            info!(
                driver = %driver,
                instance = %instance_name,
                instance_id = %instance_id,
                owner = %owner_name,
                "registered warm supervisor instance pending activation"
            );
        }

        Ok(PendingRegistrationStream {
            registry: self.clone(),
            instance_id,
            session_id,
            inner: ReceiverStream::new(receiver),
        })
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn pending_identity(
        &self,
        instance_id: &str,
    ) -> Result<SupervisorBootstrapIdentity, Status> {
        let inner = self.inner.lock().expect("pending pod registry poisoned");
        if inner.activated_instance_id.contains_key(instance_id) {
            return Err(Status::already_exists(
                "supervisor instance has already been activated",
            ));
        }
        inner
            .pending_by_instance_id
            .get(instance_id)
            .map(|pending| pending.identity.clone())
            .ok_or_else(|| Status::not_found("pending supervisor registration not found"))
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn activate(
        &self,
        instance_id: &str,
        activation: PodActivationMessage,
    ) -> Result<(), Status> {
        let pending = {
            let mut inner = self.inner.lock().expect("pending pod registry poisoned");
            if inner.activated_instance_id.contains_key(instance_id) {
                return Err(Status::already_exists(
                    "supervisor instance has already been activated",
                ));
            }
            let Some(pending) = inner.pending_by_instance_id.remove(instance_id) else {
                debug!(
                    instance_id = %instance_id,
                    "no pending supervisor registration to activate"
                );
                return Err(Status::not_found(
                    "pending supervisor registration not found",
                ));
            };
            inner
                .activated_instance_id
                .insert(instance_id.to_string(), Instant::now());
            pending
        };

        let instance_name = pending.identity.instance_name.clone();
        if pending.sender.try_send(Ok(activation)).is_err() {
            let mut inner = self.inner.lock().expect("pending pod registry poisoned");
            inner.activated_instance_id.remove(instance_id);
            warn!(
                instance = %instance_name,
                instance_id = %instance_id,
                "pending supervisor registration stream closed before activation"
            );
            return Err(Status::unavailable(
                "registered supervisor stream closed before activation",
            ));
        }

        info!(
            instance = %instance_name,
            instance_id = %instance_id,
            pending_ms = pending.registered_at.elapsed().as_millis(),
            "activated pending supervisor registration"
        );
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn fail_pending(&self, instance_id: &str, status: Status) -> Result<(), Status> {
        let pending = {
            let mut inner = self.inner.lock().expect("pending pod registry poisoned");
            if inner.activated_instance_id.contains_key(instance_id) {
                return Err(Status::already_exists(
                    "supervisor instance has already been activated",
                ));
            }
            inner.pending_by_instance_id.remove(instance_id)
        };

        let Some(pending) = pending else {
            debug!(instance_id = %instance_id, "no pending supervisor registration to fail");
            return Err(Status::not_found(
                "pending supervisor registration not found",
            ));
        };

        let instance_name = pending.identity.instance_name.clone();
        pending.sender.try_send(Err(status)).map_err(|_| {
            warn!(
                instance = %instance_name,
                instance_id = %instance_id,
                "pending supervisor registration stream closed before failure notification"
            );
            Status::unavailable("registered supervisor stream closed before failure notification")
        })?;
        info!(
            instance = %instance_name,
            instance_id = %instance_id,
            pending_ms = pending.registered_at.elapsed().as_millis(),
            "failed pending supervisor registration"
        );
        Ok(())
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn pending_count(&self) -> usize {
        self.inner
            .lock()
            .expect("pending pod registry poisoned")
            .pending_by_instance_id
            .len()
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn activated_count(&self) -> usize {
        self.inner
            .lock()
            .expect("pending pod registry poisoned")
            .activated_instance_id
            .len()
    }

    fn remove_if_session(&self, instance_id: &str, session_id: u64) {
        let removed = {
            let mut inner = self.inner.lock().expect("pending pod registry poisoned");
            if inner
                .pending_by_instance_id
                .get(instance_id)
                .is_some_and(|pending| pending.session_id == session_id)
            {
                inner.pending_by_instance_id.remove(instance_id)
            } else {
                None
            }
        };

        if let Some(pending) = removed {
            debug!(
                instance = %pending.identity.instance_name,
                instance_id = %instance_id,
                pending_ms = pending.registered_at.elapsed().as_millis(),
                "removed pending supervisor registration"
            );
        }
    }
}

pub struct PendingRegistrationStream {
    registry: Arc<SupervisorPodRegistrationRegistry>,
    instance_id: String,
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
            .remove_if_session(&self.instance_id, self.session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio_stream::StreamExt;

    fn bootstrap_identity(instance_id: &str) -> SupervisorBootstrapIdentity {
        SupervisorBootstrapIdentity {
            driver: "kubernetes".to_string(),
            instance_name: "warm-pod-a".to_string(),
            instance_id: instance_id.to_string(),
            owner_name: "sandbox-owner-a".to_string(),
            owner_uid: "owner-uid-a".to_string(),
            binding: openshell_core::supervisor_bootstrap::SupervisorBootstrapBinding::WarmPending,
        }
    }

    #[test]
    fn dropping_stream_removes_pending_registration() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        let stream = registry
            .register_pending(bootstrap_identity("pod-uid-a"))
            .expect("register pending");
        assert_eq!(registry.pending_count(), 1);
        drop(stream);
        assert_eq!(registry.pending_count(), 0);
    }

    #[test]
    fn duplicate_registration_replaces_prior_stream() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        let old = registry
            .register_pending(bootstrap_identity("pod-uid-a"))
            .expect("register old");
        let new = registry
            .register_pending(bootstrap_identity("pod-uid-a"))
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
            .register_pending(bootstrap_identity("pod-uid-a"))
            .expect("register pending");

        let activation = PodActivationMessage {
            sandbox_id: "sandbox-a".to_string(),
            sandbox_name: "sandbox-a".to_string(),
            token: "token-a".to_string(),
            token_expires_at_ms: 123,
            startup_metadata: HashMap::default(),
        };
        registry
            .activate("pod-uid-a", activation)
            .expect("activate");
        assert_eq!(registry.pending_count(), 0);
        assert_eq!(registry.activated_count(), 1);

        let received = stream
            .next()
            .await
            .expect("activation message")
            .expect("activation OK");
        assert_eq!(received.sandbox_id, "sandbox-a");
        assert!(stream.next().await.is_none());
    }

    #[test]
    fn activation_for_unknown_pod_uid_returns_not_found() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        let activation = PodActivationMessage {
            sandbox_id: "sandbox-a".to_string(),
            sandbox_name: "sandbox-a".to_string(),
            token: "token-a".to_string(),
            token_expires_at_ms: 123,
            startup_metadata: HashMap::default(),
        };

        let err = registry
            .activate("pod-uid-a", activation)
            .expect_err("unknown pod UID must fail");

        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn activation_tombstone_rejects_duplicate_activation_and_registration() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        let mut stream = registry
            .register_pending(bootstrap_identity("pod-uid-a"))
            .expect("register pending");

        let activation = PodActivationMessage {
            sandbox_id: "sandbox-a".to_string(),
            sandbox_name: "sandbox-a".to_string(),
            token: "token-a".to_string(),
            token_expires_at_ms: 123,
            startup_metadata: HashMap::default(),
        };
        registry
            .activate("pod-uid-a", activation.clone())
            .expect("activate");
        let _ = stream.next().await.expect("activation message");

        let err = registry
            .activate("pod-uid-a", activation)
            .expect_err("duplicate activation must fail");
        assert_eq!(err.code(), tonic::Code::AlreadyExists);

        let Err(err) = registry.register_pending(bootstrap_identity("pod-uid-a")) else {
            panic!("activated pod UID must not register again");
        };
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[test]
    fn closed_pending_stream_cannot_be_activated() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        let stream = registry
            .register_pending(bootstrap_identity("pod-uid-a"))
            .expect("register pending");
        drop(stream);

        let activation = PodActivationMessage {
            sandbox_id: "sandbox-a".to_string(),
            sandbox_name: "sandbox-a".to_string(),
            token: "token-a".to_string(),
            token_expires_at_ms: 123,
            startup_metadata: HashMap::default(),
        };
        let err = registry
            .activate("pod-uid-a", activation)
            .expect_err("closed stream should remove pending registration");

        assert_eq!(err.code(), tonic::Code::NotFound);
    }
}
