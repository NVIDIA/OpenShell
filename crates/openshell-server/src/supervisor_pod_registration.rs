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
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use tracing::{debug, info, warn};

const ACTIVATED_TOMBSTONE_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug)]
pub struct SupervisorPodRegistrationRegistry {
    inner: Mutex<Inner>,
    next_session_id: AtomicU64,
    registration_generation: watch::Sender<u64>,
}

impl Default for SupervisorPodRegistrationRegistry {
    fn default() -> Self {
        let (registration_generation, _) = watch::channel(0);
        Self {
            inner: Mutex::new(Inner::default()),
            next_session_id: AtomicU64::new(0),
            registration_generation,
        }
    }
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

#[derive(Debug, Clone)]
pub struct PendingRegistrationSnapshot {
    pub identity: SupervisorBootstrapIdentity,
    pub session_id: u64,
}

impl SupervisorPodRegistrationRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.registration_generation.subscribe()
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
        let now = Instant::now();

        let replaced = {
            let mut inner = self.inner.lock().expect("pending pod registry poisoned");
            prune_activated_tombstones(&mut inner, now);
            inner.activated_instance_id.remove(&instance_id);
            inner
                .pending_by_instance_id
                .insert(
                    instance_id.clone(),
                    PendingRegistration {
                        identity,
                        sender,
                        session_id,
                        registered_at: now,
                    },
                )
                .is_some()
        };
        self.registration_generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));

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
    ) -> Result<PendingRegistrationSnapshot, Status> {
        let mut inner = self.inner.lock().expect("pending pod registry poisoned");
        prune_activated_tombstones(&mut inner, Instant::now());
        if inner.activated_instance_id.contains_key(instance_id) {
            return Err(Status::already_exists(
                "supervisor instance has already been activated",
            ));
        }
        inner
            .pending_by_instance_id
            .get(instance_id)
            .map(|pending| PendingRegistrationSnapshot {
                identity: pending.identity.clone(),
                session_id: pending.session_id,
            })
            .ok_or_else(|| Status::not_found("pending supervisor registration not found"))
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn activate_if_session(
        &self,
        instance_id: &str,
        session_id: u64,
        activation: PodActivationMessage,
    ) -> Result<(), Status> {
        let now = Instant::now();
        let pending = {
            let mut inner = self.inner.lock().expect("pending pod registry poisoned");
            prune_activated_tombstones(&mut inner, now);
            if inner.activated_instance_id.contains_key(instance_id) {
                return Err(Status::already_exists(
                    "supervisor instance has already been activated",
                ));
            }
            let Some(current) = inner.pending_by_instance_id.get(instance_id) else {
                debug!(
                    instance_id = %instance_id,
                    "no pending supervisor registration to activate"
                );
                return Err(Status::not_found(
                    "pending supervisor registration not found",
                ));
            };
            if current.session_id != session_id {
                return Err(Status::aborted(
                    "pending supervisor registration was replaced",
                ));
            }
            let pending = inner
                .pending_by_instance_id
                .remove(instance_id)
                .expect("pending registration checked above");
            inner
                .activated_instance_id
                .insert(instance_id.to_string(), now);
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
    pub(crate) fn fail_if_session(
        &self,
        instance_id: &str,
        session_id: u64,
        status: Status,
    ) -> Result<(), Status> {
        let pending = {
            let mut inner = self.inner.lock().expect("pending pod registry poisoned");
            prune_activated_tombstones(&mut inner, Instant::now());
            if inner.activated_instance_id.contains_key(instance_id) {
                return Err(Status::already_exists(
                    "supervisor instance has already been activated",
                ));
            }
            let Some(current) = inner.pending_by_instance_id.get(instance_id) else {
                return Err(Status::not_found(
                    "pending supervisor registration not found",
                ));
            };
            if current.session_id != session_id {
                return Err(Status::aborted(
                    "pending supervisor registration was replaced",
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
        let mut inner = self.inner.lock().expect("pending pod registry poisoned");
        prune_activated_tombstones(&mut inner, Instant::now());
        inner.activated_instance_id.len()
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

fn prune_activated_tombstones(inner: &mut Inner, now: Instant) {
    inner.activated_instance_id.retain(|_, activated_at| {
        now.saturating_duration_since(*activated_at) < ACTIVATED_TOMBSTONE_TTL
    });
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

    fn activation() -> PodActivationMessage {
        PodActivationMessage {
            sandbox_id: "sandbox-a".to_string(),
            sandbox_name: "sandbox-a".to_string(),
            token: "token-a".to_string(),
            token_expires_at_ms: 123,
            startup_metadata: HashMap::default(),
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

        let pending = registry.pending_identity("pod-uid-a").unwrap();
        registry
            .activate_if_session("pod-uid-a", pending.session_id, activation())
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
        let err = registry
            .activate_if_session("pod-uid-a", 0, activation())
            .expect_err("unknown pod UID must fail");

        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn activation_tombstone_rejects_duplicate_activation_until_reregistration() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        let mut stream = registry
            .register_pending(bootstrap_identity("pod-uid-a"))
            .expect("register pending");

        let pending = registry.pending_identity("pod-uid-a").unwrap();
        registry
            .activate_if_session("pod-uid-a", pending.session_id, activation())
            .expect("activate");
        let _ = stream.next().await.expect("activation message");

        let err = registry
            .activate_if_session("pod-uid-a", pending.session_id, activation())
            .expect_err("duplicate activation must fail");
        assert_eq!(err.code(), tonic::Code::AlreadyExists);

        let replacement = registry
            .register_pending(bootstrap_identity("pod-uid-a"))
            .expect("new registration supersedes tombstone");
        assert_eq!(registry.activated_count(), 0);
        drop(replacement);
    }

    #[test]
    fn expired_activation_tombstones_are_pruned() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        {
            let mut inner = registry.inner.lock().expect("registry mutex poisoned");
            inner.activated_instance_id.insert(
                "expired-pod-uid".to_string(),
                Instant::now()
                    .checked_sub(ACTIVATED_TOMBSTONE_TTL + Duration::from_secs(1))
                    .expect("test tombstone timestamp"),
            );
            inner
                .activated_instance_id
                .insert("fresh-pod-uid".to_string(), Instant::now());
        }

        let stream = registry
            .register_pending(bootstrap_identity("expired-pod-uid"))
            .expect("expired tombstone must not reject registration");
        assert_eq!(registry.activated_count(), 1);
        drop(stream);
    }

    #[test]
    fn closed_pending_stream_cannot_be_activated() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        let stream = registry
            .register_pending(bootstrap_identity("pod-uid-a"))
            .expect("register pending");
        drop(stream);

        let err = registry
            .activate_if_session("pod-uid-a", 0, activation())
            .expect_err("closed stream should remove pending registration");

        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn stale_session_cannot_activate_replacement_stream() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        let old_stream = registry
            .register_pending(bootstrap_identity("pod-uid-a"))
            .expect("register old");
        let old = registry.pending_identity("pod-uid-a").unwrap();
        let mut replacement_stream = registry
            .register_pending(bootstrap_identity("pod-uid-a"))
            .expect("register replacement");
        let replacement = registry.pending_identity("pod-uid-a").unwrap();

        let err = registry
            .activate_if_session("pod-uid-a", old.session_id, activation())
            .expect_err("stale session must not activate replacement");
        assert_eq!(err.code(), tonic::Code::Aborted);
        assert_eq!(registry.pending_count(), 1);

        registry
            .activate_if_session("pod-uid-a", replacement.session_id, activation())
            .expect("activate replacement");
        assert!(replacement_stream.next().await.unwrap().is_ok());
        drop(old_stream);
    }

    #[tokio::test]
    async fn stale_session_cannot_fail_replacement_stream() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        let old_stream = registry
            .register_pending(bootstrap_identity("pod-uid-a"))
            .expect("register old");
        let old = registry.pending_identity("pod-uid-a").unwrap();
        let mut replacement_stream = registry
            .register_pending(bootstrap_identity("pod-uid-a"))
            .expect("register replacement");
        let replacement = registry.pending_identity("pod-uid-a").unwrap();

        let err = registry
            .fail_if_session(
                "pod-uid-a",
                old.session_id,
                Status::permission_denied("stale failure"),
            )
            .expect_err("stale session must not fail replacement");
        assert_eq!(err.code(), tonic::Code::Aborted);

        registry
            .activate_if_session("pod-uid-a", replacement.session_id, activation())
            .expect("activate replacement");
        assert!(replacement_stream.next().await.unwrap().is_ok());
        drop(old_stream);
    }

    #[tokio::test]
    async fn registrations_increment_coalescing_generation() {
        let registry = Arc::new(SupervisorPodRegistrationRegistry::new());
        let mut generation = registry.subscribe();

        let first = registry
            .register_pending(bootstrap_identity("pod-uid-a"))
            .expect("register first");
        let second = registry
            .register_pending(bootstrap_identity("pod-uid-b"))
            .expect("register second");

        generation.changed().await.expect("generation change");
        assert_eq!(*generation.borrow_and_update(), 2);
        drop((first, second));
    }
}
