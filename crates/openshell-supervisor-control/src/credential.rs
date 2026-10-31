// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Delivery of the gateway-minted supervisor token to the shared supervisor.
//!
//! The gateway mints and renews the token and publishes each renewal into
//! the controller. How the token reaches the supervisor process is
//! deployment packaging (the Kubernetes driver patches a Secret the
//! supervisor Pod mounts); the retry policy around that delivery is the
//! same for every packaging and lives here.

use std::fmt::Display;
use std::future::Future;
use std::time::Duration;

use tokio::sync::watch;

use crate::controller::SupervisorCredential;

/// Deliver the current supervisor token and every renewal after it.
///
/// The initial value is delivered too. A failed delivery is retried every
/// `retry` until it succeeds or a newer token supersedes it. Returns at
/// shutdown or once the publisher is gone.
pub async fn deliver_credentials<E, F, Fut>(
    mut credential: watch::Receiver<Option<SupervisorCredential>>,
    mut shutdown: watch::Receiver<bool>,
    retry: Duration,
    mut deliver: F,
) where
    E: Display,
    F: FnMut(SupervisorCredential) -> Fut,
    Fut: Future<Output = Result<(), E>>,
{
    loop {
        let current = credential.borrow_and_update().clone();
        if let Some(current) = current {
            while let Err(error) = deliver(current.clone()).await {
                tracing::warn!(%error, "supervisor token delivery failed; retrying");
                tokio::select! {
                    () = tokio::time::sleep(retry) => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                    }
                }
                if credential.has_changed().unwrap_or(true) {
                    break;
                }
            }
        }
        tokio::select! {
            changed = credential.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}
