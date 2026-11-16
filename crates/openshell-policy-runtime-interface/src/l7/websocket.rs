// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{Result, miette};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const MAX_CONCURRENT_WEBSOCKET_ASSEMBLIES: usize = 32;
pub const MAX_QUEUED_WEBSOCKET_ASSEMBLIES: usize = MAX_CONCURRENT_WEBSOCKET_ASSEMBLIES * 2;

#[derive(Clone, Debug)]
pub struct WebSocketAssemblyBudget {
    active: Arc<Semaphore>,
    waiters: Arc<Semaphore>,
}

impl Default for WebSocketAssemblyBudget {
    fn default() -> Self {
        Self::new(
            MAX_CONCURRENT_WEBSOCKET_ASSEMBLIES,
            MAX_QUEUED_WEBSOCKET_ASSEMBLIES,
        )
    }
}

impl WebSocketAssemblyBudget {
    pub fn new(active: usize, waiters: usize) -> Self {
        Self {
            active: Arc::new(Semaphore::new(active)),
            waiters: Arc::new(Semaphore::new(waiters)),
        }
    }

    pub async fn reserve(&self) -> Result<WebSocketAssemblyAdmissionOutcome> {
        if let Ok(active) = Arc::clone(&self.active).try_acquire_owned() {
            return Ok(WebSocketAssemblyAdmissionOutcome::Admitted(
                WebSocketAssemblyAdmission { _active: active },
            ));
        }
        let Ok(waiter) = Arc::clone(&self.waiters).try_acquire_owned() else {
            return Ok(WebSocketAssemblyAdmissionOutcome::QueueExhausted);
        };
        let active = Arc::clone(&self.active)
            .acquire_owned()
            .await
            .map_err(|_| miette!("websocket assembly admission semaphore closed"))?;
        drop(waiter);
        Ok(WebSocketAssemblyAdmissionOutcome::Admitted(
            WebSocketAssemblyAdmission { _active: active },
        ))
    }
}

#[derive(Debug)]
pub struct WebSocketAssemblyAdmission {
    _active: OwnedSemaphorePermit,
}

#[derive(Debug)]
pub enum WebSocketAssemblyAdmissionOutcome {
    Admitted(WebSocketAssemblyAdmission),
    QueueExhausted,
}
