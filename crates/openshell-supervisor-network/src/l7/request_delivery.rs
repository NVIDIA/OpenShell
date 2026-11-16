// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Observes local upstream writes without deciding whether a request is allowed.

use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

/// Local forwarding progress; completion does not prove upstream processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestDeliveryState {
    NotStarted,
    Started,
    Completed,
}

/// Shared by the body runner and its writer so cancellation retains progress.
#[derive(Clone, Debug, Default)]
pub struct RequestDelivery(Arc<AtomicU8>);

impl RequestDelivery {
    /// Call before awaiting a write, because an error can follow a partial write.
    pub(crate) fn start(&self) {
        let _ = self
            .0
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
    }

    /// Call only after every local body/framing write succeeds.
    pub(crate) fn complete(&self) {
        self.0.store(2, Ordering::Release);
    }

    pub(crate) fn state(&self) -> RequestDeliveryState {
        match self.0.load(Ordering::Acquire) {
            0 => RequestDeliveryState::NotStarted,
            1 => RequestDeliveryState::Started,
            // Only start and complete can write this private atomic.
            _ => RequestDeliveryState::Completed,
        }
    }
}
