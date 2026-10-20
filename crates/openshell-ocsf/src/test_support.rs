// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for asserting on emitted OCSF events in producer tests.

use std::sync::{Arc, Mutex};

use tracing_subscriber::layer::SubscriberExt;

use crate::events::OcsfEvent;
use crate::tracing_layers::{OCSF_TARGET, clone_current_event};

/// Tracing layer that records every OCSF event emitted while installed.
#[derive(Clone, Default)]
pub struct OcsfCapture(Arc<Mutex<Vec<OcsfEvent>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for OcsfCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() == OCSF_TARGET
            && let Some(ocsf) = clone_current_event()
        {
            self.0.lock().expect("capture lock").push(ocsf);
        }
    }
}

impl OcsfCapture {
    /// Install as the thread's default subscriber until the guard drops.
    #[must_use]
    pub fn install(&self) -> tracing::subscriber::DefaultGuard {
        tracing::subscriber::set_default(tracing_subscriber::registry().with(self.clone()))
    }

    /// Events captured so far.
    #[must_use]
    pub fn events(&self) -> Vec<OcsfEvent> {
        self.0.lock().expect("capture lock").clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::{BaseEventBuilder, test_sandbox_context};

    fn emit(message: &str) {
        crate::ocsf_emit!(
            BaseEventBuilder::new(&test_sandbox_context())
                .message(message)
                .build()
        );
    }

    #[test]
    fn captures_events_emitted_while_installed() {
        let capture = OcsfCapture::default();
        {
            let _guard = capture.install();
            emit("captured");
            tracing::info!("not an ocsf event");
        }
        emit("after guard dropped");

        let events = capture.events();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].base().message.as_deref(), Some("captured"));
    }
}
