// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tracing layer that captures OCSF events and forwards them as JSON bytes
//! through a telemetry buffer sender for relay to the gateway.

use std::sync::Arc;

use tracing::Subscriber;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use super::event_bridge::{OCSF_TARGET, clone_current_event};

/// Callback trait for delivering serialized OCSF events.
pub trait OcsfRelaySink: Send + Sync + 'static {
    fn send(&self, json_bytes: Vec<u8>);
}

/// A tracing layer that captures OCSF events and serializes them to JSON
/// for relay through the telemetry transport.
pub struct OcsfRelayLayer {
    sink: Arc<dyn OcsfRelaySink>,
}

impl OcsfRelayLayer {
    pub fn new(sink: Arc<dyn OcsfRelaySink>) -> Self {
        Self { sink }
    }
}

impl<S: Subscriber> Layer<S> for OcsfRelayLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != OCSF_TARGET {
            return;
        }

        let Some(ocsf_event) = clone_current_event() else {
            return;
        };

        if let Ok(json) = serde_json::to_vec(&ocsf_event) {
            self.sink.send(json);
        }
    }
}
