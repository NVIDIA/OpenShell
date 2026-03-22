// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tracing layer that writes OCSF JSONL to a writer.

use std::io::Write;
use std::sync::Mutex;

use tracing::Subscriber;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use crate::tracing_layers::event_bridge::{OCSF_TARGET, clone_current_event};

/// A tracing `Layer` that intercepts OCSF events and writes JSONL output.
///
/// Only events with `target: "ocsf"` are processed; non-OCSF events are ignored.
pub struct OcsfJsonlLayer<W: Write + Send + 'static> {
    writer: Mutex<W>,
}

impl<W: Write + Send + 'static> OcsfJsonlLayer<W> {
    /// Create a new JSONL layer writing to the given writer.
    #[must_use]
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }
}

impl<S, W> Layer<S> for OcsfJsonlLayer<W>
where
    S: Subscriber,
    W: Write + Send + 'static,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != OCSF_TARGET {
            return;
        }

        if let Some(ocsf_event) = clone_current_event()
            && let Ok(line) = ocsf_event.to_json_line()
            && let Ok(mut w) = self.writer.lock()
        {
            let _ = w.write_all(line.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jsonl_layer_creation() {
        let buffer: Vec<u8> = Vec::new();
        let _layer = OcsfJsonlLayer::new(buffer);
    }
}
