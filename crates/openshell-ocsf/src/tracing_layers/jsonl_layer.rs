// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tracing layer that writes OCSF JSONL to a writer.

use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::Subscriber;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use crate::tracing_layers::event_bridge::{OCSF_TARGET, clone_current_event};

/// A tracing `Layer` that intercepts OCSF events and writes JSONL output.
///
/// Only events with `target: "ocsf"` are processed; non-OCSF events are ignored.
///
/// An optional enabled flag (`Arc<AtomicBool>`) can be set via
/// [`with_enabled_flag`](Self::with_enabled_flag). When the flag is present and
/// `false`, the layer short-circuits without writing. This allows the sandbox
/// to hot-toggle OCSF JSONL output at runtime via the `ocsf_json_enabled`
/// setting without rebuilding the subscriber.
pub struct OcsfJsonlLayer<W: Write + Send + 'static> {
    writer: Mutex<W>,
    enabled: Option<Arc<AtomicBool>>,
}

impl<W: Write + Send + 'static> OcsfJsonlLayer<W> {
    /// Create a new JSONL layer writing to the given writer.
    #[must_use]
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
            enabled: None,
        }
    }

    /// Attach a shared boolean flag that controls whether the layer writes.
    ///
    /// When the flag is `false`, the layer receives events but discards them.
    /// When the flag is absent (the default), the layer always writes.
    #[must_use]
    pub fn with_enabled_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.enabled = Some(flag);
        self
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

        // If an enabled flag is set and it reads `false`, skip writing.
        if let Some(ref flag) = self.enabled {
            if !flag.load(Ordering::Relaxed) {
                return;
            }
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
