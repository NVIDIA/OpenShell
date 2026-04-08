// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tracing layer that writes OCSF shorthand to a writer.

use std::io::Write;
use std::sync::Mutex;

use chrono::Utc;
use tracing::Subscriber;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use crate::tracing_layers::event_bridge::{OCSF_TARGET, clone_current_event};

/// A tracing `Layer` that intercepts OCSF events and writes shorthand output.
///
/// Events with `target: "ocsf"` are formatted via `format_shorthand()`.
/// Non-OCSF events are formatted with a simple fallback.
///
/// Each line is prefixed with a UTC timestamp (`YYYY-MM-DDTHH:MM:SS.mmmZ`)
/// since this layer writes directly to a file with no outer display layer
/// to supply timestamps.
pub struct OcsfShorthandLayer<W: Write + Send + 'static> {
    writer: Mutex<W>,
    /// Whether to include non-OCSF events in the output.
    include_non_ocsf: bool,
}

impl<W: Write + Send + 'static> OcsfShorthandLayer<W> {
    /// Create a new shorthand layer writing to the given writer.
    #[must_use]
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
            include_non_ocsf: true,
        }
    }

    /// Set whether non-OCSF tracing events should be included.
    #[must_use]
    pub fn with_non_ocsf(mut self, include: bool) -> Self {
        self.include_non_ocsf = include;
        self
    }
}

impl<S, W> Layer<S> for OcsfShorthandLayer<W>
where
    S: Subscriber,
    W: Write + Send + 'static,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();

        let ts = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");

        if meta.target() == OCSF_TARGET {
            // This is an OCSF event — clone from thread-local (non-consuming)
            if let Some(ocsf_event) = clone_current_event() {
                let line = ocsf_event.format_shorthand();
                if let Ok(mut w) = self.writer.lock() {
                    let _ = writeln!(w, "{ts} OCSF {line}");
                }
            }
        } else if self.include_non_ocsf {
            // Fallback: format non-OCSF events with basic format
            let level = meta.level();
            let target = meta.target();
            // Extract message from the event fields
            let mut message = String::new();
            event.record(&mut MessageVisitor(&mut message));
            if let Ok(mut w) = self.writer.lock() {
                let _ = writeln!(w, "{ts} {level} {target}: {message}");
            }
        }
    }
}

/// Simple visitor that extracts the message field from tracing events.
struct MessageVisitor<'a>(&'a mut String);

impl tracing::field::Visit for MessageVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            *self.0 = format!("{value:?}");
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            *self.0 = value.to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shorthand_layer_creation() {
        let buffer: Vec<u8> = Vec::new();
        let _layer = OcsfShorthandLayer::new(buffer);
    }

    #[test]
    fn test_shorthand_layer_with_non_ocsf_toggle() {
        let buffer: Vec<u8> = Vec::new();
        let layer = OcsfShorthandLayer::new(buffer).with_non_ocsf(false);
        assert!(!layer.include_non_ocsf);
    }

    #[test]
    fn test_non_ocsf_fallback_includes_timestamp() {
        use std::sync::Arc;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = SyncWriter(buffer.clone());
        let layer = OcsfShorthandLayer::new(writer).with_non_ocsf(true);

        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = subscriber.set_default();

        tracing::info!("test message");

        let output = buffer.lock().unwrap();
        let line = String::from_utf8_lossy(&output);
        // Should start with a timestamp like 2026-04-01T...
        assert!(
            line.contains('T') && line.contains('Z'),
            "Expected timestamp in output, got: {line}"
        );
        assert!(
            line.contains("test message"),
            "Expected message, got: {line}"
        );
    }
}

/// Test helper: wraps `Arc<Mutex<Vec<u8>>>` so it implements `Write + Send`.
#[cfg(test)]
struct SyncWriter(std::sync::Arc<Mutex<Vec<u8>>>);

#[cfg(test)]
impl Write for SyncWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}
