// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tracing layer that writes OCSF JSONL or marked console records to a writer.

use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::Utc;
use tracing::Subscriber;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use crate::tracing_layers::event_bridge::{OCSF_TARGET, clone_current_event};

/// OCSF JSON output settings owned by one hosted sandbox instance.
///
/// Instances apply their own `ocsf_json_enabled` setting to this value. Binding them to the instance's runtime threads makes every
/// [`OcsfJsonlLayer`] use them for events those threads emit.
#[derive(Clone, Debug, Default)]
pub struct OcsfJsonSettings {
    pub enabled: Arc<AtomicBool>,
}

std::thread_local! {
    static THREAD_JSON_SETTINGS: std::cell::RefCell<Option<OcsfJsonSettings>> =
        const { std::cell::RefCell::new(None) };
}

/// Apply one hosted sandbox instance's JSON settings to events emitted on this
/// thread.
pub fn bind_thread_json_settings(settings: Option<OcsfJsonSettings>) {
    THREAD_JSON_SETTINGS.with(|current| *current.borrow_mut() = settings);
}

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
    console_format: bool,
}

impl<W: Write + Send + 'static> OcsfJsonlLayer<W> {
    /// Create a new JSONL layer writing to the given writer.
    #[must_use]
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
            enabled: None,
            console_format: false,
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

    /// Prefix each compact JSON record with a UTC timestamp and `OCSF-JSON`.
    ///
    /// Console collectors can match the marker and decode the remainder as
    /// JSON. File sinks retain plain JSONL unless this option is selected.
    #[must_use]
    pub fn with_console_format(mut self) -> Self {
        self.console_format = true;
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

        // A hosted sandbox instance's settings replace the process-wide ones.
        let instance = THREAD_JSON_SETTINGS.with(|current| current.borrow().clone());
        let enabled = instance
            .as_ref()
            .map_or(self.enabled.as_ref(), |settings| Some(&settings.enabled));

        // If an enabled flag is set and it reads `false`, skip writing.
        if let Some(flag) = enabled
            && !flag.load(Ordering::Relaxed)
        {
            return;
        }

        if let Some(ocsf_event) = clone_current_event()
            && let Ok(mut w) = self.writer.lock()
        {
            let Ok(line) = ocsf_event.to_json_line() else {
                return;
            };
            let line = if self.console_format {
                let ts = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
                format!("{ts} OCSF-JSON {line}")
            } else {
                line
            };
            // Submit the entire record in one write, including its newline.
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
