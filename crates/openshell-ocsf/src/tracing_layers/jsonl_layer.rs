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

use crate::format::downgrade::downgrade_event;
use crate::tracing_layers::event_bridge::{OCSF_TARGET, clone_current_event};

/// OCSF JSON output settings owned by one hosted supervisor session.
///
/// Sessions apply their own `ocsf_json_enabled` and schema-version settings
/// to these values. Binding them to the session's runtime threads makes every
/// [`OcsfJsonlLayer`] use them for events those threads emit.
#[derive(Clone, Debug, Default)]
pub struct OcsfJsonSettings {
    pub enabled: Arc<AtomicBool>,
    pub target_version: Arc<Mutex<String>>,
}

std::thread_local! {
    static THREAD_JSON_SETTINGS: std::cell::RefCell<Option<OcsfJsonSettings>> =
        const { std::cell::RefCell::new(None) };
}

/// Apply one hosted session's JSON settings to events emitted on this thread.
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
///
/// An optional target schema version can be set via
/// [`with_target_version`](Self::with_target_version). When set, events are
/// downgraded to the target version before writing (stripping fields and
/// profiles that don't exist in older schema versions).
pub struct OcsfJsonlLayer<W: Write + Send + 'static> {
    writer: Mutex<W>,
    enabled: Option<Arc<AtomicBool>>,
    target_version: Option<Arc<Mutex<String>>>,
    console_format: bool,
}

impl<W: Write + Send + 'static> OcsfJsonlLayer<W> {
    /// Create a new JSONL layer writing to the given writer.
    #[must_use]
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
            enabled: None,
            target_version: None,
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

    /// Attach a shared target schema version for downgrade filtering.
    ///
    /// When set, events are downgraded to the target version before writing.
    /// The version can be changed at runtime via the shared mutex.
    #[must_use]
    pub fn with_target_version(mut self, version: Arc<Mutex<String>>) -> Self {
        self.target_version = Some(version);
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

        // A hosted session's settings replace the process-wide ones.
        let session = THREAD_JSON_SETTINGS.with(|current| current.borrow().clone());
        let (enabled, target_version) = session.as_ref().map_or(
            (self.enabled.as_ref(), self.target_version.as_ref()),
            |settings| (Some(&settings.enabled), Some(&settings.target_version)),
        );

        // If an enabled flag is set and it reads `false`, skip writing.
        if let Some(flag) = enabled
            && !flag.load(Ordering::Relaxed)
        {
            return;
        }

        if let Some(ocsf_event) = clone_current_event()
            && let Ok(mut w) = self.writer.lock()
        {
            let line = if let Some(target) = target_version
                && let Ok(version) = target.lock()
                && !version.is_empty()
            {
                let Ok(mut json) = serde_json::to_value(&ocsf_event) else {
                    return;
                };
                downgrade_event(&mut json, &version);
                match serde_json::to_string(&json) {
                    Ok(mut s) => {
                        s.push('\n');
                        s
                    }
                    Err(_) => return,
                }
            } else {
                match ocsf_event.to_json_line() {
                    Ok(l) => l,
                    Err(_) => return,
                }
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
