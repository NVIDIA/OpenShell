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

use crate::format::downgrade::{DowngradeOutcome, downgrade_event, record_kept_native};
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
///
/// An optional target schema version can be set via
/// [`with_target_version`](Self::with_target_version). When set, events are
/// downgraded to the target version before writing; events that cannot
/// conform to it are written at the native version and tallied.
pub struct OcsfJsonlLayer<W: Write + Send + 'static> {
    writer: Mutex<W>,
    enabled: Option<Arc<AtomicBool>>,
    target_version: Option<Arc<Mutex<String>>>,
}

impl<W: Write + Send + 'static> OcsfJsonlLayer<W> {
    /// Create a new JSONL layer writing to the given writer.
    #[must_use]
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
            enabled: None,
            target_version: None,
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
        if let Some(ref flag) = self.enabled
            && !flag.load(Ordering::Relaxed)
        {
            return;
        }

        if let Some(ocsf_event) = clone_current_event()
            && let Ok(mut w) = self.writer.lock()
        {
            let line = if let Some(ref target) = self.target_version
                && let Ok(version) = target.lock()
                && !version.is_empty()
            {
                let Ok(mut json) = serde_json::to_value(&ocsf_event) else {
                    return;
                };
                if let DowngradeOutcome::KeptNative { reason } =
                    downgrade_event(&mut json, &version)
                {
                    record_kept_native(&reason);
                }
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

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn written_event(target: &str, event: crate::OcsfEvent) -> serde_json::Value {
        use tracing_subscriber::layer::SubscriberExt;
        let buffer = SharedBuffer::default();
        let layer = OcsfJsonlLayer::new(buffer.clone())
            .with_target_version(Arc::new(Mutex::new(target.to_string())));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || crate::ocsf_emit!(event));
        let bytes = buffer.0.lock().unwrap().clone();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn http(response: bool) -> crate::OcsfEvent {
        let ctx = crate::builders::test_sandbox_context();
        let builder = crate::HttpActivityBuilder::new(&ctx)
            .action(crate::ActionId::Denied)
            .http_request(crate::HttpRequest::new(
                "GET",
                crate::Url::new("https", "api.example.com", "/v1", 443),
            ))
            .src_endpoint(crate::Endpoint::from_ip("10.0.0.5".parse().unwrap(), 51234))
            .dst_endpoint(crate::Endpoint::from_domain("api.example.com", 443));
        if response {
            builder
                .http_response(crate::HttpResponse { code: 403 })
                .build()
        } else {
            builder.build()
        }
    }

    #[test]
    fn convertible_events_are_written_at_the_target_version() {
        let json = written_event("1.3", http(true));
        assert_eq!(json["metadata"]["version"], "1.3.0");
    }

    #[test]
    fn events_kept_native_are_written_unchanged_and_tallied() {
        let before = crate::format::downgrade::kept_native_tally().0;
        let json = written_event("1.1", http(false));
        assert_eq!(json["metadata"]["version"], crate::OCSF_VERSION);
        assert!(json.pointer("/unmapped/downgraded_from").is_none());
        let (after, latest) = crate::format::downgrade::kept_native_tally();
        assert!(after > before);
        assert!(latest.is_some_and(|reason| reason.contains("http_response")));
    }
}
