// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bridge between `OcsfEvent` structs and the tracing system.
//!
//! The `emit_ocsf_event` function stores an `OcsfEvent` in thread-local
//! storage, then emits a tracing event with target `ocsf`. The custom
//! layers intercept this target, clone the event, and format it.
//! After dispatch, `emit_ocsf_event` clears the thread-local.

use std::sync::OnceLock;

use crate::events::{BaseEventData, OcsfEvent};

static EVENT_ENRICHER: OnceLock<fn(&mut BaseEventData)> = OnceLock::new();

std::thread_local! {
    // Thread-local storage for the current OCSF event being emitted.
    // Layers clone from this; only emit_ocsf_event clears it.
    static CURRENT_EVENT: std::cell::RefCell<Option<OcsfEvent>> = const { std::cell::RefCell::new(None) };
}

/// Target string used to identify OCSF tracing events.
pub const OCSF_TARGET: &str = "ocsf";

/// Register optional process-wide event enrichment at startup.
///
/// The callback runs once per emission, before any output layer receives the
/// record, independently of trace sampling or export. It receives the common
/// base fields for every event class and should add only contextual fields,
/// preserving the record's content, classification, and timestamp. It must not
/// block, panic, or emit another OCSF event.
///
/// Returns `false` if an enricher is already registered. Without an enricher,
/// emission does not add application-specific context.
pub fn register_event_enricher(enricher: fn(&mut BaseEventData)) -> bool {
    EVENT_ENRICHER.set(enricher).is_ok()
}

fn enrich(event: &mut OcsfEvent) {
    crate::trace::enrich(event);
    if let Some(enrich) = EVENT_ENRICHER.get() {
        enrich(event.base_mut());
    }
}

/// Clone the current thread-local OCSF event, if any.
///
/// Multiple layers can call this for the same event — each receives
/// an independent clone. The thread-local is only cleared by
/// `emit_ocsf_event` after tracing dispatch completes.
pub fn clone_current_event() -> Option<OcsfEvent> {
    CURRENT_EVENT.with(|cell| cell.borrow().clone())
}

/// Emit an `OcsfEvent` through the tracing subscriber.
///
/// The OCSF layers (`OcsfShorthandLayer`, `OcsfJsonlLayer`) format it
/// as human-readable shorthand and structured JSONL for their configured sinks.
///
/// Both layers receive the event — `clone_current_event()` is non-consuming.
pub fn emit_ocsf_event(mut event: OcsfEvent) {
    enrich(&mut event);
    // Store the event in thread-local so layers can access it
    set_current_event(event);

    // Emit a tracing event with the `ocsf` target.
    // The layers detect this target and clone the OcsfEvent from thread-local.
    tracing::info!(target: "ocsf", "ocsf_event");

    // Clear the thread-local after dispatch completes.
    clear_current_event();
}

/// Store an `OcsfEvent` in the thread-local bridge so OCSF layers
/// (`OcsfJsonlLayer` / `OcsfShorthandLayer`) can `clone_current_event()` it
/// during tracing dispatch.
///
/// Pair with [`clear_current_event`] after the emit.
///
/// Exposed so callers that need to attach extra tracing fields to the *same*
/// event (e.g. the gateway's per-sandbox `sandbox_id` routing field — see
/// [`emit_ocsf_event_routed`]) can drive the bridge directly.
pub fn set_current_event(event: OcsfEvent) {
    CURRENT_EVENT.with(|cell| {
        *cell.borrow_mut() = Some(event);
    });
}

/// Clear the thread-local bridge slot. Call after the `ocsf`-target tracing
/// event has been dispatched so it does not leak into the next emit.
pub fn clear_current_event() {
    CURRENT_EVENT.with(|cell| {
        cell.borrow_mut().take();
    });
}

/// Emit an `OcsfEvent` through the structured and routed output paths.
///
/// The event is picked up by the structured OCSF layers
/// (via the thread-local bridge → `OcsfJsonlLayer` writes full JSON) AND
/// routed by the gateway's `TracingLogBus` (via the `sandbox_id` + `message`
/// tracing fields → per-sandbox stream / stdout shorthand).
///
/// This is the gateway/multi-sandbox counterpart of [`emit_ocsf_event`]: the
/// Linux in-sandbox supervisor uses the process-wide `ctx()` singleton and the
/// bare `emit_ocsf_event`, but the gateway hosts many sandboxes, so it stamps a
/// per-event `sandbox_id` field here instead. One tracing event feeds both the
/// JSONL audit file and the routing bus.
pub fn emit_ocsf_event_routed(sandbox_id: &str, mut event: OcsfEvent) {
    enrich(&mut event);
    let message = event.format_shorthand();
    set_current_event(event);
    tracing::info!(target: "ocsf", sandbox_id = %sandbox_id, message = %message);
    clear_current_event();
}

/// Convenience macro for emitting an `OcsfEvent`.
///
/// ```ignore
/// use openshell_ocsf::ocsf_emit;
/// ocsf_emit!(event);
/// ```
#[macro_export]
macro_rules! ocsf_emit {
    ($event:expr) => {
        $crate::tracing_layers::emit_ocsf_event($event)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::SeverityId;
    use crate::events::base_event::BaseEventData;
    use crate::events::{BaseEvent, OcsfEvent};
    use crate::objects::{Metadata, Product};

    std::thread_local! {
        // Registration is process-wide, but this test's callback must be inert
        // for unrelated tests running in parallel or reusing this thread later.
        static TEST_ENRICHER_SEQUENCE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    }

    fn test_enricher(event: &mut BaseEventData) {
        TEST_ENRICHER_SEQUENCE.with(|sequence| {
            if let Some(next) = sequence.get() {
                sequence.set(Some(next + 1));
                event.metadata.correlation_uid = Some("emit-time-request".into());
                event.add_unmapped("request_sequence", next);
            }
        });
    }

    fn test_event() -> OcsfEvent {
        OcsfEvent::Base(BaseEvent {
            base: BaseEventData::new(
                0,
                "Base Event",
                0,
                "Uncategorized",
                99,
                "Other",
                SeverityId::Informational,
                Metadata {
                    version: "1.8.0".to_string(),
                    product: Product::openshell_sandbox("0.1.0"),
                    profiles: vec![],
                    uid: None,
                    log_source: None,
                    correlation_uid: None,
                },
            ),
        })
    }

    #[test]
    fn test_clone_current_event_is_non_consuming() {
        CURRENT_EVENT.with(|cell| {
            *cell.borrow_mut() = Some(test_event());
        });

        // First clone succeeds
        let first = clone_current_event();
        assert!(first.is_some());
        assert_eq!(first.unwrap().class_uid(), 0);

        // Second clone also succeeds — non-consuming
        let second = clone_current_event();
        assert!(second.is_some());
        assert_eq!(second.unwrap().class_uid(), 0);

        // Clean up
        CURRENT_EVENT.with(|cell| {
            cell.borrow_mut().take();
        });
    }

    #[test]
    fn test_emit_clears_thread_local_after_dispatch() {
        // Manually store an event
        CURRENT_EVENT.with(|cell| {
            *cell.borrow_mut() = Some(test_event());
        });

        // Clear it the same way emit_ocsf_event does after dispatch
        CURRENT_EVENT.with(|cell| {
            cell.borrow_mut().take();
        });

        // Should be empty now
        assert!(clone_current_event().is_none());
    }

    /// A `Write` sink that appends into a shared buffer we can inspect.
    #[derive(Clone)]
    struct SharedWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // cp6: the gateway routed emit must (a) drive the JSONL layer with the FULL
    // structured event (parity with the Linux `ocsf_emit!` path) and (b) leave
    // no residue in the thread-local afterward.
    #[test]
    fn test_routed_emit_writes_full_json_and_clears() {
        use crate::tracing_layers::OcsfJsonlLayer;
        use tracing_subscriber::prelude::*;

        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let layer = OcsfJsonlLayer::new(SharedWriter(buf.clone()));
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            emit_ocsf_event_routed("sb-parity-1", test_event());
        });

        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        // Exactly one JSONL line, and it is valid full OCSF JSON (not shorthand).
        assert_eq!(out.matches('\n').count(), 1, "one JSONL line expected");
        let parsed: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(parsed["class_uid"], 0);
        assert!(parsed.get("metadata").is_some());

        // Thread-local must be clear after the routed emit (no bleed).
        assert!(clone_current_event().is_none());
    }

    // cp6 parity: the routed path and the bare Linux path serialize the SAME
    // structured event identically — routing fields don't alter the JSON body.
    #[test]
    fn test_routed_and_bare_paths_emit_equivalent_json() {
        use crate::tracing_layers::OcsfJsonlLayer;
        use tracing_subscriber::prelude::*;

        fn capture(f: impl FnOnce()) -> String {
            let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
            let layer = OcsfJsonlLayer::new(SharedWriter(buf.clone()));
            let subscriber = tracing_subscriber::registry().with(layer);
            tracing::subscriber::with_default(subscriber, f);
            String::from_utf8(buf.lock().unwrap().clone()).unwrap()
        }

        let event = test_event();
        let bare = capture(|| emit_ocsf_event(event.clone()));
        let routed = capture(|| emit_ocsf_event_routed("sb-1", event));

        let bare_json: serde_json::Value = serde_json::from_str(bare.trim()).unwrap();
        let routed_json: serde_json::Value = serde_json::from_str(routed.trim()).unwrap();
        assert_eq!(
            bare_json, routed_json,
            "routed emit must match the bare path JSON"
        );
    }

    #[test]
    fn event_enrichment_runs_once_for_every_class_and_output_path() {
        use crate::test_support::OcsfCapture;
        use crate::tracing_layers::OcsfJsonlLayer;
        use tracing_subscriber::prelude::*;

        assert!(register_event_enricher(test_enricher));
        assert!(!register_event_enricher(test_enricher));
        let capture = OcsfCapture::default();
        let bytes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry()
            .with(capture.clone())
            .with(OcsfJsonlLayer::new(SharedWriter(bytes.clone())));
        let context = crate::builders::test_sandbox_context();
        let mut expected = Vec::new();

        tracing::subscriber::with_default(subscriber, || {
            struct ResetEnricher;
            impl Drop for ResetEnricher {
                fn drop(&mut self) {
                    TEST_ENRICHER_SEQUENCE.with(|sequence| sequence.set(None));
                }
            }
            let plain = test_event();
            expected.push(plain.clone());
            emit_ocsf_event(plain);

            {
                let _reset = ResetEnricher;
                TEST_ENRICHER_SEQUENCE.with(|sequence| sequence.set(Some(1)));
                let mut sequence = 1;
                for routed in [false, true] {
                    for (_, mut event) in crate::builders::sample_events(&context) {
                        event.base_mut().add_unmapped("source_detail", "keep");
                        event
                            .base_mut()
                            .add_unmapped("http_event_kind", "original_kind");
                        let mut enriched = event.clone();
                        enriched.set_correlation_uid("emit-time-request");
                        enriched
                            .base_mut()
                            .add_unmapped("request_sequence", sequence);
                        expected.push(enriched);
                        if routed {
                            emit_ocsf_event_routed("test-sandbox", event);
                        } else {
                            emit_ocsf_event(event);
                        }
                        assert!(clone_current_event().is_none());
                        sequence += 1;
                    }
                }
                TEST_ENRICHER_SEQUENCE.with(|next| assert_eq!(next.get(), Some(sequence)));
            }

            let plain = test_event();
            expected.push(plain.clone());
            emit_ocsf_event_routed("test-sandbox", plain);
        });

        assert_eq!(capture.events(), expected);
        let expected_json: Vec<_> = expected
            .iter()
            .map(|event| event.to_json().unwrap())
            .collect();
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        let json: Vec<serde_json::Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(json, expected_json);
    }
}
