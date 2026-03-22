// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bridge between `OcsfEvent` structs and the tracing system.
//!
//! The `emit_ocsf_event` function stores an `OcsfEvent` in thread-local
//! storage, then emits a tracing event with target `ocsf`. The custom
//! layers intercept this target, clone the event, and format it.
//! After dispatch, `emit_ocsf_event` clears the thread-local.

use crate::events::OcsfEvent;

std::thread_local! {
    // Thread-local storage for the current OCSF event being emitted.
    // Layers clone from this; only emit_ocsf_event clears it.
    static CURRENT_EVENT: std::cell::RefCell<Option<OcsfEvent>> = const { std::cell::RefCell::new(None) };
}

/// Target string used to identify OCSF tracing events.
pub const OCSF_TARGET: &str = "ocsf";

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
/// as shorthand (`openshell.log`) and JSONL (`openshell-ocsf.log`).
///
/// Both layers receive the event — `clone_current_event()` is non-consuming.
pub fn emit_ocsf_event(event: OcsfEvent) {
    // Store the event in thread-local so layers can access it
    CURRENT_EVENT.with(|cell| {
        *cell.borrow_mut() = Some(event);
    });

    // Emit a tracing event with the `ocsf` target.
    // The layers detect this target and clone the OcsfEvent from thread-local.
    tracing::info!(target: "ocsf", "ocsf_event");

    // Clear the thread-local after dispatch completes.
    CURRENT_EVENT.with(|cell| {
        cell.borrow_mut().take();
    });
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
                    version: "1.7.0".to_string(),
                    product: Product::openshell_sandbox("0.1.0"),
                    profiles: vec![],
                    uid: None,
                    log_source: None,
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
}
