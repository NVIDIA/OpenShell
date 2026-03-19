// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bridge between `OcsfEvent` structs and the tracing system.
//!
//! The `emit_ocsf_event` function serializes an `OcsfEvent` and emits it
//! as a tracing event with target `ocsf`. The custom layers intercept
//! events with this target and format them.

use std::sync::OnceLock;

use crate::events::OcsfEvent;

std::thread_local! {
    // Thread-local storage for the current OCSF event being emitted.
    // Used by the tracing layers to retrieve the full OcsfEvent struct.
    static CURRENT_EVENT: std::cell::RefCell<Option<OcsfEvent>> = const { std::cell::RefCell::new(None) };
}

/// Target string used to identify OCSF tracing events.
pub static OCSF_TARGET: &str = "ocsf";

/// Sentinel field name on the tracing event that signals an OCSF event is available.
static _OCSF_FIELD: OnceLock<&str> = OnceLock::new();

/// Retrieve (and take) the current thread-local OCSF event, if any.
pub fn take_current_event() -> Option<OcsfEvent> {
    CURRENT_EVENT.with(|cell| cell.borrow_mut().take())
}

/// Emit an `OcsfEvent` through the tracing subscriber.
///
/// The OCSF layers (`OcsfShorthandLayer`, `OcsfJsonlLayer`) format it
/// as shorthand (`openshell.log`) and JSONL (`openshell-ocsf.log`).
pub fn emit_ocsf_event(event: OcsfEvent) {
    // Store the event in thread-local so layers can access it
    CURRENT_EVENT.with(|cell| {
        *cell.borrow_mut() = Some(event);
    });

    // Emit a tracing event with the `ocsf` target.
    // The layers detect this target and pull the OcsfEvent from thread-local.
    tracing::info!(target: "ocsf", "ocsf_event");

    // Clean up if layers didn't consume it (e.g., no OCSF layers registered)
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

    #[test]
    fn test_thread_local_store_and_take() {
        let event = OcsfEvent::Base(BaseEvent {
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
        });

        CURRENT_EVENT.with(|cell| {
            *cell.borrow_mut() = Some(event);
        });

        let taken = take_current_event();
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().class_uid(), 0);

        // Second take should be None
        assert!(take_current_event().is_none());
    }
}
