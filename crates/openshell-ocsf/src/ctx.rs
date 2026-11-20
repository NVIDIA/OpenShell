// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide and sandbox-instance-bound [`EventContext`].
//!
//! A dedicated supervisor initialises the process-wide context once via
//! [`set_ctx`]. A process hosting several sandbox instances instead binds
//! each instance's context to the threads of that instance's runtime with
//! [`bind_thread_ctx`]; a bound context takes precedence. [`ctx`] falls back
//! to a default context when neither is set (e.g. unit tests that exercise
//! builders without booting the sandbox).

use crate::{ContextRef, EventContext, EventOrigin};
use std::cell::RefCell;
use std::sync::{Arc, LazyLock, OnceLock};

static OCSF_CTX: OnceLock<EventContext> = OnceLock::new();

/// Whether events emitted by this process carry guest-sourced payload
/// (`data_origin=guest`).
///
/// Set once at startup by a supervisor whose launch descriptor marks the
/// boundary as an untrusted guest: every event whose payload was reported
/// by that boundary — process exits, connection identity — is then marked
/// so log readers cannot mistake guest reports for verified observations.
/// Trusted boundaries (container sandboxes, libkrun VM guests) leave it
/// unset. Untrusted guests always run under a dedicated supervisor, so the
/// process-wide flag cannot leak across sandbox instances.
static GUEST_DATA_ORIGIN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Mark every event emitted by this process as guest-sourced.
pub fn set_guest_data_origin(enabled: bool) {
    GUEST_DATA_ORIGIN.store(enabled, std::sync::atomic::Ordering::Release);
}

/// Whether events emitted by this process carry guest-sourced payload.
#[must_use]
pub fn guest_data_origin() -> bool {
    GUEST_DATA_ORIGIN.load(std::sync::atomic::Ordering::Acquire)
}

static OCSF_CTX_FALLBACK: LazyLock<EventContext> = LazyLock::new(|| EventContext {
    sandbox_id: String::new(),
    sandbox_name: String::new(),
    container_image: String::new(),
    container_image_uid: None,
    hostname: "test".to_string(),
    product_version: env!("CARGO_PKG_VERSION").to_string(),
    proxy_ip: std::net::IpAddr::from([127, 0, 0, 1]),
    proxy_port: 3128,
    origin: EventOrigin::Supervisor,
});

std::thread_local! {
    /// Context of the hosted sandbox instance whose runtime owns this thread.
    static THREAD_CTX: RefCell<Option<Arc<EventContext>>> = const { RefCell::new(None) };
}

/// Initialise the process-wide OCSF sandbox context.
///
/// Returns `false` if the context was already set; the caller may log and
/// continue. Intended to be called exactly once during sandbox startup.
pub fn set_ctx(ctx: EventContext) -> bool {
    OCSF_CTX.set(ctx).is_ok()
}

/// Attribute events emitted on the calling thread to one hosted sandbox
/// instance.
///
/// Instance runtimes bind every thread they start; `None` unbinds it.
pub fn bind_thread_ctx(ctx: Option<Arc<EventContext>>) {
    THREAD_CTX.with(|current| *current.borrow_mut() = ctx);
}

/// Return the context for events emitted on the calling thread.
///
/// An instance-bound context wins over the process-wide one. Falls back to a
/// default context if neither is set.
#[must_use]
pub fn ctx() -> ContextRef<'static> {
    if let Some(bound) = THREAD_CTX.with(|current| current.borrow().clone()) {
        return ContextRef::Shared(bound);
    }
    ContextRef::Borrowed(OCSF_CTX.get().unwrap_or(&OCSF_CTX_FALLBACK))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_context_names_no_sandbox() {
        assert!(OCSF_CTX_FALLBACK.container().is_none());
    }
}
