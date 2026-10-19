// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide and session-bound [`EventContext`].
//!
//! A dedicated supervisor initialises the process-wide context once via
//! [`set_ctx`]. A process hosting several supervisor sessions instead binds
//! each session's context to the threads of that session's runtime with
//! [`bind_thread_ctx`]; a bound context takes precedence. [`ctx`] falls back
//! to a default context when neither is set (e.g. unit tests that exercise
//! builders without booting the sandbox).

use crate::{ContextRef, EventContext, EventOrigin};
use std::cell::RefCell;
use std::sync::{Arc, LazyLock, OnceLock};

static OCSF_CTX: OnceLock<EventContext> = OnceLock::new();

static OCSF_CTX_FALLBACK: LazyLock<EventContext> = LazyLock::new(|| EventContext {
    sandbox_id: String::new(),
    sandbox_name: String::new(),
    container_image: String::new(),
    hostname: "test".to_string(),
    product_version: env!("CARGO_PKG_VERSION").to_string(),
    proxy_ip: std::net::IpAddr::from([127, 0, 0, 1]),
    proxy_port: 3128,
    origin: EventOrigin::Supervisor,
});

std::thread_local! {
    /// Context of the hosted session whose runtime owns this thread.
    static THREAD_CTX: RefCell<Option<Arc<EventContext>>> = const { RefCell::new(None) };
}

/// Initialise the process-wide OCSF sandbox context.
///
/// Returns `false` if the context was already set; the caller may log and
/// continue. Intended to be called exactly once during sandbox startup.
pub fn set_ctx(ctx: EventContext) -> bool {
    OCSF_CTX.set(ctx).is_ok()
}

/// Attribute events emitted on the calling thread to one hosted session.
///
/// Session runtimes bind every thread they start; `None` unbinds it.
pub fn bind_thread_ctx(ctx: Option<Arc<EventContext>>) {
    THREAD_CTX.with(|current| *current.borrow_mut() = ctx);
}

/// Return the context for events emitted on the calling thread.
///
/// A session-bound context wins over the process-wide one. Falls back to a
/// default context if neither is set.
#[must_use]
pub fn ctx() -> ContextRef<'static> {
    if let Some(bound) = THREAD_CTX.with(|current| current.borrow().clone()) {
        return ContextRef::Shared(bound);
    }
    ContextRef::Borrowed(OCSF_CTX.get().unwrap_or(&OCSF_CTX_FALLBACK))
}
