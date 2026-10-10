// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide [`EventContext`] singleton.
//!
//! Initialised once via [`set_ctx`] during sandbox start; read by every event
//! builder via [`ctx`]. Falls back to a default context when the singleton has
//! not been set (e.g. unit tests that exercise builders without booting the
//! sandbox).

use crate::{EventContext, EventOrigin};
use std::sync::{LazyLock, OnceLock};

static OCSF_CTX: OnceLock<EventContext> = OnceLock::new();

/// With `test-support`, producer tests get a production-like sandbox identity
/// so their events carry the same container and device fields production does.
#[cfg(any(test, feature = "test-support"))]
const FALLBACK_SANDBOX: (&str, &str, &str) =
    ("sandbox-test", "test-sandbox", "example/sandbox:test");
#[cfg(not(any(test, feature = "test-support")))]
const FALLBACK_SANDBOX: (&str, &str, &str) = ("", "", "");

static OCSF_CTX_FALLBACK: LazyLock<EventContext> = LazyLock::new(|| EventContext {
    sandbox_id: FALLBACK_SANDBOX.0.to_string(),
    sandbox_name: FALLBACK_SANDBOX.1.to_string(),
    container_image: FALLBACK_SANDBOX.2.to_string(),
    hostname: "test".to_string(),
    product_version: env!("CARGO_PKG_VERSION").to_string(),
    proxy_ip: std::net::IpAddr::from([127, 0, 0, 1]),
    proxy_port: 3128,
    origin: EventOrigin::Supervisor,
});

/// Initialise the process-wide OCSF sandbox context.
///
/// Returns `false` if the context was already set; the caller may log and
/// continue. Intended to be called exactly once during sandbox startup.
pub fn set_ctx(ctx: EventContext) -> bool {
    OCSF_CTX.set(ctx).is_ok()
}

/// Return a reference to the process-wide [`EventContext`].
///
/// Falls back to a default context if [`set_ctx`] has not been called (e.g.
/// during unit tests that exercise individual builders).
#[must_use]
pub fn ctx() -> &'static EventContext {
    OCSF_CTX.get().unwrap_or(&OCSF_CTX_FALLBACK)
}
