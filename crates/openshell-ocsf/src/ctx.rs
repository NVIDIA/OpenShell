// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide [`SandboxContext`] singleton.
//!
//! Initialised once via [`set_ctx`] during sandbox start; read by every event
//! builder via [`ctx`]. Falls back to a default context when the singleton has
//! not been set (e.g. unit tests that exercise builders without booting the
//! sandbox).

use crate::SandboxContext;
use std::sync::{LazyLock, OnceLock};

static OCSF_CTX: OnceLock<SandboxContext> = OnceLock::new();

static OCSF_CTX_FALLBACK: LazyLock<SandboxContext> = LazyLock::new(|| SandboxContext {
    sandbox_id: String::new(),
    sandbox_name: String::new(),
    container_image: String::new(),
    hostname: "test".to_string(),
    product_version: env!("CARGO_PKG_VERSION").to_string(),
    proxy_ip: std::net::IpAddr::from([127, 0, 0, 1]),
    proxy_port: 3128,
});

/// Initialise the process-wide OCSF sandbox context.
///
/// Returns `false` if the context was already set; the caller may log and
/// continue. Intended to be called exactly once during sandbox startup.
pub fn set_ctx(ctx: SandboxContext) -> bool {
    OCSF_CTX.set(ctx).is_ok()
}

/// Return a reference to the process-wide [`SandboxContext`].
///
/// Falls back to a default context if [`set_ctx`] has not been called (e.g.
/// during unit tests that exercise individual builders).
#[must_use]
pub fn ctx() -> &'static SandboxContext {
    OCSF_CTX.get().unwrap_or(&OCSF_CTX_FALLBACK)
}
