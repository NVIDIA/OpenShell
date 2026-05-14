// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bridge between OpenShell policy types and the Microsoft MXC sandbox runner.
//!
//! This crate is pure — it does no I/O. It holds two responsibilities:
//!
//! 1. Translate an OpenShell baseline [`SandboxPolicy`](openshell_core::proto::SandboxPolicy)
//!    plus an optional per-task
//!    [`EnvelopePolicy`](openshell_policy::EnvelopePolicy) into an MXC
//!    `ContainerConfig` JSON document, supporting **both** the stable
//!    `0.5.0-alpha` (AppContainer) and dev `0.6.0-dev` (IsolationSession)
//!    schemas via [`Schema`].
//! 2. Build the `wxc-exec` invocation contract — base64-encoded config,
//!    `--config-base64` / `--debug` / `--experimental` arg layout, and
//!    advisory exit-code classification — without spawning a process. Driver
//!    crates own the actual `Command::spawn`.
//!
//! See `rfc/0004-aegis-governance` and the Phase 2 spike (Findings 3b/3c)
//! for context.

mod invoke;
pub mod schema_alpha;
pub mod schema_dev;
mod translate;

pub use invoke::{
    CONFIG_BASE64_FLAG, DEBUG_FLAG, EXPERIMENTAL_FLAG, Schema, WxcExitClass, WxcInvocation,
    build_invocation, classify_exit_code, encode_config_base64,
};
pub use translate::{
    ContainerConfig, TranslateError, TranslateOptions, UiPolicy, translate, translate_alpha,
    translate_dev,
};
