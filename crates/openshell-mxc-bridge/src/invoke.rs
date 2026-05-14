// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `wxc-exec` (Windows) / `lxc-exec` (Linux) invocation contract.
//!
//! This module is a *builder* — it computes the program path, argument list,
//! and base64-encoded config payload that the upstream `mxc-aegis` SDK
//! passes to `pty.spawn` (`sandbox.ts:287–308`). It does **not** spawn a
//! process. Driver crates own the actual `Command::spawn`.
//!
//! The contract is intentionally tiny:
//!
//! ```text
//! wxc-exec.exe --config-base64 <b64> [--debug] [--experimental]
//! ```
//!
//! `--experimental` is required for the `0.6.0-dev` IsolationSession
//! schema and is added automatically when [`Schema::DevIsolationSession`]
//! is selected.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use base64::Engine as _;

/// CLI flag for the base64-encoded config payload.
pub const CONFIG_BASE64_FLAG: &str = "--config-base64";

/// CLI flag enabling verbose runner-side logging.
pub const DEBUG_FLAG: &str = "--debug";

/// CLI flag enabling experimental MXC features (e.g. IsolationSession).
pub const EXPERIMENTAL_FLAG: &str = "--experimental";

/// Target MXC config schema. Drives both the JSON shape and the runner
/// invocation flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Schema {
    /// Stable `0.5.0-alpha` schema. AppContainer (Windows process container)
    /// or LXC (Linux). No `--experimental` required.
    #[default]
    AlphaProcess,
    /// Dev `0.6.0-dev` schema. IsolationSession backend. Requires
    /// `--experimental` to be passed to `wxc-exec`.
    DevIsolationSession,
}

impl Schema {
    /// Whether this schema requires the `--experimental` flag.
    #[must_use]
    pub const fn requires_experimental(self) -> bool {
        matches!(self, Self::DevIsolationSession)
    }
}

/// Computed `wxc-exec` invocation. The driver crate is expected to feed
/// these into `tokio::process::Command::new(invocation.program).args(&invocation.args)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WxcInvocation {
    /// Resolved path to `wxc-exec` (Windows) or `lxc-exec` (Linux).
    pub program: PathBuf,
    /// Argument list, in order. Includes `--config-base64 <b64>` plus any
    /// flag toggles requested by the caller or implied by the schema.
    pub args: Vec<OsString>,
}

/// Encode a JSON config payload as base64, matching the SDK's
/// `Buffer.from(JSON.stringify(config), 'utf-8').toString('base64')`.
#[must_use]
pub fn encode_config_base64(config_json: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(config_json.as_bytes())
}

/// Build a [`WxcInvocation`] for the given runner path, schema, config JSON,
/// and debug toggle.
///
/// `--experimental` is appended automatically when `schema.requires_experimental()`
/// returns true.
#[must_use]
pub fn build_invocation(
    wxc_exec_path: &Path,
    schema: Schema,
    config_json: &str,
    debug: bool,
) -> WxcInvocation {
    let mut args: Vec<OsString> = Vec::with_capacity(5);
    args.push(OsString::from(CONFIG_BASE64_FLAG));
    args.push(OsString::from(encode_config_base64(config_json)));

    if debug {
        args.push(OsString::from(DEBUG_FLAG));
    }
    if schema.requires_experimental() {
        args.push(OsString::from(EXPERIMENTAL_FLAG));
    }

    WxcInvocation {
        program: wxc_exec_path.to_path_buf(),
        args,
    }
}

/// Advisory classification of a `wxc-exec` exit code.
///
/// ASSUMPTION: the upstream MXC runner does **not** publish a stable exit
/// code taxonomy. Inspecting `mxc/src/wxc/src/main.rs` shows it
/// passes through the wrapped script's exit code on success and emits `1`
/// for runner-internal failures (config parse error, unsupported backend,
/// etc.). The two cases collide on `1` and are only fully disambiguated by
/// the JSON error envelope written to stderr. Drivers should treat this
/// classification as a hint and parse stderr for definitive diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WxcExitClass {
    /// Script (and runner) exited cleanly.
    Success,
    /// Either the script exited with a non-zero status, or the runner
    /// itself failed before the script could be launched. Disambiguate via
    /// the stderr error envelope.
    ScriptOrLauncherFailure(i32),
    /// Process was killed by a signal (Unix) — exposed for callers that
    /// inspect `ExitStatus::signal()` separately. The runner itself never
    /// emits this.
    Signalled(i32),
}

/// Map an exit-status code into a [`WxcExitClass`].
#[must_use]
pub const fn classify_exit_code(code: i32) -> WxcExitClass {
    if code == 0 {
        WxcExitClass::Success
    } else {
        WxcExitClass::ScriptOrLauncherFailure(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha_schema_does_not_add_experimental() {
        let path = PathBuf::from("/opt/mxc/wxc-exec");
        let inv = build_invocation(&path, Schema::AlphaProcess, "{}", false);
        assert_eq!(inv.program, path);
        assert_eq!(inv.args[0], OsString::from(CONFIG_BASE64_FLAG));
        assert!(!inv.args.iter().any(|a| a == EXPERIMENTAL_FLAG));
        assert!(!inv.args.iter().any(|a| a == DEBUG_FLAG));
    }

    #[test]
    fn dev_schema_adds_experimental() {
        let path = PathBuf::from("/opt/mxc/wxc-exec");
        let inv = build_invocation(&path, Schema::DevIsolationSession, "{}", false);
        assert!(inv.args.iter().any(|a| a == EXPERIMENTAL_FLAG));
    }

    #[test]
    fn debug_flag_is_threaded_through() {
        let path = PathBuf::from("/opt/mxc/wxc-exec");
        let inv = build_invocation(&path, Schema::AlphaProcess, "{}", true);
        assert!(inv.args.iter().any(|a| a == DEBUG_FLAG));
    }

    #[test]
    fn config_is_base64_encoded() {
        let path = PathBuf::from("/opt/mxc/wxc-exec");
        let inv = build_invocation(
            &path,
            Schema::AlphaProcess,
            r#"{"version":"0.5.0-alpha"}"#,
            false,
        );
        let b64 = inv.args[1].to_string_lossy().into_owned();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .expect("decodes");
        assert_eq!(decoded, br#"{"version":"0.5.0-alpha"}"#);
    }

    #[test]
    fn exit_classification() {
        assert_eq!(classify_exit_code(0), WxcExitClass::Success);
        assert_eq!(
            classify_exit_code(1),
            WxcExitClass::ScriptOrLauncherFailure(1),
        );
        assert_eq!(
            classify_exit_code(42),
            WxcExitClass::ScriptOrLauncherFailure(42),
        );
    }
}
