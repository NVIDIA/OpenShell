// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor helpers — privileged processes spawned before the workload.
//!
//! A helper is a short, operator-audited daemon that the workload will talk
//! to via an approved Landlock path (typically a UDS). Helpers are spawned
//! directly by the supervisor *before* the workload and *without* the
//! per-workload sandbox: no seccomp filter, no `PR_SET_NO_NEW_PRIVS`, no
//! Landlock, no privilege drop. They inherit ambient capabilities declared
//! in the helpers config file, so daemons that need `CAP_SETUID`,
//! `CAP_NET_ADMIN`, etc. to set up per-request isolation (e.g. a capability
//! broker) can run alongside the sandboxed workload.
//!
//! The supervisor is the trust boundary. The operator vouches for each
//! helper binary shipped in the image and for the declared capabilities in
//! the config. The workload process is still sandboxed exactly as before.
//!
//! See `architecture/plans/supervisor-helpers.md` for the RFC that will
//! supersede this v0.

use miette::{IntoDiagnostic, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use tokio::process::Child;
use tracing::info;

#[cfg(target_os = "linux")]
use std::process::Stdio;
#[cfg(target_os = "linux")]
use tokio::process::Command;

#[cfg(target_os = "linux")]
use openshell_ocsf::{ActivityId, AppLifecycleBuilder, SeverityId, StatusId, ocsf_emit};

#[cfg(target_os = "linux")]
const SSH_HANDSHAKE_SECRET_ENV: &str = "OPENSHELL_SSH_HANDSHAKE_SECRET";

/// Root config document loaded from `--helpers-config <path>` or
/// `OPENSHELL_HELPERS_CONFIG`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HelpersConfig {
    #[serde(default)]
    pub helpers: Vec<HelperSpec>,
}

/// One supervisor helper. v0 schema — future RFC iterations will add Landlock,
/// restart policy, readiness fd, stdio routing, cgroup limits.
#[derive(Debug, Clone, Deserialize)]
pub struct HelperSpec {
    /// Human-readable name used in logs and OCSF events.
    pub name: String,
    /// Full argv. `command[0]` must be an absolute path; the supervisor does
    /// not consult `$PATH`.
    pub command: Vec<String>,
    /// Environment variables merged on top of the supervisor's environment.
    /// Supervisor-private values (e.g. the SSH handshake secret) are scrubbed
    /// from the inherited environment before these overrides apply.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Capabilities raised into the helper's ambient set. Names accept either
    /// `CAP_FOO` or `FOO` (case-insensitive). Each listed cap must exist in
    /// the supervisor's permitted set (which, in the default pod spec, is
    /// the full bounding set).
    #[serde(default)]
    pub ambient_caps: Vec<String>,
}

/// Runtime handle for a spawned helper.
pub struct HelperHandle {
    pub name: String,
    pub pid: u32,
    pub child: Child,
}

/// Load and validate a helpers config from disk.
///
/// # Errors
/// Returns an error if the file cannot be read, parsed, or fails validation.
pub fn load_helpers_config(path: &Path) -> Result<HelpersConfig> {
    let bytes = std::fs::read(path)
        .into_diagnostic()
        .map_err(|e| miette::miette!("reading helpers config {}: {e}", path.display()))?;
    let config: HelpersConfig = serde_json::from_slice(&bytes)
        .into_diagnostic()
        .map_err(|e| miette::miette!("parsing helpers config {}: {e}", path.display()))?;
    validate(&config)?;
    Ok(config)
}

fn validate(config: &HelpersConfig) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for helper in &config.helpers {
        if helper.name.is_empty() {
            return Err(miette::miette!("helper with empty name"));
        }
        if !seen.insert(helper.name.clone()) {
            return Err(miette::miette!("duplicate helper name {:?}", helper.name));
        }
        let argv0 = helper
            .command
            .first()
            .ok_or_else(|| miette::miette!("helper {:?} has empty command", helper.name))?;
        if !argv0.starts_with('/') {
            return Err(miette::miette!(
                "helper {:?}: command[0] must be an absolute path, got {argv0:?}",
                helper.name
            ));
        }
    }
    Ok(())
}

/// Spawn every helper in the config, in declaration order. Returns a handle
/// per spawned helper.
///
/// # Errors
/// Propagates the first helper that fails to spawn.
pub fn spawn_helpers(config: &HelpersConfig) -> Result<Vec<HelperHandle>> {
    let mut handles = Vec::with_capacity(config.helpers.len());
    for spec in &config.helpers {
        let handle = spawn_helper(spec)?;
        info!(
            name = %handle.name,
            pid = handle.pid,
            caps = ?spec.ambient_caps,
            "Supervisor helper started"
        );
        handles.push(handle);
    }
    Ok(handles)
}

#[cfg(target_os = "linux")]
fn spawn_helper(spec: &HelperSpec) -> Result<HelperHandle> {
    let caps_list = parse_caps(&spec.ambient_caps)?;

    let (program, args) = spec
        .command
        .split_first()
        .ok_or_else(|| miette::miette!("empty command"))?;

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env_remove(SSH_HANDSHAKE_SECRET_ENV)
        .env("OPENSHELL_SUPERVISOR_HELPER", &spec.name)
        .kill_on_drop(true);
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }

    // SAFETY: pre_exec runs after fork, before exec, in the child. The
    // syscalls we make (capset via the `caps` crate, prctl) are
    // async-signal-safe.
    let caps_for_child = caps_list.clone();
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(move || raise_ambient(&caps_for_child).map_err(std::io::Error::other));
    }

    let child = cmd.spawn().into_diagnostic()?;
    let pid = child.id().unwrap_or(0);

    // OCSF's unified ActivityId maps `Reset = 3` to "Start" in lifecycle context
    // (see lifecycle_label in openshell-ocsf/src/enums/activity.rs).
    ocsf_emit!(
        AppLifecycleBuilder::new(crate::ocsf_ctx())
            .activity(ActivityId::Reset)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .message(format!(
                "supervisor helper {} started (pid {pid})",
                spec.name
            ))
            .build()
    );

    Ok(HelperHandle {
        name: spec.name.clone(),
        pid,
        child,
    })
}

#[cfg(not(target_os = "linux"))]
fn spawn_helper(_spec: &HelperSpec) -> Result<HelperHandle> {
    Err(miette::miette!("supervisor helpers are Linux-only"))
}

#[cfg(target_os = "linux")]
fn parse_caps(names: &[String]) -> Result<Vec<caps::Capability>> {
    names
        .iter()
        .map(|n| {
            let canon = n
                .strip_prefix("CAP_")
                .or_else(|| n.strip_prefix("cap_"))
                .unwrap_or(n)
                .to_ascii_uppercase();
            let full = format!("CAP_{canon}");
            full.parse::<caps::Capability>()
                .map_err(|_| miette::miette!("unknown capability name {n:?}"))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn raise_ambient(caps_list: &[caps::Capability]) -> std::io::Result<()> {
    use caps::CapSet;
    for cap in caps_list {
        // Ambient requires the cap to be in both permitted and inheritable.
        // The supervisor runs with a full permitted set in the default pod
        // spec, but inheritable is empty by default — add it first.
        caps::raise(None, CapSet::Inheritable, *cap)
            .map_err(|e| std::io::Error::other(format!("raise inheritable {cap:?}: {e}")))?;
        caps::raise(None, CapSet::Ambient, *cap)
            .map_err(|e| std::io::Error::other(format!("raise ambient {cap:?}: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, cmd: &str) -> HelperSpec {
        HelperSpec {
            name: name.into(),
            command: vec![cmd.into()],
            env: HashMap::new(),
            ambient_caps: vec![],
        }
    }

    #[test]
    fn rejects_relative_command() {
        let config = HelpersConfig {
            helpers: vec![spec("h", "relative")],
        };
        assert!(validate(&config).is_err());
    }

    #[test]
    fn rejects_empty_name() {
        let config = HelpersConfig {
            helpers: vec![spec("", "/bin/true")],
        };
        assert!(validate(&config).is_err());
    }

    #[test]
    fn rejects_duplicate_names() {
        let config = HelpersConfig {
            helpers: vec![spec("dup", "/bin/true"), spec("dup", "/bin/true")],
        };
        assert!(validate(&config).is_err());
    }

    #[test]
    fn accepts_minimal_valid_config() {
        let config = HelpersConfig {
            helpers: vec![spec("h", "/bin/true")],
        };
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn parses_json_config() {
        let json =
            r#"{"helpers":[{"name":"m","command":["/bin/true"],"ambient_caps":["CAP_SETUID"]}]}"#;
        let config: HelpersConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.helpers.len(), 1);
        assert_eq!(config.helpers[0].name, "m");
        assert_eq!(config.helpers[0].ambient_caps, vec!["CAP_SETUID"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_caps_accepts_both_forms() {
        let parsed = parse_caps(&["CAP_SETUID".into(), "setgid".into()]).unwrap();
        assert_eq!(
            parsed,
            vec![caps::Capability::CAP_SETUID, caps::Capability::CAP_SETGID]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_caps_rejects_unknown() {
        assert!(parse_caps(&["CAP_NOPE".into()]).is_err());
    }
}
