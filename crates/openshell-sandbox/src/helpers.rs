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
/// Before the first helper spawns, install iptables OUTPUT rules in the
/// supervisor's netns that REJECT helper-originated egress that doesn't
/// route through the policy proxy. See `install_capture_rules` for the
/// rule set and exemption rationale.
///
/// # Errors
/// Propagates the first helper that fails to spawn. Failure to install
/// capture rules is logged but non-fatal — helpers still spawn so the
/// supervisor can boot, but the trust model is degraded (operators get
/// an OCSF event flagging the missing capture).
pub fn spawn_helpers(config: &HelpersConfig) -> Result<Vec<HelperHandle>> {
    if !config.helpers.is_empty() {
        if let Err(e) = install_capture_rules() {
            // Don't fail the spawn — degraded mode is better than no helpers.
            // The OCSF event raised inside `install_capture_rules` already
            // tells operators capture is off; tracing here is for completeness.
            tracing::warn!(
                error = %e,
                "supervisor netns capture rules failed to install; \
                 helpers will run with un-captured egress"
            );
        }
    }

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

// ── Supervisor-netns iptables capture ───────────────────────────────────────
//
// Helpers share the supervisor's network namespace by design — that's how
// the mediator UDS, OpenClaw gateway, and other operator-declared daemons
// reach services the workload sandbox couldn't reach itself. The downside:
// before this module, the supervisor netns had no iptables rules at all, so
// any helper-spawned process whose HTTP client ignores `HTTPS_PROXY` (e.g.
// Node's built-in `https.request`, which OpenClaw's `web_fetch` tool uses
// internally) could egress directly to any host the pod can reach, with no
// policy check and no audit trail.
//
// This module installs a small set of rules in the supervisor netns OUTPUT
// chain that LOG+REJECT helper-originated direct egress while exempting:
//   - the supervisor's own outbound traffic (gRPC to control plane, log
//     push, the policy proxy's upstream forwarding) via `--uid-owner 0`
//   - traffic destined for the policy proxy itself (the legitimate
//     proxy-aware path)
//   - loopback and reply packets
//
// A helper that drops privileges (e.g. `nemoclaw-start` → `gosu gateway` →
// UID 999, or `mediator-runner` → setresuid → UID 998) and then attempts a
// direct outbound TCP connection lands in the catch-all REJECT and gets a
// fast `ECONNREFUSED` plus an `openshell:helper-bypass:` LOG entry that
// `bypass_monitor` parses into an OCSF DetectionFinding.
//
// Known limitations of this v0 design:
//   1. A helper running as root before its own privilege drop is exempted
//      by the UID 0 rule — same brief window as for the supervisor's own
//      bootstrap traffic. For sclaw's helpers this is bounded to the few
//      seconds between exec and gosu/runner; documented in the helpers RFC.
//   2. The proxy hostname/IP is hard-coded here to match
//      `sandbox::linux::netns::{SUBNET_PREFIX, HOST_IP_SUFFIX}` because at
//      `spawn_helpers` time the policy hasn't been loaded yet and the
//      runtime proxy bind address isn't available. A v1 refactor that
//      moves helper spawn after policy load would replace the constant
//      with the runtime address.

/// Hard-coded supervisor-side proxy IP. Must match
/// `sandbox::linux::netns::SUBNET_PREFIX` (`10.200.0`) +
/// `HOST_IP_SUFFIX` (`1`). Hard-coding here because helpers spawn before
/// the policy is loaded and the actual proxy bind address is set.
#[cfg(target_os = "linux")]
const PROXY_IP: &str = "10.200.0.1";

/// Hard-coded proxy port. Matches the default in `lib.rs` and `proxy.rs`.
/// Same v0 limitation as `PROXY_IP` above.
#[cfg(target_os = "linux")]
const PROXY_PORT: u16 = 3128;

/// Well-known iptables paths. Mirrors `sandbox::linux::netns`'s probe set;
/// duplicated here so we can stay independent of the netns module's
/// internal API.
#[cfg(target_os = "linux")]
const IPTABLES_SEARCH_PATHS: &[&str] =
    &["/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"];

#[cfg(target_os = "linux")]
fn find_iptables() -> Option<String> {
    IPTABLES_SEARCH_PATHS
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|s| (*s).to_string())
}

#[cfg(target_os = "linux")]
fn run_iptables(iptables_cmd: &str, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(iptables_cmd)
        .args(args)
        .output()
        .into_diagnostic()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette::miette!(
            "{iptables_cmd} {} failed: {}",
            args.join(" "),
            stderr.trim()
        ));
    }
    Ok(())
}

/// Install OUTPUT-chain rules in the supervisor's netns to capture helper
/// egress. Idempotent: re-running appends duplicate ACCEPT/REJECT rules,
/// which is harmless but cosmetically noisy; in practice this runs once
/// per supervisor lifetime.
///
/// Degrades gracefully when iptables is missing — emits an OCSF event so
/// operators see the missing capture, returns `Ok(())` to let helpers
/// still spawn.
#[cfg(target_os = "linux")]
fn install_capture_rules() -> Result<()> {
    let iptables = match find_iptables() {
        Some(path) => path,
        None => {
            ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                    .severity(openshell_ocsf::SeverityId::Medium)
                    .status(openshell_ocsf::StatusId::Failure)
                    .state(openshell_ocsf::StateId::Disabled, "degraded")
                    .message(
                        "iptables not found; supervisor-netns helper capture rules \
                         will not be installed — helpers may egress without policy \
                         enforcement"
                    )
                    .build()
            );
            return Ok(());
        }
    };

    let proxy_port_str = PROXY_PORT.to_string();
    let proxy_dst = format!("{PROXY_IP}/32");

    // Rule 1: ACCEPT loopback. Mediator UDS, gateway UI, etc. depend on it.
    run_iptables(
        &iptables,
        &["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
    )?;

    // Rule 2: ACCEPT reply packets for connections we already permitted.
    run_iptables(
        &iptables,
        &[
            "-A", "OUTPUT",
            "-m", "conntrack",
            "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        ],
    )?;

    // Rule 3: ACCEPT to the policy proxy. Helpers that respect HTTPS_PROXY
    // land here; the proxy then enforces the binary + host allowlist.
    run_iptables(
        &iptables,
        &[
            "-A", "OUTPUT",
            "-d", &proxy_dst,
            "-p", "tcp",
            "--dport", &proxy_port_str,
            "-j", "ACCEPT",
        ],
    )?;

    // Rule 4: ACCEPT supervisor's own outbound. UID 0 covers the gRPC
    // control-plane connection, log push, and the policy proxy's own
    // upstream forwarding (which would otherwise loop). Helpers that
    // haven't dropped privileges yet are also covered here — see the
    // module-level comment for the bounded-window caveat.
    run_iptables(
        &iptables,
        &[
            "-A", "OUTPUT",
            "-m", "owner",
            "--uid-owner", "0",
            "-j", "ACCEPT",
        ],
    )?;

    // Rule 5: LOG bypass attempts so bypass_monitor can surface them as
    // OCSF DetectionFindings. The prefix matches the existing convention
    // used by the workload-netns LOG rules in `sandbox::linux::netns`.
    let log_prefix = "openshell:helper-bypass:";
    if let Err(e) = run_iptables(
        &iptables,
        &[
            "-A", "OUTPUT",
            "-j", "LOG",
            "--log-prefix", log_prefix,
            "--log-level", "warning",
        ],
    ) {
        // LOG is non-essential — REJECT below still catches the bypass.
        // Some kernels lack `xt_LOG`; downgrade to a warning and continue.
        tracing::warn!(error = %e, "could not install LOG rule for helper bypass");
    }

    // Rule 6: REJECT everything else with ECONNREFUSED so callers fast-fail
    // instead of hanging on a 30s connect timeout.
    run_iptables(
        &iptables,
        &[
            "-A", "OUTPUT",
            "-j", "REJECT",
            "--reject-with", "icmp-port-unreachable",
        ],
    )?;

    ocsf_emit!(
        openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
            .severity(openshell_ocsf::SeverityId::Informational)
            .status(openshell_ocsf::StatusId::Success)
            .state(openshell_ocsf::StateId::Enabled, "installed")
            .message(format!(
                "Supervisor netns capture rules installed [proxy:{PROXY_IP}:{PROXY_PORT}]"
            ))
            .build()
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_capture_rules() -> Result<()> {
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
