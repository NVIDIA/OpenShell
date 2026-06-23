// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process component of the `OpenShell` supervisor.
//!
//! Owns the entrypoint process spawn, SSH server, supervisor session, network
//! namespace, bypass monitor, child environment construction, skills install,
//! and log push. Populated by follow-up commits as modules migrate out of
//! `openshell-sandbox`.

pub mod child_env;
pub mod debug_rpc;
pub mod log_push;
pub mod managed_children;
pub mod process;
pub mod run;
pub mod sandbox;
pub mod skills;
pub mod ssh;
pub mod supervisor_session;

#[cfg(target_os = "linux")]
pub mod bypass_monitor;
#[cfg(target_os = "linux")]
pub mod netns;

use miette::Result;
use std::sync::OnceLock;

// Operator-declared bootstrap policy.
//
// The supervisor performs three privileged startup steps that an outer sandbox
// (gVisor, Firecracker, Kata) may own instead of the supervisor: network
// namespace creation, the supervisor seccomp prelude, and the workload seccomp
// filter. On bare-metal Linux all three are attempted and a host refusal is
// fatal. When the operator declares — via `--skip-bootstrap` /
// `OPENSHELL_SKIP_BOOTSTRAP` — that the environment owns one of them, the
// supervisor SKIPS it (never attempts it). Any subsystem that is NOT skipped
// and fails is still fatal. The default (skip nothing) is byte-identical to
// upstream: attempt everything, abort on any failure.

/// A privileged bootstrap step the supervisor performs at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapSubsystem {
    /// `unshare(CLONE_NEWNET)` + the veth/nftables setup behind the proxy.
    NetworkNamespace,
    /// The supervisor seccomp prelude (`apply_supervisor_startup_hardening`).
    SupervisorSeccomp,
    /// The workload per-policy seccomp filter in `sandbox::linux::enforce`.
    WorkloadSeccomp,
}

impl BootstrapSubsystem {
    /// Stable short name, used in `--skip-bootstrap` tokens and logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NetworkNamespace => "netns",
            Self::SupervisorSeccomp => "supervisor-seccomp",
            Self::WorkloadSeccomp => "workload-seccomp",
        }
    }

    /// Parse an operator-facing token. Case-insensitive; accepts the short and
    /// long spellings. Returns `None` for an unknown token.
    #[must_use]
    pub fn parse_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "netns" | "network-namespace" => Some(Self::NetworkNamespace),
            "supervisor-seccomp" | "supervisor_seccomp" => Some(Self::SupervisorSeccomp),
            "workload-seccomp" | "workload_seccomp" => Some(Self::WorkloadSeccomp),
            _ => None,
        }
    }
}

/// Set-once skip declaration. Unset (the default) skips nothing.
static SKIPPED_BOOTSTRAP: OnceLock<[bool; 3]> = OnceLock::new();

/// Declare which bootstrap subsystems the environment owns, so the supervisor
/// skips attempting them. Call once at process start, before the supervisor
/// boots; a second call is ignored.
pub fn set_skipped_bootstrap(subsystems: impl IntoIterator<Item = BootstrapSubsystem>) {
    let mut skip = [false; 3];
    for subsystem in subsystems {
        skip[subsystem as usize] = true;
    }
    let _ = SKIPPED_BOOTSTRAP.set(skip);
}

/// Parse operator tokens (`--skip-bootstrap` values / `OPENSHELL_SKIP_BOOTSTRAP`).
///
/// `all` skips every subsystem; otherwise each token must name one (see
/// [`BootstrapSubsystem::parse_token`]). Empty/blank tokens are ignored;
/// empty input skips nothing.
///
/// # Errors
/// Returns an error naming the offending token if it is not `all` or a known
/// subsystem.
pub fn parse_skip_bootstrap<I, S>(tokens: I) -> Result<Vec<BootstrapSubsystem>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut skip = Vec::new();
    for token in tokens {
        let token = token.as_ref().trim();
        if token.is_empty() {
            continue;
        }
        if token.eq_ignore_ascii_case("all") {
            return Ok(vec![
                BootstrapSubsystem::NetworkNamespace,
                BootstrapSubsystem::SupervisorSeccomp,
                BootstrapSubsystem::WorkloadSeccomp,
            ]);
        }
        match BootstrapSubsystem::parse_token(token) {
            Some(subsystem) => skip.push(subsystem),
            None => {
                return Err(miette::miette!(
                    "unknown --skip-bootstrap subsystem '{token}' \
                     (expected: netns, supervisor-seccomp, workload-seccomp, or all)"
                ));
            }
        }
    }
    Ok(skip)
}

/// Whether the operator declared `subsystem` as environment-owned. A skipped
/// subsystem is not attempted; a non-skipped subsystem's failure stays fatal.
pub(crate) fn bootstrap_skipped(subsystem: BootstrapSubsystem) -> bool {
    SKIPPED_BOOTSTRAP
        .get()
        .is_some_and(|skip| skip[subsystem as usize])
}

#[cfg(test)]
mod bootstrap_tests {
    use super::{BootstrapSubsystem, parse_skip_bootstrap};

    const ALL: [BootstrapSubsystem; 3] = [
        BootstrapSubsystem::NetworkNamespace,
        BootstrapSubsystem::SupervisorSeccomp,
        BootstrapSubsystem::WorkloadSeccomp,
    ];

    #[test]
    fn parse_all_expands_to_every_subsystem() {
        assert_eq!(parse_skip_bootstrap(["all"]).unwrap().len(), 3);
    }

    #[test]
    fn parse_named_subset_preserves_order() {
        let got = parse_skip_bootstrap(["netns", "workload-seccomp"]).unwrap();
        assert_eq!(
            got,
            vec![
                BootstrapSubsystem::NetworkNamespace,
                BootstrapSubsystem::WorkloadSeccomp
            ]
        );
    }

    #[test]
    fn parse_skips_blanks_and_rejects_unknown() {
        assert!(parse_skip_bootstrap(["", "  "]).unwrap().is_empty());
        assert!(parse_skip_bootstrap(["bogus"]).is_err());
    }

    #[test]
    fn token_roundtrips_via_as_str() {
        for subsystem in ALL {
            assert_eq!(
                BootstrapSubsystem::parse_token(subsystem.as_str()),
                Some(subsystem)
            );
        }
    }
}
