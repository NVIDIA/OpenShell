// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Closed diagnostics for authenticated startup reports and trusted launcher exits.
//!
//! The supervisor reports a code in the existing admission error field. The
//! gateway projects only these fixed diagnostics, never backend error text.

/// Reserved exit of a trusted supervisor whose workload launch did not
/// complete unambiguously. It does not prove workload code never ran.
pub const SUPERVISOR_EXIT_LAUNCH_UNCONFIRMED: i32 = 84;

/// Public condition reason for an ambiguous workload launch.
pub const LAUNCH_UNCONFIRMED_CONDITION: &str = "WorkloadLaunchUnconfirmed";

/// Fixed diagnostic for the trusted supervisor's ambiguous launch failure.
pub const LAUNCH_UNCONFIRMED_DIAGNOSTIC: &str = "Workload startup failed or could not be confirmed; check the executable, working directory, execution permissions and runtime, then stop the sandbox and wait for cleanup before retrying";

/// A mandatory check failed in the trusted runtime launcher, before it
/// consumed the protected bootstrap or started any workload process.
///
/// Drivers may interpret these codes only for the runtime launcher itself,
/// never for the canonical workload's separately reported exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeStartupFailure {
    /// The host cannot provide the mandatory Landlock ABI.
    LandlockUnavailable,
    /// The active Landlock allow/deny check failed.
    LandlockEnforcement,
    /// Another mandatory runtime isolation check failed.
    Qualification,
}

impl RuntimeStartupFailure {
    /// Exit status owned by the trusted launcher, not by an agent process.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::LandlockUnavailable => 81,
            Self::LandlockEnforcement => 82,
            Self::Qualification => 83,
        }
    }

    /// Classify an observed exit of the trusted runtime launcher.
    #[must_use]
    pub const fn from_exit_code(code: i64) -> Option<Self> {
        match code {
            81 => Some(Self::LandlockUnavailable),
            82 => Some(Self::LandlockEnforcement),
            83 => Some(Self::Qualification),
            _ => None,
        }
    }

    /// Fixed condition reason for an observed trusted-launcher failure.
    #[must_use]
    pub const fn condition_reason(self) -> &'static str {
        match self {
            Self::LandlockUnavailable => "LandlockUnavailable",
            Self::LandlockEnforcement => "LandlockEnforcementFailed",
            Self::Qualification => "RuntimeQualificationFailed",
        }
    }

    /// Fixed public diagnostic without paths, arguments, or probe output.
    #[must_use]
    pub const fn diagnostic(self) -> &'static str {
        match self {
            Self::LandlockUnavailable => {
                "Sandbox runtime qualification failed: Landlock ABI v3 or newer is unavailable; check the kernel used by the runtime and its seccomp configuration"
            }
            Self::LandlockEnforcement => {
                "Sandbox runtime qualification failed: the Landlock allow/deny check failed; check the host filesystem and runtime configuration"
            }
            Self::Qualification => {
                "Sandbox runtime qualification failed: a mandatory isolation check failed; check host prerequisites and runtime configuration"
            }
        }
    }
}

impl std::fmt::Display for RuntimeStartupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.diagnostic())
    }
}

impl std::error::Error for RuntimeStartupFailure {}

/// The trusted operation whose startup outcome failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendStartupStage {
    /// Constructing the selected backend client.
    Build,
    /// Attaching the admitted runtime generation.
    Attach,
    /// Confirming the isolation boundary before starting workload code.
    Confirm,
    /// Launching the workload entrypoint after isolation confirmation.
    StartAgent,
}

impl BackendStartupStage {
    /// Stable token used with the existing backend error-kind classification.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Attach => "attach",
            Self::Confirm => "confirm",
            Self::StartAgent => "start-agent",
        }
    }
}

/// Project an exact startup failure code into a bounded, credential-free
/// diagnostic. Unknown and legacy error strings have no projection.
///
/// Only use this projection for an authenticated, generation-fenced startup
/// report. An unconfirmed launch does not prove that workload execution stopped.
#[must_use]
pub fn backend_startup_diagnostic(code: &str) -> Option<String> {
    let (stage, kind) = code.strip_prefix("openshell.backend.")?.split_once('.')?;
    if stage == "start-agent" {
        return (kind == "unconfirmed").then(|| LAUNCH_UNCONFIRMED_DIAGNOSTIC.to_string());
    }
    let stage = match stage {
        "build" => "client construction",
        "attach" => "attachment",
        "confirm" => "isolation confirmation",
        _ => return None,
    };
    let recovery = match kind {
        "invalid" => {
            "the launch descriptor or admitted identity did not match; check the installation and recreate the sandbox"
        }
        "denied" => {
            "the backend rejected the admitted policy or identity; review the policy and recreate the sandbox"
        }
        "unavailable" => {
            "the backend was unavailable; check its service and host qualification, then retry after cleanup"
        }
        "unsupported" => {
            "the backend does not support the requested operation; choose a compatible backend configuration"
        }
        "failed" => {
            "the backend could not establish isolation; check the installation and host qualification before retrying after cleanup"
        }
        "terminated" => {
            "the isolation boundary was lost before workload execution; check the backend service and recreate the sandbox"
        }
        _ => return None,
    };
    Some(format!("Isolation backend {stage} failed: {recovery}"))
}
