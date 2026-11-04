// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Closed startup failure codes carried by pre-start configuration refusals.
//!
//! The supervisor reports a code in the existing admission error field. The
//! gateway projects only these fixed diagnostics, never backend error text.

/// The trusted operation that failed before workload execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendStartupStage {
    /// Constructing the selected backend client.
    Build,
    /// Attaching the admitted runtime generation.
    Attach,
    /// Confirming the isolation boundary before starting workload code.
    Confirm,
}

impl BackendStartupStage {
    /// Stable token used with the existing backend error-kind classification.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Attach => "attach",
            Self::Confirm => "confirm",
        }
    }
}

/// Project an exact startup failure code into a bounded, credential-free
/// diagnostic. Unknown and legacy error strings have no projection.
///
/// Only use this projection for an authenticated, generation-fenced
/// `refused_before_start` report; ordinary runtime errors are not startup claims.
#[must_use]
pub fn backend_startup_diagnostic(code: &str) -> Option<String> {
    let (stage, kind) = code.strip_prefix("openshell.backend.")?.split_once('.')?;
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
