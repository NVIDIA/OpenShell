// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Result of a driver's `preflight` subcommand.
//!
//! `openshell-driver-<name> preflight --config <path>` validates the driver's
//! configuration from a startup document without starting the driver, opening
//! sockets, or changing runtime state, and reports on stdout, as one JSON
//! object, whether the configuration is acceptable. The gateway treats a
//! failure, a timeout, or output larger than [`MAX_PREFLIGHT_OUTPUT_BYTES`] as
//! a failed preflight.

use serde::{Deserialize, Serialize};

/// Largest preflight output the gateway accepts.
pub const MAX_PREFLIGHT_OUTPUT_BYTES: usize = 16 * 1024;

/// What a driver reports about a startup document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightResult {
    pub ok: bool,
    /// Why the configuration was rejected, for the operator. Omitted when ok.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PreflightResult {
    #[must_use]
    pub const fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }

    #[must_use]
    pub fn rejected(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
        }
    }

    /// Serialize as the single JSON line a driver prints.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a preflight result always serializes")
    }

    /// Parse a driver's preflight output.
    ///
    /// # Errors
    ///
    /// Returns a message when the output is too large or is not a result.
    pub fn parse(output: &[u8]) -> Result<Self, String> {
        if output.len() > MAX_PREFLIGHT_OUTPUT_BYTES {
            return Err(format!(
                "preflight output exceeds {MAX_PREFLIGHT_OUTPUT_BYTES} bytes"
            ));
        }
        serde_json::from_slice(output).map_err(|error| format!("invalid preflight output: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_round_trip_and_omit_the_error_when_ok() {
        let ok = PreflightResult::ok();
        assert_eq!(ok.to_json(), r#"{"ok":true}"#);
        assert_eq!(PreflightResult::parse(ok.to_json().as_bytes()), Ok(ok));

        let rejected = PreflightResult::rejected("vcpus must be positive");
        assert_eq!(
            PreflightResult::parse(rejected.to_json().as_bytes()),
            Ok(rejected)
        );
    }

    #[test]
    fn oversized_or_malformed_output_is_rejected() {
        let large = vec![b' '; MAX_PREFLIGHT_OUTPUT_BYTES + 1];
        assert!(
            PreflightResult::parse(&large)
                .unwrap_err()
                .contains("exceeds")
        );
        assert!(
            PreflightResult::parse(b"fine")
                .unwrap_err()
                .contains("invalid")
        );
    }
}
