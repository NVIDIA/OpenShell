// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Result of a driver's `probe` subcommand.
//!
//! `openshell-driver-<name> probe` reports on stdout, as one JSON object,
//! whether the driver is usable on this host. The gateway runs it during
//! auto-detection and treats a failure, a timeout, or output larger than
//! [`MAX_PROBE_OUTPUT_BYTES`] as "not available". The probe reports
//! availability only. Which available driver is selected stays with the
//! gateway.

use serde::{Deserialize, Serialize};

/// Largest probe output the gateway accepts.
pub const MAX_PROBE_OUTPUT_BYTES: usize = 4096;

/// What a driver reports about the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeResult {
    pub available: bool,
    /// Why the driver is not usable, for the operator. Omitted when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ProbeResult {
    #[must_use]
    pub const fn available() -> Self {
        Self {
            available: true,
            reason: None,
        }
    }

    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            available: false,
            reason: Some(reason.into()),
        }
    }

    /// Serialize as the single JSON line a driver prints.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a probe result always serializes")
    }

    /// Parse a driver's probe output.
    ///
    /// # Errors
    ///
    /// Returns a message when the output is too large or is not a probe result.
    pub fn parse(output: &[u8]) -> Result<Self, String> {
        if output.len() > MAX_PROBE_OUTPUT_BYTES {
            return Err(format!(
                "probe output exceeds {MAX_PROBE_OUTPUT_BYTES} bytes"
            ));
        }
        serde_json::from_slice(output).map_err(|error| format!("invalid probe output: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_round_trip_and_omit_the_reason_when_available() {
        let available = ProbeResult::available();
        assert_eq!(available.to_json(), r#"{"available":true}"#);
        assert_eq!(
            ProbeResult::parse(available.to_json().as_bytes()),
            Ok(available)
        );

        let missing = ProbeResult::unavailable("no socket");
        assert_eq!(
            ProbeResult::parse(missing.to_json().as_bytes()),
            Ok(missing)
        );
    }

    #[test]
    fn oversized_or_malformed_output_is_rejected() {
        let large = vec![b' '; MAX_PROBE_OUTPUT_BYTES + 1];
        assert!(ProbeResult::parse(&large).unwrap_err().contains("exceeds"));
        assert!(ProbeResult::parse(b"yes").unwrap_err().contains("invalid"));
        assert!(ProbeResult::parse(br#"{"available":true,"extra":1}"#).is_err());
    }
}
