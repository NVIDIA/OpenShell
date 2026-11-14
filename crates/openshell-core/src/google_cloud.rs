// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared destinations and environment keys used by the GCP metadata emulator.
//!
//! Provider environment defaults and discovery keys belong to imported
//! profiles; this module holds only the names required by the supervisor's
//! metadata protocol.

// ── Metadata emulator ───────────────────────────────────────────────────────

/// Hostname served by the GCE metadata emulator via proxy interception.
pub const METADATA_HOST: &str = "gcp.metadata.openshell.internal";

/// Reserved loopback destination relayed to the supervisor metadata emulator.
/// Go's metadata client dials this directly (bypasses `HTTP_PROXY`).
pub const METADATA_LOOPBACK_ADDR: &str = "127.0.0.1:8174";

/// Match only the reserved metadata service, never a host cloud metadata IP.
pub fn is_metadata_destination(destination: std::net::SocketAddr) -> bool {
    destination == std::net::SocketAddr::from(([127, 0, 0, 1], 8174))
}

// ── Metadata environment keys ───────────────────────────────────────────────

/// Env vars that carry the GCP project ID inside sandboxes.
pub const PROJECT_ID_ENV_VARS: &[&str] = &["GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT"];

/// Env vars that carry the GCP service account email inside sandboxes.
pub const SERVICE_ACCOUNT_EMAIL_ENV_VARS: &[&str] = &["GCP_SERVICE_ACCOUNT_EMAIL"];

// ── Token search order ──────────────────────────────────────────────────────

/// GCP token env vars searched in priority order by the metadata emulator.
/// SA token wins over ADC if both are configured, matching GCP's own
/// credential precedence.
pub const TOKEN_ENV_KEYS: &[&str] = &["GCP_SA_ACCESS_TOKEN", "GCP_ADC_ACCESS_TOKEN"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_destination_matches_only_reserved_loopback_endpoint() {
        assert!(is_metadata_destination(
            METADATA_LOOPBACK_ADDR.parse().unwrap()
        ));
        for address in [
            "127.0.0.1:8175",
            "127.0.0.2:8174",
            "169.254.169.254:80",
            "[::1]:8174",
        ] {
            assert!(!is_metadata_destination(address.parse().unwrap()));
        }
    }
}
