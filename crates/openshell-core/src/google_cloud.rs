// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared GCP constants for the metadata emulator, provider env injection,
//! and credential resolution.
//!
//! This module is the single source of truth for GCP naming: env var aliases,
//! provider config keys, token search order, and Vertex-specific env vars.
//! `openshell-server`, `openshell-providers`, and `openshell-sandbox`
//! import from here.

// ── Metadata emulator ───────────────────────────────────────────────────────

/// Hostname served by the GCE metadata emulator via proxy interception.
pub const METADATA_HOST: &str = "gcp.metadata.openshell.internal";

/// Loopback address for the GCE metadata server inside sandbox namespaces.
/// Go's metadata client dials this directly (bypasses `HTTP_PROXY`).
pub const METADATA_LOOPBACK_ADDR: &str = "127.0.0.1:8174";

// ── Env var alias arrays ────────────────────────────────────────────────────

/// Env vars that carry the GCP project ID inside sandboxes.
pub const PROJECT_ID_ENV_VARS: &[&str] = &["GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT"];

/// Env vars that carry the GCP region/location inside sandboxes.
pub const REGION_ENV_VARS: &[&str] = &["CLOUD_ML_REGION", "GCP_LOCATION"];

/// Env vars that carry the GCP service account email inside sandboxes.
pub const SERVICE_ACCOUNT_EMAIL_ENV_VARS: &[&str] = &["GCP_SERVICE_ACCOUNT_EMAIL"];

// ── Provider config keys ────────────────────────────────────────────────────

/// Config key for project ID in `gcp` providers.
pub const GCP_PROJECT_ID_CONFIG_KEY: &str = "project_id";

/// Config key for region in `gcp` providers.
pub const GCP_REGION_CONFIG_KEY: &str = "region";

/// Config key for service account email in `gcp` providers.
pub const GCP_SERVICE_ACCOUNT_EMAIL_CONFIG_KEY: &str = "service_account_email";

// ── Token search order ──────────────────────────────────────────────────────

/// GCP token env vars searched in priority order by the metadata emulator.
/// SA token wins over ADC if both are configured, matching GCP's own
/// credential precedence.
pub const TOKEN_ENV_KEYS: &[&str] = &["GCP_SA_ACCESS_TOKEN", "GCP_ADC_ACCESS_TOKEN"];

// ── Vertex-specific env vars ────────────────────────────────────────────────

/// Env var injected to signal Vertex AI usage to Goose.
pub const GOOSE_PROVIDER_ENV_VAR: &str = "GOOSE_PROVIDER";

/// Env var for Anthropic Vertex project ID (consumed by Claude Code SDK).
pub const ANTHROPIC_VERTEX_PROJECT_ID_ENV_VAR: &str = "ANTHROPIC_VERTEX_PROJECT_ID";

/// Env var for Vertex location (consumed by Claude Code SDK).
pub const VERTEX_LOCATION_ENV_VAR: &str = "VERTEX_LOCATION";

/// Non-secret GCP/Vertex config vars that must be resolved to real values
/// in the child environment. Everything else stays as placeholders for
/// proxy-time resolution.
///
/// This list MUST be the union of all alias arrays above plus all
/// Vertex-specific env vars. If you add an alias to `PROJECT_ID_ENV_VARS`,
/// `REGION_ENV_VARS`, or a Vertex constant, add it here too.
pub const STATIC_CONFIG_KEYS: &[&str] = &[
    // project_id aliases
    "GCP_PROJECT_ID",
    "GOOGLE_CLOUD_PROJECT",
    // region aliases
    "CLOUD_ML_REGION",
    "GCP_LOCATION",
    // service account email
    "GCP_SERVICE_ACCOUNT_EMAIL",
    // Vertex-specific non-secret config
    GOOSE_PROVIDER_ENV_VAR,
    ANTHROPIC_VERTEX_PROJECT_ID_ENV_VAR,
    VERTEX_LOCATION_ENV_VAR,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn static_config_keys_matches_alias_arrays_and_vertex_vars() {
        let expected: HashSet<&str> = PROJECT_ID_ENV_VARS
            .iter()
            .chain(REGION_ENV_VARS)
            .chain(SERVICE_ACCOUNT_EMAIL_ENV_VARS)
            .copied()
            .chain([
                GOOSE_PROVIDER_ENV_VAR,
                ANTHROPIC_VERTEX_PROJECT_ID_ENV_VAR,
                VERTEX_LOCATION_ENV_VAR,
            ])
            .collect();
        let actual: HashSet<&str> = STATIC_CONFIG_KEYS.iter().copied().collect();
        assert_eq!(
            expected,
            actual,
            "STATIC_CONFIG_KEYS must be the union of all alias arrays + Vertex vars. \
             Missing: {:?}, Extra: {:?}",
            expected.difference(&actual).collect::<Vec<_>>(),
            actual.difference(&expected).collect::<Vec<_>>(),
        );
    }
}
