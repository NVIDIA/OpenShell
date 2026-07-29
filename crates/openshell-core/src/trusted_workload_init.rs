// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared constants for driver-neutral trusted workload initialization.

use crate::proto::compute::v1::{TrustedWorkloadInitEnvelope, TrustedWorkloadInitPlan};
use prost::Message;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Versioned compute-driver capability required by trusted initialization.
pub const FEATURE: &str = "trusted-workload-init.v1";

/// Platform ceiling for a single transient initializer payload.
///
/// This leaves deterministic headroom below Podman's 512,000-byte secret
/// limit for the signed execution metadata carried in the same envelope.
pub const MAX_PAYLOAD_BYTES: usize = 384 * 1024;

/// Current driver-to-supervisor envelope schema.
pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;

/// Maximum encoded driver-to-supervisor envelope size.
pub const MAX_ENVELOPE_BYTES: usize = 500_000;

/// Root-only envelope mount visible to the sandbox supervisor.
pub const ENVELOPE_MOUNT_PATH: &str = "/etc/openshell/trusted-init/request.pb";

/// Fixed supervisor argument that activates trusted initialization.
pub const ENVELOPE_CLI_FLAG: &str = "--trusted-init-file";

/// Private exec-form health probe run from the side-loaded supervisor binary.
///
/// Container drivers use this instead of an image-provided healthcheck or
/// image shell so untrusted image content cannot advertise readiness before
/// initialization and supervisor startup complete.
pub const HEALTHCHECK_SUBCOMMAND: &str = "__trusted-init-healthcheck-v1";

/// Root-owned, workload-readable receipt written after successful initialization.
pub const RECEIPT_PATH: &str = "/var/lib/openshell/trusted-init/receipt.json";

/// Fixed environment variable naming the receipt that the supervisor owns.
pub const CHILD_RECEIPT_FILE_ENV: &str = "OPENSHELL_TRUSTED_INIT_RECEIPT_FILE";

/// Fixed environment variable naming the resolved registration.
pub const CHILD_CONTRACT_ENV: &str = "OPENSHELL_TRUSTED_INIT_CONTRACT";

/// Driver- and supervisor-owned trees that an initializer may never mutate.
pub const RESERVED_WRITABLE_TREES: &[&str] = &[
    "/etc/openshell",
    "/etc/openshell-tls",
    "/var/lib/openshell/trusted-init",
    "/opt/openshell",
    "/run/netns",
    "/run/secrets",
    "/var/run/netns",
    "/var/run/secrets",
    "/proc",
    "/sys",
    "/dev",
];

#[must_use]
pub fn is_supervisor_env_var(key: &str) -> bool {
    key.starts_with("OPENSHELL_TRUSTED_INIT_")
}

/// Validate a gateway-resolved plan at the compute-driver trust boundary.
pub fn validate_plan(plan: &TrustedWorkloadInitPlan, image: &str) -> Result<(), String> {
    if plan.contract_id.is_empty() {
        return Err("trusted workload initialization contract_id is required".to_string());
    }
    if plan.image != image {
        return Err(format!(
            "trusted workload initialization image '{}' does not match sandbox image '{image}'",
            plan.image
        ));
    }
    if plan.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "trusted workload initialization payload exceeds platform limit ({} > {MAX_PAYLOAD_BYTES})",
            plan.payload.len()
        ));
    }
    let actual_digest = hex::encode(Sha256::digest(&plan.payload));
    if plan.payload_sha256 != actual_digest {
        return Err("trusted workload initialization payload digest mismatch".to_string());
    }
    if plan.command.is_empty() || !valid_executable_path(Path::new(&plan.command[0])) {
        return Err(
            "trusted workload initialization command must name a normalized absolute executable"
                .to_string(),
        );
    }
    let executable = Path::new(&plan.command[0]);
    if plan.timeout_seconds == 0 || plan.timeout_seconds > 300 {
        return Err(
            "trusted workload initialization timeout_seconds must be between 1 and 300".to_string(),
        );
    }
    if plan.writable_paths.is_empty()
        || plan
            .writable_paths
            .iter()
            .any(|path| !valid_writable_path(Path::new(path)))
    {
        return Err(
            "trusted workload initialization writable_paths must be normalized absolute paths that do not overlap supervisor-owned trees".to_string(),
        );
    }
    if plan
        .writable_paths
        .iter()
        .map(Path::new)
        .any(|path| executable.starts_with(path) || path.starts_with(executable))
    {
        return Err(
            "trusted workload initialization command executable must not overlap writable_paths"
                .to_string(),
        );
    }
    if plan
        .capabilities
        .iter()
        .any(|capability| !matches!(capability.as_str(), "CHOWN" | "FOWNER"))
    {
        return Err(
            "trusted workload initialization capabilities contain a disallowed capability"
                .to_string(),
        );
    }
    Ok(())
}

fn valid_writable_path(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    if !path.is_absolute()
        || raw == "/"
        || raw.ends_with('/')
        || raw.contains("//")
        || raw
            .split('/')
            .any(|component| component == "." || component == "..")
    {
        return false;
    }
    RESERVED_WRITABLE_TREES
        .iter()
        .map(Path::new)
        .all(|reserved| !path.starts_with(reserved) && !reserved.starts_with(path))
}

fn valid_executable_path(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    let normalized = path.is_absolute()
        && raw != "/"
        && !raw.ends_with('/')
        && !raw.contains("//")
        && !raw
            .split('/')
            .any(|component| component == "." || component == "..");
    normalized
        && RESERVED_WRITABLE_TREES
            .iter()
            .chain(["/sandbox", "/tmp", "/var/tmp", "/run", "/var/run"].iter())
            .map(Path::new)
            .all(|reserved| !path.starts_with(reserved))
}

/// Seal a validated gateway plan into the driver-owned root-only envelope.
pub fn encode_envelope(
    sandbox_id: &str,
    plan: &TrustedWorkloadInitPlan,
    resolved_image_id: &str,
) -> Result<Vec<u8>, String> {
    if sandbox_id.trim().is_empty() {
        return Err("trusted initializer sandbox ID is required".to_string());
    }
    if resolved_image_id.trim().is_empty() {
        return Err("trusted initializer resolved image ID is required".to_string());
    }
    let envelope = TrustedWorkloadInitEnvelope {
        schema_version: ENVELOPE_SCHEMA_VERSION,
        sandbox_id: sandbox_id.to_string(),
        plan: Some(plan.clone()),
        resolved_image_id: resolved_image_id.to_string(),
    };
    let encoded = envelope.encode_to_vec();
    if encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(format!(
            "trusted initializer envelope exceeds platform limit ({} > {MAX_ENVELOPE_BYTES})",
            encoded.len()
        ));
    }
    Ok(encoded)
}

/// Decode and validate a driver-owned trusted initialization envelope.
pub fn decode_envelope(
    bytes: &[u8],
    expected_sandbox_id: &str,
) -> Result<TrustedWorkloadInitEnvelope, String> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(format!(
            "trusted initializer envelope exceeds platform limit ({} > {MAX_ENVELOPE_BYTES})",
            bytes.len()
        ));
    }
    let envelope = TrustedWorkloadInitEnvelope::decode(bytes)
        .map_err(|error| format!("decode trusted initializer envelope failed: {error}"))?;
    if envelope.schema_version != ENVELOPE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported trusted initializer envelope schema {}",
            envelope.schema_version
        ));
    }
    if envelope.sandbox_id != expected_sandbox_id {
        return Err("trusted initializer envelope sandbox ID mismatch".to_string());
    }
    let plan = envelope
        .plan
        .as_ref()
        .ok_or_else(|| "trusted initializer envelope plan is required".to_string())?;
    validate_plan(plan, &plan.image)?;
    if envelope.resolved_image_id.trim().is_empty() {
        return Err("trusted initializer resolved image ID is required".to_string());
    }
    Ok(envelope)
}

/// Stable digest binding every operator-owned execution field in a plan.
#[must_use]
pub fn plan_sha256(plan: &TrustedWorkloadInitPlan) -> String {
    hex::encode(Sha256::digest(plan.encode_to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> TrustedWorkloadInitPlan {
        let payload = b"onboarding".to_vec();
        TrustedWorkloadInitPlan {
            contract_id: "example.onboarding.v1".to_string(),
            payload_sha256: hex::encode(Sha256::digest(&payload)),
            payload,
            command: vec!["/usr/local/bin/onboard".to_string()],
            timeout_seconds: 30,
            writable_paths: vec!["/etc/example-agent".to_string()],
            image: format!("sha256:{}", "a".repeat(64)),
            capabilities: vec!["CHOWN".to_string()],
        }
    }

    #[test]
    fn envelope_binds_sandbox_plan_and_inspected_image() {
        let plan = plan();
        let resolved_image = format!("sha256:{}", "b".repeat(64));
        let encoded = encode_envelope("sandbox-id", &plan, &resolved_image).unwrap();
        let decoded = decode_envelope(&encoded, "sandbox-id").unwrap();

        assert_eq!(decoded.plan, Some(plan));
        assert_eq!(decoded.resolved_image_id, resolved_image);
        assert!(decode_envelope(&encoded, "other-sandbox").is_err());
    }

    #[test]
    fn driver_validation_rejects_supervisor_path_ancestors() {
        let mut plan = plan();
        plan.writable_paths = vec!["/var/lib".to_string()];

        assert!(validate_plan(&plan, &plan.image).is_err());
    }

    #[test]
    fn driver_validation_rejects_writable_command_ancestor() {
        let mut plan = plan();
        plan.writable_paths = vec!["/usr/local".to_string()];

        assert!(validate_plan(&plan, &plan.image).is_err());
    }

    #[test]
    fn driver_validation_rejects_driver_owned_tree_ancestors() {
        for path in ["/opt", "/run", "/etc/openshell-tls"] {
            let mut plan = plan();
            plan.writable_paths = vec![path.to_string()];
            assert!(
                validate_plan(&plan, &plan.image).is_err(),
                "{path} must be reserved"
            );
        }
    }
}
