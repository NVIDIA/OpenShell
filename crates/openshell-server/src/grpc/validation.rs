// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Request validation helpers for the gRPC service.
//!
//! All functions in this module are pure — they take proto types or primitives
//! and return `Result<(), Status>`.  No server state is required.

#![allow(clippy::result_large_err)] // Validation returns Result<_, Status>

use openshell_core::proto::{
    ExecSandboxRequest, Provider, SandboxPolicy as ProtoSandboxPolicy, SandboxTemplate,
};
use prost::Message;
use tonic::Status;

use super::{
    MAX_ENVIRONMENT_ENTRIES, MAX_LOG_LEVEL_LEN, MAX_MAP_KEY_LEN, MAX_MAP_VALUE_LEN, MAX_NAME_LEN,
    MAX_POLICY_SIZE, MAX_PROVIDER_CONFIG_ENTRIES, MAX_PROVIDER_CREDENTIALS_ENTRIES,
    MAX_PROVIDER_TYPE_LEN, MAX_PROVIDERS, MAX_TEMPLATE_MAP_ENTRIES, MAX_TEMPLATE_STRING_LEN,
    MAX_TEMPLATE_STRUCT_SIZE,
};

// ---------------------------------------------------------------------------
// Exec request validation
// ---------------------------------------------------------------------------

/// Maximum number of arguments in the command array.
pub(super) const MAX_EXEC_COMMAND_ARGS: usize = 1024;
/// Maximum length of a single command argument or environment value (bytes).
pub(super) const MAX_EXEC_ARG_LEN: usize = 32 * 1024; // 32 KiB
/// Maximum length of the workdir field (bytes).
pub(super) const MAX_EXEC_WORKDIR_LEN: usize = 4096;

/// Validate fields of an `ExecSandboxRequest` for control characters and size
/// limits before constructing a shell command string.
pub(super) fn validate_exec_request_fields(req: &ExecSandboxRequest) -> Result<(), Status> {
    if req.command.len() > MAX_EXEC_COMMAND_ARGS {
        return Err(Status::invalid_argument(format!(
            "command array exceeds {MAX_EXEC_COMMAND_ARGS} argument limit"
        )));
    }
    for (i, arg) in req.command.iter().enumerate() {
        if arg.len() > MAX_EXEC_ARG_LEN {
            return Err(Status::invalid_argument(format!(
                "command argument {i} exceeds {MAX_EXEC_ARG_LEN} byte limit"
            )));
        }
        reject_control_chars(arg, &format!("command argument {i}"))?;
    }
    for (key, value) in &req.environment {
        if value.len() > MAX_EXEC_ARG_LEN {
            return Err(Status::invalid_argument(format!(
                "environment value for '{key}' exceeds {MAX_EXEC_ARG_LEN} byte limit"
            )));
        }
        reject_control_chars(value, &format!("environment value for '{key}'"))?;
    }
    if !req.workdir.is_empty() {
        if req.workdir.len() > MAX_EXEC_WORKDIR_LEN {
            return Err(Status::invalid_argument(format!(
                "workdir exceeds {MAX_EXEC_WORKDIR_LEN} byte limit"
            )));
        }
        reject_control_chars(&req.workdir, "workdir")?;
    }
    Ok(())
}

/// Reject null bytes and newlines in a user-supplied value.
pub(super) fn reject_control_chars(value: &str, field_name: &str) -> Result<(), Status> {
    if value.bytes().any(|b| b == 0) {
        return Err(Status::invalid_argument(format!(
            "{field_name} contains null bytes"
        )));
    }
    if value.bytes().any(|b| b == b'\n' || b == b'\r') {
        return Err(Status::invalid_argument(format!(
            "{field_name} contains newline or carriage return characters"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sandbox spec validation
// ---------------------------------------------------------------------------

/// Validate field sizes on a `CreateSandboxRequest` before persisting.
///
/// Returns `INVALID_ARGUMENT` on the first field that exceeds its limit.
pub(super) fn validate_sandbox_spec(
    name: &str,
    spec: &openshell_core::proto::SandboxSpec,
) -> Result<(), Status> {
    // --- request.name ---
    if name.len() > MAX_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "name exceeds maximum length ({} > {MAX_NAME_LEN})",
            name.len()
        )));
    }

    // --- spec.providers ---
    if spec.providers.len() > MAX_PROVIDERS {
        return Err(Status::invalid_argument(format!(
            "providers list exceeds maximum ({} > {MAX_PROVIDERS})",
            spec.providers.len()
        )));
    }

    // --- spec.log_level ---
    if spec.log_level.len() > MAX_LOG_LEVEL_LEN {
        return Err(Status::invalid_argument(format!(
            "log_level exceeds maximum length ({} > {MAX_LOG_LEVEL_LEN})",
            spec.log_level.len()
        )));
    }

    // --- spec.environment ---
    validate_string_map(
        &spec.environment,
        MAX_ENVIRONMENT_ENTRIES,
        MAX_MAP_KEY_LEN,
        MAX_MAP_VALUE_LEN,
        "spec.environment",
    )?;

    // --- spec.template ---
    if let Some(ref tmpl) = spec.template {
        validate_sandbox_template(tmpl)?;
    }

    // --- spec.policy serialized size ---
    if let Some(ref policy) = spec.policy {
        let size = policy.encoded_len();
        if size > MAX_POLICY_SIZE {
            return Err(Status::invalid_argument(format!(
                "policy serialized size exceeds maximum ({size} > {MAX_POLICY_SIZE})"
            )));
        }
    }

    Ok(())
}

/// Validate template-level field sizes.
fn validate_sandbox_template(tmpl: &SandboxTemplate) -> Result<(), Status> {
    // String fields.
    for (field, value) in [
        ("template.image", &tmpl.image),
        ("template.runtime_class_name", &tmpl.runtime_class_name),
        ("template.agent_socket", &tmpl.agent_socket),
    ] {
        if value.len() > MAX_TEMPLATE_STRING_LEN {
            return Err(Status::invalid_argument(format!(
                "{field} exceeds maximum length ({} > {MAX_TEMPLATE_STRING_LEN})",
                value.len()
            )));
        }
    }

    // Map fields.
    validate_string_map(
        &tmpl.labels,
        MAX_TEMPLATE_MAP_ENTRIES,
        MAX_MAP_KEY_LEN,
        MAX_MAP_VALUE_LEN,
        "template.labels",
    )?;
    validate_string_map(
        &tmpl.annotations,
        MAX_TEMPLATE_MAP_ENTRIES,
        MAX_MAP_KEY_LEN,
        MAX_MAP_VALUE_LEN,
        "template.annotations",
    )?;
    validate_string_map(
        &tmpl.environment,
        MAX_TEMPLATE_MAP_ENTRIES,
        MAX_MAP_KEY_LEN,
        MAX_MAP_VALUE_LEN,
        "template.environment",
    )?;

    // Struct fields (serialized size).
    if let Some(ref s) = tmpl.resources {
        let size = s.encoded_len();
        if size > MAX_TEMPLATE_STRUCT_SIZE {
            return Err(Status::invalid_argument(format!(
                "template.resources serialized size exceeds maximum ({size} > {MAX_TEMPLATE_STRUCT_SIZE})"
            )));
        }
    }
    if let Some(ref s) = tmpl.volume_claim_templates {
        let size = s.encoded_len();
        if size > MAX_TEMPLATE_STRUCT_SIZE {
            return Err(Status::invalid_argument(format!(
                "template.volume_claim_templates serialized size exceeds maximum ({size} > {MAX_TEMPLATE_STRUCT_SIZE})"
            )));
        }
    }

    Ok(())
}

/// Validate a `map<string, string>` field: entry count, key length, value length.
pub(super) fn validate_string_map(
    map: &std::collections::HashMap<String, String>,
    max_entries: usize,
    max_key_len: usize,
    max_value_len: usize,
    field_name: &str,
) -> Result<(), Status> {
    if map.len() > max_entries {
        return Err(Status::invalid_argument(format!(
            "{field_name} exceeds maximum entries ({} > {max_entries})",
            map.len()
        )));
    }
    for (key, value) in map {
        if key.len() > max_key_len {
            return Err(Status::invalid_argument(format!(
                "{field_name} key exceeds maximum length ({} > {max_key_len})",
                key.len()
            )));
        }
        if value.len() > max_value_len {
            return Err(Status::invalid_argument(format!(
                "{field_name} value exceeds maximum length ({} > {max_value_len})",
                value.len()
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Provider field validation
// ---------------------------------------------------------------------------

/// Validate field sizes on a `Provider` before persisting.
pub(super) fn validate_provider_fields(provider: &Provider) -> Result<(), Status> {
    let name_len = provider.metadata.as_ref().map_or(0, |m| m.name.len());
    if name_len > MAX_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "provider.name exceeds maximum length ({name_len} > {MAX_NAME_LEN})"
        )));
    }
    if provider.r#type.len() > MAX_PROVIDER_TYPE_LEN {
        return Err(Status::invalid_argument(format!(
            "provider.type exceeds maximum length ({} > {MAX_PROVIDER_TYPE_LEN})",
            provider.r#type.len()
        )));
    }
    validate_string_map(
        &provider.credentials,
        MAX_PROVIDER_CREDENTIALS_ENTRIES,
        MAX_MAP_KEY_LEN,
        MAX_MAP_VALUE_LEN,
        "provider.credentials",
    )?;
    validate_string_map(
        &provider.config,
        MAX_PROVIDER_CONFIG_ENTRIES,
        MAX_MAP_KEY_LEN,
        MAX_MAP_VALUE_LEN,
        "provider.config",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Label selector validation
// ---------------------------------------------------------------------------

/// Validate a label selector string format.
///
/// Format: "key1=value1,key2=value2"
/// Returns `INVALID_ARGUMENT` if the selector has invalid format.
/// Validate a label key according to Kubernetes requirements.
///
/// Label keys have an optional prefix and required name, separated by `/`:
/// - Prefix (optional): DNS subdomain format, max 253 chars
/// - Name (required): alphanumeric + `-._`, max 63 chars, must start/end with alphanumeric
/// - Total length including `/` must not exceed 253 chars
///
/// Examples: `app`, `kubernetes.io/app`, `example.com/my-label`
///
/// See: <https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/>
pub(super) fn validate_label_key(key: &str) -> Result<(), Status> {
    if key.is_empty() {
        return Err(Status::invalid_argument("label key cannot be empty"));
    }

    if key.len() > 253 {
        return Err(Status::invalid_argument(format!(
            "label key exceeds 253 characters: '{key}'"
        )));
    }

    // Split into optional prefix and required name
    let (prefix, name) = if let Some((p, n)) = key.split_once('/') {
        (Some(p), n)
    } else {
        (None, key)
    };

    // Validate name segment (required, max 63 chars)
    if name.is_empty() {
        return Err(Status::invalid_argument(format!(
            "label key name segment cannot be empty: '{key}'"
        )));
    }

    if name.len() > 63 {
        return Err(Status::invalid_argument(format!(
            "label key name segment exceeds 63 characters: '{key}'"
        )));
    }

    // Name must contain only alphanumeric, hyphens, underscores, and dots
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(Status::invalid_argument(format!(
            "label key name segment contains invalid characters (must be alphanumeric, '-', '_', or '.'): '{key}'"
        )));
    }

    // Name must start and end with alphanumeric
    let first = name.chars().next().unwrap(); // safe: we checked !is_empty()
    let last = name.chars().last().unwrap();
    if !first.is_alphanumeric() {
        return Err(Status::invalid_argument(format!(
            "label key name segment must start with alphanumeric character: '{key}'"
        )));
    }
    if !last.is_alphanumeric() {
        return Err(Status::invalid_argument(format!(
            "label key name segment must end with alphanumeric character: '{key}'"
        )));
    }

    // Validate prefix if present (DNS subdomain format)
    if let Some(prefix) = prefix {
        if prefix.is_empty() {
            return Err(Status::invalid_argument(format!(
                "label key prefix cannot be empty when '/' is present: '{key}'"
            )));
        }

        if prefix.len() > 253 {
            return Err(Status::invalid_argument(format!(
                "label key prefix exceeds 253 characters: '{key}'"
            )));
        }

        // DNS subdomain: lowercase alphanumeric, hyphens, and dots only
        if !prefix
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
        {
            return Err(Status::invalid_argument(format!(
                "label key prefix must be a DNS subdomain (lowercase alphanumeric, '-', '.'): '{key}'"
            )));
        }

        // Must not start or end with hyphen or dot
        if prefix.starts_with('-')
            || prefix.starts_with('.')
            || prefix.ends_with('-')
            || prefix.ends_with('.')
        {
            return Err(Status::invalid_argument(format!(
                "label key prefix cannot start or end with '-' or '.': '{key}'"
            )));
        }

        // Must not contain consecutive dots
        if prefix.contains("..") {
            return Err(Status::invalid_argument(format!(
                "label key prefix cannot contain consecutive dots: '{key}'"
            )));
        }
    }

    Ok(())
}

/// Validate a label value according to Kubernetes requirements.
///
/// Label values:
/// - Can be empty (Kubernetes allows empty values)
/// - Max 63 characters
/// - If non-empty, must contain only alphanumeric, hyphens, underscores, and dots
/// - If non-empty, must start and end with alphanumeric character
///
/// See: <https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/>
pub(super) fn validate_label_value(value: &str) -> Result<(), Status> {
    // Empty values are allowed in Kubernetes
    if value.is_empty() {
        return Ok(());
    }

    if value.len() > 63 {
        return Err(Status::invalid_argument(format!(
            "label value exceeds 63 characters: '{value}'"
        )));
    }

    // Must contain only alphanumeric, hyphens, underscores, and dots
    if !value
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(Status::invalid_argument(format!(
            "label value contains invalid characters (must be alphanumeric, '-', '_', or '.'): '{value}'"
        )));
    }

    // Must start and end with alphanumeric
    let first = value.chars().next().unwrap(); // safe: we checked !is_empty()
    let last = value.chars().last().unwrap();
    if !first.is_alphanumeric() {
        return Err(Status::invalid_argument(format!(
            "label value must start with alphanumeric character: '{value}'"
        )));
    }
    if !last.is_alphanumeric() {
        return Err(Status::invalid_argument(format!(
            "label value must end with alphanumeric character: '{value}'"
        )));
    }

    Ok(())
}

/// Validate a label selector string format.
///
/// Format: "key1=value1,key2=value2"
/// Each key and value is validated using `validate_label_key` and `validate_label_value`.
/// Empty selectors are allowed. Trailing commas are ignored.
pub(super) fn validate_label_selector(selector: &str) -> Result<(), Status> {
    if selector.trim().is_empty() {
        return Ok(());
    }

    for pair in selector.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }

        let parts: Vec<&str> = pair.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(Status::invalid_argument(format!(
                "invalid label selector: expected 'key=value', got '{pair}'"
            )));
        }

        let key = parts[0].trim();
        let value = parts[1].trim();

        if key.is_empty() {
            return Err(Status::invalid_argument(format!(
                "invalid label selector: key cannot be empty in '{pair}'"
            )));
        }

        // Validate key and value using the Kubernetes-compliant validators
        validate_label_key(key)?;
        validate_label_value(value)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Object metadata validation
// ---------------------------------------------------------------------------

/// Validate that object metadata is present and contains required fields.
///
/// This ensures that all resources have valid metadata with non-empty ID and name,
/// preventing issues where missing metadata could lead to security vulnerabilities
/// (e.g., empty string IDs/names matching unintended resources).
///
/// Returns `INVALID_ARGUMENT` if metadata is missing or invalid.
pub(super) fn validate_object_metadata(
    metadata: Option<&openshell_core::proto::datamodel::v1::ObjectMeta>,
    resource_type: &str,
) -> Result<(), Status> {
    let metadata = metadata
        .ok_or_else(|| Status::invalid_argument(format!("{resource_type} metadata is required")))?;

    if metadata.id.is_empty() {
        return Err(Status::invalid_argument(format!(
            "{resource_type} metadata.id cannot be empty"
        )));
    }

    if metadata.name.is_empty() {
        return Err(Status::invalid_argument(format!(
            "{resource_type} metadata.name cannot be empty"
        )));
    }

    // Validate all labels in metadata
    for (key, value) in &metadata.labels {
        validate_label_key(key)?;
        validate_label_value(value)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Policy validation
// ---------------------------------------------------------------------------

/// Validate that a policy does not contain unsafe content.
///
/// Delegates to [`openshell_policy::validate_sandbox_policy`] and converts
/// violations into a gRPC `INVALID_ARGUMENT` status.
pub(super) fn validate_policy_safety(policy: &ProtoSandboxPolicy) -> Result<(), Status> {
    if let Err(violations) = openshell_policy::validate_sandbox_policy(policy) {
        let messages: Vec<String> = violations.iter().map(ToString::to_string).collect();
        return Err(Status::invalid_argument(format!(
            "policy contains unsafe content: {}",
            messages.join("; ")
        )));
    }
    Ok(())
}

/// Validate that static policy fields (filesystem, landlock, process) haven't changed
/// from the baseline (version 1) policy.
pub(super) fn validate_static_fields_unchanged(
    baseline: &ProtoSandboxPolicy,
    new: &ProtoSandboxPolicy,
) -> Result<(), Status> {
    // Filesystem: allow additive changes (new paths can be added, but
    // existing paths cannot be removed and include_workdir cannot change).
    // This supports the supervisor's baseline path enrichment at startup.
    // Note: Landlock is a one-way door — adding paths to the stored policy
    // has no effect on a running child process; the enriched paths only
    // take effect on the next restart.
    validate_filesystem_additive(baseline.filesystem.as_ref(), new.filesystem.as_ref())?;

    if baseline.landlock != new.landlock {
        return Err(Status::invalid_argument(
            "landlock policy cannot be changed on a live sandbox (applied at startup)",
        ));
    }
    if baseline.process != new.process {
        return Err(Status::invalid_argument(
            "process policy cannot be changed on a live sandbox (applied at startup)",
        ));
    }
    Ok(())
}

/// Validate that a filesystem policy update is purely additive: all baseline
/// paths must still be present, `include_workdir` must not change, but new
/// paths may be added.
fn validate_filesystem_additive(
    baseline: Option<&openshell_core::proto::FilesystemPolicy>,
    new: Option<&openshell_core::proto::FilesystemPolicy>,
) -> Result<(), Status> {
    match (baseline, new) {
        (Some(base), Some(upd)) => {
            if base.include_workdir != upd.include_workdir {
                return Err(Status::invalid_argument(
                    "filesystem include_workdir cannot be changed on a live sandbox",
                ));
            }
            for path in &base.read_only {
                if !upd.read_only.contains(path) {
                    return Err(Status::invalid_argument(format!(
                        "filesystem read_only path '{path}' cannot be removed on a live sandbox"
                    )));
                }
            }
            for path in &base.read_write {
                if !upd.read_write.contains(path) {
                    return Err(Status::invalid_argument(format!(
                        "filesystem read_write path '{path}' cannot be removed on a live sandbox"
                    )));
                }
            }
        }
        (Some(_), None) => {
            return Err(Status::invalid_argument(
                "filesystem policy cannot be removed on a live sandbox",
            ));
        }
        // Baseline had no filesystem policy, or neither side has one — allowed
        // (enrichment from empty, or no-op).
        (None, _) => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Log filtering helpers
// ---------------------------------------------------------------------------

/// Check if a log line's source matches the filter list.
/// Empty source is treated as "gateway" for backward compatibility.
pub(super) fn source_matches(log_source: &str, filters: &[String]) -> bool {
    let effective = if log_source.is_empty() {
        "gateway"
    } else {
        log_source
    };
    filters.iter().any(|f| f == effective)
}

/// Check if a log line's level meets the minimum level threshold.
/// Empty `min_level` means no filtering (all levels pass).
pub(super) fn level_matches(log_level: &str, min_level: &str) -> bool {
    if min_level.is_empty() {
        return true;
    }
    let to_num = |s: &str| match s.to_uppercase().as_str() {
        "ERROR" => 0,
        "WARN" => 1,
        "INFO" | "OCSF" => 2,
        "DEBUG" => 3,
        "TRACE" => 4,
        _ => 5, // unknown levels always pass
    };
    to_num(log_level) <= to_num(min_level)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::SandboxSpec;
    use std::collections::HashMap;
    use tonic::Code;

    use crate::grpc::{
        MAX_ENVIRONMENT_ENTRIES, MAX_LOG_LEVEL_LEN, MAX_MAP_KEY_LEN, MAX_MAP_VALUE_LEN,
        MAX_NAME_LEN, MAX_POLICY_SIZE, MAX_PROVIDER_CONFIG_ENTRIES,
        MAX_PROVIDER_CREDENTIALS_ENTRIES, MAX_PROVIDER_TYPE_LEN, MAX_PROVIDERS,
        MAX_TEMPLATE_MAP_ENTRIES, MAX_TEMPLATE_STRING_LEN, MAX_TEMPLATE_STRUCT_SIZE,
    };

    // ---- Sandbox spec validation ----

    fn default_spec() -> SandboxSpec {
        SandboxSpec::default()
    }

    #[test]
    fn level_matches_treats_ocsf_as_info() {
        assert!(level_matches("OCSF", "INFO"));
        assert!(!level_matches("OCSF", "WARN"));
    }

    #[test]
    fn validate_sandbox_spec_accepts_gpu_flag() {
        let spec = SandboxSpec {
            gpu: true,
            ..Default::default()
        };
        assert!(validate_sandbox_spec("gpu-sandbox", &spec).is_ok());
    }

    #[test]
    fn validate_sandbox_spec_accepts_empty_defaults() {
        assert!(validate_sandbox_spec("", &default_spec()).is_ok());
    }

    #[test]
    fn validate_sandbox_spec_accepts_at_limit_name() {
        let name = "a".repeat(MAX_NAME_LEN);
        assert!(validate_sandbox_spec(&name, &default_spec()).is_ok());
    }

    #[test]
    fn validate_sandbox_spec_rejects_over_limit_name() {
        let name = "a".repeat(MAX_NAME_LEN + 1);
        let err = validate_sandbox_spec(&name, &default_spec()).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("name"));
    }

    #[test]
    fn validate_sandbox_spec_accepts_at_limit_providers() {
        let spec = SandboxSpec {
            providers: (0..MAX_PROVIDERS).map(|i| format!("p-{i}")).collect(),
            ..Default::default()
        };
        assert!(validate_sandbox_spec("ok", &spec).is_ok());
    }

    #[test]
    fn validate_sandbox_spec_rejects_over_limit_providers() {
        let spec = SandboxSpec {
            providers: (0..=MAX_PROVIDERS).map(|i| format!("p-{i}")).collect(),
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("providers"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_over_limit_log_level() {
        let spec = SandboxSpec {
            log_level: "x".repeat(MAX_LOG_LEVEL_LEN + 1),
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("log_level"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_too_many_env_entries() {
        let env: HashMap<String, String> = (0..=MAX_ENVIRONMENT_ENTRIES)
            .map(|i| (format!("K{i}"), "v".to_string()))
            .collect();
        let spec = SandboxSpec {
            environment: env,
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("environment"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_oversized_env_key() {
        let mut env = HashMap::new();
        env.insert("k".repeat(MAX_MAP_KEY_LEN + 1), "v".to_string());
        let spec = SandboxSpec {
            environment: env,
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("key"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_oversized_env_value() {
        let mut env = HashMap::new();
        env.insert("KEY".to_string(), "v".repeat(MAX_MAP_VALUE_LEN + 1));
        let spec = SandboxSpec {
            environment: env,
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("value"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_oversized_template_image() {
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                image: "x".repeat(MAX_TEMPLATE_STRING_LEN + 1),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("template.image"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_too_many_template_labels() {
        let labels: HashMap<String, String> = (0..=MAX_TEMPLATE_MAP_ENTRIES)
            .map(|i| (format!("k{i}"), "v".to_string()))
            .collect();
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                labels,
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("template.labels"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_oversized_template_struct() {
        use prost_types::{Struct, Value, value::Kind};

        let mut fields = std::collections::BTreeMap::new();
        let big_str = "x".repeat(MAX_TEMPLATE_STRUCT_SIZE);
        fields.insert(
            "big".to_string(),
            Value {
                kind: Some(Kind::StringValue(big_str)),
            },
        );
        let big_struct = Struct { fields };
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                resources: Some(big_struct),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("template.resources"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_oversized_policy() {
        use openshell_core::proto::NetworkPolicyRule;
        use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;

        let mut policy = ProtoSandboxPolicy::default();
        let big_name = "x".repeat(MAX_POLICY_SIZE);
        policy
            .network_policies
            .insert(big_name, NetworkPolicyRule::default());
        let spec = SandboxSpec {
            policy: Some(policy),
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("policy"));
    }

    #[test]
    fn validate_sandbox_spec_accepts_valid_spec() {
        let spec = SandboxSpec {
            log_level: "debug".to_string(),
            providers: vec!["p1".to_string()],
            environment: std::iter::once(("KEY".to_string(), "val".to_string())).collect(),
            template: Some(SandboxTemplate {
                image: "nvcr.io/test:latest".to_string(),
                runtime_class_name: "kata".to_string(),
                labels: std::iter::once(("app".to_string(), "test".to_string())).collect(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(validate_sandbox_spec("my-sandbox", &spec).is_ok());
    }

    // ---- Provider field validation ----

    fn one_credential() -> HashMap<String, String> {
        std::iter::once(("KEY".to_string(), "val".to_string())).collect()
    }

    fn make_test_provider(
        name: &str,
        provider_type: &str,
        credentials: HashMap<String, String>,
        config: HashMap<String, String>,
    ) -> Provider {
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: String::new(),
                name: name.to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
            }),
            r#type: provider_type.to_string(),
            credentials,
            config,
        }
    }

    #[test]
    fn validate_provider_fields_accepts_valid() {
        let provider = make_test_provider(
            "my-provider",
            "claude",
            one_credential(),
            std::iter::once(("endpoint".to_string(), "https://example.com".to_string())).collect(),
        );
        assert!(validate_provider_fields(&provider).is_ok());
    }

    #[test]
    fn validate_provider_fields_rejects_over_limit_name() {
        let provider = make_test_provider(
            &"a".repeat(MAX_NAME_LEN + 1),
            "claude",
            one_credential(),
            HashMap::new(),
        );
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("provider.name"));
    }

    #[test]
    fn validate_provider_fields_rejects_over_limit_type() {
        let provider = make_test_provider(
            "ok",
            &"x".repeat(MAX_PROVIDER_TYPE_LEN + 1),
            one_credential(),
            HashMap::new(),
        );
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("provider.type"));
    }

    #[test]
    fn validate_provider_fields_rejects_too_many_credentials() {
        let creds: HashMap<String, String> = (0..=MAX_PROVIDER_CREDENTIALS_ENTRIES)
            .map(|i| (format!("K{i}"), "v".to_string()))
            .collect();
        let provider = make_test_provider("ok", "claude", creds, HashMap::new());
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("provider.credentials"));
    }

    #[test]
    fn validate_provider_fields_rejects_too_many_config() {
        let config: HashMap<String, String> = (0..=MAX_PROVIDER_CONFIG_ENTRIES)
            .map(|i| (format!("K{i}"), "v".to_string()))
            .collect();
        let provider = make_test_provider("ok", "claude", one_credential(), config);
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("provider.config"));
    }

    #[test]
    fn validate_provider_fields_at_limit_name_accepted() {
        let provider = make_test_provider(
            &"a".repeat(MAX_NAME_LEN),
            "claude",
            one_credential(),
            HashMap::new(),
        );
        assert!(validate_provider_fields(&provider).is_ok());
    }

    #[test]
    fn validate_provider_fields_rejects_oversized_credential_key() {
        let mut creds = HashMap::new();
        creds.insert("k".repeat(MAX_MAP_KEY_LEN + 1), "v".to_string());
        let provider = make_test_provider("ok", "claude", creds, HashMap::new());
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("key"));
    }

    #[test]
    fn validate_provider_fields_rejects_oversized_config_value() {
        let mut config = HashMap::new();
        config.insert("k".to_string(), "v".repeat(MAX_MAP_VALUE_LEN + 1));
        let provider = make_test_provider("ok", "claude", one_credential(), config);
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("value"));
    }

    // ---- Label selector validation ----

    // ---- Label key validation ----

    #[test]
    fn validate_label_key_accepts_simple_names() {
        assert!(validate_label_key("app").is_ok());
        assert!(validate_label_key("my-app").is_ok());
        assert!(validate_label_key("my_app").is_ok());
        assert!(validate_label_key("my.app").is_ok());
        assert!(validate_label_key("app123").is_ok());
        assert!(validate_label_key("a1-b2_c3.d4").is_ok());
    }

    #[test]
    fn validate_label_key_accepts_prefixed_names() {
        assert!(validate_label_key("kubernetes.io/app").is_ok());
        assert!(validate_label_key("example.com/my-label").is_ok());
        assert!(validate_label_key("sub.domain.example.com/name").is_ok());
        assert!(validate_label_key("a.b/c").is_ok());
    }

    #[test]
    fn validate_label_key_rejects_empty() {
        let err = validate_label_key("").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("cannot be empty"));
    }

    #[test]
    fn validate_label_key_rejects_name_starting_with_hyphen() {
        let err = validate_label_key("-app").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("must start with alphanumeric"));
    }

    #[test]
    fn validate_label_key_rejects_name_ending_with_hyphen() {
        let err = validate_label_key("app-").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("must end with alphanumeric"));
    }

    #[test]
    fn validate_label_key_rejects_name_starting_with_underscore() {
        let err = validate_label_key("_app").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("must start with alphanumeric"));
    }

    #[test]
    fn validate_label_key_rejects_name_starting_with_dot() {
        let err = validate_label_key(".app").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("must start with alphanumeric"));
    }

    #[test]
    fn validate_label_key_rejects_name_too_long() {
        let long_name = "a".repeat(64);
        let err = validate_label_key(&long_name).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("exceeds 63 characters"));
    }

    #[test]
    fn validate_label_key_accepts_name_at_max_length() {
        let max_name = format!("a{}z", "b".repeat(61));
        assert!(validate_label_key(&max_name).is_ok());
    }

    #[test]
    fn validate_label_key_rejects_total_length_too_long() {
        let long_key = format!("{}/app", "a".repeat(250));
        let err = validate_label_key(&long_key).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("exceeds 253 characters"));
    }

    #[test]
    fn validate_label_key_rejects_empty_prefix() {
        let err = validate_label_key("/app").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("prefix cannot be empty"));
    }

    #[test]
    fn validate_label_key_rejects_empty_name_after_prefix() {
        let err = validate_label_key("kubernetes.io/").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("name segment cannot be empty"));
    }

    #[test]
    fn validate_label_key_rejects_prefix_with_uppercase() {
        let err = validate_label_key("Example.com/app").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("must be a DNS subdomain"));
    }

    #[test]
    fn validate_label_key_rejects_prefix_starting_with_hyphen() {
        let err = validate_label_key("-example.com/app").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            err.message()
                .contains("cannot start or end with '-' or '.'")
        );
    }

    #[test]
    fn validate_label_key_rejects_prefix_ending_with_dot() {
        let err = validate_label_key("example.com./app").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            err.message()
                .contains("cannot start or end with '-' or '.'")
        );
    }

    #[test]
    fn validate_label_key_rejects_prefix_with_consecutive_dots() {
        let err = validate_label_key("example..com/app").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("cannot contain consecutive dots"));
    }

    #[test]
    fn validate_label_key_rejects_invalid_characters() {
        let err = validate_label_key("app@name").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("invalid characters"));
    }

    // ---- Label value validation ----

    #[test]
    fn validate_label_value_accepts_empty() {
        // Kubernetes allows empty label values
        assert!(validate_label_value("").is_ok());
    }

    #[test]
    fn validate_label_value_accepts_valid_values() {
        assert!(validate_label_value("prod").is_ok());
        assert!(validate_label_value("my-value").is_ok());
        assert!(validate_label_value("my_value").is_ok());
        assert!(validate_label_value("my.value").is_ok());
        assert!(validate_label_value("value123").is_ok());
        assert!(validate_label_value("v1-2_3.4").is_ok());
    }

    #[test]
    fn validate_label_value_accepts_max_length() {
        let max_value = format!("a{}z", "b".repeat(61));
        assert!(validate_label_value(&max_value).is_ok());
    }

    #[test]
    fn validate_label_value_rejects_too_long() {
        let long_value = "a".repeat(64);
        let err = validate_label_value(&long_value).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("exceeds 63 characters"));
    }

    #[test]
    fn validate_label_value_rejects_starting_with_hyphen() {
        let err = validate_label_value("-value").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("must start with alphanumeric"));
    }

    #[test]
    fn validate_label_value_rejects_ending_with_hyphen() {
        let err = validate_label_value("value-").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("must end with alphanumeric"));
    }

    #[test]
    fn validate_label_value_rejects_starting_with_underscore() {
        let err = validate_label_value("_value").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("must start with alphanumeric"));
    }

    #[test]
    fn validate_label_value_rejects_starting_with_dot() {
        let err = validate_label_value(".value").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("must start with alphanumeric"));
    }

    #[test]
    fn validate_label_value_rejects_invalid_characters() {
        let err = validate_label_value("value@123").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("invalid characters"));
    }

    // ---- Label selector validation ----

    #[test]
    fn validate_label_selector_accepts_empty() {
        assert!(validate_label_selector("").is_ok());
        assert!(validate_label_selector("  ").is_ok());
    }

    #[test]
    fn validate_label_selector_accepts_single_pair() {
        assert!(validate_label_selector("env=prod").is_ok());
        assert!(validate_label_selector("  env=prod  ").is_ok());
    }

    #[test]
    fn validate_label_selector_accepts_multiple_pairs() {
        assert!(validate_label_selector("env=prod,team=platform").is_ok());
        assert!(validate_label_selector("env=prod, team=platform").is_ok());
    }

    #[test]
    fn validate_label_selector_rejects_missing_equals() {
        let err = validate_label_selector("env:prod").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("expected 'key=value'"));
    }

    #[test]
    fn validate_label_selector_rejects_empty_key() {
        let err = validate_label_selector("=prod").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("key cannot be empty"));
    }

    #[test]
    fn validate_label_selector_accepts_empty_value() {
        // Kubernetes allows empty label values
        assert!(validate_label_selector("env=").is_ok());
        assert!(validate_label_selector("app=,env=prod").is_ok());
    }

    #[test]
    fn validate_label_selector_allows_trailing_comma() {
        // Trailing commas are treated as empty pairs and ignored
        assert!(validate_label_selector("env=prod,").is_ok());
    }

    #[test]
    fn validate_label_selector_accepts_prefixed_keys() {
        assert!(validate_label_selector("kubernetes.io/app=web").is_ok());
        assert!(validate_label_selector("example.com/env=prod,team=platform").is_ok());
    }

    #[test]
    fn validate_label_selector_rejects_invalid_key_format() {
        // Key starting with hyphen
        let err = validate_label_selector("-app=prod").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("must start with alphanumeric"));
    }

    #[test]
    fn validate_label_selector_rejects_invalid_value_format() {
        // Value starting with hyphen
        let err = validate_label_selector("env=-prod").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("must start with alphanumeric"));
    }

    #[test]
    fn validate_label_selector_rejects_oversized_key() {
        let long_key = "a".repeat(64);
        let selector = format!("{long_key}=value");
        let err = validate_label_selector(&selector).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("exceeds 63 characters"));
    }

    #[test]
    fn validate_label_selector_rejects_oversized_value() {
        let long_value = "a".repeat(64);
        let selector = format!("key={long_value}");
        let err = validate_label_selector(&selector).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("exceeds 63 characters"));
    }

    // ---- Policy safety ----

    #[test]
    fn validate_policy_safety_rejects_root_user() {
        use openshell_core::proto::{FilesystemPolicy, ProcessPolicy};

        let policy = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/usr".into()],
                read_write: vec!["/tmp".into()],
            }),
            process: Some(ProcessPolicy {
                run_as_user: "root".into(),
                run_as_group: "sandbox".into(),
            }),
            ..Default::default()
        };
        let err = validate_policy_safety(&policy).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("root"));
    }

    #[test]
    fn validate_policy_safety_rejects_path_traversal() {
        use openshell_core::proto::FilesystemPolicy;

        let policy = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/usr/../etc/shadow".into()],
                read_write: vec!["/tmp".into()],
            }),
            ..Default::default()
        };
        let err = validate_policy_safety(&policy).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("traversal"));
    }

    #[test]
    fn validate_policy_safety_rejects_overly_broad_path() {
        use openshell_core::proto::FilesystemPolicy;

        let policy = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/usr".into()],
                read_write: vec!["/".into()],
            }),
            ..Default::default()
        };
        let err = validate_policy_safety(&policy).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("broad"));
    }

    #[test]
    fn validate_policy_safety_accepts_valid_policy() {
        let policy = openshell_policy::restrictive_default_policy();
        assert!(validate_policy_safety(&policy).is_ok());
    }

    #[test]
    fn validate_policy_safety_rejects_tld_wildcard() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let mut policy = openshell_policy::restrictive_default_policy();
        policy.network_policies.insert(
            "bad".into(),
            NetworkPolicyRule {
                name: "bad-rule".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "*.com".into(),
                    port: 443,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let err = validate_policy_safety(&policy).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("TLD wildcard"));
    }

    // ---- Static field validation ----

    #[test]
    fn validate_static_fields_allows_unchanged() {
        use openshell_core::proto::{FilesystemPolicy, LandlockPolicy, ProcessPolicy};

        let policy = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/usr".into()],
                read_write: vec!["/tmp".into()],
            }),
            landlock: Some(LandlockPolicy {
                compatibility: "best_effort".into(),
            }),
            process: Some(ProcessPolicy {
                run_as_user: "sandbox".into(),
                run_as_group: "sandbox".into(),
            }),
            ..Default::default()
        };
        assert!(validate_static_fields_unchanged(&policy, &policy).is_ok());
    }

    #[test]
    fn validate_static_fields_allows_additive_filesystem() {
        use openshell_core::proto::FilesystemPolicy;

        let baseline = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_only: vec!["/usr".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let additive = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_only: vec!["/usr".into(), "/lib".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(validate_static_fields_unchanged(&baseline, &additive).is_ok());
    }

    #[test]
    fn validate_static_fields_rejects_filesystem_removal() {
        use openshell_core::proto::FilesystemPolicy;

        let baseline = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_only: vec!["/usr".into(), "/lib".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let removed = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_only: vec!["/usr".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let result = validate_static_fields_unchanged(&baseline, &removed);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("/lib"));
    }

    #[test]
    fn validate_static_fields_rejects_filesystem_deletion() {
        use openshell_core::proto::FilesystemPolicy;

        let baseline = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_only: vec!["/usr".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let deleted = ProtoSandboxPolicy {
            filesystem: None,
            ..Default::default()
        };
        let result = validate_static_fields_unchanged(&baseline, &deleted);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("removed"));
    }

    #[test]
    fn validate_static_fields_allows_filesystem_enrichment_from_none() {
        use openshell_core::proto::FilesystemPolicy;

        let baseline = ProtoSandboxPolicy {
            filesystem: None,
            ..Default::default()
        };
        let enriched = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_only: vec!["/usr".into(), "/lib".into(), "/etc".into()],
                read_write: vec!["/sandbox".into(), "/tmp".into()],
                include_workdir: true,
            }),
            ..Default::default()
        };
        assert!(validate_static_fields_unchanged(&baseline, &enriched).is_ok());
    }

    #[test]
    fn validate_static_fields_rejects_include_workdir_change() {
        use openshell_core::proto::FilesystemPolicy;

        let baseline = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let changed = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                include_workdir: false,
                ..Default::default()
            }),
            ..Default::default()
        };
        let result = validate_static_fields_unchanged(&baseline, &changed);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("include_workdir"));
    }

    // ---- Exec validation ----

    #[test]
    fn reject_control_chars_allows_normal_values() {
        assert!(reject_control_chars("hello world", "test").is_ok());
        assert!(reject_control_chars("$(cmd)", "test").is_ok());
        assert!(reject_control_chars("", "test").is_ok());
    }

    #[test]
    fn reject_control_chars_rejects_null_bytes() {
        assert!(reject_control_chars("hello\x00world", "test").is_err());
    }

    #[test]
    fn reject_control_chars_rejects_newlines() {
        assert!(reject_control_chars("line1\nline2", "test").is_err());
        assert!(reject_control_chars("line1\rline2", "test").is_err());
    }
}
