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
    if provider.name.len() > MAX_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "provider.name exceeds maximum length ({} > {MAX_NAME_LEN})",
            provider.name.len()
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
        "INFO" => 2,
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

    #[test]
    fn validate_provider_fields_accepts_valid() {
        let provider = Provider {
            id: String::new(),
            name: "my-provider".to_string(),
            r#type: "claude".to_string(),
            credentials: one_credential(),
            config: std::iter::once(("endpoint".to_string(), "https://example.com".to_string()))
                .collect(),
        };
        assert!(validate_provider_fields(&provider).is_ok());
    }

    #[test]
    fn validate_provider_fields_rejects_over_limit_name() {
        let provider = Provider {
            id: String::new(),
            name: "a".repeat(MAX_NAME_LEN + 1),
            r#type: "claude".to_string(),
            credentials: one_credential(),
            config: HashMap::new(),
        };
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("provider.name"));
    }

    #[test]
    fn validate_provider_fields_rejects_over_limit_type() {
        let provider = Provider {
            id: String::new(),
            name: "ok".to_string(),
            r#type: "x".repeat(MAX_PROVIDER_TYPE_LEN + 1),
            credentials: one_credential(),
            config: HashMap::new(),
        };
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("provider.type"));
    }

    #[test]
    fn validate_provider_fields_rejects_too_many_credentials() {
        let creds: HashMap<String, String> = (0..=MAX_PROVIDER_CREDENTIALS_ENTRIES)
            .map(|i| (format!("K{i}"), "v".to_string()))
            .collect();
        let provider = Provider {
            id: String::new(),
            name: "ok".to_string(),
            r#type: "claude".to_string(),
            credentials: creds,
            config: HashMap::new(),
        };
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("provider.credentials"));
    }

    #[test]
    fn validate_provider_fields_rejects_too_many_config() {
        let config: HashMap<String, String> = (0..=MAX_PROVIDER_CONFIG_ENTRIES)
            .map(|i| (format!("K{i}"), "v".to_string()))
            .collect();
        let provider = Provider {
            id: String::new(),
            name: "ok".to_string(),
            r#type: "claude".to_string(),
            credentials: one_credential(),
            config,
        };
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("provider.config"));
    }

    #[test]
    fn validate_provider_fields_at_limit_name_accepted() {
        let provider = Provider {
            id: String::new(),
            name: "a".repeat(MAX_NAME_LEN),
            r#type: "claude".to_string(),
            credentials: one_credential(),
            config: HashMap::new(),
        };
        assert!(validate_provider_fields(&provider).is_ok());
    }

    #[test]
    fn validate_provider_fields_rejects_oversized_credential_key() {
        let mut creds = HashMap::new();
        creds.insert("k".repeat(MAX_MAP_KEY_LEN + 1), "v".to_string());
        let provider = Provider {
            id: String::new(),
            name: "ok".to_string(),
            r#type: "claude".to_string(),
            credentials: creds,
            config: HashMap::new(),
        };
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("key"));
    }

    #[test]
    fn validate_provider_fields_rejects_oversized_config_value() {
        let mut config = HashMap::new();
        config.insert("k".to_string(), "v".repeat(MAX_MAP_VALUE_LEN + 1));
        let provider = Provider {
            id: String::new(),
            name: "ok".to_string(),
            r#type: "claude".to_string(),
            credentials: one_credential(),
            config,
        };
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("value"));
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
