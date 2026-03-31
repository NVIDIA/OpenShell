// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Embedded OPA policy engine using regorus.
//!
//! Wraps [`regorus::Engine`] to evaluate Rego policies for sandbox network
//! access decisions. The engine is loaded once at sandbox startup and queried
//! on every proxy CONNECT request.

use crate::policy::{FilesystemPolicy, LandlockCompatibility, LandlockPolicy, ProcessPolicy};
use miette::Result;
use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Baked-in rego rules for OPA policy evaluation.
/// These rules define the network access decision logic and static config
/// passthroughs. They reference `data.sandbox.*` for policy data.
const BAKED_POLICY_RULES: &str = include_str!("../data/sandbox-policy.rego");

/// Result of evaluating a network access request against OPA policy.
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    pub matched_policy: Option<String>,
}

/// Network action returned by OPA `network_action` rule.
///
/// - `Allow`: endpoint + binary explicitly matched in a network policy
/// - `Deny`: no matching policy
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkAction {
    Allow { matched_policy: Option<String> },
    Deny { reason: String },
}

/// Input for a network access policy evaluation.
pub struct NetworkInput {
    pub host: String,
    pub port: u16,
    pub binary_path: PathBuf,
    pub binary_sha256: String,
    /// Ancestor binary paths from process tree walk (parent, grandparent, ...).
    pub ancestors: Vec<PathBuf>,
    /// Absolute paths extracted from `/proc/<pid>/cmdline` of the socket-owning
    /// process and its ancestors. Captures script paths (e.g. `/usr/local/bin/claude`)
    /// that don't appear in `/proc/<pid>/exe` because the interpreter (node) is the exe.
    pub cmdline_paths: Vec<PathBuf>,
}

/// Sandbox configuration extracted from OPA data at startup.
pub struct SandboxConfig {
    pub filesystem: FilesystemPolicy,
    pub landlock: LandlockPolicy,
    pub process: ProcessPolicy,
}

/// Embedded OPA policy engine.
///
/// Thread-safe: the inner `regorus::Engine` requires `&mut self` for
/// evaluation, so access is serialized via a `Mutex`. This is acceptable
/// because policy evaluation is fast (microseconds) and contention is low
/// (one eval per CONNECT request).
pub struct OpaEngine {
    engine: Mutex<regorus::Engine>,
}

impl OpaEngine {
    /// Load policy from a `.rego` rules file and data from a YAML file.
    ///
    /// Preprocesses the YAML data to expand access presets and validate L7 config.
    pub fn from_files(policy_path: &Path, data_path: &Path) -> Result<Self> {
        let yaml_str = std::fs::read_to_string(data_path).map_err(|e| {
            miette::miette!("failed to read YAML data from {}: {e}", data_path.display())
        })?;
        let mut engine = regorus::Engine::new();
        engine
            .add_policy_from_file(policy_path)
            .map_err(|e| miette::miette!("{e}"))?;
        let data_json = preprocess_yaml_data(&yaml_str)?;
        engine
            .add_data_json(&data_json)
            .map_err(|e| miette::miette!("{e}"))?;
        Ok(Self {
            engine: Mutex::new(engine),
        })
    }

    /// Load policy rules and data from strings (data is YAML).
    ///
    /// Preprocesses the YAML data to expand access presets and validate L7 config.
    pub fn from_strings(policy: &str, data_yaml: &str) -> Result<Self> {
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("policy.rego".into(), policy.into())
            .map_err(|e| miette::miette!("{e}"))?;
        let data_json = preprocess_yaml_data(data_yaml)?;
        engine
            .add_data_json(&data_json)
            .map_err(|e| miette::miette!("{e}"))?;
        Ok(Self {
            engine: Mutex::new(engine),
        })
    }

    /// Create OPA engine from a typed proto policy.
    ///
    /// Uses baked-in rego rules and converts the proto's typed fields to JSON
    /// data under the `sandbox` key (matching `data.sandbox.*` references in
    /// the rego rules).
    ///
    /// Expands access presets and validates L7 config.
    pub fn from_proto(proto: &ProtoSandboxPolicy) -> Result<Self> {
        let data_json_str = proto_to_opa_data_json(proto);

        // Parse back to Value for preprocessing, then re-serialize
        let mut data: serde_json::Value = serde_json::from_str(&data_json_str)
            .map_err(|e| miette::miette!("internal: failed to parse proto JSON: {e}"))?;

        // Validate BEFORE expanding presets
        let (errors, warnings) = crate::l7::validate_l7_policies(&data);
        for w in &warnings {
            tracing::warn!(warning = %w, "L7 policy validation warning");
        }
        if !errors.is_empty() {
            return Err(miette::miette!(
                "L7 policy validation failed:\n{}",
                errors.join("\n")
            ));
        }

        // Expand access presets to explicit rules after validation
        crate::l7::expand_access_presets(&mut data);

        let data_json = data.to_string();
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("policy.rego".into(), BAKED_POLICY_RULES.into())
            .map_err(|e| miette::miette!("{e}"))?;
        engine
            .add_data_json(&data_json)
            .map_err(|e| miette::miette!("{e}"))?;
        Ok(Self {
            engine: Mutex::new(engine),
        })
    }

    /// Evaluate a network access request against the loaded policy.
    ///
    /// Builds an OPA input document from the `NetworkInput`, evaluates the
    /// `allow_network` rule, and returns a `PolicyDecision` with the result,
    /// deny reason, and matched policy name.
    pub fn evaluate_network(&self, input: &NetworkInput) -> Result<PolicyDecision> {
        let ancestor_strs: Vec<String> = input
            .ancestors
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let cmdline_strs: Vec<String> = input
            .cmdline_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let input_json = serde_json::json!({
            "exec": {
                "path": input.binary_path.to_string_lossy(),
                "ancestors": ancestor_strs,
                "cmdline_paths": cmdline_strs,
            },
            "network": {
                "host": input.host,
                "port": input.port,
            }
        });

        let mut engine = self
            .engine
            .lock()
            .map_err(|_| miette::miette!("OPA engine lock poisoned"))?;

        engine
            .set_input_json(&input_json.to_string())
            .map_err(|e| miette::miette!("{e}"))?;

        let allowed = engine
            .eval_rule("data.openshell.sandbox.allow_network".into())
            .map_err(|e| miette::miette!("{e}"))?;
        let allowed = allowed == regorus::Value::from(true);

        let reason = engine
            .eval_rule("data.openshell.sandbox.deny_reason".into())
            .map_err(|e| miette::miette!("{e}"))?;
        let reason = value_to_string(&reason);

        let matched = engine
            .eval_rule("data.openshell.sandbox.matched_network_policy".into())
            .map_err(|e| miette::miette!("{e}"))?;
        let matched_policy = if matched == regorus::Value::Undefined {
            None
        } else {
            Some(value_to_string(&matched))
        };

        Ok(PolicyDecision {
            allowed,
            reason,
            matched_policy,
        })
    }

    /// Evaluate a network access request and return a routing action.
    ///
    /// Uses the OPA `network_action` rule which returns one of:
    /// `"allow"` or `"deny"`.
    pub fn evaluate_network_action(&self, input: &NetworkInput) -> Result<NetworkAction> {
        let ancestor_strs: Vec<String> = input
            .ancestors
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let cmdline_strs: Vec<String> = input
            .cmdline_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let input_json = serde_json::json!({
            "exec": {
                "path": input.binary_path.to_string_lossy(),
                "ancestors": ancestor_strs,
                "cmdline_paths": cmdline_strs,
            },
            "network": {
                "host": input.host,
                "port": input.port,
            }
        });

        let mut engine = self
            .engine
            .lock()
            .map_err(|_| miette::miette!("OPA engine lock poisoned"))?;

        engine
            .set_input_json(&input_json.to_string())
            .map_err(|e| miette::miette!("{e}"))?;

        let action_val = engine
            .eval_rule("data.openshell.sandbox.network_action".into())
            .map_err(|e| miette::miette!("{e}"))?;
        let action_str = value_to_string(&action_val);

        let matched = engine
            .eval_rule("data.openshell.sandbox.matched_network_policy".into())
            .map_err(|e| miette::miette!("{e}"))?;
        let matched_policy = if matched == regorus::Value::Undefined {
            None
        } else {
            Some(value_to_string(&matched))
        };

        match action_str.as_str() {
            "allow" => Ok(NetworkAction::Allow { matched_policy }),
            _ => {
                let reason_val = engine
                    .eval_rule("data.openshell.sandbox.deny_reason".into())
                    .map_err(|e| miette::miette!("{e}"))?;
                let reason = value_to_string(&reason_val);
                Ok(NetworkAction::Deny { reason })
            }
        }
    }

    /// Reload policy and data from strings (data is YAML).
    ///
    /// Designed for future gRPC hot-reload from the openshell gateway.
    /// Replaces the entire engine atomically. Routes through the full
    /// preprocessing pipeline (port normalization, L7 validation, preset
    /// expansion) to maintain consistency with `from_strings()`.
    pub fn reload(&self, policy: &str, data_yaml: &str) -> Result<()> {
        let new = Self::from_strings(policy, data_yaml)?;
        let new_engine = new
            .engine
            .into_inner()
            .map_err(|_| miette::miette!("lock poisoned on new engine"))?;
        let mut engine = self
            .engine
            .lock()
            .map_err(|_| miette::miette!("OPA engine lock poisoned"))?;
        *engine = new_engine;
        Ok(())
    }

    /// Reload policy from a proto `SandboxPolicy` message.
    ///
    /// Reuses the full `from_proto()` pipeline (proto-to-JSON conversion, L7
    /// validation, access preset expansion) so the reload has identical
    /// validation guarantees as initial load. Atomically replaces the inner
    /// engine on success; on failure the previous engine is untouched (LKG).
    pub fn reload_from_proto(&self, proto: &ProtoSandboxPolicy) -> Result<()> {
        // Build a complete new engine through the same validated pipeline.
        let new = Self::from_proto(proto)?;
        let new_engine = new
            .engine
            .into_inner()
            .map_err(|_| miette::miette!("lock poisoned on new engine"))?;
        let mut engine = self
            .engine
            .lock()
            .map_err(|_| miette::miette!("OPA engine lock poisoned"))?;
        *engine = new_engine;
        Ok(())
    }

    /// Query static sandbox configuration from the OPA data module.
    ///
    /// Extracts `filesystem_policy`, `landlock`, and `process` from the Rego
    /// data and converts them into the Rust policy structs used by the sandbox
    /// runtime for filesystem preparation, Landlock setup, and privilege dropping.
    pub fn query_sandbox_config(&self) -> Result<SandboxConfig> {
        let mut engine = self
            .engine
            .lock()
            .map_err(|_| miette::miette!("OPA engine lock poisoned"))?;

        // Query filesystem policy
        let fs_val = engine
            .eval_rule("data.openshell.sandbox.filesystem_policy".into())
            .map_err(|e| miette::miette!("{e}"))?;
        let filesystem = parse_filesystem_policy(&fs_val);

        // Query landlock policy
        let ll_val = engine
            .eval_rule("data.openshell.sandbox.landlock_policy".into())
            .map_err(|e| miette::miette!("{e}"))?;
        let landlock = parse_landlock_policy(&ll_val);

        // Query process policy
        let proc_val = engine
            .eval_rule("data.openshell.sandbox.process_policy".into())
            .map_err(|e| miette::miette!("{e}"))?;
        let process = parse_process_policy(&proc_val);

        Ok(SandboxConfig {
            filesystem,
            landlock,
            process,
        })
    }

    /// Query the L7 endpoint config for a matched policy and host:port.
    ///
    /// After L4 evaluation allows a CONNECT, this method queries the Rego data
    /// to get the full endpoint object for the matched policy. Returns the raw
    /// `regorus::Value` which can be parsed by `l7::parse_l7_config()`.
    pub fn query_endpoint_config(&self, input: &NetworkInput) -> Result<Option<regorus::Value>> {
        let ancestor_strs: Vec<String> = input
            .ancestors
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let cmdline_strs: Vec<String> = input
            .cmdline_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let input_json = serde_json::json!({
            "exec": {
                "path": input.binary_path.to_string_lossy(),
                "ancestors": ancestor_strs,
                "cmdline_paths": cmdline_strs,
            },
            "network": {
                "host": input.host,
                "port": input.port,
            }
        });

        let mut engine = self
            .engine
            .lock()
            .map_err(|_| miette::miette!("OPA engine lock poisoned"))?;

        engine
            .set_input_json(&input_json.to_string())
            .map_err(|e| miette::miette!("{e}"))?;

        let val = engine
            .eval_rule("data.openshell.sandbox.matched_endpoint_config".into())
            .map_err(|e| miette::miette!("{e}"))?;

        if val == regorus::Value::Undefined {
            Ok(None)
        } else {
            Ok(Some(val))
        }
    }

    /// Query `allowed_ips` from the matched endpoint config for a given request.
    ///
    /// Returns the list of CIDR/IP strings from the endpoint's `allowed_ips`
    /// field, or an empty vec if the field is absent or the endpoint has no
    /// match. This is used by the proxy to decide between full SSRF blocking
    /// and allowlist-based IP validation.
    pub fn query_allowed_ips(&self, input: &NetworkInput) -> Result<Vec<String>> {
        match self.query_endpoint_config(input)? {
            Some(val) => Ok(get_str_array(&val, "allowed_ips")),
            None => Ok(vec![]),
        }
    }

    /// Clone the inner regorus engine for per-tunnel L7 evaluation.
    ///
    /// With the `arc` feature enabled, this shares compiled policy via Arc
    /// and only duplicates interpreter state (~microseconds). The cloned
    /// engine can be used without Mutex contention.
    pub fn clone_engine_for_tunnel(&self) -> Result<regorus::Engine> {
        let engine = self
            .engine
            .lock()
            .map_err(|_| miette::miette!("OPA engine lock poisoned"))?;
        Ok(engine.clone())
    }
}

/// Convert a `regorus::Value` to a string, handling various types.
fn value_to_string(val: &regorus::Value) -> String {
    match val {
        regorus::Value::String(s) => s.to_string(),
        regorus::Value::Undefined => String::new(),
        other => other.to_string(),
    }
}

/// Extract a string from a `regorus::Value` object field.
fn get_str(val: &regorus::Value, key: &str) -> Option<String> {
    let key_val = regorus::Value::String(key.into());
    match val {
        regorus::Value::Object(map) => match map.get(&key_val) {
            Some(regorus::Value::String(s)) => Some(s.to_string()),
            _ => None,
        },
        _ => None,
    }
}

/// Extract a bool from a `regorus::Value` object field.
fn get_bool(val: &regorus::Value, key: &str) -> Option<bool> {
    let key_val = regorus::Value::String(key.into());
    match val {
        regorus::Value::Object(map) => match map.get(&key_val) {
            Some(regorus::Value::Bool(b)) => Some(*b),
            _ => None,
        },
        _ => None,
    }
}

/// Extract a string array from a `regorus::Value` object field.
fn get_str_array(val: &regorus::Value, key: &str) -> Vec<String> {
    let key_val = regorus::Value::String(key.into());
    match val {
        regorus::Value::Object(map) => match map.get(&key_val) {
            Some(regorus::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    if let regorus::Value::String(s) = v {
                        Some(s.to_string())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => vec![],
        },
        _ => vec![],
    }
}

fn parse_filesystem_policy(val: &regorus::Value) -> FilesystemPolicy {
    FilesystemPolicy {
        read_only: get_str_array(val, "read_only")
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        read_write: get_str_array(val, "read_write")
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        include_workdir: get_bool(val, "include_workdir").unwrap_or(true),
    }
}

fn parse_landlock_policy(val: &regorus::Value) -> LandlockPolicy {
    let compat = get_str(val, "compatibility").unwrap_or_default();
    LandlockPolicy {
        compatibility: if compat == "hard_requirement" {
            LandlockCompatibility::HardRequirement
        } else {
            LandlockCompatibility::BestEffort
        },
    }
}

fn parse_process_policy(val: &regorus::Value) -> ProcessPolicy {
    ProcessPolicy {
        run_as_user: get_str(val, "run_as_user"),
        run_as_group: get_str(val, "run_as_group"),
    }
}

/// Preprocess YAML policy data: parse, normalize, validate, expand access presets, return JSON.
fn preprocess_yaml_data(yaml_str: &str) -> Result<String> {
    let mut data: serde_json::Value = serde_yaml::from_str(yaml_str)
        .map_err(|e| miette::miette!("failed to parse YAML data: {e}"))?;

    // Normalize port → ports for all endpoints so Rego always sees "ports" array.
    normalize_endpoint_ports(&mut data);

    // Validate BEFORE expanding presets (catches user errors like rules+access)
    let (errors, warnings) = crate::l7::validate_l7_policies(&data);
    for w in &warnings {
        tracing::warn!(warning = %w, "L7 policy validation warning");
    }
    if !errors.is_empty() {
        return Err(miette::miette!(
            "L7 policy validation failed:\n{}",
            errors.join("\n")
        ));
    }

    // Expand access presets to explicit rules after validation
    crate::l7::expand_access_presets(&mut data);

    serde_json::to_string(&data).map_err(|e| miette::miette!("failed to serialize data: {e}"))
}

/// Normalize endpoint port/ports in JSON data.
///
/// YAML policies may use `port: N` (single) or `ports: [N, M]` (multi).
/// This normalizes all endpoints to have a `ports` array so Rego rules
/// only need to reference `endpoint.ports[_]`.
fn normalize_endpoint_ports(data: &mut serde_json::Value) {
    let Some(policies) = data
        .get_mut("network_policies")
        .and_then(|v| v.as_object_mut())
    else {
        return;
    };

    for (_name, policy) in policies.iter_mut() {
        let Some(endpoints) = policy.get_mut("endpoints").and_then(|v| v.as_array_mut()) else {
            continue;
        };

        for ep in endpoints.iter_mut() {
            let ep_obj = match ep.as_object_mut() {
                Some(obj) => obj,
                None => continue,
            };

            // If "ports" already exists and is non-empty, keep it.
            let has_ports = ep_obj
                .get("ports")
                .and_then(|v| v.as_array())
                .is_some_and(|a| !a.is_empty());

            if !has_ports {
                // Promote scalar "port" to "ports" array.
                let port = ep_obj
                    .get("port")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                if port > 0 {
                    ep_obj.insert(
                        "ports".to_string(),
                        serde_json::Value::Array(vec![serde_json::json!(port)]),
                    );
                }
            }

            // Remove scalar "port" — Rego only uses "ports".
            ep_obj.remove("port");
        }
    }
}

/// Convert typed proto policy fields to JSON suitable for `engine.add_data_json()`.
///
/// The rego rules reference `data.*` directly, so the JSON structure has
/// top-level keys matching the data expectations:
/// - `data.filesystem_policy`
/// - `data.landlock`
/// - `data.process`
/// - `data.network_policies`
fn proto_to_opa_data_json(proto: &ProtoSandboxPolicy) -> String {
    let filesystem_policy = proto.filesystem.as_ref().map_or_else(
        || {
            serde_json::json!({
                "include_workdir": true,
                "read_only": [],
                "read_write": [],
            })
        },
        |fs| {
            serde_json::json!({
                "include_workdir": fs.include_workdir,
                "read_only": fs.read_only,
                "read_write": fs.read_write,
            })
        },
    );

    let landlock = proto.landlock.as_ref().map_or_else(
        || serde_json::json!({"compatibility": "best_effort"}),
        |ll| serde_json::json!({"compatibility": ll.compatibility}),
    );

    let process = proto.process.as_ref().map_or_else(
        || {
            serde_json::json!({
                "run_as_user": "sandbox",
                "run_as_group": "sandbox",
            })
        },
        |p| {
            serde_json::json!({
                "run_as_user": p.run_as_user,
                "run_as_group": p.run_as_group,
            })
        },
    );

    let network_policies: serde_json::Map<String, serde_json::Value> = proto
        .network_policies
        .iter()
        .map(|(key, rule)| {
            let endpoints: Vec<serde_json::Value> = rule
                .endpoints
                .iter()
                .map(|e| {
                    // Normalize port/ports: ports takes precedence, then
                    // single port promoted to array. Rego always sees "ports".
                    let ports: Vec<u32> = if !e.ports.is_empty() {
                        e.ports.clone()
                    } else if e.port > 0 {
                        vec![e.port]
                    } else {
                        vec![]
                    };
                    let mut ep = serde_json::json!({"host": e.host, "ports": ports});
                    if !e.protocol.is_empty() {
                        ep["protocol"] = e.protocol.clone().into();
                    }
                    if !e.tls.is_empty() {
                        ep["tls"] = e.tls.clone().into();
                    }
                    if !e.enforcement.is_empty() {
                        ep["enforcement"] = e.enforcement.clone().into();
                    }
                    if !e.access.is_empty() {
                        ep["access"] = e.access.clone().into();
                    }
                    if !e.rules.is_empty() {
                        let rules: Vec<serde_json::Value> = e
                            .rules
                            .iter()
                            .map(|r| {
                                let a = r.allow.as_ref();
                                let mut allow = serde_json::json!({
                                    "method": a.map_or("", |a| &a.method),
                                    "path": a.map_or("", |a| &a.path),
                                    "command": a.map_or("", |a| &a.command),
                                });
                                let query: serde_json::Map<String, serde_json::Value> = a
                                    .map(|allow| {
                                        allow
                                            .query
                                            .iter()
                                            .map(|(key, matcher)| {
                                                let mut matcher_json = serde_json::json!({});
                                                if !matcher.glob.is_empty() {
                                                    matcher_json["glob"] =
                                                        matcher.glob.clone().into();
                                                }
                                                if !matcher.any.is_empty() {
                                                    matcher_json["any"] =
                                                        matcher.any.clone().into();
                                                }
                                                (key.clone(), matcher_json)
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                if !query.is_empty() {
                                    allow["query"] = query.into();
                                }
                                serde_json::json!({ "allow": allow })
                            })
                            .collect();
                        ep["rules"] = rules.into();
                    }
                    if !e.allowed_ips.is_empty() {
                        ep["allowed_ips"] = e.allowed_ips.clone().into();
                    }
                    ep
                })
                .collect();
            let binaries: Vec<serde_json::Value> = rule
                .binaries
                .iter()
                .map(|b| serde_json::json!({"path": b.path}))
                .collect();
            (
                key.clone(),
                serde_json::json!({
                    "name": rule.name,
                    "endpoints": endpoints,
                    "binaries": binaries,
                }),
            )
        })
        .collect();

    serde_json::json!({
        "filesystem_policy": filesystem_policy,
        "landlock": landlock,
        "process": process,
        "network_policies": network_policies,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    use openshell_core::proto::{
        FilesystemPolicy as ProtoFs, L7Allow, L7QueryMatcher, L7Rule, NetworkBinary,
        NetworkEndpoint, NetworkPolicyRule, ProcessPolicy as ProtoProc,
        SandboxPolicy as ProtoSandboxPolicy,
    };

    const TEST_POLICY: &str = include_str!("../data/sandbox-policy.rego");
    const TEST_DATA_YAML: &str = include_str!("../testdata/sandbox-policy.yaml");

    fn test_engine() -> OpaEngine {
        OpaEngine::from_strings(TEST_POLICY, TEST_DATA_YAML).expect("Failed to load test policy")
    }

    fn test_proto() -> ProtoSandboxPolicy {
        let mut network_policies = std::collections::HashMap::new();
        network_policies.insert(
            "claude_code".to_string(),
            NetworkPolicyRule {
                name: "claude_code".to_string(),
                endpoints: vec![
                    NetworkEndpoint {
                        host: "api.anthropic.com".to_string(),
                        port: 443,
                        ..Default::default()
                    },
                    NetworkEndpoint {
                        host: "statsig.anthropic.com".to_string(),
                        port: 443,
                        ..Default::default()
                    },
                ],
                binaries: vec![NetworkBinary {
                    path: "/usr/local/bin/claude".to_string(),
                    ..Default::default()
                }],
            },
        );
        network_policies.insert(
            "gitlab".to_string(),
            NetworkPolicyRule {
                name: "gitlab".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "gitlab.com".to_string(),
                    port: 443,
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/glab".to_string(),
                    ..Default::default()
                }],
            },
        );
        ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(ProtoFs {
                include_workdir: true,
                read_only: vec!["/usr".to_string(), "/lib".to_string()],
                read_write: vec!["/sandbox".to_string(), "/tmp".to_string()],
            }),
            landlock: Some(openshell_core::proto::LandlockPolicy {
                compatibility: "best_effort".to_string(),
            }),
            process: Some(ProtoProc {
                run_as_user: "sandbox".to_string(),
                run_as_group: "sandbox".to_string(),
            }),
            network_policies,
        }
    }

    #[test]
    fn allowed_binary_and_endpoint() {
        let engine = test_engine();
        // Simulates Claude Code: exe is /usr/bin/node, script is /usr/local/bin/claude
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![PathBuf::from("/usr/local/bin/claude")],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Expected allow, got deny: {}",
            decision.reason
        );
        assert_eq!(decision.matched_policy.as_deref(), Some("claude_code"));
    }

    #[test]
    fn wrong_binary_denied() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(!decision.allowed);
        assert!(
            decision.reason.contains("not allowed"),
            "Expected specific deny reason, got: {}",
            decision.reason
        );
    }

    #[test]
    fn wrong_endpoint_denied() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "evil.example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(!decision.allowed);
        assert!(
            decision.reason.contains("endpoint"),
            "Expected endpoint deny reason, got: {}",
            decision.reason
        );
    }

    #[test]
    fn unknown_binary_default_deny() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            binary_path: PathBuf::from("/tmp/malicious"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(!decision.allowed);
    }

    #[test]
    fn github_policy_allows_git() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "github.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/git"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Expected allow, got deny: {}",
            decision.reason
        );
        assert_eq!(
            decision.matched_policy.as_deref(),
            Some("github_ssh_over_https")
        );
    }

    #[test]
    fn case_insensitive_host_matching() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "API.ANTHROPIC.COM".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![PathBuf::from("/usr/local/bin/claude")],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Expected case-insensitive match, got deny: {}",
            decision.reason
        );
    }

    #[test]
    fn wrong_port_denied() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 80,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(!decision.allowed);
    }

    #[test]
    fn query_sandbox_config_extracts_filesystem() {
        let engine = test_engine();
        let config = engine.query_sandbox_config().unwrap();
        assert!(config.filesystem.include_workdir);
        assert!(config.filesystem.read_only.contains(&PathBuf::from("/usr")));
        assert!(
            config
                .filesystem
                .read_write
                .contains(&PathBuf::from("/tmp"))
        );
    }

    #[test]
    fn query_sandbox_config_extracts_process() {
        let engine = test_engine();
        let config = engine.query_sandbox_config().unwrap();
        assert_eq!(config.process.run_as_user.as_deref(), Some("sandbox"));
        assert_eq!(config.process.run_as_group.as_deref(), Some("sandbox"));
    }

    #[test]
    fn from_strings_and_from_files_produce_same_results() {
        let engine = test_engine();

        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![PathBuf::from("/usr/local/bin/claude")],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(decision.allowed);
    }

    #[test]
    fn reload_replaces_policy() {
        let engine = test_engine();

        // Verify initial policy works
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![PathBuf::from("/usr/local/bin/claude")],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(decision.allowed);

        // Reload with a policy that has no network policies (deny all)
        let empty_data = r"
filesystem_policy:
  include_workdir: true
  read_only: []
  read_write: []
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies: {}
";
        engine.reload(TEST_POLICY, empty_data).unwrap();

        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            !decision.allowed,
            "Expected deny after reload with empty policies"
        );
    }

    #[test]
    fn ancestor_binary_allowed() {
        // Use github policy: binary /usr/bin/git is the policy binary.
        // If the socket process is /usr/bin/python3 but its ancestor is /usr/bin/git, allow.
        let engine = test_engine();
        let input = NetworkInput {
            host: "github.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![PathBuf::from("/usr/bin/git")],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Expected allow via ancestor match, got deny: {}",
            decision.reason
        );
        assert_eq!(
            decision.matched_policy.as_deref(),
            Some("github_ssh_over_https")
        );
    }

    #[test]
    fn no_ancestor_match_denied() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "github.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![PathBuf::from("/usr/bin/bash")],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(!decision.allowed);
        assert!(
            decision.reason.contains("not allowed"),
            "Expected 'not allowed' in deny reason, got: {}",
            decision.reason
        );
    }

    #[test]
    fn deep_ancestor_chain_matches() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "github.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![PathBuf::from("/usr/bin/sh"), PathBuf::from("/usr/bin/git")],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Expected allow via deep ancestor match, got deny: {}",
            decision.reason
        );
    }

    #[test]
    fn empty_ancestors_falls_back_to_direct() {
        let engine = test_engine();
        // Direct binary path match still works with empty ancestors and cmdline
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/local/bin/claude"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Direct path match should still work with empty ancestors"
        );
    }

    #[test]
    fn glob_pattern_matches_binary() {
        // Test with a policy that uses glob patterns
        let glob_data = r#"
network_policies:
  glob_test:
    name: glob_test
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: "/usr/bin/*" }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, glob_data).unwrap();
        let input = NetworkInput {
            host: "example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Expected glob pattern to match binary, got deny: {}",
            decision.reason
        );
    }

    #[test]
    fn glob_pattern_matches_ancestor() {
        let glob_data = r#"
network_policies:
  glob_test:
    name: glob_test
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: "/usr/local/bin/*" }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, glob_data).unwrap();
        let input = NetworkInput {
            host: "example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![PathBuf::from("/usr/local/bin/claude")],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Expected glob pattern to match ancestor, got deny: {}",
            decision.reason
        );
    }

    #[test]
    fn glob_pattern_no_cross_segment() {
        // * should NOT match across / boundaries
        let glob_data = r#"
network_policies:
  glob_test:
    name: glob_test
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: "/usr/bin/*" }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, glob_data).unwrap();
        let input = NetworkInput {
            host: "example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/subdir/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(!decision.allowed, "Glob * should not cross / boundaries");
    }

    #[test]
    fn cmdline_path_does_not_grant_access() {
        // Simulates: node runs /usr/local/bin/my-tool (a script with shebang).
        // exe = /usr/bin/node, cmdline contains /usr/local/bin/my-tool.
        // cmdline_paths are attacker-controlled (argv[0] spoofing) and must
        // NOT be used as a grant-access signal.
        let cmdline_data = r"
network_policies:
  script_test:
    name: script_test
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: /usr/local/bin/my-tool }
";
        let engine = OpaEngine::from_strings(TEST_POLICY, cmdline_data).unwrap();
        let input = NetworkInput {
            host: "example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![PathBuf::from("/usr/bin/bash")],
            cmdline_paths: vec![PathBuf::from("/usr/local/bin/my-tool")],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            !decision.allowed,
            "cmdline_paths must not grant network access (argv[0] is spoofable)"
        );
    }

    #[test]
    fn cmdline_path_no_match_denied() {
        let cmdline_data = r"
network_policies:
  script_test:
    name: script_test
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: /usr/local/bin/my-tool }
";
        let engine = OpaEngine::from_strings(TEST_POLICY, cmdline_data).unwrap();
        let input = NetworkInput {
            host: "example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![PathBuf::from("/usr/bin/bash")],
            cmdline_paths: vec![
                PathBuf::from("/usr/bin/node"),
                PathBuf::from("/tmp/script.js"),
            ],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(!decision.allowed);
    }

    #[test]
    fn cmdline_glob_pattern_does_not_grant_access() {
        let glob_data = r#"
network_policies:
  glob_test:
    name: glob_test
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: "/usr/local/bin/*" }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, glob_data).unwrap();
        let input = NetworkInput {
            host: "example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/node"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![PathBuf::from("/usr/local/bin/claude")],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            !decision.allowed,
            "cmdline_paths must not match globs for granting access (argv[0] is spoofable)"
        );
    }

    #[test]
    fn from_proto_allows_matching_request() {
        let proto = test_proto();
        let engine = OpaEngine::from_proto(&proto).expect("Failed to create engine from proto");
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/local/bin/claude"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Expected allow from proto-based engine, got deny: {}",
            decision.reason
        );
        assert_eq!(decision.matched_policy.as_deref(), Some("claude_code"));
    }

    #[test]
    fn from_proto_denies_unmatched_request() {
        let proto = test_proto();
        let engine = OpaEngine::from_proto(&proto).expect("Failed to create engine from proto");
        let input = NetworkInput {
            host: "evil.example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(!decision.allowed);
    }

    #[test]
    fn from_proto_extracts_sandbox_config() {
        let proto = test_proto();
        let engine = OpaEngine::from_proto(&proto).expect("Failed to create engine from proto");
        let config = engine.query_sandbox_config().unwrap();
        assert!(config.filesystem.include_workdir);
        assert!(config.filesystem.read_only.contains(&PathBuf::from("/usr")));
        assert!(
            config
                .filesystem
                .read_write
                .contains(&PathBuf::from("/tmp"))
        );
        assert_eq!(config.process.run_as_user.as_deref(), Some("sandbox"));
        assert_eq!(config.process.run_as_group.as_deref(), Some("sandbox"));
    }

    // ========================================================================
    // L7 request evaluation tests
    // ========================================================================

    const L7_TEST_DATA: &str = r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.com
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/repos/**"
          - allow:
              method: POST
              path: "/repos/*/issues"
    binaries:
      - { path: /usr/bin/curl }
  readonly_api:
    name: readonly_api
    endpoints:
      - host: api.readonly.com
        port: 8080
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - { path: /usr/bin/curl }
  full_api:
    name: full_api
    endpoints:
      - host: api.full.com
        port: 8080
        protocol: rest
        enforcement: audit
        access: full
    binaries:
      - { path: /usr/bin/curl }
  query_api:
    name: query_api
    endpoints:
      - host: api.query.com
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/download"
              query:
                tag: "foo-*"
          - allow:
              method: GET
              path: "/search"
              query:
                tag:
                  any: ["foo-*", "bar-*"]
    binaries:
      - { path: /usr/bin/curl }
  l4_only:
    name: l4_only
    endpoints:
      - { host: l4only.example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
filesystem_policy:
  include_workdir: true
  read_only: []
  read_write: []
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
"#;

    fn l7_engine() -> OpaEngine {
        OpaEngine::from_strings(TEST_POLICY, L7_TEST_DATA).expect("Failed to load L7 test data")
    }

    fn l7_input(host: &str, port: u16, method: &str, path: &str) -> serde_json::Value {
        l7_input_with_query(host, port, method, path, serde_json::json!({}))
    }

    fn l7_input_with_query(
        host: &str,
        port: u16,
        method: &str,
        path: &str,
        query_params: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "network": { "host": host, "port": port },
            "exec": {
                "path": "/usr/bin/curl",
                "ancestors": [],
                "cmdline_paths": []
            },
            "request": {
                "method": method,
                "path": path,
                "query_params": query_params
            }
        })
    }

    fn eval_l7(engine: &OpaEngine, input: &serde_json::Value) -> bool {
        let mut eng = engine.engine.lock().unwrap();
        eng.set_input_json(&input.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap();
        val == regorus::Value::from(true)
    }

    #[test]
    fn l7_get_allowed_by_rules() {
        let engine = l7_engine();
        let input = l7_input("api.example.com", 8080, "GET", "/repos/myorg/foo");
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_post_allowed_by_rules() {
        let engine = l7_engine();
        let input = l7_input("api.example.com", 8080, "POST", "/repos/myorg/issues");
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_delete_denied_by_rules() {
        let engine = l7_engine();
        let input = l7_input("api.example.com", 8080, "DELETE", "/repos/myorg/foo");
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_get_wrong_path_denied() {
        let engine = l7_engine();
        let input = l7_input("api.example.com", 8080, "GET", "/admin/settings");
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_readonly_preset_allows_get() {
        let engine = l7_engine();
        let input = l7_input("api.readonly.com", 8080, "GET", "/anything");
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_readonly_preset_allows_head() {
        let engine = l7_engine();
        let input = l7_input("api.readonly.com", 8080, "HEAD", "/anything");
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_readonly_preset_allows_options() {
        let engine = l7_engine();
        let input = l7_input("api.readonly.com", 8080, "OPTIONS", "/anything");
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_readonly_preset_denies_post() {
        let engine = l7_engine();
        let input = l7_input("api.readonly.com", 8080, "POST", "/anything");
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_readonly_preset_denies_delete() {
        let engine = l7_engine();
        let input = l7_input("api.readonly.com", 8080, "DELETE", "/anything");
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_full_preset_allows_everything() {
        let engine = l7_engine();
        for method in &["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] {
            let input = l7_input("api.full.com", 8080, method, "/any/path");
            assert!(
                eval_l7(&engine, &input),
                "{method} should be allowed with full preset"
            );
        }
    }

    #[test]
    fn l7_method_matching_case_insensitive() {
        let engine = l7_engine();
        let input = l7_input("api.example.com", 8080, "get", "/repos/myorg/foo");
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_path_glob_matching() {
        let engine = l7_engine();
        // /repos/** should match /repos/org/repo
        let input = l7_input("api.example.com", 8080, "GET", "/repos/org/repo");
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_query_glob_allows_matching_duplicate_values() {
        let engine = l7_engine();
        let input = l7_input_with_query(
            "api.query.com",
            8080,
            "GET",
            "/download",
            serde_json::json!({
                "tag": ["foo-a", "foo-b"],
                "extra": ["ignored"],
            }),
        );
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_query_glob_denies_on_mismatched_duplicate_value() {
        let engine = l7_engine();
        let input = l7_input_with_query(
            "api.query.com",
            8080,
            "GET",
            "/download",
            serde_json::json!({
                "tag": ["foo-a", "evil"],
            }),
        );
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_query_any_allows_if_every_value_matches_any_pattern() {
        let engine = l7_engine();
        let input = l7_input_with_query(
            "api.query.com",
            8080,
            "GET",
            "/search",
            serde_json::json!({
                "tag": ["foo-a", "bar-b"],
            }),
        );
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_query_missing_required_key_denied() {
        let engine = l7_engine();
        let input = l7_input_with_query(
            "api.query.com",
            8080,
            "GET",
            "/download",
            serde_json::json!({}),
        );
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_query_rules_from_proto_are_enforced() {
        let mut query = std::collections::HashMap::new();
        query.insert(
            "tag".to_string(),
            L7QueryMatcher {
                glob: "foo-*".to_string(),
                any: vec![],
            },
        );

        let mut network_policies = std::collections::HashMap::new();
        network_policies.insert(
            "query_proto".to_string(),
            NetworkPolicyRule {
                name: "query_proto".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.proto.com".to_string(),
                    port: 8080,
                    protocol: "rest".to_string(),
                    enforcement: "enforce".to_string(),
                    rules: vec![L7Rule {
                        allow: Some(L7Allow {
                            method: "GET".to_string(),
                            path: "/download".to_string(),
                            command: String::new(),
                            query,
                        }),
                    }],
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/curl".to_string(),
                    ..Default::default()
                }],
            },
        );

        let proto = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(ProtoFs {
                include_workdir: true,
                read_only: vec![],
                read_write: vec![],
            }),
            landlock: Some(openshell_core::proto::LandlockPolicy {
                compatibility: "best_effort".to_string(),
            }),
            process: Some(ProtoProc {
                run_as_user: "sandbox".to_string(),
                run_as_group: "sandbox".to_string(),
            }),
            network_policies,
        };

        let engine = OpaEngine::from_proto(&proto).expect("engine from proto");
        let allow_input = l7_input_with_query(
            "api.proto.com",
            8080,
            "GET",
            "/download",
            serde_json::json!({ "tag": ["foo-a"] }),
        );
        assert!(eval_l7(&engine, &allow_input));

        let deny_input = l7_input_with_query(
            "api.proto.com",
            8080,
            "GET",
            "/download",
            serde_json::json!({ "tag": ["evil"] }),
        );
        assert!(!eval_l7(&engine, &deny_input));
    }

    #[test]
    fn l7_no_request_on_l4_only_endpoint() {
        // L4-only endpoint should not match L7 allow_request
        let engine = l7_engine();
        let input = l7_input("l4only.example.com", 443, "GET", "/anything");
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_wrong_binary_denied_even_with_matching_rules() {
        let engine = l7_engine();
        let input = serde_json::json!({
            "network": { "host": "api.example.com", "port": 8080 },
            "exec": {
                "path": "/usr/bin/python3",
                "ancestors": [],
                "cmdline_paths": []
            },
            "request": {
                "method": "GET",
                "path": "/repos/myorg/foo"
            }
        });
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_deny_reason_populated() {
        let engine = l7_engine();
        let input = l7_input("api.example.com", 8080, "DELETE", "/repos/myorg/foo");
        let mut eng = engine.engine.lock().unwrap();
        eng.set_input_json(&input.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.request_deny_reason".into())
            .unwrap();
        let reason = match val {
            regorus::Value::String(s) => s.to_string(),
            _ => String::new(),
        };
        assert!(
            reason.contains("not permitted"),
            "Expected deny reason, got: {reason}"
        );
    }

    #[test]
    fn l7_endpoint_config_returned_for_l7_endpoint() {
        let engine = l7_engine();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let config = engine.query_endpoint_config(&input).unwrap();
        assert!(config.is_some(), "Expected L7 config for rest endpoint");
        let config = config.unwrap();
        let l7 = crate::l7::parse_l7_config(&config).unwrap();
        assert_eq!(l7.protocol, crate::l7::L7Protocol::Rest);
        assert_eq!(l7.enforcement, crate::l7::EnforcementMode::Enforce);
    }

    #[test]
    fn l7_endpoint_config_none_for_l4_only() {
        let engine = l7_engine();
        let input = NetworkInput {
            host: "l4only.example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let config = engine.query_endpoint_config(&input).unwrap();
        assert!(
            config.is_none(),
            "Expected no L7 config for L4-only endpoint"
        );
    }

    #[test]
    fn l7_clone_engine_for_tunnel() {
        let engine = l7_engine();
        let cloned = engine.clone_engine_for_tunnel().unwrap();
        // Verify the cloned engine can evaluate
        let input_json = l7_input("api.example.com", 8080, "GET", "/repos/myorg/foo");
        let mut eng = cloned;
        eng.set_input_json(&input_json.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap();
        assert_eq!(val, regorus::Value::from(true));
    }

    // ========================================================================
    // Overlapping policies (duplicate host:port) — regression tests
    // ========================================================================

    /// Two network_policies entries covering the same host:port with L7 rules.
    /// Before the fix, this caused regorus to fail with
    /// "duplicated definition of local variable ep" in allow_request.
    const OVERLAPPING_L7_TEST_DATA: &str = r#"
network_policies:
  test_server:
    name: test_server
    endpoints:
      - host: 192.168.1.100
        port: 8567
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "**"
    binaries:
      - { path: /usr/bin/curl }
  allow_192_168_1_100_8567:
    name: allow_192_168_1_100_8567
    endpoints:
      - host: 192.168.1.100
        port: 8567
        protocol: rest
        enforcement: enforce
        allowed_ips:
          - 192.168.1.100
        rules:
          - allow:
              method: GET
              path: "**"
    binaries:
      - { path: /usr/bin/curl }
filesystem_policy:
  include_workdir: true
  read_only: []
  read_write: []
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
"#;

    #[test]
    fn l7_overlapping_policies_allow_request_does_not_crash() {
        let engine = OpaEngine::from_strings(TEST_POLICY, OVERLAPPING_L7_TEST_DATA)
            .expect("engine should load overlapping data");
        let input = l7_input("192.168.1.100", 8567, "GET", "/test");
        // Should not panic or error — must evaluate to true.
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_overlapping_policies_deny_request_does_not_crash() {
        let engine = OpaEngine::from_strings(TEST_POLICY, OVERLAPPING_L7_TEST_DATA)
            .expect("engine should load overlapping data");
        let input = l7_input("192.168.1.100", 8567, "DELETE", "/test");
        // DELETE is not in the rules, so should deny — but must not crash.
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn overlapping_policies_endpoint_config_returns_result() {
        let engine = OpaEngine::from_strings(TEST_POLICY, OVERLAPPING_L7_TEST_DATA)
            .expect("engine should load overlapping data");
        let input = NetworkInput {
            host: "192.168.1.100".into(),
            port: 8567,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: String::new(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        // Should return config from one of the entries without error.
        let config = engine.query_endpoint_config(&input).unwrap();
        assert!(
            config.is_some(),
            "Expected endpoint config for overlapping policies"
        );
    }

    // ========================================================================
    // network_action tests
    // ========================================================================

    const INFERENCE_TEST_DATA: &str = r#"
network_policies:
  claude_code:
    name: claude_code
    endpoints:
      - { host: api.anthropic.com, port: 443 }
    binaries:
      - { path: /usr/local/bin/claude }
  gitlab:
    name: gitlab
    endpoints:
      - { host: gitlab.com, port: 443 }
    binaries:
      - { path: /usr/bin/glab }
filesystem_policy:
  include_workdir: true
  read_only: []
  read_write: []
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
"#;

    const NO_INFERENCE_TEST_DATA: &str = r#"
network_policies:
  gitlab:
    name: gitlab
    endpoints:
      - { host: gitlab.com, port: 443 }
    binaries:
      - { path: /usr/bin/glab }
filesystem_policy:
  include_workdir: true
  read_only: []
  read_write: []
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
"#;

    fn inference_engine() -> OpaEngine {
        OpaEngine::from_strings(TEST_POLICY, INFERENCE_TEST_DATA)
            .expect("Failed to load inference test data")
    }

    fn no_inference_engine() -> OpaEngine {
        OpaEngine::from_strings(TEST_POLICY, NO_INFERENCE_TEST_DATA)
            .expect("Failed to load no-inference test data")
    }

    #[test]
    fn explicitly_allowed_endpoint_binary_returns_allow() {
        let engine = inference_engine();
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/local/bin/claude"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let action = engine.evaluate_network_action(&input).unwrap();
        assert_eq!(
            action,
            NetworkAction::Allow {
                matched_policy: Some("claude_code".to_string())
            },
        );
    }

    #[test]
    fn unknown_endpoint_returns_deny() {
        let engine = inference_engine();
        let input = NetworkInput {
            host: "api.openai.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let action = engine.evaluate_network_action(&input).unwrap();
        match &action {
            NetworkAction::Deny { .. } => {}
            other => panic!("Expected Deny, got: {other:?}"),
        }
    }

    #[test]
    fn unknown_endpoint_without_inference_returns_deny() {
        let engine = no_inference_engine();
        let input = NetworkInput {
            host: "api.openai.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let action = engine.evaluate_network_action(&input).unwrap();
        match &action {
            NetworkAction::Deny { .. } => {}
            other => panic!("Expected Deny, got: {other:?}"),
        }
    }

    #[test]
    fn endpoint_in_policy_binary_not_allowed_returns_deny() {
        // api.anthropic.com is declared but python3 is not in the binary list.
        // With binary allow/deny, this is denied.
        let engine = inference_engine();
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let action = engine.evaluate_network_action(&input).unwrap();
        match &action {
            NetworkAction::Deny { .. } => {}
            other => panic!("Expected Deny, got: {other:?}"),
        }
    }

    #[test]
    fn endpoint_in_policy_binary_not_allowed_without_inference_returns_deny() {
        let engine = no_inference_engine();
        let input = NetworkInput {
            host: "gitlab.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let action = engine.evaluate_network_action(&input).unwrap();
        match &action {
            NetworkAction::Deny { .. } => {}
            other => panic!("Expected Deny, got: {other:?}"),
        }
    }

    #[test]
    fn from_proto_explicitly_allowed_returns_allow() {
        let proto = test_proto();
        let engine = OpaEngine::from_proto(&proto).expect("engine from proto");
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/local/bin/claude"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let action = engine.evaluate_network_action(&input).unwrap();
        assert_eq!(
            action,
            NetworkAction::Allow {
                matched_policy: Some("claude_code".to_string())
            },
        );
    }

    #[test]
    fn from_proto_unknown_endpoint_returns_deny() {
        let proto = test_proto();
        let engine = OpaEngine::from_proto(&proto).expect("engine from proto");
        let input = NetworkInput {
            host: "api.openai.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let action = engine.evaluate_network_action(&input).unwrap();
        match &action {
            NetworkAction::Deny { .. } => {}
            other => panic!("Expected Deny, got: {other:?}"),
        }
    }

    #[test]
    fn network_action_with_dev_policy() {
        let engine = test_engine();
        // claude direct to api.anthropic.com → allow (explicit match)
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/local/bin/claude"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let action = engine.evaluate_network_action(&input).unwrap();
        assert_eq!(
            action,
            NetworkAction::Allow {
                matched_policy: Some("claude_code".to_string())
            },
        );

        // git to github.com → allow
        let input = NetworkInput {
            host: "github.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/git"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let action = engine.evaluate_network_action(&input).unwrap();
        assert_eq!(
            action,
            NetworkAction::Allow {
                matched_policy: Some("github_ssh_over_https".to_string())
            },
        );
    }

    // ========================================================================
    // allowed_ips tests
    // ========================================================================

    const ALLOWED_IPS_TEST_DATA: &str = r#"
network_policies:
  # Mode 2: host + allowed_ips
  internal_api:
    name: internal_api
    endpoints:
      - host: my-service.corp.net
        port: 8080
        allowed_ips: ["10.0.5.0/24"]
    binaries:
      - { path: /usr/bin/curl }
  # Mode 3: allowed_ips only (no host) — uses port 9443 to avoid overlap
  private_network:
    name: private_network
    endpoints:
      - port: 9443
        allowed_ips: ["172.16.0.0/12", "192.168.1.1"]
    binaries:
      - { path: /usr/bin/curl }
  # Mode 1: host only (no allowed_ips) — standard behavior
  public_api:
    name: public_api
    endpoints:
      - { host: api.github.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
filesystem_policy:
  include_workdir: true
  read_only: []
  read_write: []
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
"#;

    fn allowed_ips_engine() -> OpaEngine {
        OpaEngine::from_strings(TEST_POLICY, ALLOWED_IPS_TEST_DATA)
            .expect("Failed to load allowed_ips test data")
    }

    #[test]
    fn allowed_ips_mode2_host_plus_ips_allows() {
        let engine = allowed_ips_engine();
        let input = NetworkInput {
            host: "my-service.corp.net".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Mode 2 (host+IPs) should allow: {}",
            decision.reason
        );
        assert_eq!(decision.matched_policy.as_deref(), Some("internal_api"));
    }

    #[test]
    fn allowed_ips_mode2_returns_allowed_ips() {
        let engine = allowed_ips_engine();
        let input = NetworkInput {
            host: "my-service.corp.net".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let ips = engine.query_allowed_ips(&input).unwrap();
        assert_eq!(ips, vec!["10.0.5.0/24"]);
    }

    #[test]
    fn allowed_ips_mode3_hostless_allows_any_domain() {
        let engine = allowed_ips_engine();
        // Any hostname on port 9443 should match the private_network policy
        let input = NetworkInput {
            host: "anything.example.com".into(),
            port: 9443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Mode 3 (IPs only) should allow any domain on matching port: {}",
            decision.reason
        );
    }

    #[test]
    fn allowed_ips_mode3_returns_allowed_ips() {
        let engine = allowed_ips_engine();
        let input = NetworkInput {
            host: "anything.example.com".into(),
            port: 9443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let ips = engine.query_allowed_ips(&input).unwrap();
        assert_eq!(ips, vec!["172.16.0.0/12", "192.168.1.1"]);
    }

    #[test]
    fn allowed_ips_mode1_no_ips_returns_empty() {
        let engine = allowed_ips_engine();
        let input = NetworkInput {
            host: "api.github.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let ips = engine.query_allowed_ips(&input).unwrap();
        assert!(ips.is_empty(), "Mode 1 should return no allowed_ips");
    }

    #[test]
    fn allowed_ips_mode3_wrong_port_denied() {
        let engine = allowed_ips_engine();
        // Port 12345 doesn't match any policy
        let input = NetworkInput {
            host: "anything.example.com".into(),
            port: 12345,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(!decision.allowed, "Mode 3: wrong port should deny");
    }

    #[test]
    fn allowed_ips_proto_round_trip() {
        // Test that allowed_ips survives proto → OPA data → query
        let mut network_policies = std::collections::HashMap::new();
        network_policies.insert(
            "internal".to_string(),
            NetworkPolicyRule {
                name: "internal".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "internal.corp.net".to_string(),
                    port: 8080,
                    allowed_ips: vec!["10.0.5.0/24".to_string(), "10.0.6.0/24".to_string()],
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/curl".to_string(),
                    ..Default::default()
                }],
            },
        );
        let proto = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(ProtoFs {
                include_workdir: true,
                read_only: vec![],
                read_write: vec![],
            }),
            landlock: Some(openshell_core::proto::LandlockPolicy {
                compatibility: "best_effort".to_string(),
            }),
            process: Some(ProtoProc {
                run_as_user: "sandbox".to_string(),
                run_as_group: "sandbox".to_string(),
            }),
            network_policies,
        };
        let engine = OpaEngine::from_proto(&proto).expect("Failed to create engine from proto");

        let input = NetworkInput {
            host: "internal.corp.net".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let ips = engine.query_allowed_ips(&input).unwrap();
        assert_eq!(ips, vec!["10.0.5.0/24", "10.0.6.0/24"]);
    }

    // ========================================================================
    // Multi-port endpoint tests
    // ========================================================================

    #[test]
    fn multi_port_endpoint_matches_first_port() {
        let data = r#"
network_policies:
  multi:
    name: multi
    endpoints:
      - { host: api.example.com, ports: [443, 8443] }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "First port in multi-port should match: {}",
            decision.reason
        );
    }

    #[test]
    fn multi_port_endpoint_matches_second_port() {
        let data = r#"
network_policies:
  multi:
    name: multi
    endpoints:
      - { host: api.example.com, ports: [443, 8443] }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 8443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Second port in multi-port should match: {}",
            decision.reason
        );
    }

    #[test]
    fn multi_port_endpoint_rejects_unlisted_port() {
        let data = r#"
network_policies:
  multi:
    name: multi
    endpoints:
      - { host: api.example.com, ports: [443, 8443] }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 80,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(!decision.allowed, "Unlisted port should be denied");
    }

    #[test]
    fn single_port_backwards_compat() {
        // Old-style YAML with just `port: 443` should still work
        let data = r#"
network_policies:
  compat:
    name: compat
    endpoints:
      - { host: api.example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Single port backwards compat: {}",
            decision.reason
        );

        // Wrong port should still deny
        let input_bad = NetworkInput {
            host: "api.example.com".into(),
            port: 80,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input_bad).unwrap();
        assert!(!decision.allowed);
    }

    #[test]
    fn hostless_endpoint_multi_port() {
        let data = r#"
network_policies:
  private:
    name: private
    endpoints:
      - ports: [80, 443]
        allowed_ips: ["10.0.0.0/8"]
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        // Port 80
        let input80 = NetworkInput {
            host: "anything.internal".into(),
            port: 80,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input80).unwrap();
        assert!(
            decision.allowed,
            "Hostless multi-port should match port 80: {}",
            decision.reason
        );
        // Port 443
        let input443 = NetworkInput {
            host: "anything.internal".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input443).unwrap();
        assert!(
            decision.allowed,
            "Hostless multi-port should match port 443: {}",
            decision.reason
        );
        // Port 8080 should deny
        let input_bad = NetworkInput {
            host: "anything.internal".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input_bad).unwrap();
        assert!(!decision.allowed);
    }

    #[test]
    fn from_proto_multi_port_allows_matching() {
        let mut network_policies = std::collections::HashMap::new();
        network_policies.insert(
            "multi".to_string(),
            NetworkPolicyRule {
                name: "multi".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.example.com".to_string(),
                    port: 443,
                    ports: vec![443, 8443],
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/curl".to_string(),
                    ..Default::default()
                }],
            },
        );
        let proto = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(ProtoFs {
                include_workdir: true,
                read_only: vec![],
                read_write: vec![],
            }),
            landlock: Some(openshell_core::proto::LandlockPolicy {
                compatibility: "best_effort".to_string(),
            }),
            process: Some(ProtoProc {
                run_as_user: "sandbox".to_string(),
                run_as_group: "sandbox".to_string(),
            }),
            network_policies,
        };
        let engine = OpaEngine::from_proto(&proto).unwrap();
        // Port 443
        let input443 = NetworkInput {
            host: "api.example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        assert!(engine.evaluate_network(&input443).unwrap().allowed);
        // Port 8443
        let input8443 = NetworkInput {
            host: "api.example.com".into(),
            port: 8443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        assert!(engine.evaluate_network(&input8443).unwrap().allowed);
        // Port 80 denied
        let input80 = NetworkInput {
            host: "api.example.com".into(),
            port: 80,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        assert!(!engine.evaluate_network(&input80).unwrap().allowed);
    }

    // ========================================================================
    // Host wildcard tests
    // ========================================================================

    #[test]
    fn wildcard_host_matches_subdomain() {
        let data = r#"
network_policies:
  wildcard:
    name: wildcard
    endpoints:
      - { host: "*.example.com", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "*.example.com should match api.example.com: {}",
            decision.reason
        );
    }

    #[test]
    fn wildcard_host_rejects_deep_subdomain() {
        // * should match single DNS label only (does not cross .)
        let data = r#"
network_policies:
  wildcard:
    name: wildcard
    endpoints:
      - { host: "*.example.com", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "deep.sub.example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            !decision.allowed,
            "*.example.com should NOT match deep.sub.example.com"
        );
    }

    #[test]
    fn wildcard_host_rejects_exact_domain() {
        let data = r#"
network_policies:
  wildcard:
    name: wildcard
    endpoints:
      - { host: "*.example.com", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            !decision.allowed,
            "*.example.com should NOT match example.com (requires at least one label)"
        );
    }

    #[test]
    fn wildcard_host_case_insensitive() {
        let data = r#"
network_policies:
  wildcard:
    name: wildcard
    endpoints:
      - { host: "*.EXAMPLE.COM", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Host wildcards should be case-insensitive: {}",
            decision.reason
        );
    }

    #[test]
    fn wildcard_host_plus_port() {
        let data = r#"
network_policies:
  wildcard:
    name: wildcard
    endpoints:
      - { host: "*.example.com", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        // Right host, wrong port
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 80,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(!decision.allowed, "Wildcard host on wrong port should deny");
    }

    #[test]
    fn wildcard_host_multi_port() {
        let data = r#"
network_policies:
  wildcard:
    name: wildcard
    endpoints:
      - { host: "*.example.com", ports: [443, 8443] }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 8443,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Wildcard host + multi-port should match: {}",
            decision.reason
        );
    }

    #[test]
    fn wildcard_host_l7_rules_apply() {
        let data = r#"
network_policies:
  wildcard_l7:
    name: wildcard_l7
    endpoints:
      - host: "*.example.com"
        port: 8080
        protocol: rest
        enforcement: enforce
        tls: terminate
        rules:
          - allow:
              method: GET
              path: "/api/**"
    binaries:
      - { path: /usr/bin/curl }
filesystem_policy:
  include_workdir: true
  read_only: []
  read_write: []
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        // L7 GET to /api/foo — should be allowed
        let input = l7_input("api.example.com", 8080, "GET", "/api/foo");
        assert!(
            eval_l7(&engine, &input),
            "L7 rule should apply to wildcard-matched host"
        );
        // L7 DELETE to /api/foo — should be denied by L7 rule
        let input_bad = l7_input("api.example.com", 8080, "DELETE", "/api/foo");
        assert!(
            !eval_l7(&engine, &input_bad),
            "L7 DELETE should be denied even on wildcard host"
        );
    }

    #[test]
    fn wildcard_host_l7_endpoint_config_returned() {
        let data = r#"
network_policies:
  wildcard_l7:
    name: wildcard_l7
    endpoints:
      - host: "*.example.com"
        port: 8080
        protocol: rest
        enforcement: enforce
        tls: terminate
        rules:
          - allow:
              method: GET
              path: "**"
    binaries:
      - { path: /usr/bin/curl }
filesystem_policy:
  include_workdir: true
  read_only: []
  read_write: []
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 8080,
            binary_path: PathBuf::from("/usr/bin/curl"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let config = engine.query_endpoint_config(&input).unwrap();
        assert!(
            config.is_some(),
            "Should return endpoint config for wildcard-matched host"
        );
        let config = config.unwrap();
        let l7 = crate::l7::parse_l7_config(&config).unwrap();
        assert_eq!(l7.protocol, crate::l7::L7Protocol::Rest);
        assert_eq!(l7.enforcement, crate::l7::EnforcementMode::Enforce);
    }

    #[test]
    fn l7_multi_port_request_evaluation() {
        let data = r#"
network_policies:
  multi_l7:
    name: multi_l7
    endpoints:
      - host: api.example.com
        ports: [8080, 9090]
        protocol: rest
        enforcement: enforce
        tls: terminate
        rules:
          - allow:
              method: GET
              path: "**"
    binaries:
      - { path: /usr/bin/curl }
filesystem_policy:
  include_workdir: true
  read_only: []
  read_write: []
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        // GET on port 8080 — allowed
        let input1 = l7_input("api.example.com", 8080, "GET", "/anything");
        assert!(
            eval_l7(&engine, &input1),
            "L7 on first port of multi-port should work"
        );
        // GET on port 9090 — allowed
        let input2 = l7_input("api.example.com", 9090, "GET", "/anything");
        assert!(
            eval_l7(&engine, &input2),
            "L7 on second port of multi-port should work"
        );
    }
}
