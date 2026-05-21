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
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

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
/// - `Allow`: endpoint matched in a network policy
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
    generation: Arc<AtomicU64>,
}

/// Generation guard captured when an HTTP tunnel or request path starts.
#[derive(Clone)]
pub struct PolicyGenerationGuard {
    captured_generation: u64,
    current_generation: Arc<AtomicU64>,
}

impl PolicyGenerationGuard {
    pub fn captured_generation(&self) -> u64 {
        self.captured_generation
    }

    pub fn current_generation(&self) -> u64 {
        self.current_generation.load(Ordering::Acquire)
    }

    pub fn is_stale(&self) -> bool {
        self.current_generation() != self.captured_generation
    }

    pub fn ensure_current(&self) -> Result<()> {
        if self.is_stale() {
            return Err(miette::miette!(
                "policy generation is stale [captured_generation:{} current_generation:{}]",
                self.captured_generation(),
                self.current_generation(),
            ));
        }
        Ok(())
    }
}

/// Per-tunnel L7 policy evaluator bound to the engine generation captured when
/// the tunnel was established.
pub struct TunnelPolicyEngine {
    engine: Mutex<regorus::Engine>,
    generation_guard: PolicyGenerationGuard,
}

impl TunnelPolicyEngine {
    pub fn captured_generation(&self) -> u64 {
        self.generation_guard.captured_generation()
    }

    pub fn current_generation(&self) -> u64 {
        self.generation_guard.current_generation()
    }

    pub fn is_stale(&self) -> bool {
        self.generation_guard.is_stale()
    }

    pub fn generation_guard(&self) -> &PolicyGenerationGuard {
        &self.generation_guard
    }

    pub(crate) fn engine(&self) -> &Mutex<regorus::Engine> {
        &self.engine
    }
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
            generation: Arc::new(AtomicU64::new(0)),
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
            generation: Arc::new(AtomicU64::new(0)),
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
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                    .severity(openshell_ocsf::SeverityId::Medium)
                    .status(openshell_ocsf::StatusId::Success)
                    .state(openshell_ocsf::StateId::Enabled, "validated")
                    .unmapped("warning", serde_json::json!(w.clone()))
                    .message(format!("L7 policy validation warning: {w}"))
                    .build()
            );
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
            generation: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Evaluate a network access request against the loaded policy.
    ///
    /// Builds an OPA input document from the `NetworkInput`, evaluates the
    /// `allow_network` rule, and returns a `PolicyDecision` with the result,
    /// deny reason, and matched policy name.
    pub fn evaluate_network(&self, input: &NetworkInput) -> Result<PolicyDecision> {
        let input_json = serde_json::json!({
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
        Ok(self.evaluate_network_action_with_generation(input)?.0)
    }

    /// Evaluate network action and return the policy generation used for the evaluation.
    pub fn evaluate_network_action_with_generation(
        &self,
        input: &NetworkInput,
    ) -> Result<(NetworkAction, u64)> {
        let input_json = serde_json::json!({
            "network": {
                "host": input.host,
                "port": input.port,
            }
        });

        let mut engine = self
            .engine
            .lock()
            .map_err(|_| miette::miette!("OPA engine lock poisoned"))?;
        let generation = self.current_generation();

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

        if action_str == "allow" {
            Ok((NetworkAction::Allow { matched_policy }, generation))
        } else {
            let reason_val = engine
                .eval_rule("data.openshell.sandbox.deny_reason".into())
                .map_err(|e| miette::miette!("{e}"))?;
            let reason = value_to_string(&reason_val);
            Ok((NetworkAction::Deny { reason }, generation))
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
        self.generation.fetch_add(1, Ordering::AcqRel);
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
        self.generation.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    /// Current policy generation. Successful reloads increment this value.
    pub fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Return a guard for a previously captured policy generation.
    pub fn generation_guard(&self, expected_generation: u64) -> Result<PolicyGenerationGuard> {
        let generation = self.current_generation();
        if generation != expected_generation {
            return Err(miette::miette!(
                "policy changed before HTTP relay started [expected_generation:{expected_generation} current_generation:{generation}]"
            ));
        }
        Ok(PolicyGenerationGuard {
            captured_generation: generation,
            current_generation: Arc::clone(&self.generation),
        })
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
        Ok(self.query_endpoint_config_with_generation(input)?.0)
    }

    /// Query L7 endpoint config and return the policy generation used for the query.
    pub fn query_endpoint_config_with_generation(
        &self,
        input: &NetworkInput,
    ) -> Result<(Option<regorus::Value>, u64)> {
        let (configs, generation) = self.query_endpoint_configs_with_generation(input)?;
        Ok((configs.into_iter().next(), generation))
    }

    /// Query all matching endpoint configs and return the policy generation used for the query.
    pub fn query_endpoint_configs_with_generation(
        &self,
        input: &NetworkInput,
    ) -> Result<(Vec<regorus::Value>, u64)> {
        let input_json = serde_json::json!({
            "network": {
                "host": input.host,
                "port": input.port,
            }
        });

        let mut engine = self
            .engine
            .lock()
            .map_err(|_| miette::miette!("OPA engine lock poisoned"))?;
        let generation = self.current_generation();

        engine
            .set_input_json(&input_json.to_string())
            .map_err(|e| miette::miette!("{e}"))?;

        let val = engine
            .eval_rule("data.openshell.sandbox._matching_endpoint_configs".into())
            .map_err(|e| miette::miette!("{e}"))?;

        match val {
            regorus::Value::Undefined => Ok((Vec::new(), generation)),
            regorus::Value::Array(values) => Ok((values.to_vec(), generation)),
            other => Ok((vec![other], generation)),
        }
    }

    /// Query `allowed_ips` from the matched endpoint config for a given request.
    ///
    /// Returns the list of CIDR/IP strings from the endpoint's `allowed_ips`
    /// field, or an empty vec if the field is absent or the endpoint has no
    /// match. This is used by the proxy to decide between full SSRF blocking
    /// and allowlist-based IP validation.
    pub fn query_allowed_ips(&self, input: &NetworkInput) -> Result<Vec<String>> {
        Ok(self
            .query_endpoint_config(input)?
            .map(|val| get_str_array(&val, "allowed_ips"))
            .unwrap_or_default())
    }

    /// Clone the inner regorus engine for per-tunnel L7 evaluation.
    ///
    /// With the `arc` feature enabled, this shares compiled policy via Arc
    /// and only duplicates interpreter state (~microseconds). The cloned
    /// engine can be used without Mutex contention.
    pub fn clone_engine_for_tunnel(&self, expected_generation: u64) -> Result<TunnelPolicyEngine> {
        let engine = self
            .engine
            .lock()
            .map_err(|_| miette::miette!("OPA engine lock poisoned"))?;
        let generation = self.current_generation();
        if generation != expected_generation {
            return Err(miette::miette!(
                "policy changed before L7 tunnel started [expected_generation:{expected_generation} current_generation:{generation}]"
            ));
        }
        Ok(TunnelPolicyEngine {
            engine: Mutex::new(engine.clone()),
            generation_guard: PolicyGenerationGuard {
                captured_generation: generation,
                current_generation: Arc::clone(&self.generation),
            },
        })
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
    let mut data: serde_json::Value = serde_yml::from_str(yaml_str)
        .map_err(|e| miette::miette!("failed to parse YAML data: {e}"))?;

    // Normalize port → ports for all endpoints so Rego always sees "ports" array.
    normalize_endpoint_ports(&mut data);

    // Validate BEFORE expanding presets (catches user errors like rules+access)
    let (errors, warnings) = crate::l7::validate_l7_policies(&data);
    for w in &warnings {
        openshell_ocsf::ocsf_emit!(
            openshell_ocsf::ConfigStateChangeBuilder::new(crate::ocsf_ctx())
                .severity(openshell_ocsf::SeverityId::Medium)
                .status(openshell_ocsf::StatusId::Success)
                .state(openshell_ocsf::StateId::Enabled, "validated")
                .unmapped("warning", serde_json::json!(w.clone()))
                .message(format!("L7 policy validation warning: {w}"))
                .build()
        );
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
            let Some(ep_obj) = ep.as_object_mut() else {
                continue;
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

/// Serialize a typed proto `SandboxPolicy` to OPA data JSON.
///
/// The rego rules reference `data.*` directly, so the JSON structure has
/// top-level keys matching the data expectations:
/// - `data.filesystem_policy`
/// - `data.landlock`
/// - `data.process`
/// - `data.network_policies`
///
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
                    if !e.path.is_empty() {
                        ep["path"] = e.path.clone().into();
                    }
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
                                    "operation_type": a.map_or("", |a| &a.operation_type),
                                    "operation_name": a.map_or("", |a| &a.operation_name),
                                });
                                if let Some(a) = a
                                    && !a.fields.is_empty()
                                {
                                    allow["fields"] = a.fields.clone().into();
                                }
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
                    if !e.deny_rules.is_empty() {
                        let deny_rules: Vec<serde_json::Value> = e
                            .deny_rules
                            .iter()
                            .map(|d| {
                                let mut deny = serde_json::json!({});
                                if !d.method.is_empty() {
                                    deny["method"] = d.method.clone().into();
                                }
                                if !d.path.is_empty() {
                                    deny["path"] = d.path.clone().into();
                                }
                                if !d.command.is_empty() {
                                    deny["command"] = d.command.clone().into();
                                }
                                if !d.operation_type.is_empty() {
                                    deny["operation_type"] = d.operation_type.clone().into();
                                }
                                if !d.operation_name.is_empty() {
                                    deny["operation_name"] = d.operation_name.clone().into();
                                }
                                if !d.fields.is_empty() {
                                    deny["fields"] = d.fields.clone().into();
                                }
                                let query: serde_json::Map<String, serde_json::Value> = d
                                    .query
                                    .iter()
                                    .map(|(key, matcher)| {
                                        let mut matcher_json = serde_json::json!({});
                                        if !matcher.glob.is_empty() {
                                            matcher_json["glob"] = matcher.glob.clone().into();
                                        }
                                        if !matcher.any.is_empty() {
                                            matcher_json["any"] = matcher.any.clone().into();
                                        }
                                        (key.clone(), matcher_json)
                                    })
                                    .collect();
                                if !query.is_empty() {
                                    deny["query"] = query.into();
                                }
                                deny
                            })
                            .collect();
                        ep["deny_rules"] = deny_rules.into();
                    }
                    if e.allow_encoded_slash {
                        ep["allow_encoded_slash"] = true.into();
                    }
                    if e.websocket_credential_rewrite {
                        ep["websocket_credential_rewrite"] = true.into();
                    }
                    if e.request_body_credential_rewrite {
                        ep["request_body_credential_rewrite"] = true.into();
                    }
                    if !e.persisted_queries.is_empty() {
                        ep["persisted_queries"] = e.persisted_queries.clone().into();
                    }
                    if !e.graphql_persisted_queries.is_empty() {
                        let persisted: serde_json::Map<String, serde_json::Value> = e
                            .graphql_persisted_queries
                            .iter()
                            .map(|(key, op)| {
                                (
                                    key.clone(),
                                    serde_json::json!({
                                        "operation_type": op.operation_type,
                                        "operation_name": op.operation_name,
                                        "fields": op.fields,
                                    }),
                                )
                            })
                            .collect();
                        ep["graphql_persisted_queries"] = persisted.into();
                    }
                    if e.graphql_max_body_bytes > 0 {
                        ep["graphql_max_body_bytes"] = e.graphql_max_body_bytes.into();
                    }
                    ep
                })
                .collect();
            (
                key.clone(),
                serde_json::json!({
                    "name": rule.name,
                    "endpoints": endpoints,
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
#[allow(
    clippy::needless_raw_string_hashes,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::match_wildcard_for_single_variants,
    reason = "Test code: test fixtures and panic-on-unexpected matches are idiomatic in tests."
)]
mod tests {
    use super::*;

    use openshell_core::proto::{
        FilesystemPolicy as ProtoFs, L7Allow, L7QueryMatcher, L7Rule, NetworkEndpoint,
        NetworkPolicyRule, ProcessPolicy as ProtoProc, SandboxPolicy as ProtoSandboxPolicy,
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
    fn allowed_endpoint() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            cmdline_paths: vec![],
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
    fn wrong_endpoint_denied() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "evil.example.com".into(),
            port: 443,
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
    fn github_policy_allows_git() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "github.com".into(),
            port: 443,
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Expected allow, got deny: {}",
            decision.reason
        );
        // Multiple policies (github_ssh_over_https, copilot) cover github.com:443;
        // rego picks the lexicographically smallest name.
        assert!(
            decision.matched_policy.is_some(),
            "Expected a matched policy name"
        );
    }

    #[test]
    fn case_insensitive_host_matching() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "API.ANTHROPIC.COM".into(),
            port: 443,
            cmdline_paths: vec![],
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
            cmdline_paths: vec![],
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
            cmdline_paths: vec![],
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
    fn from_proto_allows_matching_request() {
        let proto = test_proto();
        let engine = OpaEngine::from_proto(&proto).expect("Failed to create engine from proto");
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
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
  readonly_api:
    name: readonly_api
    endpoints:
      - host: api.readonly.com
        port: 8080
        protocol: rest
        enforcement: enforce
        access: read-only
  full_api:
    name: full_api
    endpoints:
      - host: api.full.com
        port: 8080
        protocol: rest
        enforcement: audit
        access: full
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
  graphql_api:
    name: graphql_api
    endpoints:
      - host: api.graphql.com
        port: 443
        protocol: graphql
        enforcement: enforce
        persisted_queries: allow_registered
        graphql_persisted_queries:
          abc123:
            operation_type: query
            operation_name: Viewer
            fields: [viewer]
        rules:
          - allow:
              operation_type: query
              fields: [viewer, repository]
          - allow:
              operation_type: mutation
              operation_name: Issue*
              fields: [createIssue, deleteRepository]
        deny_rules:
          - operation_type: mutation
            fields: [deleteRepository]
  graphql_readonly:
    name: graphql_readonly
    endpoints:
      - host: gql.readonly.com
        port: 443
        protocol: graphql
        enforcement: enforce
        access: read-only
  graphql_ws:
    name: graphql_ws
    endpoints:
      - host: realtime.graphql.com
        ports: [443]
        path: "/graphql"
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/graphql"
          - allow:
              operation_type: query
              fields: [viewer]
          - allow:
              operation_type: subscription
              fields: [messageAdded]
        deny_rules:
          - operation_type: mutation
  l4_only:
    name: l4_only
    endpoints:
      - { host: l4only.example.com, port: 443 }
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
            "request": {
                "method": method,
                "path": path,
                "query_params": query_params
            }
        })
    }

    fn l7_graphql_input(host: &str, operations: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "network": { "host": host, "port": 443 },
            "request": {
                "method": "POST",
                "path": "/graphql",
                "query_params": {},
                "graphql": {
                    "operations": operations
                }
            }
        })
    }

    fn l7_graphql_error_input(host: &str, error: &str) -> serde_json::Value {
        serde_json::json!({
            "network": { "host": host, "port": 443 },
            "request": {
                "method": "POST",
                "path": "/graphql",
                "query_params": {},
                "graphql": {
                    "operations": [],
                    "error": error
                }
            }
        })
    }

    fn l7_websocket_graphql_input(host: &str, operations: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "network": { "host": host, "port": 443 },
            "request": {
                "method": "WEBSOCKET_TEXT",
                "path": "/graphql",
                "query_params": {},
                "graphql": {
                    "operations": operations
                }
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
    fn l7_graphql_query_allowed_by_field_rule() {
        let engine = l7_engine();
        let input = l7_graphql_input(
            "api.graphql.com",
            serde_json::json!([{
                "operation_type": "query",
                "operation_name": "RepoLookup",
                "fields": ["repository"],
                "persisted_query": false
            }]),
        );
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_graphql_unlisted_field_denied() {
        let engine = l7_engine();
        let input = l7_graphql_input(
            "api.graphql.com",
            serde_json::json!([{
                "operation_type": "query",
                "fields": ["viewer", "adminAuditLog"],
                "persisted_query": false
            }]),
        );
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_graphql_batch_denied_if_any_operation_unallowed() {
        let engine = l7_engine();
        let input = l7_graphql_input(
            "api.graphql.com",
            serde_json::json!([
                {
                    "operation_type": "query",
                    "fields": ["viewer"],
                    "persisted_query": false
                },
                {
                    "operation_type": "mutation",
                    "operation_name": "DeleteRepo",
                    "fields": ["deleteRepository"],
                    "persisted_query": false
                }
            ]),
        );
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_graphql_deny_rule_takes_precedence() {
        let engine = l7_engine();
        let input = l7_graphql_input(
            "api.graphql.com",
            serde_json::json!([{
                "operation_type": "mutation",
                "operation_name": "IssueDelete",
                "fields": ["deleteRepository"],
                "persisted_query": false
            }]),
        );
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_graphql_registered_hash_only_query_allowed() {
        let engine = l7_engine();
        let input = l7_graphql_input(
            "api.graphql.com",
            serde_json::json!([{
                "operation_type": "",
                "operation_name": "Viewer",
                "fields": [],
                "persisted_query": true,
                "persisted_query_hash": "abc123"
            }]),
        );
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_graphql_unregistered_hash_only_query_denied() {
        let engine = l7_engine();
        let input = l7_graphql_input(
            "api.graphql.com",
            serde_json::json!([{
                "operation_type": "",
                "operation_name": "Viewer",
                "fields": [],
                "persisted_query": true,
                "persisted_query_hash": "missing"
            }]),
        );
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_graphql_unregistered_hash_only_query_has_deny_reason() {
        let engine = l7_engine();
        let input = l7_graphql_input(
            "api.graphql.com",
            serde_json::json!([{
                "operation_type": "",
                "operation_name": "Viewer",
                "fields": [],
                "persisted_query": true,
                "persisted_query_hash": "missing"
            }]),
        );
        let mut eng = engine.engine.lock().unwrap();
        eng.set_input_json(&input.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.request_deny_reason".into())
            .unwrap();
        assert_eq!(
            val,
            regorus::Value::String("GraphQL persisted query is not registered".into())
        );
    }

    #[test]
    fn l7_graphql_parse_error_denied() {
        let engine = l7_engine();
        let input = l7_graphql_error_input("api.graphql.com", "GraphQL document parse error");
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_graphql_readonly_access_allows_query_and_denies_mutation() {
        let engine = l7_engine();
        let query = l7_graphql_input(
            "gql.readonly.com",
            serde_json::json!([{
                "operation_type": "query",
                "fields": ["viewer"],
                "persisted_query": false
            }]),
        );
        assert!(eval_l7(&engine, &query));

        let mutation = l7_graphql_input(
            "gql.readonly.com",
            serde_json::json!([{
                "operation_type": "mutation",
                "fields": ["createIssue"],
                "persisted_query": false
            }]),
        );
        assert!(!eval_l7(&engine, &mutation));
    }

    #[test]
    fn l7_websocket_graphql_subscription_allowed_by_field_rule() {
        let engine = l7_engine();
        let input = l7_websocket_graphql_input(
            "realtime.graphql.com",
            serde_json::json!([{
                "operation_type": "subscription",
                "operation_name": "NewMessages",
                "fields": ["messageAdded"],
                "persisted_query": false
            }]),
        );
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_websocket_graphql_unlisted_field_denied() {
        let engine = l7_engine();
        let input = l7_websocket_graphql_input(
            "realtime.graphql.com",
            serde_json::json!([{
                "operation_type": "query",
                "fields": ["adminAuditLog"],
                "persisted_query": false
            }]),
        );
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_websocket_graphql_deny_rule_takes_precedence() {
        let engine = l7_engine();
        let input = l7_websocket_graphql_input(
            "realtime.graphql.com",
            serde_json::json!([{
                "operation_type": "mutation",
                "operation_name": "DeleteRepo",
                "fields": ["deleteRepository"],
                "persisted_query": false
            }]),
        );
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_websocket_graphql_not_bypassed_by_generic_text_rule() {
        let data = r#"
network_policies:
  graphql_ws:
    name: graphql_ws
    endpoints:
      - host: realtime.graphql.com
        ports: [443]
        path: "/graphql"
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/graphql"
          - allow:
              method: WEBSOCKET_TEXT
              path: "/graphql"
          - allow:
              operation_type: query
              fields: [viewer]
"#;
        let data_json: serde_json::Value =
            serde_yml::from_str(data).expect("fixture should parse as YAML");
        let mut rego = regorus::Engine::new();
        rego.add_policy("policy.rego".into(), TEST_POLICY.into())
            .expect("policy should load");
        rego.add_data_json(&data_json.to_string())
            .expect("data should load");
        let engine = OpaEngine {
            engine: Mutex::new(rego),
            generation: Arc::new(AtomicU64::new(0)),
        };
        let input = l7_websocket_graphql_input(
            "realtime.graphql.com",
            serde_json::json!([{
                "operation_type": "query",
                "fields": ["adminAuditLog"],
                "persisted_query": false
            }]),
        );
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_endpoint_path_scopes_rest_and_graphql_on_same_host() {
        let data = r#"
network_policies:
  mixed_api:
    name: mixed_api
    endpoints:
      - host: api.github.test
        port: 443
        path: "/repos/**"
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: "*"
              path: "/**"
      - host: api.github.test
        port: 443
        path: "/graphql"
        protocol: graphql
        enforcement: enforce
        rules:
          - allow:
              operation_type: query
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();

        let rest_write = l7_input("api.github.test", 443, "POST", "/repos/org/repo/issues");
        assert!(eval_l7(&engine, &rest_write));

        let graphql_query = l7_graphql_input(
            "api.github.test",
            serde_json::json!([{
                "operation_type": "query",
                "fields": ["viewer"],
                "persisted_query": false
            }]),
        );
        assert!(eval_l7(&engine, &graphql_query));

        let graphql_mutation = l7_graphql_input(
            "api.github.test",
            serde_json::json!([{
                "operation_type": "mutation",
                "fields": ["deleteRepository"],
                "persisted_query": false
            }]),
        );
        assert!(
            !eval_l7(&engine, &graphql_mutation),
            "REST rules on the same host must not allow a GraphQL mutation"
        );
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
                            operation_type: String::new(),
                            operation_name: String::new(),
                            fields: Vec::new(),
                        }),
                    }],
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
    fn l7_endpoint_config_preserves_proto_allow_encoded_slash() {
        let mut network_policies = std::collections::HashMap::new();
        network_policies.insert(
            "npm".to_string(),
            NetworkPolicyRule {
                name: "npm".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "registry.npmjs.org".to_string(),
                    port: 443,
                    protocol: "rest".to_string(),
                    enforcement: "enforce".to_string(),
                    access: "read-only".to_string(),
                    allow_encoded_slash: true,
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
        let input = NetworkInput {
            host: "registry.npmjs.org".into(),
            port: 443,
            cmdline_paths: vec![],
        };

        let config = engine
            .query_endpoint_config(&input)
            .unwrap()
            .expect("endpoint config");
        let l7 = crate::l7::parse_l7_config(&config).unwrap();
        assert!(l7.allow_encoded_slash);
    }

    #[test]
    fn l7_endpoint_config_preserves_proto_websocket_credential_rewrite() {
        let mut network_policies = std::collections::HashMap::new();
        network_policies.insert(
            "gateway".to_string(),
            NetworkPolicyRule {
                name: "gateway".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "gateway.example.com".to_string(),
                    port: 443,
                    protocol: "rest".to_string(),
                    enforcement: "enforce".to_string(),
                    access: "full".to_string(),
                    websocket_credential_rewrite: true,
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
        let input = NetworkInput {
            host: "gateway.example.com".into(),
            port: 443,
            cmdline_paths: vec![],
        };

        let config = engine
            .query_endpoint_config(&input)
            .unwrap()
            .expect("endpoint config");
        let l7 = crate::l7::parse_l7_config(&config).unwrap();
        assert!(l7.websocket_credential_rewrite);
    }

    #[test]
    fn l7_endpoint_config_preserves_proto_request_body_credential_rewrite() {
        let mut network_policies = std::collections::HashMap::new();
        network_policies.insert(
            "slack".to_string(),
            NetworkPolicyRule {
                name: "slack".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "slack.com".to_string(),
                    port: 443,
                    protocol: "rest".to_string(),
                    enforcement: "enforce".to_string(),
                    access: "read-write".to_string(),
                    request_body_credential_rewrite: true,
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
        let input = NetworkInput {
            host: "slack.com".into(),
            port: 443,
            cmdline_paths: vec![],
        };

        let config = engine
            .query_endpoint_config(&input)
            .unwrap()
            .expect("endpoint config");
        let l7 = crate::l7::parse_l7_config(&config).unwrap();
        assert!(l7.request_body_credential_rewrite);
    }

    #[test]
    fn l7_endpoint_config_none_for_l4_only() {
        let engine = l7_engine();
        let input = NetworkInput {
            host: "l4only.example.com".into(),
            port: 443,
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
        let cloned = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        // Verify the cloned engine can evaluate
        let input_json = l7_input("api.example.com", 8080, "GET", "/repos/myorg/foo");
        let mut eng = cloned.engine().lock().unwrap();
        eng.set_input_json(&input_json.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap();
        assert_eq!(val, regorus::Value::from(true));
    }

    #[test]
    fn policy_generation_starts_at_zero_and_increments_on_successful_reload() {
        let engine = l7_engine();
        assert_eq!(engine.current_generation(), 0);

        engine.reload(TEST_POLICY, L7_TEST_DATA).unwrap();

        assert_eq!(engine.current_generation(), 1);
    }

    #[test]
    fn policy_generation_does_not_increment_on_failed_reload() {
        let engine = l7_engine();
        engine.reload(TEST_POLICY, L7_TEST_DATA).unwrap();
        assert_eq!(engine.current_generation(), 1);

        let invalid_l7_data = r#"
network_policies:
  bad_api:
    name: bad_api
    endpoints:
      - host: api.example.com
        port: 8080
        protocol: invalid-protocol
"#;
        assert!(engine.reload(TEST_POLICY, invalid_l7_data).is_err());
        assert_eq!(engine.current_generation(), 1);

        let input_json = l7_input("api.example.com", 8080, "GET", "/repos/myorg/foo");
        let cloned = engine
            .clone_engine_for_tunnel(engine.current_generation())
            .unwrap();
        let mut eng = cloned.engine().lock().unwrap();
        eng.set_input_json(&input_json.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap();
        assert_eq!(val, regorus::Value::from(true));
    }

    #[test]
    fn endpoint_config_generation_matches_query_generation() {
        let engine = l7_engine();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 8080,
            cmdline_paths: vec![],
        };

        let (config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        assert!(config.is_some());
        assert_eq!(generation, engine.current_generation());

        engine.reload(TEST_POLICY, L7_TEST_DATA).unwrap();

        let (config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        assert!(config.is_some());
        assert_eq!(generation, engine.current_generation());
        assert_eq!(generation, 1);
    }

    #[test]
    fn tunnel_clone_rejects_stale_generation() {
        let engine = l7_engine();
        let captured_generation = engine.current_generation();
        engine.reload(TEST_POLICY, L7_TEST_DATA).unwrap();

        assert!(engine.clone_engine_for_tunnel(captured_generation).is_err());
    }

    // ========================================================================
    // Deny rules tests
    // ========================================================================

    const L7_DENY_TEST_DATA: &str = r#"
network_policies:
  github_api:
    name: github_api
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-write
        deny_rules:
          - method: POST
            path: "/repos/*/pulls/*/reviews"
          - method: PUT
            path: "/repos/*/branches/*/protection"
          - method: "*"
            path: "/repos/*/rulesets"
  deny_with_query:
    name: deny_with_query
    endpoints:
      - host: api.restricted.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        deny_rules:
          - method: POST
            path: "/admin/**"
            query:
              force: "true"
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

    fn l7_deny_engine() -> OpaEngine {
        OpaEngine::from_strings(TEST_POLICY, L7_DENY_TEST_DATA)
            .expect("Failed to load deny test data")
    }

    #[test]
    fn l7_deny_rule_blocks_allowed_method_path() {
        let engine = l7_deny_engine();
        // POST to reviews is allowed by read-write preset but denied by deny rule
        let input = l7_input(
            "api.github.com",
            443,
            "POST",
            "/repos/myorg/pulls/123/reviews",
        );
        let mut eng = engine.engine.lock().unwrap();
        eng.set_input_json(&input.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap();
        assert_eq!(
            val,
            regorus::Value::from(false),
            "deny rule should block POST to reviews"
        );
    }

    #[test]
    fn l7_deny_rule_allows_non_matching_requests() {
        let engine = l7_deny_engine();
        // GET repos/issues is allowed and not denied
        let input = l7_input("api.github.com", 443, "GET", "/repos/myorg/issues");
        let mut eng = engine.engine.lock().unwrap();
        eng.set_input_json(&input.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap();
        assert_eq!(
            val,
            regorus::Value::from(true),
            "non-denied GET should be allowed"
        );
    }

    #[test]
    fn l7_deny_rule_allows_same_method_different_path() {
        let engine = l7_deny_engine();
        // POST to issues is allowed (deny only targets reviews)
        let input = l7_input("api.github.com", 443, "POST", "/repos/myorg/issues");
        let mut eng = engine.engine.lock().unwrap();
        eng.set_input_json(&input.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap();
        assert_eq!(
            val,
            regorus::Value::from(true),
            "POST to issues should be allowed"
        );
    }

    #[test]
    fn l7_deny_rule_blocks_wildcard_method() {
        let engine = l7_deny_engine();
        // GET /repos/myorg/rulesets should be denied (method: "*")
        let input = l7_input("api.github.com", 443, "GET", "/repos/myorg/rulesets");
        let mut eng = engine.engine.lock().unwrap();
        eng.set_input_json(&input.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap();
        assert_eq!(
            val,
            regorus::Value::from(false),
            "wildcard method deny should block GET"
        );
    }

    #[test]
    fn l7_deny_rule_blocks_put_protection() {
        let engine = l7_deny_engine();
        let input = l7_input(
            "api.github.com",
            443,
            "PUT",
            "/repos/myorg/branches/main/protection",
        );
        let mut eng = engine.engine.lock().unwrap();
        eng.set_input_json(&input.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap();
        assert_eq!(
            val,
            regorus::Value::from(false),
            "PUT to branch protection should be denied"
        );
    }

    #[test]
    fn l7_deny_reason_populated_when_deny_rule_matches() {
        let engine = l7_deny_engine();
        let input = l7_input(
            "api.github.com",
            443,
            "POST",
            "/repos/myorg/pulls/123/reviews",
        );
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
            reason.contains("deny rule"),
            "Expected deny rule reason, got: {reason}"
        );
    }

    #[test]
    fn l7_deny_rule_with_query_blocks_matching_params() {
        let engine = l7_deny_engine();
        // POST /admin/settings with force=true should be denied
        let input = l7_input_with_query(
            "api.restricted.com",
            443,
            "POST",
            "/admin/settings",
            serde_json::json!({"force": ["true"]}),
        );
        let mut eng = engine.engine.lock().unwrap();
        eng.set_input_json(&input.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap();
        assert_eq!(
            val,
            regorus::Value::from(false),
            "deny with matching query should block"
        );
    }

    #[test]
    fn l7_deny_rule_with_query_allows_non_matching_params() {
        let engine = l7_deny_engine();
        // POST /admin/settings with force=false should be allowed (query doesn't match deny)
        let input = l7_input_with_query(
            "api.restricted.com",
            443,
            "POST",
            "/admin/settings",
            serde_json::json!({"force": ["false"]}),
        );
        let mut eng = engine.engine.lock().unwrap();
        eng.set_input_json(&input.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap();
        assert_eq!(
            val,
            regorus::Value::from(true),
            "deny with non-matching query should allow"
        );
    }

    #[test]
    fn l7_deny_rule_with_query_blocks_when_any_value_matches() {
        let engine = l7_deny_engine();
        // POST /admin/settings with force=true&force=false should STILL be denied
        // because at least one value ("true") matches the deny rule.
        // This is fail-closed: any matching value triggers the deny.
        let input = l7_input_with_query(
            "api.restricted.com",
            443,
            "POST",
            "/admin/settings",
            serde_json::json!({"force": ["true", "false"]}),
        );
        let mut eng = engine.engine.lock().unwrap();
        eng.set_input_json(&input.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap();
        assert_eq!(
            val,
            regorus::Value::from(false),
            "deny should fire when ANY value matches, even with mixed values"
        );
    }

    #[test]
    fn l7_deny_rule_without_matching_query_key_allows() {
        let engine = l7_deny_engine();
        // POST /admin/settings with no query params -- deny rule has query.force=true,
        // so no match (key not present) and request should be allowed
        let input = l7_input("api.restricted.com", 443, "POST", "/admin/settings");
        let mut eng = engine.engine.lock().unwrap();
        eng.set_input_json(&input.to_string()).unwrap();
        let val = eng
            .eval_rule("data.openshell.sandbox.allow_request".into())
            .unwrap();
        assert_eq!(
            val,
            regorus::Value::from(true),
            "deny without matching query key should allow"
        );
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
  gitlab:
    name: gitlab
    endpoints:
      - { host: gitlab.com, port: 443 }
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
            cmdline_paths: vec![],
        };
        let action = engine.evaluate_network_action(&input).unwrap();
        assert_eq!(
            action,
            NetworkAction::Allow {
                matched_policy: Some("claude_code".to_string())
            },
        );

        // git to github.com → allow (multiple policies cover github.com:443)
        let input = NetworkInput {
            host: "github.com".into(),
            port: 443,
            cmdline_paths: vec![],
        };
        let action = engine.evaluate_network_action(&input).unwrap();
        match &action {
            NetworkAction::Allow { matched_policy } => {
                assert!(matched_policy.is_some(), "Expected a matched policy");
            }
            other => panic!("Expected Allow for github.com:443, got: {other:?}"),
        }
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
  # Mode 3: allowed_ips only (no host) — uses port 9443 to avoid overlap
  private_network:
    name: private_network
    endpoints:
      - port: 9443
        allowed_ips: ["172.16.0.0/12", "192.168.1.1"]
  # Mode 1: host only (no allowed_ips) — standard behavior
  public_api:
    name: public_api
    endpoints:
      - { host: api.github.com, port: 443 }
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
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 443,
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
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 8443,
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
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 80,
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
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 443,
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
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        // Port 80
        let input80 = NetworkInput {
            host: "anything.internal".into(),
            port: 80,
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
            cmdline_paths: vec![],
        };
        assert!(engine.evaluate_network(&input443).unwrap().allowed);
        // Port 8443
        let input8443 = NetworkInput {
            host: "api.example.com".into(),
            port: 8443,
            cmdline_paths: vec![],
        };
        assert!(engine.evaluate_network(&input8443).unwrap().allowed);
        // Port 80 denied
        let input80 = NetworkInput {
            host: "api.example.com".into(),
            port: 80,
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
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 443,
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
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "deep.sub.example.com".into(),
            port: 443,
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
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "example.com".into(),
            port: 443,
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
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 443,
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
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        // Right host, wrong port
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 80,
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
"#;
        let engine = OpaEngine::from_strings(TEST_POLICY, data).unwrap();
        let input = NetworkInput {
            host: "api.example.com".into(),
            port: 8443,
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

    #[test]
    fn reload_from_proto_works() {
        let proto = test_proto();
        let engine = OpaEngine::from_proto(&proto).expect("from_proto should succeed");

        // Verify initial policy works
        let input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(decision.allowed);

        // Reload with same proto
        engine
            .reload_from_proto(&proto)
            .expect("reload_from_proto should succeed");

        // Should still work
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "reload_from_proto should preserve behavior"
        );
    }

    #[test]
    fn hot_reload_picks_up_new_policies() {
        let proto = test_proto();
        let engine = OpaEngine::from_proto(&proto).expect("initial load should succeed");

        // Verify initial policy allows claude
        let claude_input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            cmdline_paths: vec![],
        };
        assert!(engine.evaluate_network(&claude_input).unwrap().allowed);

        // Create a new proto with an additional policy
        let mut new_proto = test_proto();
        new_proto.network_policies.insert(
            "python_api".to_string(),
            NetworkPolicyRule {
                name: "python_api".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "pypi.org".to_string(),
                    port: 443,
                    ..Default::default()
                }],
            },
        );

        // Hot-reload
        engine
            .reload_from_proto(&new_proto)
            .expect("hot-reload should succeed");

        // Old policy should still work
        assert!(
            engine.evaluate_network(&claude_input).unwrap().allowed,
            "Old policies should survive hot-reload"
        );

        // New policy should also work
        let python_input = NetworkInput {
            host: "pypi.org".into(),
            port: 443,
            cmdline_paths: vec![],
        };
        assert!(
            engine.evaluate_network(&python_input).unwrap().allowed,
            "New policy should be active after hot-reload"
        );
    }

    #[test]
    fn hot_reload_replaces_engine_atomically() {
        // Test that a successful reload preserves the engine behavior
        let proto = test_proto();
        let engine = OpaEngine::from_proto(&proto).expect("initial load should succeed");

        let claude_input = NetworkInput {
            host: "api.anthropic.com".into(),
            port: 443,
            cmdline_paths: vec![],
        };
        assert!(engine.evaluate_network(&claude_input).unwrap().allowed);

        // Reload with same proto — should succeed and preserve behavior
        engine
            .reload_from_proto(&proto)
            .expect("reload should succeed");

        assert!(
            engine.evaluate_network(&claude_input).unwrap().allowed,
            "Engine should work after successful reload"
        );
    }

    #[test]
    fn l7_head_allowed_where_get_is_allowed() {
        let engine = l7_engine();
        let input = l7_input("api.example.com", 8080, "HEAD", "/repos/myorg/foo");
        assert!(eval_l7(&engine, &input));
    }

    #[test]
    fn l7_head_denied_when_only_post_allowed() {
        let engine = OpaEngine::from_strings(
            TEST_POLICY,
            "network_policies:\n  p:\n    name: p\n    endpoints:\n      - host: h.test\n        port: 80\n        protocol: rest\n        enforcement: enforce\n        rules:\n          - allow: {method: POST, path: \"/\"}\n",
        )
        .unwrap();
        let input = l7_input("h.test", 80, "HEAD", "/");
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_options_not_implicitly_allowed_by_get() {
        let engine = l7_engine();
        let input = l7_input("api.example.com", 8080, "OPTIONS", "/repos/myorg/foo");
        assert!(!eval_l7(&engine, &input));
    }

    #[test]
    fn l7_head_blocked_by_deny_rule_targeting_get() {
        // deny_rules use method_matches() too; a deny on GET must also block HEAD.
        let engine = OpaEngine::from_strings(
            TEST_POLICY,
            "network_policies:\n  p:\n    name: p\n    endpoints:\n      - host: h.test\n        port: 80\n        protocol: rest\n        enforcement: enforce\n        access: full\n        deny_rules:\n          - method: GET\n            path: \"/protected\"\n",
        )
        .unwrap();
        let input = l7_input("h.test", 80, "HEAD", "/protected");
        assert!(!eval_l7(&engine, &input));
    }
}
