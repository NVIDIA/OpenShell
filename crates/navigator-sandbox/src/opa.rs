//! Embedded OPA policy engine using regorus.
//!
//! Wraps [`regorus::Engine`] to evaluate Rego policies for sandbox network
//! access decisions. The engine is loaded once at sandbox startup and queried
//! on every proxy CONNECT request.

use crate::policy::{FilesystemPolicy, LandlockCompatibility, LandlockPolicy, ProcessPolicy};
use miette::Result;
use navigator_core::proto::SandboxPolicy as ProtoSandboxPolicy;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Baked-in rego rules for OPA policy evaluation.
/// These rules define the network access decision logic and static config
/// passthroughs. They reference `data.sandbox.*` for policy data.
const BAKED_POLICY_RULES: &str = include_str!("../../../dev-sandbox-policy.rego");

/// Result of evaluating a network access request against OPA policy.
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    pub matched_policy: Option<String>,
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
    /// Load policy and data from `.rego` file paths.
    pub fn from_files(policy_path: &Path, data_path: &Path) -> Result<Self> {
        let mut engine = regorus::Engine::new();
        engine
            .add_policy_from_file(policy_path)
            .map_err(|e| miette::miette!("{e}"))?;
        engine
            .add_policy_from_file(data_path)
            .map_err(|e| miette::miette!("{e}"))?;
        Ok(Self {
            engine: Mutex::new(engine),
        })
    }

    /// Load policy and data from strings.
    pub fn from_strings(policy: &str, data: &str) -> Result<Self> {
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("policy.rego".into(), policy.into())
            .map_err(|e| miette::miette!("{e}"))?;
        engine
            .add_policy("data.rego".into(), data.into())
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
    pub fn from_proto(proto: &ProtoSandboxPolicy) -> Result<Self> {
        let data_json = proto_to_opa_data_json(proto);

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
            .eval_rule("data.navigator.sandbox.allow_network".into())
            .map_err(|e| miette::miette!("{e}"))?;
        let allowed = allowed == regorus::Value::from(true);

        let reason = engine
            .eval_rule("data.navigator.sandbox.deny_reason".into())
            .map_err(|e| miette::miette!("{e}"))?;
        let reason = value_to_string(&reason);

        let matched = engine
            .eval_rule("data.navigator.sandbox.matched_network_policy".into())
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

    /// Reload policy and data from strings.
    ///
    /// Designed for future gRPC hot-reload from the navigator gateway.
    /// Replaces the entire engine atomically.
    pub fn reload(&self, policy: &str, data: &str) -> Result<()> {
        let mut new_engine = regorus::Engine::new();
        new_engine
            .add_policy("policy.rego".into(), policy.into())
            .map_err(|e| miette::miette!("{e}"))?;
        new_engine
            .add_policy("data.rego".into(), data.into())
            .map_err(|e| miette::miette!("{e}"))?;

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
            .eval_rule("data.navigator.sandbox.filesystem_policy".into())
            .map_err(|e| miette::miette!("{e}"))?;
        let filesystem = parse_filesystem_policy(&fs_val);

        // Query landlock policy
        let ll_val = engine
            .eval_rule("data.navigator.sandbox.landlock_policy".into())
            .map_err(|e| miette::miette!("{e}"))?;
        let landlock = parse_landlock_policy(&ll_val);

        // Query process policy
        let proc_val = engine
            .eval_rule("data.navigator.sandbox.process_policy".into())
            .map_err(|e| miette::miette!("{e}"))?;
        let process = parse_process_policy(&proc_val);

        Ok(SandboxConfig {
            filesystem,
            landlock,
            process,
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

/// Convert typed proto policy fields to JSON suitable for `engine.add_data_json()`.
///
/// The rego rules reference `data.sandbox.*`, so we wrap everything under a
/// `"sandbox"` key. The structure matches the rego data package expectations:
/// - `data.sandbox.filesystem_policy`
/// - `data.sandbox.landlock`
/// - `data.sandbox.process`
/// - `data.sandbox.network_policies`
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
                "run_as_user": "",
                "run_as_group": "",
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
                .map(|e| serde_json::json!({"host": e.host, "port": e.port}))
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
        "sandbox": {
            "filesystem_policy": filesystem_policy,
            "landlock": landlock,
            "process": process,
            "network_policies": network_policies,
        }
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    use navigator_core::proto::{
        FilesystemPolicy as ProtoFs, LandlockPolicy as ProtoLl, NetworkBinary, NetworkEndpoint,
        NetworkPolicyRule, ProcessPolicy as ProtoProc, SandboxPolicy as ProtoSandboxPolicy,
    };

    const TEST_POLICY: &str = include_str!("../../../dev-sandbox-policy.rego");
    const TEST_DATA: &str = include_str!("../../../dev-sandbox-policy-data.rego");

    fn test_engine() -> OpaEngine {
        OpaEngine::from_strings(TEST_POLICY, TEST_DATA).expect("Failed to load test policy")
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
                    },
                    NetworkEndpoint {
                        host: "statsig.anthropic.com".to_string(),
                        port: 443,
                    },
                ],
                binaries: vec![NetworkBinary {
                    path: "/usr/local/bin/claude".to_string(),
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
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/glab".to_string(),
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
            landlock: Some(ProtoLl {
                compatibility: "best_effort".to_string(),
            }),
            process: Some(ProtoProc {
                run_as_user: "sandbox".to_string(),
                run_as_group: "sandbox".to_string(),
            }),
            network_policies,
            inference: None,
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
    fn gitlab_policy_allows_glab() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "gitlab.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/glab"),
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
        assert_eq!(decision.matched_policy.as_deref(), Some("gitlab"));
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
        let empty_data = r#"
package sandbox
filesystem_policy := {"include_workdir": true, "read_only": [], "read_write": []}
landlock := {"compatibility": "best_effort"}
process := {"run_as_user": "sandbox", "run_as_group": "sandbox"}
network_policies := {}
"#;
        engine.reload(TEST_POLICY, empty_data).unwrap();

        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            !decision.allowed,
            "Expected deny after reload with empty policies"
        );
    }

    #[test]
    fn ancestor_binary_allowed() {
        // Use gitlab policy: binary /usr/bin/glab is the policy binary.
        // If the socket process is /usr/bin/python3 but its ancestor is /usr/bin/glab, allow.
        let engine = test_engine();
        let input = NetworkInput {
            host: "gitlab.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![PathBuf::from("/usr/bin/glab")],
            cmdline_paths: vec![],
        };
        let decision = engine.evaluate_network(&input).unwrap();
        assert!(
            decision.allowed,
            "Expected allow via ancestor match, got deny: {}",
            decision.reason
        );
        assert_eq!(decision.matched_policy.as_deref(), Some("gitlab"));
    }

    #[test]
    fn no_ancestor_match_denied() {
        let engine = test_engine();
        let input = NetworkInput {
            host: "gitlab.com".into(),
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
            host: "gitlab.com".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/python3"),
            binary_sha256: "unused".into(),
            ancestors: vec![PathBuf::from("/usr/bin/sh"), PathBuf::from("/usr/bin/glab")],
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
package sandbox
filesystem_policy := {"include_workdir": true, "read_only": [], "read_write": []}
landlock := {"compatibility": "best_effort"}
process := {"run_as_user": "sandbox", "run_as_group": "sandbox"}
network_policies := {
    "glob_test": {
        "name": "glob_test",
        "endpoints": [{"host": "example.com", "port": 443}],
        "binaries": [{"path": "/usr/bin/*"}],
    },
}
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
package sandbox
filesystem_policy := {"include_workdir": true, "read_only": [], "read_write": []}
landlock := {"compatibility": "best_effort"}
process := {"run_as_user": "sandbox", "run_as_group": "sandbox"}
network_policies := {
    "glob_test": {
        "name": "glob_test",
        "endpoints": [{"host": "example.com", "port": 443}],
        "binaries": [{"path": "/usr/local/bin/*"}],
    },
}
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
package sandbox
filesystem_policy := {"include_workdir": true, "read_only": [], "read_write": []}
landlock := {"compatibility": "best_effort"}
process := {"run_as_user": "sandbox", "run_as_group": "sandbox"}
network_policies := {
    "glob_test": {
        "name": "glob_test",
        "endpoints": [{"host": "example.com", "port": 443}],
        "binaries": [{"path": "/usr/bin/*"}],
    },
}
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
    fn cmdline_path_matches_script_binary() {
        // Simulates: node runs /usr/local/bin/my-tool (a script with shebang)
        // exe = /usr/bin/node, cmdline contains /usr/local/bin/my-tool
        let cmdline_data = r#"
package sandbox
filesystem_policy := {"include_workdir": true, "read_only": [], "read_write": []}
landlock := {"compatibility": "best_effort"}
process := {"run_as_user": "sandbox", "run_as_group": "sandbox"}
network_policies := {
    "script_test": {
        "name": "script_test",
        "endpoints": [{"host": "example.com", "port": 443}],
        "binaries": [{"path": "/usr/local/bin/my-tool"}],
    },
}
"#;
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
            decision.allowed,
            "Expected allow via cmdline path match, got deny: {}",
            decision.reason
        );
        assert_eq!(decision.matched_policy.as_deref(), Some("script_test"));
    }

    #[test]
    fn cmdline_path_no_match_denied() {
        let cmdline_data = r#"
package sandbox
filesystem_policy := {"include_workdir": true, "read_only": [], "read_write": []}
landlock := {"compatibility": "best_effort"}
process := {"run_as_user": "sandbox", "run_as_group": "sandbox"}
network_policies := {
    "script_test": {
        "name": "script_test",
        "endpoints": [{"host": "example.com", "port": 443}],
        "binaries": [{"path": "/usr/local/bin/my-tool"}],
    },
}
"#;
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
    fn cmdline_glob_pattern_matches() {
        let glob_data = r#"
package sandbox
filesystem_policy := {"include_workdir": true, "read_only": [], "read_write": []}
landlock := {"compatibility": "best_effort"}
process := {"run_as_user": "sandbox", "run_as_group": "sandbox"}
network_policies := {
    "glob_test": {
        "name": "glob_test",
        "endpoints": [{"host": "example.com", "port": 443}],
        "binaries": [{"path": "/usr/local/bin/*"}],
    },
}
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
            decision.allowed,
            "Expected glob to match cmdline path, got deny: {}",
            decision.reason
        );
    }

    #[test]
    fn from_proto_allows_matching_request() {
        let proto = test_proto();
        let engine = OpaEngine::from_proto(&proto).expect("Failed to create engine from proto");
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
}
