//! Shared sandbox policy parsing and defaults for Navigator.
//!
//! Provides YAML→proto conversion for sandbox policies, with a built-in
//! default policy embedded from `dev-sandbox-policy.yaml`.

use std::collections::HashMap;

use miette::{IntoDiagnostic, Result, WrapErr};
use navigator_core::proto::{
    FilesystemPolicy, L7Allow, L7Rule, LandlockPolicy, NetworkBinary, NetworkEndpoint,
    NetworkPolicyRule, ProcessPolicy, SandboxPolicy,
};
use serde::Deserialize;

/// Built-in default sandbox policy YAML (embedded at compile time).
const DEFAULT_SANDBOX_POLICY_YAML: &str = include_str!("../../../dev-sandbox-policy.yaml");

// ---------------------------------------------------------------------------
// YAML serde types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    #[serde(default)]
    inference: Option<InferenceDef>,
    #[serde(default)]
    filesystem_policy: Option<FilesystemDef>,
    #[serde(default)]
    landlock: Option<LandlockDef>,
    #[serde(default)]
    process: Option<ProcessDef>,
    #[serde(default)]
    network_policies: HashMap<String, NetworkPolicyRuleDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemDef {
    #[serde(default)]
    include_workdir: bool,
    #[serde(default)]
    read_only: Vec<String>,
    #[serde(default)]
    read_write: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LandlockDef {
    #[serde(default)]
    compatibility: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessDef {
    #[serde(default)]
    run_as_user: String,
    #[serde(default)]
    run_as_group: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InferenceDef {
    #[serde(default)]
    allowed_routes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkPolicyRuleDef {
    #[serde(default)]
    name: String,
    #[serde(default)]
    endpoints: Vec<NetworkEndpointDef>,
    #[serde(default)]
    binaries: Vec<NetworkBinaryDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkEndpointDef {
    host: String,
    port: u32,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    enforcement: String,
    #[serde(default)]
    access: String,
    #[serde(default)]
    rules: Vec<L7RuleDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct L7RuleDef {
    allow: L7AllowDef,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct L7AllowDef {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    command: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkBinaryDef {
    path: String,
    /// Deprecated: ignored. Kept for backward compat with existing YAML files.
    #[serde(default)]
    #[allow(dead_code)]
    harness: bool,
}

// ---------------------------------------------------------------------------
// YAML → proto conversion
// ---------------------------------------------------------------------------

fn convert_policy(raw: PolicyFile) -> SandboxPolicy {
    let network_policies = raw
        .network_policies
        .into_iter()
        .map(|(key, rule)| {
            let proto_rule = NetworkPolicyRule {
                name: if rule.name.is_empty() {
                    key.clone()
                } else {
                    rule.name
                },
                endpoints: rule
                    .endpoints
                    .into_iter()
                    .map(|e| NetworkEndpoint {
                        host: e.host,
                        port: e.port,
                        protocol: e.protocol,
                        tls: e.tls,
                        enforcement: e.enforcement,
                        access: e.access,
                        rules: e
                            .rules
                            .into_iter()
                            .map(|r| L7Rule {
                                allow: Some(L7Allow {
                                    method: r.allow.method,
                                    path: r.allow.path,
                                    command: r.allow.command,
                                }),
                            })
                            .collect(),
                    })
                    .collect(),
                binaries: rule
                    .binaries
                    .into_iter()
                    .map(|b| NetworkBinary {
                        path: b.path,
                        ..Default::default()
                    })
                    .collect(),
            };
            (key, proto_rule)
        })
        .collect();

    SandboxPolicy {
        version: raw.version,
        filesystem: raw.filesystem_policy.map(|fs| FilesystemPolicy {
            include_workdir: fs.include_workdir,
            read_only: fs.read_only,
            read_write: fs.read_write,
        }),
        landlock: raw.landlock.map(|ll| LandlockPolicy {
            compatibility: ll.compatibility,
        }),
        process: raw.process.map(|p| ProcessPolicy {
            run_as_user: p.run_as_user,
            run_as_group: p.run_as_group,
        }),
        network_policies,
        inference: raw
            .inference
            .map(|inf| navigator_core::proto::InferencePolicy {
                allowed_routes: inf.allowed_routes,
                ..Default::default()
            }),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a sandbox policy from a YAML string.
pub fn parse_sandbox_policy(yaml: &str) -> Result<SandboxPolicy> {
    let raw: PolicyFile = serde_yaml::from_str(yaml)
        .into_diagnostic()
        .wrap_err("failed to parse sandbox policy YAML")?;
    Ok(convert_policy(raw))
}

/// Load a sandbox policy with the standard resolution order:
///
/// 1. `cli_path` argument (e.g. from a `--policy` flag)
/// 2. `NAVIGATOR_SANDBOX_POLICY` environment variable
/// 3. Built-in default (`dev-sandbox-policy.yaml`)
pub fn load_sandbox_policy(cli_path: Option<&str>) -> Result<SandboxPolicy> {
    let contents = if let Some(p) = cli_path {
        let path = std::path::Path::new(p);
        std::fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read sandbox policy from {}", path.display()))?
    } else if let Ok(policy_path) = std::env::var("NAVIGATOR_SANDBOX_POLICY") {
        let path = std::path::Path::new(&policy_path);
        std::fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read sandbox policy from {}", path.display()))?
    } else {
        DEFAULT_SANDBOX_POLICY_YAML.to_string()
    };
    parse_sandbox_policy(&contents)
}

/// Return the built-in default sandbox policy.
pub fn default_sandbox_policy() -> SandboxPolicy {
    // The embedded YAML is known-good; unwrap is safe.
    parse_sandbox_policy(DEFAULT_SANDBOX_POLICY_YAML)
        .expect("built-in dev-sandbox-policy.yaml must be valid")
}

/// Clear `run_as_user` / `run_as_group` from the policy's process section.
///
/// Call this when a custom image is specified, since the image may lack the
/// default "sandbox" user/group.
pub fn clear_process_identity(policy: &mut SandboxPolicy) {
    if let Some(ref mut process) = policy.process {
        process.run_as_user = String::new();
        process.run_as_group = String::new();
    }
}
