// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sound, deliberately narrow policy-containment checks.
//!
//! This module is independent of the legacy proposal-risk model. It parses the
//! authority-bearing fields it understands and fails closed when another field
//! could affect the result.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_yml::Value;
use z3::ast::{Ast, Bool, Int, Regexp, String as Z3String};
use z3::{Context, Params, SatResult, Solver};

const READ_ONLY_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];
const READ_WRITE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"];
const LAYER_L4: &str = "l4";
const LAYER_REST: &str = "rest";
const WORKDIR_SYMBOL: &str = "<OCI_WORKDIR>";
const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;
const MAX_YAML_DEPTH: usize = 64;
const MAX_YAML_NODES: usize = 100_000;

/// Parser error for a containment input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePolicyError(String);

impl fmt::Display for ParsePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ParsePolicyError {}

/// Policy representation used only by maximum-boundary checking.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ContainmentPolicy {
    version: u32,
    #[serde(default)]
    filesystem_policy: FilesystemPolicy,
    #[serde(default)]
    network_policies: BTreeMap<String, NetworkRule>,
    #[serde(default)]
    landlock: Option<Value>,
    #[serde(default)]
    process: Option<Value>,
    #[serde(default)]
    network_middlewares: BTreeMap<String, Value>,
    // Managed-maximum metadata changes workflow, not authority. Retain it in
    // the parsed representation without letting it alter containment.
    #[serde(default)]
    metadata: Option<ManagedPolicyMetadata>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

impl ContainmentPolicy {
    /// Managed-maximum metadata retained from the input, when present.
    #[must_use]
    pub const fn metadata(&self) -> Option<&ManagedPolicyMetadata> {
        self.metadata.as_ref()
    }
}

/// Workflow metadata carried by a managed-maximum document.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct ManagedPolicyMetadata {
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub allowed_modes: Vec<String>,
    #[serde(default)]
    pub default_mode: String,
    #[serde(default)]
    pub audit_label: String,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct FilesystemPolicy {
    #[serde(default)]
    include_workdir: bool,
    #[serde(default)]
    read_only: Vec<String>,
    #[serde(default)]
    read_write: Vec<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            // Match the runtime default when `filesystem_policy` is absent.
            // Serde still uses `false` for an omitted `include_workdir` field
            // inside an explicitly present filesystem policy.
            include_workdir: true,
            read_only: Vec::new(),
            read_write: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct NetworkRule {
    #[serde(default, rename = "name")]
    _name: String,
    #[serde(default)]
    endpoints: Vec<Endpoint>,
    #[serde(default)]
    binaries: Vec<Binary>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct Binary {
    path: String,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "The endpoint parser accounts for independent policy-schema toggles."
)]
struct Endpoint {
    #[serde(default)]
    host: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    enforcement: String,
    #[serde(default)]
    access: String,
    #[serde(default)]
    rules: Vec<AllowRule>,
    #[serde(default)]
    deny_rules: Vec<DenyRule>,
    #[serde(default)]
    allowed_ips: Vec<String>,
    #[serde(default)]
    review: Review,
    #[serde(default)]
    allow_encoded_slash: bool,
    #[serde(default)]
    websocket_credential_rewrite: bool,
    #[serde(default)]
    request_body_credential_rewrite: bool,
    #[serde(default)]
    allow_uninspected_credentials: bool,
    #[serde(default)]
    persisted_queries: String,
    #[serde(default)]
    graphql_persisted_queries: BTreeMap<String, Value>,
    #[serde(default)]
    graphql_max_body_bytes: u32,
    #[serde(default)]
    credential_signing: String,
    #[serde(default)]
    signing_service: String,
    #[serde(default)]
    signing_region: String,
    #[serde(default)]
    credential_binding: Option<Value>,
    #[serde(default)]
    json_rpc: Option<Value>,
    #[serde(default)]
    mcp: Option<Value>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

impl Endpoint {
    fn effective_ports(&self) -> Vec<u16> {
        if self.ports.is_empty() {
            (self.port != 0).then_some(self.port).into_iter().collect()
        } else {
            self.ports.clone()
        }
    }

    fn protocol_kind(&self) -> Protocol {
        if self.protocol.is_empty() || self.protocol.eq_ignore_ascii_case("tcp") {
            Protocol::L4
        } else {
            Protocol::Rest
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct AllowRule {
    allow: Allow,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct Allow {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    review: Review,
    #[serde(default)]
    query: BTreeMap<String, Value>,
    #[serde(default)]
    operation_type: String,
    #[serde(default)]
    operation_name: String,
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    tool: Option<Value>,
    #[serde(default)]
    params: BTreeMap<String, Value>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct DenyRule {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    query: BTreeMap<String, Value>,
    #[serde(default)]
    operation_type: String,
    #[serde(default)]
    operation_name: String,
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    tool: Option<Value>,
    #[serde(default)]
    params: BTreeMap<String, Value>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
struct Review {
    #[serde(default, rename = "required")]
    _required: bool,
    #[serde(default, rename = "reason")]
    _reason: String,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

/// Parse one captured YAML input for containment checking.
pub fn parse_policy_str(source: &str) -> Result<ContainmentPolicy, ParsePolicyError> {
    if source.len() > MAX_POLICY_BYTES {
        return Err(ParsePolicyError(format!(
            "policy exceeds the {MAX_POLICY_BYTES}-byte input limit"
        )));
    }
    let value: Value = serde_yml::from_str(source)
        .map_err(|error| ParsePolicyError(format!("invalid policy YAML: {error}")))?;
    validate_yaml_shape(&value)?;
    let mut policy: ContainmentPolicy = serde_yml::from_str(source)
        .map_err(|error| ParsePolicyError(format!("invalid policy YAML: {error}")))?;
    if policy.version != 1 {
        return Err(ParsePolicyError(format!(
            "unsupported policy version {}; expected version 1",
            policy.version
        )));
    }
    normalize_filesystem_paths(&mut policy.filesystem_policy)?;
    Ok(policy)
}

fn validate_yaml_shape(root: &Value) -> Result<(), ParsePolicyError> {
    let mut stack = vec![(root, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_YAML_NODES {
            return Err(ParsePolicyError(format!(
                "policy exceeds the {MAX_YAML_NODES}-node YAML limit"
            )));
        }
        if depth > MAX_YAML_DEPTH {
            return Err(ParsePolicyError(format!(
                "policy exceeds the {MAX_YAML_DEPTH}-level YAML depth limit"
            )));
        }
        match value {
            Value::Sequence(values) => {
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Mapping(values) => {
                stack.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::Tagged(value) => stack.push((value.value(), depth + 1)),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn normalize_filesystem_paths(policy: &mut FilesystemPolicy) -> Result<(), ParsePolicyError> {
    for path in policy.read_only.iter_mut().chain(&mut policy.read_write) {
        *path = normalize_path(path)?;
    }
    Ok(())
}

fn normalize_path(path: &str) -> Result<String, ParsePolicyError> {
    if !path.starts_with('/') {
        return Err(ParsePolicyError(format!(
            "filesystem path '{path}' must be absolute"
        )));
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                return Err(ParsePolicyError(format!(
                    "filesystem path '{path}' contains an unsupported '..' segment"
                )));
            }
            value => parts.push(value),
        }
    }
    Ok(if parts.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", parts.join("/"))
    })
}

/// Per-invocation solver limits. These never modify Z3 global parameters.
#[derive(Debug, Clone, Copy)]
pub struct CheckOptions {
    pub timeout: Duration,
}

/// Stable reason identifiers for automation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    UnsupportedPolicyShape,
    UnresolvedWorkdir,
    UnresolvedBinaryPath,
    UnresolvedFilesystemPath,
    SolverTimeout,
    SolverUnknown,
    ResourceLimit,
    InvalidWitness,
    Cancelled,
}

impl ReasonCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPolicyShape => "unsupported_policy_shape",
            Self::UnresolvedWorkdir => "unresolved_workdir",
            Self::UnresolvedBinaryPath => "unresolved_binary_path",
            Self::UnresolvedFilesystemPath => "unresolved_filesystem_path",
            Self::SolverTimeout => "solver_timeout",
            Self::SolverUnknown => "solver_unknown",
            Self::ResourceLimit => "resource_limit",
            Self::InvalidWitness => "invalid_witness",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Authority domains modeled by this engine version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckDomain {
    Filesystem,
    NetworkL4,
    NetworkRest,
}

impl CheckDomain {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::NetworkL4 => "network_l4",
            Self::NetworkRest => "network_rest",
        }
    }
}

/// Scope attached to every completed or recoverably incomplete check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckScope {
    pub model_version: &'static str,
    pub policy_version: u32,
    pub domains: &'static [CheckDomain],
}

static DOMAINS: &[CheckDomain] = &[
    CheckDomain::Filesystem,
    CheckDomain::NetworkL4,
    CheckDomain::NetworkRest,
];
fn check_scope() -> &'static CheckScope {
    static SCOPE: CheckScope = CheckScope {
        model_version: "maximum-boundary-v1",
        policy_version: 1,
        domains: DOMAINS,
    };
    &SCOPE
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemAccess {
    Read,
    Write,
}

impl FilesystemAccess {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    L4,
    Rest,
}

impl Protocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::L4 => "l4",
            Self::Rest => "rest",
        }
    }
}

/// Concrete action showing why containment failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Counterexample {
    Filesystem {
        access: FilesystemAccess,
        path: String,
    },
    Network {
        binary: Option<String>,
        ancestor_binary: Option<String>,
        binary_identity_required: bool,
        host: String,
        port: u16,
        protocol: Protocol,
        method: Option<String>,
        path: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithinEvidence;

impl WithinEvidence {
    #[must_use]
    pub fn scope(&self) -> &'static CheckScope {
        check_scope()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceedsEvidence(Counterexample);

impl ExceedsEvidence {
    #[must_use]
    pub fn scope(&self) -> &'static CheckScope {
        check_scope()
    }

    #[must_use]
    pub const fn counterexample(&self) -> &Counterexample {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasonEvidence {
    code: ReasonCode,
    reason: String,
}

impl ReasonEvidence {
    #[must_use]
    pub fn scope(&self) -> &'static CheckScope {
        check_scope()
    }

    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        self.code
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Result of a maximum-boundary proof attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    Within(WithinEvidence),
    Exceeds(ExceedsEvidence),
    Unsupported(ReasonEvidence),
    Inconclusive(ReasonEvidence),
}

impl CheckResult {
    /// Construct the standard typed result for a caller-observed cancellation.
    #[must_use]
    pub fn cancelled() -> Self {
        cancelled_result()
    }
}

struct SymbolicAction {
    binary: Z3String,
    ancestor_binary: Z3String,
    host: Z3String,
    port: Int,
    layer: Z3String,
    method: Z3String,
    path: Z3String,
}

enum NetworkSolve {
    Within,
    Exceeds(Counterexample),
    Incomplete(CheckResult),
}

/// Determine whether every modeled candidate action is allowed by `maximum`.
#[must_use]
pub fn check_within_maximum(
    maximum: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    options: CheckOptions,
) -> CheckResult {
    check_within_maximum_inner(maximum, candidate, options, None)
}

/// Determine containment while allowing a caller-owned cancellation flag to
/// interrupt the solver. The caller remains responsible for signal handling.
#[must_use]
pub fn check_within_maximum_cancellable(
    maximum: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    options: CheckOptions,
    cancelled: &AtomicBool,
) -> CheckResult {
    check_within_maximum_inner(maximum, candidate, options, Some(cancelled))
}

fn check_within_maximum_inner(
    maximum: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    options: CheckOptions,
    cancelled: Option<&AtomicBool>,
) -> CheckResult {
    if let Some(reason) = unsupported_reason("maximum", maximum) {
        return unsupported(reason.0, reason.1);
    }
    if let Some(reason) = unsupported_reason("candidate", candidate) {
        return unsupported(reason.0, reason.1);
    }
    if let Some(reason) = resource_limit_reason(maximum, candidate) {
        return CheckResult::Inconclusive(ReasonEvidence {
            code: ReasonCode::ResourceLimit,
            reason,
        });
    }
    if cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        return cancelled_result();
    }
    if options.timeout.is_zero() {
        return CheckResult::Inconclusive(ReasonEvidence {
            code: ReasonCode::SolverTimeout,
            reason: "solver timeout must be positive".to_owned(),
        });
    }
    if let Some(reason) = unresolved_workdir_reason(maximum, candidate) {
        return unsupported(ReasonCode::UnresolvedWorkdir, reason);
    }
    if maximum == candidate {
        return CheckResult::Within(WithinEvidence);
    }
    let filesystem_result = check_filesystem(maximum, candidate);
    if let Some(result @ CheckResult::Exceeds(_)) = filesystem_result {
        return result;
    }
    let started = Instant::now();
    for binary_identity_required in [false, true] {
        match solve_network_mode(
            maximum,
            candidate,
            binary_identity_required,
            started,
            options.timeout,
            cancelled,
        ) {
            NetworkSolve::Within => {}
            NetworkSolve::Exceeds(counterexample) => {
                return CheckResult::Exceeds(ExceedsEvidence(counterexample));
            }
            NetworkSolve::Incomplete(result) => return result,
        }
        if binary_identity_required && has_ambiguous_candidate_binary_path(maximum, candidate) {
            return unsupported(
                ReasonCode::UnresolvedBinaryPath,
                "network containment depends on image-specific binary symlink resolution"
                    .to_owned(),
            );
        }
    }
    if unresolved_exact_deny_symlink(maximum, candidate) {
        return unsupported(
            ReasonCode::UnresolvedBinaryPath,
            "network deny containment depends on image-specific exact binary symlink resolution"
                .to_owned(),
        );
    }
    filesystem_result.unwrap_or(CheckResult::Within(WithinEvidence))
}

fn solve_network_mode(
    maximum: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    binary_identity_required: bool,
    started: Instant,
    timeout: Duration,
    cancelled: Option<&AtomicBool>,
) -> NetworkSolve {
    if network_is_structurally_contained(maximum, candidate, binary_identity_required) {
        return NetworkSolve::Within;
    }
    let solver = Solver::new();
    let action = symbolic_action(if binary_identity_required {
        "strict_maximum_policy_action"
    } else {
        "relaxed_maximum_policy_action"
    });
    assert_action_domain(&solver, &action, binary_identity_required);
    solver.assert(Bool::and(&[
        policy_allows(candidate, &action, binary_identity_required),
        !policy_allows(maximum, &action, binary_identity_required),
    ]));

    let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
        return NetworkSolve::Incomplete(solver_timeout_result());
    };
    let remaining_ms = u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX);
    if remaining_ms == 0 {
        return NetworkSolve::Incomplete(solver_timeout_result());
    }
    let mut params = Params::new();
    params.set_u32("timeout", remaining_ms);
    if cancelled.is_some() {
        // The caller owns SIGINT. Z3's handler would replace it during check(),
        // leaving the cancellation flag unset even when the solve is interrupted.
        params.set_bool("ctrl_c", false);
    }
    solver.set_params(&params);
    let solve_result = solver_check(&solver, cancelled);
    if cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        return NetworkSolve::Incomplete(cancelled_result());
    }
    match solve_result {
        SatResult::Unsat => NetworkSolve::Within,
        SatResult::Unknown => {
            let reason = solver
                .get_reason_unknown()
                .unwrap_or_else(|| "Z3 returned unknown".to_owned());
            let code = if reason.to_ascii_lowercase().contains("timeout") {
                ReasonCode::SolverTimeout
            } else {
                ReasonCode::SolverUnknown
            };
            NetworkSolve::Incomplete(CheckResult::Inconclusive(ReasonEvidence { code, reason }))
        }
        SatResult::Sat => solver
            .get_model()
            .and_then(|model| counterexample_from_model(&model, &action, binary_identity_required))
            .filter(|counterexample| {
                counterexample_satisfies_predicate(maximum, candidate, counterexample)
            })
            .map_or_else(
                || {
                    NetworkSolve::Incomplete(CheckResult::Inconclusive(ReasonEvidence {
                        code: ReasonCode::InvalidWitness,
                        reason: "solver returned a model that could not be decoded".to_owned(),
                    }))
                },
                NetworkSolve::Exceeds,
            ),
    }
}

fn solver_timeout_result() -> CheckResult {
    CheckResult::Inconclusive(ReasonEvidence {
        code: ReasonCode::SolverTimeout,
        reason: "solver timeout elapsed".to_owned(),
    })
}

fn cancelled_result() -> CheckResult {
    CheckResult::Inconclusive(ReasonEvidence {
        code: ReasonCode::Cancelled,
        reason: "containment check was cancelled".to_owned(),
    })
}

fn solver_check(solver: &Solver, cancelled: Option<&AtomicBool>) -> SatResult {
    let Some(cancelled) = cancelled else {
        return solver.check();
    };
    let finished = AtomicBool::new(false);
    let context = Context::thread_local();
    let handle = context.handle();
    std::thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            while !finished.load(Ordering::Acquire) && !cancelled.load(Ordering::Relaxed) {
                std::thread::park_timeout(Duration::from_millis(10));
            }
            if cancelled.load(Ordering::Relaxed) {
                handle.interrupt();
            }
        });
        let result = solver.check();
        finished.store(true, Ordering::Release);
        watcher.thread().unpark();
        watcher.join().expect("cancellation watcher must not panic");
        result
    })
}

fn unsupported(code: ReasonCode, reason: String) -> CheckResult {
    CheckResult::Unsupported(ReasonEvidence { code, reason })
}

/// Prove straightforward REST containment without invoking the solver. This
/// covers the common case where selectors are identical and the candidate only
/// narrows explicit method/path grants. More complex unions still use Z3.
fn network_is_structurally_contained(
    maximum: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    binary_identity_required: bool,
) -> bool {
    if maximum
        .network_policies
        .values()
        .flat_map(|rule| &rule.endpoints)
        .any(|endpoint| !endpoint.deny_rules.is_empty())
    {
        return false;
    }
    candidate.network_policies.values().all(|candidate_rule| {
        maximum.network_policies.values().any(|maximum_rule| {
            rule_structurally_contains(maximum_rule, candidate_rule, binary_identity_required)
        })
    })
}

fn rule_structurally_contains(
    maximum: &NetworkRule,
    candidate: &NetworkRule,
    binary_identity_required: bool,
) -> bool {
    (!binary_identity_required
        || candidate.binaries.iter().all(|candidate_binary| {
            maximum
                .binaries
                .iter()
                .any(|maximum_binary| maximum_binary.path == candidate_binary.path)
        }))
        && candidate.endpoints.iter().all(|candidate_endpoint| {
            maximum.endpoints.iter().any(|maximum_endpoint| {
                rest_endpoint_structurally_contains(maximum_endpoint, candidate_endpoint)
            })
        })
}

fn rest_endpoint_structurally_contains(maximum: &Endpoint, candidate: &Endpoint) -> bool {
    if maximum.protocol_kind() != Protocol::Rest
        || candidate.protocol_kind() != Protocol::Rest
        || !maximum.host.eq_ignore_ascii_case(&candidate.host)
        || maximum.path != candidate.path
        || !candidate
            .effective_ports()
            .iter()
            .all(|port| maximum.effective_ports().contains(port))
        || !maximum.access.is_empty()
        || !candidate.access.is_empty()
        || !maximum.deny_rules.is_empty()
        || !candidate.deny_rules.is_empty()
    {
        return false;
    }

    candidate.rules.iter().all(|candidate_rule| {
        if candidate_rule.allow.method.is_empty() {
            return false;
        }
        maximum.rules.iter().any(|maximum_rule| {
            method_pattern_contains(&maximum_rule.allow.method, &candidate_rule.allow.method)
                && path_pattern_contains(&maximum_rule.allow.path, &candidate_rule.allow.path)
        })
    })
}

fn method_pattern_contains(maximum: &str, candidate: &str) -> bool {
    maximum == "*"
        || maximum.eq_ignore_ascii_case(candidate)
        || (maximum.eq_ignore_ascii_case("GET") && candidate.eq_ignore_ascii_case("HEAD"))
}

fn path_pattern_contains(maximum: &str, candidate: &str) -> bool {
    // Inputs are already validated. Keep this sufficient proof deliberately
    // limited to equality and a terminal recursive path segment.
    let maximum = if maximum.is_empty() { "**" } else { maximum };
    let candidate = if candidate.is_empty() {
        "**"
    } else {
        candidate
    };
    maximum == candidate
        || maximum == "**"
        || maximum.strip_suffix("/**").is_some_and(|prefix| {
            candidate
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
        })
}

fn symbolic_action(name: &str) -> SymbolicAction {
    let _context = Context::thread_local();
    SymbolicAction {
        binary: Z3String::new_const(format!("{name}_binary")),
        ancestor_binary: Z3String::new_const(format!("{name}_ancestor_binary")),
        host: Z3String::new_const(format!("{name}_host")),
        port: Int::new_const(format!("{name}_port")),
        layer: Z3String::new_const(format!("{name}_layer")),
        method: Z3String::new_const(format!("{name}_method")),
        path: Z3String::new_const(format!("{name}_path")),
    }
}

fn assert_action_domain(solver: &Solver, action: &SymbolicAction, binary_identity_required: bool) {
    if binary_identity_required {
        solver.assert(action.binary.regex_matches(&glob_regex("/**", "/")));
        solver.assert(action.binary.length().le(4_096));
        solver.assert(
            action
                .ancestor_binary
                .regex_matches(&glob_regex("/**", "/")),
        );
        solver.assert(action.ancestor_binary.length().le(4_096));
    }
    // Keep `action.host` unconstrained: the runtime applies host globs to raw
    // proxy input before DNS validation, so DNS structure and resolver length
    // limits are not properties of the action domain.
    solver.assert(Int::from_u64(1).le(&action.port));
    solver.assert(action.port.le(65_535));
    solver.assert(str_eq_any(&action.layer, &[LAYER_L4, LAYER_REST]));
    solver.assert(!action.method.eq(""));
    solver.assert(
        Z3String::from_str("/")
            .expect("valid Z3 string")
            .prefix(&action.path),
    );
    solver.assert(action.path.length().le(4_096));
    for forbidden in ["//", "/./", "/../", ";", "?", "#"] {
        solver.assert(!action.path.contains(forbidden));
    }
    solver.assert(!action.path.eq("/."));
    solver.assert(!action.path.eq("/.."));
    solver.assert(!Z3String::from_str("/.").unwrap().suffix(&action.path));
    solver.assert(!Z3String::from_str("/..").unwrap().suffix(&action.path));
}

fn policy_allows(
    policy: &ContainmentPolicy,
    action: &SymbolicAction,
    binary_identity_required: bool,
) -> Bool {
    let allowed = bool_or(
        policy
            .network_policies
            .values()
            .map(|rule| rule_allows(rule, action, binary_identity_required)),
    );
    let denied = bool_or(
        policy
            .network_policies
            .values()
            .map(|rule| rule_denies(rule, action, binary_identity_required)),
    );
    Bool::and(&[allowed, !denied])
}

fn rule_allows(
    rule: &NetworkRule,
    action: &SymbolicAction,
    binary_identity_required: bool,
) -> Bool {
    Bool::and(&[
        binaries_match(rule, action, binary_identity_required),
        bool_or(
            rule.endpoints
                .iter()
                .map(|endpoint| endpoint_allows(endpoint, action)),
        ),
    ])
}

fn rule_denies(
    rule: &NetworkRule,
    action: &SymbolicAction,
    binary_identity_required: bool,
) -> Bool {
    Bool::and(&[
        binaries_match(rule, action, binary_identity_required),
        bool_or(
            rule.endpoints
                .iter()
                .map(|endpoint| endpoint_denies(endpoint, action)),
        ),
    ])
}

fn binaries_match(
    rule: &NetworkRule,
    action: &SymbolicAction,
    binary_identity_required: bool,
) -> Bool {
    if !binary_identity_required {
        return Bool::from_bool(true);
    }
    bool_or(rule.binaries.iter().flat_map(|binary| {
        let pattern = glob_regex(&binary.path, "/");
        [
            action.binary.regex_matches(&pattern),
            action.ancestor_binary.regex_matches(&pattern),
        ]
    }))
}

fn endpoint_allows(endpoint: &Endpoint, action: &SymbolicAction) -> Bool {
    let common = endpoint_matches_connection(endpoint, action);
    match endpoint.protocol_kind() {
        Protocol::L4 => common,
        Protocol::Rest => Bool::and(&[
            common,
            action.layer.eq(LAYER_REST),
            endpoint_path_matches(endpoint, action),
            rest_endpoint_allows(endpoint, action),
        ]),
    }
}

fn endpoint_denies(endpoint: &Endpoint, action: &SymbolicAction) -> Bool {
    if endpoint.protocol_kind() != Protocol::Rest || endpoint.deny_rules.is_empty() {
        return Bool::from_bool(false);
    }
    Bool::and(&[
        endpoint_matches_connection(endpoint, action),
        action.layer.eq(LAYER_REST),
        endpoint_path_matches(endpoint, action),
        bool_or(
            endpoint
                .deny_rules
                .iter()
                .map(|deny| method_and_path_match(&deny.method, &deny.path, action)),
        ),
    ])
}

fn rest_endpoint_allows(endpoint: &Endpoint, action: &SymbolicAction) -> Bool {
    match endpoint.access.as_str() {
        "read-only" => methods_match(action, READ_ONLY_METHODS, "**"),
        "read-write" => methods_match(action, READ_WRITE_METHODS, "**"),
        "full" => any_method_matches(action, "**"),
        _ => bool_or(
            endpoint
                .rules
                .iter()
                .map(|rule| method_and_path_match(&rule.allow.method, &rule.allow.path, action)),
        ),
    }
}

fn endpoint_matches_connection(endpoint: &Endpoint, action: &SymbolicAction) -> Bool {
    Bool::and(&[
        bool_or(
            endpoint
                .effective_ports()
                .into_iter()
                .map(|port| action.port.eq(Int::from_u64(u64::from(port)))),
        ),
        action
            .host
            .regex_matches(&glob_regex(&endpoint.host.to_ascii_lowercase(), ".")),
    ])
}

fn endpoint_path_matches(endpoint: &Endpoint, action: &SymbolicAction) -> Bool {
    let path = if endpoint.path.is_empty() {
        "**"
    } else {
        &endpoint.path
    };
    action.path.regex_matches(&glob_regex(path, "/"))
}

fn method_and_path_match(method: &str, path: &str, action: &SymbolicAction) -> Bool {
    if method.is_empty() {
        return Bool::from_bool(false);
    }
    let path = if path.is_empty() { "**" } else { path };
    if method == "*" {
        any_method_matches(action, path)
    } else if method.eq_ignore_ascii_case("GET") {
        methods_match(action, &["GET", "HEAD"], path)
    } else {
        methods_match(action, &[method], path)
    }
}

fn any_method_matches(action: &SymbolicAction, path: &str) -> Bool {
    action.path.regex_matches(&glob_regex(path, "/"))
}

fn methods_match(action: &SymbolicAction, methods: &[&str], path: &str) -> Bool {
    Bool::and(&[
        str_eq_any_case_insensitive(&action.method, methods),
        action.path.regex_matches(&glob_regex(path, "/")),
    ])
}

fn counterexample_from_model(
    model: &z3::Model,
    action: &SymbolicAction,
    binary_identity_required: bool,
) -> Option<Counterexample> {
    let port = model.eval(&action.port, true)?.as_u64()?;
    let layer = model_string_exact(model, &action.layer)?;
    let binary = if binary_identity_required {
        let binary = model_string_exact(model, &action.binary)?;
        if !is_canonical_runtime_binary_path(&binary) {
            return None;
        }
        Some(binary)
    } else {
        None
    };
    let ancestor_binary = if binary_identity_required {
        let binary = model_string_exact(model, &action.ancestor_binary)?;
        if !is_canonical_runtime_binary_path(&binary) {
            return None;
        }
        Some(binary)
    } else {
        None
    };
    let host = model_string_exact(model, &action.host)?;
    if !is_canonical_dns_host(&host) {
        return None;
    }
    let protocol = if layer == LAYER_L4 {
        Protocol::L4
    } else {
        Protocol::Rest
    };
    let (method, path) = if protocol == Protocol::Rest {
        let method = model_string_exact(model, &action.method)?;
        let path = model_string_exact(model, &action.path)?;
        if !is_http_method(&method) || !is_canonical_rest_path(&path) {
            return None;
        }
        (Some(method), Some(path))
    } else {
        (None, None)
    };
    Some(Counterexample::Network {
        binary,
        ancestor_binary,
        binary_identity_required,
        host,
        port: u16::try_from(port).ok()?,
        protocol,
        method,
        path,
    })
}

/// Decode a model string only when encoding it again produces the exact same
/// solver value. `as_string` uses a lossy C-string boundary in the Rust Z3
/// binding, so accepting its output alone could publish an altered witness.
fn model_string_exact(model: &z3::Model, value: &Z3String) -> Option<String> {
    let evaluated = model.eval(value, true)?;
    let decoded = evaluated.as_string()?;
    // Some Z3 versions expose non-ASCII UTF-8 bytes through `Z3_get_string`
    // as `\u{..}` sequences. The binding does not distinguish that encoding
    // from literal text, so do not risk publishing the serialization as a
    // concrete witness.
    if decoded.contains("\\u{") {
        return None;
    }
    let reconstructed = Z3String::from_str(&decoded).ok()?;
    (evaluated.eq(reconstructed).simplify().as_bool() == Some(true)).then_some(decoded)
}

fn counterexample_satisfies_predicate(
    maximum: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    counterexample: &Counterexample,
) -> bool {
    let Counterexample::Network {
        binary,
        ancestor_binary,
        binary_identity_required,
        host,
        port,
        protocol,
        method,
        path,
    } = counterexample
    else {
        return false;
    };
    let concrete = SymbolicAction {
        binary: Z3String::from_str(binary.as_deref().unwrap_or("")).unwrap(),
        ancestor_binary: Z3String::from_str(ancestor_binary.as_deref().unwrap_or("")).unwrap(),
        host: Z3String::from_str(host).unwrap(),
        port: Int::from_u64(u64::from(*port)),
        layer: Z3String::from_str(protocol.as_str()).unwrap(),
        method: Z3String::from_str(method.as_deref().unwrap_or("GET")).unwrap(),
        path: Z3String::from_str(path.as_deref().unwrap_or("/")).unwrap(),
    };
    Bool::and(&[
        policy_allows(candidate, &concrete, *binary_identity_required),
        !policy_allows(maximum, &concrete, *binary_identity_required),
    ])
    .simplify()
    .as_bool()
        == Some(true)
}

fn is_canonical_runtime_binary_path(path: &str) -> bool {
    path.len() <= 4 * 1024 && is_canonical_pattern_path(path) && !path.chars().any(char::is_control)
}

fn is_canonical_dns_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
                && label.as_bytes().first().is_some_and(|byte| *byte != b'-')
                && label.as_bytes().last().is_some_and(|byte| *byte != b'-')
        })
}

fn is_http_method(method: &str) -> bool {
    !method.is_empty()
        && method.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_canonical_rest_path(path: &str) -> bool {
    if path.is_empty()
        || path.len() > 4 * 1024
        || !path.starts_with('/')
        || path.contains("//")
        || path.contains(';')
        || path.contains('?')
        || path.contains('#')
    {
        return false;
    }
    let bytes = path.as_bytes();
    if bytes.iter().any(|byte| !(0x21..=0x7e).contains(byte))
        || path.split('/').any(|segment| matches!(segment, "." | ".."))
    {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            if bytes[index] != b'/' && !is_literal_canonical_pchar(bytes[index]) {
                return false;
            }
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len()
            || !bytes[index + 1].is_ascii_hexdigit()
            || !bytes[index + 2].is_ascii_hexdigit()
            || bytes[index + 1].is_ascii_lowercase()
            || bytes[index + 2].is_ascii_lowercase()
        {
            return false;
        }
        let decoded = u8::from_str_radix(&path[index + 1..index + 3], 16).expect("checked hex");
        if decoded == b'/'
            || decoded == b';'
            || decoded.is_ascii_control()
            || is_literal_canonical_pchar(decoded)
        {
            return false;
        }
        index += 3;
    }
    true
}

fn is_literal_canonical_pchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b'='
                | b':'
                | b'@'
        )
}

fn unresolved_workdir_reason(
    maximum: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
) -> Option<String> {
    let maximum_writes = &maximum.filesystem_policy.read_write;
    let mut maximum_reads = maximum.filesystem_policy.read_only.clone();
    maximum_reads.extend(maximum_writes.iter().cloned());

    if candidate.filesystem_policy.include_workdir
        && !maximum.filesystem_policy.include_workdir
        && !maximum_writes.iter().any(|path| path == "/")
    {
        return Some(
            "candidate filesystem authority depends on an unresolved image workdir".to_owned(),
        );
    }
    if maximum.filesystem_policy.include_workdir
        && (candidate
            .filesystem_policy
            .read_write
            .iter()
            .any(|path| !path_is_covered(path, maximum_writes))
            || candidate
                .filesystem_policy
                .read_only
                .iter()
                .any(|path| !path_is_covered(path, &maximum_reads)))
    {
        return Some(
            "maximum filesystem authority depends on an unresolved image workdir".to_owned(),
        );
    }
    None
}

fn has_ambiguous_candidate_binary_path(
    maximum: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
) -> bool {
    maximum.network_policies.values().any(|maximum_rule| {
        maximum_rule
            .binaries
            .iter()
            .filter(|binary| binary.path.contains('*') && binary.path != "/**")
            .any(|maximum_binary| {
                candidate.network_policies.values().any(|candidate_rule| {
                    endpoint_authority_sets_overlap(
                        &candidate_rule.endpoints,
                        &maximum_rule.endpoints,
                    ) && candidate_rule.binaries.iter().any(|candidate_binary| {
                        !candidate_binary.path.contains('*')
                            && glob::Pattern::new(&maximum_binary.path)
                                .is_ok_and(|pattern| pattern.matches(&candidate_binary.path))
                            && !maximum.network_policies.values().any(|exact_rule| {
                                endpoint_authority_sets_equal(
                                    &candidate_rule.endpoints,
                                    &exact_rule.endpoints,
                                ) && exact_rule
                                    .binaries
                                    .iter()
                                    .any(|exact_binary| exact_binary.path == candidate_binary.path)
                            })
                    })
                })
            })
    })
}

fn unresolved_exact_deny_symlink(
    maximum: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
) -> bool {
    maximum.network_policies.values().any(|maximum_rule| {
        let maximum_deny_endpoints = maximum_rule
            .endpoints
            .iter()
            .filter(|endpoint| !endpoint.deny_rules.is_empty())
            .collect::<Vec<_>>();
        if maximum_deny_endpoints.is_empty() {
            return false;
        }
        maximum_rule
            .binaries
            .iter()
            .filter(|binary| !binary.path.contains('*'))
            .any(|maximum_binary| {
                candidate.network_policies.values().any(|candidate_rule| {
                    let endpoints_overlap = candidate_rule
                        .endpoints
                        .iter()
                        .filter(|endpoint| !endpoint.deny_rules.is_empty())
                        .any(|candidate_endpoint| {
                            maximum_deny_endpoints.iter().any(|maximum_endpoint| {
                                endpoint_authority_may_overlap(candidate_endpoint, maximum_endpoint)
                            })
                        });
                    endpoints_overlap
                        && candidate_rule.binaries.iter().any(|candidate_binary| {
                            candidate_binary.path.contains('*')
                                && candidate_binary.path != "/**"
                                && glob::Pattern::new(&candidate_binary.path)
                                    .is_ok_and(|pattern| pattern.matches(&maximum_binary.path))
                        })
                })
            })
    })
}

fn endpoint_authority_sets_overlap(left: &[Endpoint], right: &[Endpoint]) -> bool {
    left.iter().any(|endpoint| {
        right
            .iter()
            .any(|other| endpoint_authority_may_overlap(endpoint, other))
    })
}

fn endpoint_authority_sets_equal(left: &[Endpoint], right: &[Endpoint]) -> bool {
    left.iter().all(|endpoint| {
        right
            .iter()
            .any(|other| endpoint_authority_equal(endpoint, other))
    }) && right.iter().all(|endpoint| {
        left.iter()
            .any(|other| endpoint_authority_equal(endpoint, other))
    })
}

fn endpoint_authority_may_overlap(left: &Endpoint, right: &Endpoint) -> bool {
    let ports_overlap = left
        .effective_ports()
        .iter()
        .any(|port| right.effective_ports().contains(port));
    let hosts_may_overlap = left.host.eq_ignore_ascii_case(&right.host)
        || left.host.contains('*')
        || right.host.contains('*');
    ports_overlap && hosts_may_overlap
}

fn endpoint_authority_equal(left: &Endpoint, right: &Endpoint) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.review = Review::default();
    right.review = Review::default();
    for rule in &mut left.rules {
        rule.allow.review = Review::default();
    }
    for rule in &mut right.rules {
        rule.allow.review = Review::default();
    }
    let rules_equal = left.rules.iter().all(|rule| right.rules.contains(rule))
        && right.rules.iter().all(|rule| left.rules.contains(rule));
    let denies_equal = left
        .deny_rules
        .iter()
        .all(|rule| right.deny_rules.contains(rule))
        && right
            .deny_rules
            .iter()
            .all(|rule| left.deny_rules.contains(rule));
    left.rules.clear();
    right.rules.clear();
    left.deny_rules.clear();
    right.deny_rules.clear();
    rules_equal && denies_equal && left == right
}

fn check_filesystem(
    maximum: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
) -> Option<CheckResult> {
    let mut maximum_writes = maximum.filesystem_policy.read_write.clone();
    if maximum.filesystem_policy.include_workdir {
        maximum_writes.push(WORKDIR_SYMBOL.to_owned());
    }
    let mut maximum_reads = maximum.filesystem_policy.read_only.clone();
    maximum_reads.extend(maximum_writes.iter().cloned());

    let mut unresolved = None;
    for (access, candidates, maxima) in [
        (
            FilesystemAccess::Write,
            &candidate.filesystem_policy.read_write,
            &maximum_writes,
        ),
        (
            FilesystemAccess::Read,
            &candidate.filesystem_policy.read_only,
            &maximum_reads,
        ),
    ] {
        for path in candidates {
            if path_is_covered(path, maxima) {
                continue;
            }
            if maxima.is_empty() {
                return Some(CheckResult::Exceeds(ExceedsEvidence(
                    Counterexample::Filesystem {
                        access,
                        path: path.clone(),
                    },
                )));
            }
            // Landlock resolves paths in the sandbox. Lexical descendants can
            // point outside an ancestor, and unrelated paths can alias it.
            unresolved = Some(unsupported(
                ReasonCode::UnresolvedFilesystemPath,
                format!(
                    "filesystem {access} containment for '{path}' depends on sandbox path resolution; use matching paths in candidate and maximum",
                    access = access.as_str()
                ),
            ));
        }
    }
    unresolved
}

fn path_is_covered(candidate: &str, maximum_paths: &[String]) -> bool {
    maximum_paths
        .iter()
        .any(|maximum| maximum == "/" || candidate == maximum)
}

fn unsupported_reason(label: &str, policy: &ContainmentPolicy) -> Option<(ReasonCode, String)> {
    let unsupported = |detail: String| {
        Some((
            ReasonCode::UnsupportedPolicyShape,
            format!("{label} policy {detail}"),
        ))
    };
    if !policy.extra.is_empty() {
        return unsupported(format!(
            "uses unsupported top-level fields: {}",
            keys(&policy.extra)
        ));
    }
    if label == "candidate" && policy.metadata.is_some() {
        return unsupported("contains managed-maximum metadata".to_owned());
    }
    if policy
        .metadata
        .as_ref()
        .is_some_and(|metadata| !metadata.extra.is_empty())
    {
        return unsupported("uses unsupported managed-metadata fields".to_owned());
    }
    if policy.landlock.is_some()
        || policy.process.is_some()
        || !policy.network_middlewares.is_empty()
    {
        return unsupported("uses process, Landlock, or network middleware controls".to_owned());
    }
    if !policy.filesystem_policy.extra.is_empty() {
        return unsupported(format!(
            "uses unsupported filesystem fields: {}",
            keys(&policy.filesystem_policy.extra)
        ));
    }
    for (rule_name, rule) in &policy.network_policies {
        if !rule.extra.is_empty() {
            return unsupported(format!("rule '{rule_name}' uses unsupported fields"));
        }
        for binary in &rule.binaries {
            if let Some(reason) = unsupported_network_literal(&binary.path) {
                return unsupported(format!("rule '{rule_name}' binary path {reason}"));
            }
            if binary.path.is_empty()
                || !is_canonical_pattern_path(&binary.path)
                || !binary.extra.is_empty()
                || unsupported_glob(&binary.path)
            {
                return unsupported(format!("rule '{rule_name}' uses an unsupported binary"));
            }
        }
        for endpoint in &rule.endpoints {
            let context = format!("rule '{rule_name}'");
            if let Some(reason) = unsupported_network_literal(&endpoint.host) {
                return unsupported(format!("{context} endpoint host {reason}"));
            }
            if let Some(reason) = unsupported_network_literal(&endpoint.path) {
                return unsupported(format!("{context} endpoint path {reason}"));
            }
            if endpoint.host.is_empty()
                || endpoint.effective_ports().is_empty()
                || (endpoint.port != 0 && !endpoint.ports.is_empty())
            {
                return unsupported(format!("{context} has no unambiguous host and port"));
            }
            if unsupported_host_glob(&endpoint.host) {
                return unsupported(format!(
                    "{context} endpoint host uses an unsupported pattern"
                ));
            }
            if unsupported_glob(&endpoint.path)
                || (!endpoint.path.is_empty() && !is_canonical_pattern_path(&endpoint.path))
            {
                return unsupported(format!("{context} uses an unsupported glob"));
            }
            if !endpoint.path.is_empty() && !endpoint.path.starts_with('/') {
                return unsupported(format!("{context} uses a non-canonical endpoint path"));
            }
            if endpoint.host.contains(':') {
                return unsupported(format!(
                    "{context} uses an IP-literal shape outside the DNS host model"
                ));
            }
            if !endpoint.extra.is_empty()
                || !endpoint.allowed_ips.is_empty()
                || !matches!(endpoint.tls.as_str(), "" | "terminate" | "passthrough")
                || endpoint.allow_encoded_slash
                || endpoint.websocket_credential_rewrite
                || endpoint.request_body_credential_rewrite
                || endpoint.allow_uninspected_credentials
                || !endpoint.persisted_queries.is_empty()
                || !endpoint.graphql_persisted_queries.is_empty()
                || endpoint.graphql_max_body_bytes != 0
                || !endpoint.credential_signing.is_empty()
                || !endpoint.signing_service.is_empty()
                || !endpoint.signing_region.is_empty()
                || endpoint.credential_binding.is_some()
                || endpoint.json_rpc.is_some()
                || endpoint.mcp.is_some()
                || !endpoint.review.extra.is_empty()
            {
                return unsupported(format!(
                    "{context} uses authority outside the initial model"
                ));
            }
            let protocol = endpoint.protocol.to_ascii_lowercase();
            if !matches!(protocol.as_str(), "" | "tcp" | "rest") {
                return unsupported(format!(
                    "{context} uses protocol '{}'; only L4 TCP and REST are modeled",
                    endpoint.protocol
                ));
            }
            if protocol == "tcp" && endpoint.host.parse::<IpAddr>().is_ok() {
                return unsupported(format!(
                    "{context} uses an IP literal with explicit TCP semantics"
                ));
            }
            if protocol == "rest" {
                if endpoint.enforcement != "enforce" {
                    return unsupported(format!("{context} uses REST without enforced inspection"));
                }
                if (!endpoint.access.is_empty() && !endpoint.rules.is_empty())
                    || (endpoint.access.is_empty() && endpoint.rules.is_empty())
                    || (!endpoint.access.is_empty()
                        && !matches!(
                            endpoint.access.as_str(),
                            "read-only" | "read-write" | "full"
                        ))
                {
                    return unsupported(format!("{context} has an unsupported REST allow shape"));
                }
            } else if !endpoint.enforcement.is_empty()
                || !endpoint.access.is_empty()
                || !endpoint.path.is_empty()
                || !endpoint.rules.is_empty()
                || !endpoint.deny_rules.is_empty()
            {
                return unsupported(format!("{context} mixes REST controls into L4 authority"));
            }
            for rule in &endpoint.rules {
                if let Some(reason) = unsupported_network_literal(&rule.allow.method) {
                    return unsupported(format!("{context} REST allow method {reason}"));
                }
                if let Some(reason) = unsupported_network_literal(&rule.allow.path) {
                    return unsupported(format!("{context} REST allow path {reason}"));
                }
                if !rule.extra.is_empty() || unsupported_allow(&rule.allow) {
                    return unsupported(format!("{context} uses an unsupported REST allow rule"));
                }
            }
            for rule in &endpoint.deny_rules {
                if let Some(reason) = unsupported_network_literal(&rule.method) {
                    return unsupported(format!("{context} REST deny method {reason}"));
                }
                if let Some(reason) = unsupported_network_literal(&rule.path) {
                    return unsupported(format!("{context} REST deny path {reason}"));
                }
                if unsupported_deny(rule) {
                    return unsupported(format!("{context} uses an unsupported REST deny rule"));
                }
            }
        }
    }
    let endpoints = policy
        .network_policies
        .values()
        .flat_map(|rule| rule.endpoints.iter())
        .collect::<Vec<_>>();
    if endpoints.iter().enumerate().any(|(index, endpoint)| {
        endpoints[index + 1..].iter().any(|other| {
            endpoint.protocol_kind() != other.protocol_kind()
                && endpoint_authority_may_overlap(endpoint, other)
        })
    }) {
        return unsupported(
            "contains overlapping L4 and REST endpoints whose inspection selection is not modeled"
                .to_owned(),
        );
    }
    None
}

fn unsupported_network_literal(value: &str) -> Option<&'static str> {
    if !value.is_ascii() {
        Some("contains a non-ASCII literal")
    } else if value.contains('\0') {
        Some("contains an embedded NUL byte")
    } else {
        None
    }
}

fn resource_limit_reason(
    maximum: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
) -> Option<String> {
    const MAX_RULES: usize = 1_024;
    const MAX_ENDPOINTS: usize = 4_096;
    const MAX_BINARIES: usize = 4_096;
    const MAX_L7_RULES: usize = 16_384;
    const MAX_PATTERN_BYTES: usize = 4 * 1024;
    const MAX_TOTAL_PATTERN_BYTES: usize = 1024 * 1024;

    let policies = [maximum, candidate];
    let rule_count = policies
        .iter()
        .map(|policy| policy.network_policies.len())
        .sum::<usize>();
    let endpoint_count = policies
        .iter()
        .flat_map(|policy| policy.network_policies.values())
        .map(|rule| rule.endpoints.len())
        .sum::<usize>();
    let binary_count = policies
        .iter()
        .flat_map(|policy| policy.network_policies.values())
        .map(|rule| rule.binaries.len())
        .sum::<usize>();
    let l7_count = policies
        .iter()
        .flat_map(|policy| policy.network_policies.values())
        .flat_map(|rule| &rule.endpoints)
        .map(|endpoint| endpoint.rules.len() + endpoint.deny_rules.len())
        .sum::<usize>();
    let mut total_pattern_bytes = 0_usize;
    let mut longest_pattern = 0_usize;
    for policy in policies {
        let mut account = |value: &str| {
            total_pattern_bytes = total_pattern_bytes.saturating_add(value.len());
            longest_pattern = longest_pattern.max(value.len());
        };
        for path in policy
            .filesystem_policy
            .read_only
            .iter()
            .chain(&policy.filesystem_policy.read_write)
        {
            account(path);
        }
        for rule in policy.network_policies.values() {
            for binary in &rule.binaries {
                account(&binary.path);
            }
            for endpoint in &rule.endpoints {
                account(&endpoint.host);
                account(&endpoint.path);
                for rule in &endpoint.rules {
                    account(&rule.allow.path);
                    account(&rule.allow.method);
                }
                for rule in &endpoint.deny_rules {
                    account(&rule.path);
                    account(&rule.method);
                }
            }
        }
    }

    (rule_count > MAX_RULES
        || endpoint_count > MAX_ENDPOINTS
        || binary_count > MAX_BINARIES
        || l7_count > MAX_L7_RULES
        || longest_pattern > MAX_PATTERN_BYTES
        || total_pattern_bytes > MAX_TOTAL_PATTERN_BYTES)
        .then(|| {
            format!(
                "containment model exceeds resource limits (rules={rule_count}, endpoints={endpoint_count}, binaries={binary_count}, l7_rules={l7_count}, pattern_bytes={total_pattern_bytes}, longest_pattern={longest_pattern})"
            )
        })
}

fn unsupported_allow(rule: &Allow) -> bool {
    rule.method.is_empty()
        || !rule.command.is_empty()
        || !rule.query.is_empty()
        || !rule.operation_type.is_empty()
        || !rule.operation_name.is_empty()
        || !rule.fields.is_empty()
        || rule.tool.is_some()
        || !rule.params.is_empty()
        || !rule.extra.is_empty()
        || !rule.review.extra.is_empty()
        || (!rule.path.is_empty() && !rule.path.starts_with('/'))
        || (!rule.path.is_empty() && !is_canonical_pattern_path(&rule.path))
        || unsupported_glob(&rule.path)
}

fn unsupported_deny(rule: &DenyRule) -> bool {
    rule.method.is_empty()
        || !rule.command.is_empty()
        || !rule.query.is_empty()
        || !rule.operation_type.is_empty()
        || !rule.operation_name.is_empty()
        || !rule.fields.is_empty()
        || rule.tool.is_some()
        || !rule.params.is_empty()
        || !rule.extra.is_empty()
        || (!rule.path.is_empty() && !rule.path.starts_with('/'))
        || (!rule.path.is_empty() && !is_canonical_pattern_path(&rule.path))
        || unsupported_glob(&rule.path)
}

fn is_canonical_pattern_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains("//")
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}

fn keys(values: &BTreeMap<String, Value>) -> String {
    values.keys().cloned().collect::<Vec<_>>().join(", ")
}

fn unsupported_glob(pattern: &str) -> bool {
    pattern
        .chars()
        .any(|character| matches!(character, '?' | '[' | ']' | '{' | '}' | '\\'))
}

fn unsupported_host_glob(pattern: &str) -> bool {
    if unsupported_glob(pattern)
        || pattern == "*"
        || pattern == "**"
        || pattern.chars().any(char::is_whitespace)
        || pattern.split('.').any(str::is_empty)
    {
        return true;
    }
    let labels = pattern.split('.').collect::<Vec<_>>();
    let minimum_name_len = labels
        .iter()
        .map(|label| label.bytes().filter(|byte| *byte != b'*').count().max(1))
        .sum::<usize>()
        + labels.len().saturating_sub(1);
    minimum_name_len > 253
        || labels.iter().enumerate().any(|(index, label)| {
            let first = label.as_bytes().first().copied();
            let last = label.as_bytes().last().copied();
            let minimum_label_len = label.bytes().filter(|byte| *byte != b'*').count().max(1);
            minimum_label_len > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'*'))
                || first == Some(b'-')
                || last == Some(b'-')
                || (label.contains("**") && *label != "**")
                || (index > 0 && label.contains('*') && *label != "*" && *label != "**")
        })
}

fn bool_or(values: impl IntoIterator<Item = Bool>) -> Bool {
    let values = values.into_iter().collect::<Vec<_>>();
    if values.is_empty() {
        Bool::from_bool(false)
    } else {
        Bool::or(&values)
    }
}

fn str_eq_any(value: &Z3String, options: &[&str]) -> Bool {
    bool_or(options.iter().map(|option| value.eq(*option)))
}

fn str_eq_any_case_insensitive(value: &Z3String, options: &[&str]) -> Bool {
    bool_or(
        options
            .iter()
            .map(|option| value.eq(option.to_ascii_uppercase())),
    )
}

fn glob_regex(pattern: &str, separator: &str) -> Regexp {
    if pattern == "**" {
        return Regexp::full();
    }
    if separator == "/" {
        return path_glob_regex(pattern);
    }
    let mut parts = Vec::new();
    let mut chars = pattern.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '*' && chars.peek() == Some(&'*') {
            chars.next();
            parts.push(Regexp::full());
        } else if character == '*' {
            let wildcard = non_separator_regex(separator);
            parts.push(wildcard.star());
        } else {
            parts.push(Regexp::literal(&character.to_string()));
        }
    }
    if parts.is_empty() {
        Regexp::literal("")
    } else {
        let refs = parts.iter().collect::<Vec<_>>();
        Regexp::concat(&refs)
    }
}

fn path_glob_regex(pattern: &str) -> Regexp {
    let mut parts = Vec::new();
    let mut segments = pattern.split('/').peekable();
    while let Some(segment) = segments.next() {
        if segment == "**" {
            // glob.match collapses consecutive recursive components. A middle
            // ** includes its following slash and can match zero directories.
            while segments.peek() == Some(&"**") {
                segments.next();
            }
            let recursive = Regexp::full();
            parts.push(if segments.peek().is_some() {
                Regexp::union(&[
                    &Regexp::literal(""),
                    &Regexp::concat(&[&recursive, &Regexp::literal("/")]),
                ])
            } else {
                recursive
            });
        } else {
            for character in segment.chars() {
                // Embedded stars, including **, cannot cross a separator.
                parts.push(if character == '*' {
                    non_separator_regex("/").star()
                } else {
                    Regexp::literal(&character.to_string())
                });
            }
            if segments.peek().is_some() {
                parts.push(Regexp::literal("/"));
            }
        }
    }
    if parts.is_empty() {
        Regexp::literal("")
    } else {
        Regexp::concat(&parts.iter().collect::<Vec<_>>())
    }
}

fn non_separator_regex(separator: &str) -> Regexp {
    // Runtime globs match Unicode values. Describe a non-empty separator-free
    // sequence from Z3's full string language instead of limiting wildcards to
    // character ranges. This works with both supported Z3 versions; callers'
    // `star` and `plus` operations preserve the runtime wildcard languages.
    let contains_separator = Regexp::concat(&[
        &Regexp::full(),
        &Regexp::literal(separator),
        &Regexp::full(),
    ]);
    Regexp::intersect(&[
        &contains_separator.complement(),
        &Regexp::literal("").complement(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    fn parse(value: &str) -> ContainmentPolicy {
        parse_policy_str(value).expect("valid policy")
    }

    fn options() -> CheckOptions {
        CheckOptions {
            timeout: Duration::from_secs(10),
        }
    }

    #[test]
    fn filesystem_containment_and_counterexample() {
        let maximum =
            parse("version: 1\nfilesystem_policy: { read_only: [/usr], read_write: [/tmp] }\n");
        let within = parse("version: 1\nfilesystem_policy: { read_only: [/usr, /tmp] }\n");
        let exceeds = parse("version: 1\nfilesystem_policy: { read_write: [/workspace] }\n");
        assert!(matches!(
            check_within_maximum(&maximum, &within, options()),
            CheckResult::Within(_)
        ));
        assert!(matches!(
            check_within_maximum(
                &parse("version: 1\nfilesystem_policy: {}\n"),
                &exceeds,
                options()
            ),
            CheckResult::Exceeds(_)
        ));
    }

    #[test]
    fn absent_filesystem_policy_uses_the_runtime_workdir_default() {
        let omitted = parse("version: 1\n");
        assert!(omitted.filesystem_policy.include_workdir);

        let explicit = parse("version: 1\nfilesystem_policy: {}\n");
        assert!(!explicit.filesystem_policy.include_workdir);

        assert!(matches!(
            check_within_maximum(&explicit, &omitted, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnresolvedWorkdir
        ));
    }

    #[test]
    fn l4_contains_rest_but_not_the_reverse() {
        let l4 = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let rest = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_maximum(&l4, &rest, options()),
            CheckResult::Within(_)
        ));
        assert!(matches!(
            check_within_maximum(&rest, &l4, options()),
            CheckResult::Exceeds(_)
        ));
    }

    #[test]
    fn network_containment_covers_disabled_binary_identity() {
        let maximum = parse("version: 1\n");
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: []\n",
        );
        let result = check_within_maximum(&maximum, &candidate, options());
        assert!(matches!(
            result,
            CheckResult::Exceeds(ref evidence)
                if matches!(
                    evidence.counterexample(),
                    Counterexample::Network {
                        binary: None,
                        binary_identity_required: false,
                        ..
                    }
                )
        ));
    }

    #[test]
    fn underscore_hosts_are_present_in_the_full_action_domain() {
        let cases = [
            ("api_internal.example.com", ""),
            ("_service.example.com", "tcp"),
            ("a_b.test", "rest"),
        ];

        for (host, protocol) in cases {
            let endpoint = if protocol == "rest" {
                format!(
                    "{{ host: {host}, port: 443, protocol: rest, enforcement: enforce, access: read-only }}"
                )
            } else if protocol == "tcp" {
                format!("{{ host: {host}, port: 443, protocol: tcp }}")
            } else {
                format!("{{ host: {host}, port: 443 }}")
            };
            let candidate = parse(&format!(
                "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{endpoint}]\n    binaries: []\n"
            ));
            let result = check_within_maximum(&parse("version: 1\n"), &candidate, options());
            assert!(
                matches!(
                    result,
                    CheckResult::Exceeds(ref evidence)
                        if matches!(
                            evidence.counterexample(),
                            Counterexample::Network { host: witness, .. } if witness == host
                        )
                ),
                "protocol={protocol:?} host={host}: {result:?}"
            );
        }
    }

    #[test]
    fn underscore_hosts_preserve_exact_and_wildcard_containment() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  maximum:\n    endpoints: [{ host: '*.example.com', port: 443 }]\n    binaries: []\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  candidate:\n    endpoints: [{ host: api_internal.example.com, port: 443 }]\n    binaries: []\n",
        );
        assert!(matches!(
            check_within_maximum(&maximum, &candidate, options()),
            CheckResult::Within(_)
        ));

        let exact_maximum = parse(
            "version: 1\nnetwork_policies:\n  maximum:\n    endpoints: [{ host: _service.example.com, port: 443, protocol: tcp }]\n    binaries: []\n",
        );
        let exact_candidate = parse(
            "version: 1\nnetwork_policies:\n  candidate:\n    endpoints: [{ host: _service.example.com, port: 443, protocol: tcp }]\n    binaries: []\n",
        );
        assert!(matches!(
            check_within_maximum(&exact_maximum, &exact_candidate, options()),
            CheckResult::Within(_)
        ));
    }

    #[test]
    fn host_action_domain_covers_noncanonical_wildcard_matches() {
        for (pattern, host) in [
            ("*.example.com", ".example.com".to_owned()),
            ("**.example.com", "api..example.com".to_owned()),
            ("*.example.com", "é.example.com".to_owned()),
            ("*.example.com", "$service.example.com".to_owned()),
            ("*.example.com", "-api.example.com".to_owned()),
            ("*.example.com", format!("{}.example.com", "a".repeat(242))),
        ] {
            let solver = Solver::new();
            let action = symbolic_action("host_superset");
            assert_action_domain(&solver, &action, false);
            solver.assert(action.host.eq(Z3String::from_str(&host).unwrap()));
            solver.assert(action.host.regex_matches(&glob_regex(pattern, ".")));
            assert_eq!(
                solver.check(),
                SatResult::Sat,
                "pattern={pattern:?} host={host:?}"
            );
        }
    }

    #[test]
    fn host_literals_enforce_modeled_label_and_name_boundaries() {
        let maximum_length = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(maximum_length.len(), 253);
        assert!(is_canonical_dns_host(&maximum_length));
        assert!(!unsupported_host_glob(&maximum_length));
        assert!(is_canonical_dns_host("_service.example.com"));
        assert!(is_canonical_dns_host("api-internal.example.com"));

        let oversized_label = format!("{}.example.com", "a".repeat(64));
        assert!(!is_canonical_dns_host(&oversized_label));
        assert!(unsupported_host_glob(&oversized_label));

        let oversized_name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert_eq!(oversized_name.len(), 254);
        assert!(!is_canonical_dns_host(&oversized_name));
        assert!(unsupported_host_glob(&oversized_name));
        assert!(unsupported_host_glob("api$.example.com"));
        for unsupported in ["-api.example.com", "api-.example.com"] {
            assert!(!is_canonical_dns_host(unsupported));
            assert!(unsupported_host_glob(unsupported));

            let candidate = parse(&format!(
                "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{{ host: {unsupported}, port: 443 }}]\n    binaries: []\n"
            ));
            assert!(matches!(
                check_within_maximum(&parse("version: 1\n"), &candidate, options()),
                CheckResult::Unsupported(ref evidence)
                    if evidence.reason_code() == ReasonCode::UnsupportedPolicyShape
                        && evidence.reason().contains("endpoint host")
            ));
        }
    }

    #[test]
    fn differing_binary_selectors_are_checked_when_identity_is_required() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/wget }]\n",
        );
        let result = check_within_maximum(&maximum, &candidate, options());
        assert!(matches!(
            result,
            CheckResult::Exceeds(ref evidence)
                if matches!(
                    evidence.counterexample(),
                    Counterexample::Network {
                        binary_identity_required: true,
                        ..
                    }
                )
        ));
    }

    #[test]
    fn explicit_deny_removes_authority() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: full\n        deny_rules: [{ method: DELETE, path: /** }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: DELETE, path: /private/resource } }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let result = check_within_maximum(&maximum, &candidate, options());
        assert!(matches!(result, CheckResult::Exceeds(_)), "{result:?}");
    }

    #[test]
    fn host_wildcard_zero_length_suffix_preserves_exact_deny() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: 'api*.example.com', port: 443, protocol: rest, enforcement: enforce, access: full }\n    binaries: [{ path: /usr/bin/curl }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: full\n        deny_rules: [{ method: GET, path: '/**' }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: 'api*.example.com', port: 443, protocol: rest, enforcement: enforce, access: full }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let result = check_within_maximum(&maximum, &candidate, options());
        assert!(matches!(
            result,
            CheckResult::Exceeds(ref evidence)
                if matches!(
                    evidence.counterexample(),
                    Counterexample::Network { host, .. } if host == "api.example.com"
                )
        ));
    }

    #[test]
    fn ancestor_binary_can_supply_a_maximum_deny() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: /usr/bin/curl }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-only\n        deny_rules: [{ method: '*', path: '/**' }]\n    binaries: [{ path: /usr/bin/python3 }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: /usr/bin/curl }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-only\n        deny_rules: [{ method: '*', path: '/**' }]\n    binaries: [{ path: /usr/bin/node }]\n",
        );
        let result = check_within_maximum(&maximum, &candidate, options());
        assert!(
            matches!(
                result,
                CheckResult::Exceeds(ref evidence)
                    if matches!(
                        evidence.counterexample(),
                        Counterexample::Network {
                            binary: Some(binary),
                            ancestor_binary: Some(ancestor),
                            binary_identity_required: true,
                            ..
                        } if (binary == "/usr/bin/curl" && ancestor == "/usr/bin/python3")
                            || (binary == "/usr/bin/python3" && ancestor == "/usr/bin/curl")
                    )
            ),
            "{result:?}"
        );
    }

    #[test]
    fn exact_maximum_deny_under_candidate_glob_requires_image_resolution() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: '/**' }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-only\n        deny_rules: [{ method: '*', path: '/**' }]\n    binaries: [{ path: /venv/bin/python }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: '/**' }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-only\n        deny_rules: [{ method: '*', path: '/**' }]\n    binaries: [{ path: '/venv/bin/*' }]\n",
        );
        assert!(matches!(
            check_within_maximum(&maximum, &candidate, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnresolvedBinaryPath
        ));
    }

    #[test]
    fn definite_network_expansion_precedes_symlink_uncertainty() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: '/**' }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-only\n        deny_rules: [{ method: '*', path: '/**' }]\n    binaries: [{ path: /venv/bin/python }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: '/**' }]\n  extra:\n    endpoints: [{ host: extra.example.com, port: 443 }]\n    binaries: [{ path: '/**' }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-only\n        deny_rules: [{ method: '*', path: '/**' }]\n    binaries: [{ path: '/venv/bin/*' }]\n",
        );
        assert!(matches!(
            check_within_maximum(&maximum, &candidate, options()),
            CheckResult::Exceeds(_)
        ));
    }

    #[test]
    fn overlapping_l4_and_rest_authority_is_unsupported() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - { host: api.example.com, port: 443 }\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_maximum(&maximum, &candidate, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnsupportedPolicyShape
        ));
    }

    #[test]
    fn methods_longer_than_sixty_four_bytes_are_in_the_action_domain() {
        let method = "X".repeat(65);
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, rules: [{ allow: { method: GET, path: '/**' } }] }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(&format!(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - {{ host: api.example.com, port: 443, protocol: rest, enforcement: enforce, rules: [{{ allow: {{ method: {method}, path: '/**' }} }}] }}\n    binaries: [{{ path: /usr/bin/curl }}]\n"
        ));
        let result = check_within_maximum(&maximum, &candidate, options());
        assert!(matches!(
            result,
            CheckResult::Exceeds(ref evidence)
                if matches!(
                    evidence.counterexample(),
                    Counterexample::Network { method: Some(value), .. } if value == &method
                )
        ));
    }

    #[test]
    fn rest_methods_and_paths_must_be_narrower() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: GET, path: '/repos/**' } }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let narrower = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: GET, path: '/repos/NVIDIA/**' } }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let broader_method = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: POST, path: '/repos/NVIDIA/**' } }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let result = check_within_maximum(&maximum, &narrower, options());
        assert!(matches!(result, CheckResult::Within(_)), "{result:?}");
        let result = check_within_maximum(&maximum, &broader_method, options());
        assert!(matches!(result, CheckResult::Exceeds(_)), "{result:?}");
    }

    #[test]
    fn structural_path_containment_requires_a_recursive_segment_boundary() {
        assert!(path_pattern_contains("/repos/**", "/repos/NVIDIA/**"));
        assert!(!path_pattern_contains("/repos/**", "/repository/NVIDIA/**"));
        assert!(!path_pattern_contains("/repos**", "/repos/NVIDIA/**"));
    }

    #[test]
    fn structural_fast_path_does_not_ignore_separate_maximum_denies() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, rules: [{ allow: { method: GET, path: '/repos/**' } }] }\n    binaries: [{ path: /usr/bin/curl }]\n  deny:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full, deny_rules: [{ method: GET, path: '/repos/private/**' }] }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, rules: [{ allow: { method: GET, path: '/repos/private/**' } }] }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(!network_is_structurally_contained(
            &maximum, &candidate, true
        ));
    }

    #[test]
    fn unknown_and_environment_dependent_shapes_fail_closed() {
        let unknown = parse("version: 1\nfuture_authority: true\n");
        assert!(matches!(
            check_within_maximum(&unknown, &unknown, options()),
            CheckResult::Unsupported(_)
        ));
        let workdir = parse("version: 1\nfilesystem_policy: { include_workdir: true }\n");
        let empty = parse("version: 1\nfilesystem_policy: {}\n");
        assert!(matches!(
            check_within_maximum(&empty, &workdir, options()),
            CheckResult::Unsupported(_)
        ));
        let maximum_workdir = parse("version: 1\nfilesystem_policy: { include_workdir: true }\n");
        let explicit = parse("version: 1\nfilesystem_policy: { read_write: [/workspace] }\n");
        assert!(matches!(
            check_within_maximum(&maximum_workdir, &explicit, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnresolvedWorkdir
        ));
    }

    #[test]
    fn exact_binary_under_a_maximum_glob_requires_image_resolution() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*3' }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/python3 }]\n",
        );
        let result = check_within_maximum(&maximum, &candidate, options());
        assert!(
            matches!(
                result,
                CheckResult::Unsupported(ref evidence)
                    if evidence.reason_code() == ReasonCode::UnresolvedBinaryPath
            ),
            "{result:?}"
        );
    }

    #[test]
    fn unrelated_maximum_glob_does_not_make_exact_containment_unsupported() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n  unrelated:\n    endpoints: [{ host: other.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_maximum(&maximum, &candidate, options()),
            CheckResult::Within(_)
        ));
    }

    #[test]
    fn redundant_maximum_glob_does_not_hide_equivalent_exact_containment() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n  glob:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let result = check_within_maximum(&maximum, &candidate, options());
        assert!(matches!(result, CheckResult::Within(_)), "{result:?}");
    }

    #[test]
    fn unrelated_universal_glob_does_not_hide_symlink_ambiguity() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  ambiguous:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n  unrelated:\n    endpoints: [{ host: unrelated.example.com, port: 80 }]\n    binaries: [{ path: '/**' }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_maximum(&maximum, &candidate, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnresolvedBinaryPath
        ));
    }

    #[test]
    fn shared_glob_does_not_hide_exact_binary_symlink_ambiguity() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  shared:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  shared:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }, { path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_maximum(&maximum, &candidate, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnresolvedBinaryPath
        ));
    }

    #[test]
    fn wildcard_endpoint_overlap_does_not_hide_symlink_ambiguity() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  shared:\n    endpoints: [{ host: '*.example.com', port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  shared:\n    endpoints: [{ host: '*.example.com', port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_maximum(&maximum, &candidate, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnresolvedBinaryPath
        ));
    }

    #[test]
    fn ambiguity_check_preserves_shared_unrelated_globs() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n  ambiguous:\n    endpoints: [{ host: unrelated.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n  shared:\n    endpoints: [{ host: shared.example.com, port: 443 }, { host: mirror.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n  shared:\n    endpoints: [{ host: mirror.example.com, port: 443 }, { host: shared.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n",
        );
        assert!(matches!(
            check_within_maximum(&maximum, &candidate, options()),
            CheckResult::Within(_)
        ));
    }

    #[test]
    fn reflexive_and_rule_order_invariant() {
        let first = parse(
            "version: 1\nnetwork_policies:\n  a:\n    endpoints: [{ host: '*.example.com', port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n  b:\n    endpoints: [{ host: api.example.org, port: 8443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let second = parse(
            "version: 1\nnetwork_policies:\n  b:\n    endpoints: [{ host: api.example.org, port: 8443 }]\n    binaries: [{ path: /usr/bin/curl }]\n  a:\n    endpoints: [{ host: '*.example.com', port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n",
        );
        let reflexive = check_within_maximum(&first, &first, options());
        assert!(matches!(reflexive, CheckResult::Within(_)), "{reflexive:?}");
        assert!(matches!(
            check_within_maximum(&first, &second, options()),
            CheckResult::Within(_)
        ));
        assert!(matches!(
            check_within_maximum(&second, &first, options()),
            CheckResult::Within(_)
        ));
    }

    #[test]
    fn containment_is_transitive() {
        let broad = parse("version: 1\nfilesystem_policy: { read_write: [/workspace, /tmp] }\n");
        let middle = parse("version: 1\nfilesystem_policy: { read_write: [/workspace] }\n");
        let narrow = parse("version: 1\nfilesystem_policy: { read_only: [/workspace] }\n");
        assert!(matches!(
            check_within_maximum(&broad, &middle, options()),
            CheckResult::Within(_)
        ));
        assert!(matches!(
            check_within_maximum(&middle, &narrow, options()),
            CheckResult::Within(_)
        ));
        assert!(matches!(
            check_within_maximum(&broad, &narrow, options()),
            CheckResult::Within(_)
        ));
    }

    #[test]
    fn removed_binary_harness_field_is_unsupported() {
        let policy = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl, harness: true }]\n",
        );
        assert!(matches!(
            check_within_maximum(&policy, &policy, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnsupportedPolicyShape
        ));
    }

    #[test]
    fn excessive_model_size_is_inconclusive() {
        let maximum = parse("version: 1\n");
        let mut candidate = parse("version: 1\n");
        for index in 0..=1_024 {
            candidate.network_policies.insert(
                format!("rule-{index}"),
                NetworkRule {
                    _name: String::new(),
                    endpoints: Vec::new(),
                    binaries: Vec::new(),
                    extra: BTreeMap::new(),
                },
            );
        }
        assert!(matches!(
            check_within_maximum(&maximum, &candidate, options()),
            CheckResult::Inconclusive(ref evidence)
                if evidence.reason_code() == ReasonCode::ResourceLimit
        ));
    }

    #[test]
    fn invalid_version_and_relative_path_are_input_errors() {
        assert!(parse_policy_str("version: 2\n").is_err());
        assert!(parse_policy_str("version: 1\nfilesystem_policy: { read_only: [tmp] }\n").is_err());
        assert!(parse_policy_str("version: 1\nversion: 1\n").is_err());
        let mut deep = String::from("version: 1\nfuture:\n");
        for depth in 0..=MAX_YAML_DEPTH {
            writeln!(deep, "{}level-{depth}:", "  ".repeat(depth + 1)).unwrap();
        }
        writeln!(deep, "{}true", "  ".repeat(MAX_YAML_DEPTH + 2)).unwrap();
        assert!(parse_policy_str(&deep).is_err());
    }

    #[test]
    fn rest_counterexamples_must_be_canonical_runtime_paths() {
        for path in ["/", "/repos/NVIDIA/", "/a%20b"] {
            assert!(is_canonical_rest_path(path), "rejected {path}");
        }
        for path in ["/a//b", "/a/../b", "/a/./b", "/a;b", "/a%2fb", "/a%41"] {
            assert!(!is_canonical_rest_path(path), "accepted {path}");
        }
    }

    #[test]
    fn a_pre_cancelled_check_is_inconclusive() {
        let policy = parse("version: 1\n");
        let cancelled = AtomicBool::new(true);
        assert!(matches!(
            check_within_maximum_cancellable(&policy, &policy, options(), &cancelled),
            CheckResult::Inconclusive(ref evidence)
                if evidence.reason_code() == ReasonCode::Cancelled
        ));
    }

    #[test]
    fn review_reason_and_deprecated_tls_spelling_do_not_change_authority() {
        let maximum = parse(
            "version: 1\nmetadata: { policy_id: ceiling, version: 7, allowed_modes: [ask], default_mode: ask, audit_label: production }\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        tls: terminate\n        enforcement: enforce\n        access: read-only\n        review: { required: true, reason: sensitive }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules:\n          - allow: { method: GET, path: '/v1/**', review: { required: true, reason: inspect } }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_maximum(&maximum, &candidate, options()),
            CheckResult::Within(_)
        ));
        let metadata = maximum.metadata().expect("managed metadata retained");
        assert_eq!(metadata.policy_id, "ceiling");
        assert_eq!(metadata.version, 7);
    }

    #[test]
    fn host_wildcards_do_not_cross_or_elide_labels() {
        let maximum = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: '*.example.com', port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let nested = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: deep.api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_maximum(&maximum, &nested, options()),
            CheckResult::Exceeds(_)
        ));
        let recursive = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: '**.example.com', port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_maximum(&recursive, &nested, options()),
            CheckResult::Within(_)
        ));
    }

    #[test]
    fn host_model_matches_the_runtime_matcher() {
        let cases = [
            ("api.example.com", "api.example.com"),
            ("api.example.com", "other.example.com"),
            ("*.example.com", "api.example.com"),
            ("*.example.com", "deep.api.example.com"),
            ("**.example.com", "deep.api.example.com"),
            ("**.example.com", "example.com"),
            ("api*.example.com", "api.example.com"),
            ("api*.example.com", "api-v2.example.com"),
            ("api*.example.com", "api_internal.example.com"),
            ("*.example.com", "_service.example.com"),
            ("*.example.com", ".example.com"),
            ("**.example.com", "api..example.com"),
            ("*.example.com", "é.example.com"),
            ("*.example.com", "$service.example.com"),
            ("*.example.com", "-api.example.com"),
            ("api-internal.example.com", "api-internal.example.com"),
        ];
        let mut runtime = regorus::Engine::new();
        for (pattern, host) in cases {
            let query = format!(
                "glob.match({}, [\".\"], {})",
                serde_json::to_string(pattern).unwrap(),
                serde_json::to_string(host).unwrap()
            );
            let actual = runtime.eval_query(query, false).unwrap();
            let expected = actual.result[0].expressions[0].value == regorus::Value::from(true);
            let solver = Solver::new();
            let modeled = Z3String::from_str(host)
                .unwrap()
                .regex_matches(&glob_regex(pattern, "."));
            solver.assert(!modeled);
            let prover = solver.check() == SatResult::Unsat;
            assert_eq!(prover, expected, "pattern={pattern} host={host}");
        }
    }

    #[test]
    fn filesystem_normalization_matches_the_runtime_helper() {
        for path in ["/", "/usr//bin/", "/workspace/./cache"] {
            let parsed = parse(&format!(
                "version: 1\nfilesystem_policy: {{ read_only: [{path}] }}\n"
            ));
            assert_eq!(
                parsed.filesystem_policy.read_only[0],
                openshell_core::paths::normalize_path(path)
            );
        }
    }

    #[test]
    fn filesystem_comparisons_do_not_assume_path_ancestry_or_distinctness() {
        for access in ["read_only", "read_write"] {
            let maximum = parse(&format!(
                "version: 1\nfilesystem_policy: {{ {access}: [/safe] }}\n"
            ));
            for path in [
                "/safe/link",
                "/safe/child/file",
                "/elsewhere",
                "/safe-prefix",
            ] {
                let candidate = parse(&format!(
                    "version: 1\nfilesystem_policy: {{ {access}: [{path}] }}\n"
                ));
                assert!(
                    matches!(
                        check_within_maximum(&maximum, &candidate, options()),
                        CheckResult::Unsupported(ref evidence)
                            if evidence.reason_code() == ReasonCode::UnresolvedFilesystemPath
                    ),
                    "access={access} path={path}"
                );
            }
            let matching = parse(&format!(
                "version: 1\nfilesystem_policy: {{ {access}: [/safe, /safe] }}\n"
            ));
            assert!(matches!(
                check_within_maximum(&maximum, &matching, options()),
                CheckResult::Within(_)
            ));
            let root = parse(&format!(
                "version: 1\nfilesystem_policy: {{ {access}: [/] }}\n"
            ));
            assert!(matches!(
                check_within_maximum(&root, &maximum, options()),
                CheckResult::Within(_)
            ));
        }
    }

    #[test]
    fn path_globs_match_the_runtime_builtin() {
        let mut runtime = regorus::Engine::new();
        for pattern in [
            "/a/**/b",
            "/**/b",
            "/a/**/**/b",
            "/a/**",
            "/a/**/**",
            "/a/**/",
            "/a/*/b",
            "/a/x**/b",
            "/a/**x/b",
            "/a/***/b",
            "/a/**/x*/**/b",
        ] {
            for path in [
                "/a/b",
                "/a/x/b",
                "/a/x/y/b",
                "/b",
                "/a/",
                "/a",
                "/a/xb",
                "/a/x/z/xb/y/b",
                "/a/c",
                "/a/é/b",
                "/a/汉/b",
                "/a/e\u{301}/b",
                "/a/😀/b",
            ] {
                let query = format!(
                    "glob.match({}, [\"/\"], {})",
                    serde_json::to_string(pattern).unwrap(),
                    serde_json::to_string(path).unwrap()
                );
                let actual = runtime.eval_query(query, false).unwrap();
                let expected = actual.result[0].expressions[0].value == regorus::Value::from(true);
                let solver = Solver::new();
                solver.assert(
                    Z3String::from_str(path)
                        .unwrap()
                        .regex_matches(&glob_regex(pattern, "/")),
                );
                assert_eq!(
                    solver.check() == SatResult::Sat,
                    expected,
                    "pattern={pattern} path={path}"
                );
            }
        }
    }

    #[test]
    fn z3_string_boundary_decodes_exactly_or_fails_closed() {
        for (expected, exactly_decodable) in [
            ("ascii", true),
            (r"a\b", true),
            ("é", false),
            ("e\u{301}", false),
            ("𐐷", false),
            ("😀", false),
        ] {
            let solver = Solver::new();
            let value = Z3String::fresh_const("round_trip");
            solver.assert(value.eq(Z3String::from_str(expected).unwrap()));
            assert_eq!(solver.check(), SatResult::Sat, "value={expected:?}");
            let model = solver.get_model().unwrap();
            let decoded = model_string_exact(&model, &value);
            if exactly_decodable {
                assert_eq!(decoded.as_deref(), Some(expected), "value={expected:?}");
            } else if let Some(decoded) = decoded {
                assert_eq!(decoded, expected, "value={expected:?}");
            }
        }
    }

    #[test]
    fn unicode_network_literals_are_unsupported_in_both_inputs() {
        let policies = [
            (
                "binary path",
                "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/é*' }]\n",
            ),
            (
                "endpoint host",
                "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: 'é.example.com', port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
            ),
            (
                "endpoint path",
                "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, path: '/é/**', access: full }\n    binaries: [{ path: /usr/bin/curl }]\n",
            ),
            (
                "REST allow method",
                "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: 'GÉT', path: '/**' } }]\n    binaries: [{ path: /usr/bin/curl }]\n",
            ),
            (
                "REST allow path",
                "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: GET, path: '/é/**' } }]\n    binaries: [{ path: /usr/bin/curl }]\n",
            ),
            (
                "REST deny method",
                "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: GET, path: '/**' } }]\n        deny_rules: [{ method: 'DÉLETE', path: '/**' }]\n    binaries: [{ path: /usr/bin/curl }]\n",
            ),
            (
                "REST deny path",
                "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: GET, path: '/**' } }]\n        deny_rules: [{ method: GET, path: '/é/**' }]\n    binaries: [{ path: /usr/bin/curl }]\n",
            ),
        ];
        let empty = parse("version: 1\n");
        for (field, yaml) in policies {
            let policy = parse(yaml);
            for (maximum, candidate, label) in [
                (&policy, &empty, "maximum"),
                (&empty, &policy, "candidate"),
                (&policy, &policy, "maximum"),
            ] {
                let result = check_within_maximum(maximum, candidate, options());
                assert!(
                    matches!(
                        result,
                        CheckResult::Unsupported(ref evidence)
                            if evidence.reason_code() == ReasonCode::UnsupportedPolicyShape
                                && evidence.reason().contains(label)
                                && evidence.reason().contains(field)
                    ),
                    "field={field} input={label} result={result:?}"
                );
            }
        }
    }

    #[test]
    fn embedded_nul_network_literal_is_unsupported_before_solving() {
        assert_eq!(unsupported_network_literal("ascii"), None);
        assert_eq!(
            unsupported_network_literal("é"),
            Some("contains a non-ASCII literal")
        );
        assert_eq!(
            unsupported_network_literal("G\0ET"),
            Some("contains an embedded NUL byte")
        );

        let policy = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: \"G\\0ET\", path: '/**' } }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let empty = parse("version: 1\n");
        for (maximum, candidate, label) in [
            (&policy, &empty, "maximum"),
            (&empty, &policy, "candidate"),
            (&policy, &policy, "maximum"),
        ] {
            let result = check_within_maximum(maximum, candidate, options());
            assert!(
                matches!(
                    result,
                    CheckResult::Unsupported(ref evidence)
                        if evidence.reason_code() == ReasonCode::UnsupportedPolicyShape
                            && evidence.reason().contains(label)
                            && evidence.reason().contains("REST allow method")
                            && evidence.reason().contains("NUL")
                ),
                "input={label} result={result:?}"
            );
        }
    }
}
