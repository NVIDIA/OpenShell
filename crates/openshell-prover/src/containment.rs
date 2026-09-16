// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sound, deliberately narrow policy-containment checks.
//!
//! This module is independent of the legacy proposal-risk model. It parses the
//! canonical authored schema and fails closed when authority falls outside its
//! supported containment model.
//!
//! Callers construct [`CheckOptions`] with [`CheckOptions::new`] and should
//! match extensible enums with a wildcard arm. [`CheckResult`] deliberately
//! remains exhaustive: its four outcomes are the stable, closed result-state
//! contract, and authorization should accept only [`CheckResult::Within`].

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use openshell_policy_schema::{
    AccessPreset, FilesystemPolicy, L7Allow as Allow, L7DenyRule as DenyRule, LandlockPolicy,
    NetworkBinary as Binary, NetworkEndpoint as Endpoint, NetworkMiddleware,
    NetworkPolicyRule as NetworkRule, PolicyDocument, ProcessPolicy,
};
use z3::ast::{Ast, Bool, Int, Regexp, String as Z3String};
use z3::{Context, Params, SatResult, Solver};

mod execution;
mod ip;

const LAYER_L4: &str = "l4";
const LAYER_REST: &str = "rest";
const WORKDIR_SYMBOL: &str = "<OCI_WORKDIR>";
const MAX_RULES: usize = 1_024;
const MAX_ENDPOINTS: usize = 4_096;
const MAX_BINARIES: usize = 4_096;
const MAX_PORT_ENTRIES: usize = 65_536;
const MAX_L7_RULES: usize = 16_384;
const MAX_IP_RANGES: usize = 4_096;
const MAX_PATTERN_BYTES: usize = 4 * 1024;
const MAX_TOTAL_PATTERN_BYTES: usize = 1024 * 1024;

/// Parser error for a containment input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePolicyError(String);

impl fmt::Display for ParsePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ParsePolicyError {}

/// Policy representation used by boundary checking, projected from the canonical
/// authored schema. Construction always goes through the shared bounded parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentPolicy {
    filesystem_policy: FilesystemPolicy,
    network_policies: BTreeMap<String, NetworkRule>,
    landlock: Option<LandlockPolicy>,
    process: Option<ProcessPolicy>,
    network_middlewares: BTreeMap<String, NetworkMiddleware>,
}

trait ContainmentEndpoint {
    fn protocol_kind(&self) -> Protocol;
}

impl ContainmentEndpoint for Endpoint {
    fn protocol_kind(&self) -> Protocol {
        if self.is_l4() {
            Protocol::L4
        } else {
            Protocol::Rest
        }
    }
}

/// Parse one captured YAML or JSON input using the canonical authored schema.
pub fn parse_policy_str(source: &str) -> Result<ContainmentPolicy, ParsePolicyError> {
    let document = openshell_policy_schema::parse_policy(source)
        .map_err(|error| ParsePolicyError(format!("invalid policy: {error:#}")))?;
    let mut filesystem_policy = document.effective_filesystem_policy();
    normalize_filesystem_paths(&mut filesystem_policy)?;
    let PolicyDocument {
        version: _,
        filesystem_policy: _,
        network_policies,
        landlock,
        process,
        network_middlewares,
    } = document;
    Ok(ContainmentPolicy {
        filesystem_policy,
        network_policies,
        landlock,
        process,
        network_middlewares,
    })
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
    if path.split('/').any(|part| part == "..") {
        return Err(ParsePolicyError(format!(
            "filesystem path '{path}' contains an unsupported '..' segment"
        )));
    }
    Ok(openshell_policy_schema::normalize_path(path))
}

/// Per-invocation solver limits. These never modify Z3 global parameters.
///
/// Construct options with [`CheckOptions::new`]. The struct is extensible so
/// future settings can receive defaults without breaking callers.
///
/// ```compile_fail
/// use openshell_prover::containment::CheckOptions;
/// use std::time::Duration;
///
/// let _options = CheckOptions { timeout: Duration::from_secs(1) };
/// ```
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct CheckOptions {
    pub timeout: Duration,
}

impl CheckOptions {
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

/// Stable reason identifiers for automation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
pub enum CheckDomain {
    Filesystem,
    NetworkL4,
    NetworkRest,
    Process,
    Landlock,
}

impl CheckDomain {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::NetworkL4 => "network_l4",
            Self::NetworkRest => "network_rest",
            Self::Process => "process",
            Self::Landlock => "landlock",
        }
    }
}

/// Scope attached to every completed or recoverably incomplete check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CheckScope {
    pub model_version: &'static str,
    pub policy_version: u32,
    pub domains: &'static [CheckDomain],
}

static DOMAINS: &[CheckDomain] = &[
    CheckDomain::Filesystem,
    CheckDomain::NetworkL4,
    CheckDomain::NetworkRest,
    CheckDomain::Process,
    CheckDomain::Landlock,
];
fn check_scope() -> &'static CheckScope {
    static SCOPE: CheckScope = CheckScope {
        model_version: "boundary-v2",
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
#[non_exhaustive]
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
#[non_exhaustive]
pub enum Counterexample {
    #[non_exhaustive]
    Process {
        field: &'static str,
        boundary: String,
        candidate: String,
    },
    #[non_exhaustive]
    Landlock { boundary: String, candidate: String },
    #[non_exhaustive]
    Filesystem {
        access: FilesystemAccess,
        path: String,
    },
    #[non_exhaustive]
    Network {
        binary: Option<String>,
        ancestor_binary: Option<String>,
        binary_identity_required: bool,
        host: String,
        destination_ip: IpAddr,
        trusted_gateway: bool,
        port: u16,
        protocol: Protocol,
        method: Option<String>,
        path: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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

/// Result of a boundary proof attempt.
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
    ip: ip::SymbolicIp,
    trusted_gateway: Bool,
}

enum NetworkSolve {
    Within,
    Exceeds(Counterexample),
    Incomplete(CheckResult),
}

/// Determine whether every modeled candidate action is allowed by `boundary`.
#[must_use]
pub fn check_within_boundary(
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    options: CheckOptions,
) -> CheckResult {
    check_within_boundary_inner(boundary, candidate, options, None)
}

/// Determine containment while allowing a caller-owned cancellation flag to
/// interrupt the solver. The caller remains responsible for signal handling.
#[must_use]
pub fn check_within_boundary_cancellable(
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    options: CheckOptions,
    cancelled: &AtomicBool,
) -> CheckResult {
    check_within_boundary_inner(boundary, candidate, options, Some(cancelled))
}

fn check_within_boundary_inner(
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    options: CheckOptions,
    cancelled: Option<&AtomicBool>,
) -> CheckResult {
    if let Some(result) =
        preflight_and_validate_policies(boundary, candidate, options, cancelled, |policy| {
            validate_supported_policy(policy, cancelled)
        })
    {
        return result;
    }
    if let Some(reason) = unresolved_workdir_reason(boundary, candidate) {
        return unsupported(ReasonCode::UnresolvedWorkdir, reason);
    }
    if let Some(result) = execution::check(boundary, candidate) {
        return result;
    }
    if boundary == candidate {
        return CheckResult::Within(WithinEvidence);
    }
    let filesystem_result = check_filesystem(boundary, candidate);
    if let Some(result @ CheckResult::Exceeds(_)) = filesystem_result {
        return result;
    }
    let started = Instant::now();
    for binary_identity_required in [false, true] {
        if binary_identity_required && has_ambiguous_candidate_binary_path(boundary, candidate) {
            return unsupported(
                ReasonCode::UnresolvedBinaryPath,
                "network containment depends on image-specific binary symlink resolution"
                    .to_owned(),
            );
        }
        match solve_network_mode(
            boundary,
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
    }
    if unresolved_exact_deny_symlink(boundary, candidate) {
        return unsupported(
            ReasonCode::UnresolvedBinaryPath,
            "network deny containment depends on image-specific exact binary symlink resolution"
                .to_owned(),
        );
    }
    filesystem_result.unwrap_or(CheckResult::Within(WithinEvidence))
}

fn preflight_and_validate_policies<F>(
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    options: CheckOptions,
    cancelled: Option<&AtomicBool>,
    mut validate: F,
) -> Option<CheckResult>
where
    F: FnMut(&ContainmentPolicy) -> Result<(), PolicyValidationError>,
{
    // Cancellation and aggregate limits intentionally take precedence over
    // semantic shape errors. This keeps validation work bounded and lets an
    // already-cancelled invocation stop before inspecting either policy.
    if cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        return Some(cancelled_result());
    }
    if let Some(reason) = resource_limit_reason(boundary, candidate) {
        if cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Some(cancelled_result());
        }
        return Some(CheckResult::Inconclusive(ReasonEvidence {
            code: ReasonCode::ResourceLimit,
            reason,
        }));
    }
    if options.timeout.is_zero() {
        return Some(CheckResult::Inconclusive(ReasonEvidence {
            code: ReasonCode::SolverTimeout,
            reason: "solver timeout must be positive".to_owned(),
        }));
    }
    for (context, policy) in [("boundary", boundary), ("candidate", candidate)] {
        match validate(policy) {
            Ok(()) => {}
            Err(PolicyValidationError::Cancelled) => return Some(cancelled_result()),
            Err(PolicyValidationError::Unsupported(feature)) => {
                return Some(unsupported(
                    feature.reason_code,
                    format!("{context} policy {}", feature.detail),
                ));
            }
        }
    }
    if cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        return Some(cancelled_result());
    }
    None
}

fn solve_network_mode(
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    binary_identity_required: bool,
    started: Instant,
    timeout: Duration,
    cancelled: Option<&AtomicBool>,
) -> NetworkSolve {
    if network_is_structurally_contained(boundary, candidate, binary_identity_required) {
        return NetworkSolve::Within;
    }
    if let Some(witness) = concrete_network_witness(boundary, candidate, binary_identity_required) {
        return NetworkSolve::Exceeds(witness);
    }
    let solver = Solver::new();
    let action = symbolic_action(if binary_identity_required {
        "strict_boundary_policy_action"
    } else {
        "relaxed_boundary_policy_action"
    });
    assert_action_domain(&solver, &action, binary_identity_required);
    solver.assert(
        Bool::and(&[
            policy_allows(candidate, &action, binary_identity_required),
            !policy_allows(boundary, &action, binary_identity_required),
        ])
        .simplify(),
    );

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
                counterexample_satisfies_predicate(boundary, candidate, counterexample)
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

/// A few concrete requests make common counterexamples cheap and readable.
/// Each is replayed against the full predicate. Failure to find one never
/// establishes containment: the unrestricted symbolic query still follows.
fn concrete_network_witness(
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    binary_identity_required: bool,
) -> Option<Counterexample> {
    for (rule, endpoint) in candidate
        .network_policies
        .values()
        .flat_map(|rule| rule.endpoints.iter().map(move |endpoint| (rule, endpoint)))
        .take(8)
    {
        let host = endpoint
            .host
            .to_ascii_lowercase()
            .replace("**", "a")
            .replace('*', "a");
        let binary = binary_identity_required.then(|| {
            rule.binaries.first().map_or_else(
                || "/usr/bin/worker".to_owned(),
                |binary| binary.path.replace("**", "a").replace('*', "a"),
            )
        });
        let method = endpoint
            .rules
            .first()
            .map_or("GET", |rule| rule.allow.method.as_str())
            .to_ascii_uppercase();
        let path = endpoint
            .rules
            .first()
            .map_or(endpoint.path.as_str(), |rule| rule.allow.path.as_str());
        let path = if path.is_empty() {
            "/".to_owned()
        } else {
            path.replace("**", "a").replace('*', "a")
        };
        if !is_canonical_dns_host(&host)
            || !is_canonical_rest_path(&path)
            || !is_http_method(&method)
        {
            continue;
        }
        for destination_ip in ip::sample_addresses(endpoint) {
            let witness = Counterexample::Network {
                binary: binary.clone(),
                ancestor_binary: binary.clone(),
                binary_identity_required,
                host: host.clone(),
                destination_ip,
                trusted_gateway: false,
                port: endpoint.effective_ports()[0],
                protocol: endpoint.protocol_kind(),
                method: (endpoint.protocol_kind() == Protocol::Rest).then(|| method.clone()),
                path: (endpoint.protocol_kind() == Protocol::Rest).then(|| path.clone()),
            };
            if counterexample_satisfies_predicate(boundary, candidate, &witness) {
                return Some(witness);
            }
        }
    }
    None
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
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    binary_identity_required: bool,
) -> bool {
    if boundary
        .network_policies
        .values()
        .flat_map(|rule| &rule.endpoints)
        .any(|endpoint| !endpoint.deny_rules.is_empty())
    {
        return false;
    }
    candidate.network_policies.values().all(|candidate_rule| {
        boundary.network_policies.values().any(|boundary_rule| {
            rule_structurally_contains(boundary_rule, candidate_rule, binary_identity_required)
        })
    })
}

fn rule_structurally_contains(
    boundary: &NetworkRule,
    candidate: &NetworkRule,
    binary_identity_required: bool,
) -> bool {
    (!binary_identity_required
        || candidate.binaries.iter().all(|candidate_binary| {
            boundary
                .binaries
                .iter()
                .any(|boundary_binary| boundary_binary.path == candidate_binary.path)
        }))
        && candidate.endpoints.iter().all(|candidate_endpoint| {
            boundary.endpoints.iter().any(|boundary_endpoint| {
                rest_endpoint_structurally_contains(boundary_endpoint, candidate_endpoint)
            })
        })
}

fn rest_endpoint_structurally_contains(boundary: &Endpoint, candidate: &Endpoint) -> bool {
    if boundary.protocol_kind() != Protocol::Rest
        || candidate.protocol_kind() != Protocol::Rest
        || !boundary.host.eq_ignore_ascii_case(&candidate.host)
        || boundary.path != candidate.path
        || boundary.allowed_ips != candidate.allowed_ips
        || !candidate
            .effective_ports()
            .iter()
            .all(|port| boundary.effective_ports().contains(port))
        || !boundary.access.is_empty()
        || !candidate.access.is_empty()
        || !boundary.deny_rules.is_empty()
        || !candidate.deny_rules.is_empty()
    {
        return false;
    }

    candidate.rules.iter().all(|candidate_rule| {
        if candidate_rule.allow.method.is_empty() {
            return false;
        }
        boundary.rules.iter().any(|boundary_rule| {
            method_pattern_contains(&boundary_rule.allow.method, &candidate_rule.allow.method)
                && path_pattern_contains(&boundary_rule.allow.path, &candidate_rule.allow.path)
        })
    })
}

fn method_pattern_contains(boundary: &str, candidate: &str) -> bool {
    boundary == "*"
        || boundary.eq_ignore_ascii_case(candidate)
        || (boundary.eq_ignore_ascii_case("GET") && candidate.eq_ignore_ascii_case("HEAD"))
}

fn path_pattern_contains(boundary: &str, candidate: &str) -> bool {
    // Inputs are already validated. Keep this sufficient proof deliberately
    // limited to equality and a terminal recursive path segment.
    let boundary = if boundary.is_empty() { "**" } else { boundary };
    let candidate = if candidate.is_empty() {
        "**"
    } else {
        candidate
    };
    boundary == candidate
        || boundary == "**"
        || boundary.strip_suffix("/**").is_some_and(|prefix| {
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
        ip: ip::SymbolicIp::new(name),
        trusted_gateway: Bool::new_const(format!("{name}_trusted_gateway")),
    }
}

fn assert_action_domain(solver: &Solver, action: &SymbolicAction, binary_identity_required: bool) {
    action.ip.assert_domain(solver);
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
    Bool::and(&[
        allowed,
        !denied,
        ip::policy_allows(policy, action, binary_identity_required),
    ])
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
    match AccessPreset::parse(&endpoint.access) {
        Some(AccessPreset::Full) => any_method_matches(action, "**"),
        Some(preset) => methods_match(action, preset.methods("rest"), "**"),
        None => bool_or(
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
        destination_ip: action.ip.decode(model)?,
        trusted_gateway: model.eval(&action.trusted_gateway, true)?.as_bool()?,
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
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
    counterexample: &Counterexample,
) -> bool {
    let Counterexample::Network {
        binary,
        ancestor_binary,
        binary_identity_required,
        host,
        destination_ip,
        trusted_gateway,
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
        ip: ip::SymbolicIp::concrete(*destination_ip),
        trusted_gateway: Bool::from_bool(*trusted_gateway),
    };
    Bool::and(&[
        policy_allows(candidate, &concrete, *binary_identity_required),
        !policy_allows(boundary, &concrete, *binary_identity_required),
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
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
) -> Option<String> {
    let boundary_writes = &boundary.filesystem_policy.read_write;
    let mut boundary_reads = boundary.filesystem_policy.read_only.clone();
    boundary_reads.extend(boundary_writes.iter().cloned());

    if candidate.filesystem_policy.include_workdir
        && !boundary.filesystem_policy.include_workdir
        && !boundary_writes.iter().any(|path| path == "/")
    {
        return Some(
            "candidate filesystem authority depends on an unresolved image workdir".to_owned(),
        );
    }
    if boundary.filesystem_policy.include_workdir
        && (candidate
            .filesystem_policy
            .read_write
            .iter()
            .any(|path| !path_is_covered(path, boundary_writes))
            || candidate
                .filesystem_policy
                .read_only
                .iter()
                .any(|path| !path_is_covered(path, &boundary_reads)))
    {
        return Some(
            "boundary filesystem authority depends on an unresolved image workdir".to_owned(),
        );
    }
    None
}

// The glob crate rejects some runtime-supported patterns (for example `cu**`).
// Its parse errors cannot rule out overlap in either symlink uncertainty guard.
fn has_ambiguous_candidate_binary_path(
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
) -> bool {
    boundary.network_policies.values().any(|boundary_rule| {
        boundary_rule
            .binaries
            .iter()
            .filter(|binary| binary.path.contains('*') && binary.path != "/**")
            .any(|boundary_binary| {
                candidate.network_policies.values().any(|candidate_rule| {
                    endpoint_authority_sets_overlap(
                        &candidate_rule.endpoints,
                        &boundary_rule.endpoints,
                    ) && candidate_rule.binaries.iter().any(|candidate_binary| {
                        !candidate_binary.path.contains('*')
                            && glob::Pattern::new(&boundary_binary.path)
                                .map_or(true, |pattern| pattern.matches(&candidate_binary.path))
                            && !boundary.network_policies.values().any(|exact_rule| {
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
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
) -> bool {
    boundary.network_policies.values().any(|boundary_rule| {
        let boundary_deny_endpoints = boundary_rule
            .endpoints
            .iter()
            .filter(|endpoint| !endpoint.deny_rules.is_empty())
            .collect::<Vec<_>>();
        if boundary_deny_endpoints.is_empty() {
            return false;
        }
        boundary_rule
            .binaries
            .iter()
            .filter(|binary| !binary.path.contains('*'))
            .any(|boundary_binary| {
                candidate.network_policies.values().any(|candidate_rule| {
                    let endpoints_overlap = candidate_rule
                        .endpoints
                        .iter()
                        .filter(|endpoint| !endpoint.deny_rules.is_empty())
                        .any(|candidate_endpoint| {
                            boundary_deny_endpoints.iter().any(|boundary_endpoint| {
                                endpoint_authority_may_overlap(
                                    candidate_endpoint,
                                    boundary_endpoint,
                                )
                            })
                        });
                    endpoints_overlap
                        && candidate_rule.binaries.iter().any(|candidate_binary| {
                            candidate_binary.path.contains('*')
                                && candidate_binary.path != "/**"
                                && glob::Pattern::new(&candidate_binary.path)
                                    .map_or(true, |pattern| pattern.matches(&boundary_binary.path))
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
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
) -> Option<CheckResult> {
    let mut boundary_writes = boundary.filesystem_policy.read_write.clone();
    if boundary.filesystem_policy.include_workdir {
        boundary_writes.push(WORKDIR_SYMBOL.to_owned());
    }
    let mut boundary_reads = boundary.filesystem_policy.read_only.clone();
    boundary_reads.extend(boundary_writes.iter().cloned());

    let mut unresolved = None;
    for (access, candidates, maxima) in [
        (
            FilesystemAccess::Write,
            &candidate.filesystem_policy.read_write,
            &boundary_writes,
        ),
        (
            FilesystemAccess::Read,
            &candidate.filesystem_policy.read_only,
            &boundary_reads,
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
                    "filesystem {access} containment for '{path}' depends on sandbox path resolution; use matching paths in candidate and boundary",
                    access = access.as_str()
                ),
            ));
        }
    }
    unresolved
}

fn path_is_covered(candidate: &str, boundary_paths: &[String]) -> bool {
    boundary_paths
        .iter()
        .any(|boundary| boundary == "/" || candidate == boundary)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnsupportedFeature {
    reason_code: ReasonCode,
    detail: String,
}

enum PolicyValidationError {
    Unsupported(UnsupportedFeature),
    Cancelled,
}

impl From<UnsupportedFeature> for PolicyValidationError {
    fn from(feature: UnsupportedFeature) -> Self {
        Self::Unsupported(feature)
    }
}

impl UnsupportedFeature {
    fn policy_shape(detail: impl Into<String>) -> Self {
        Self {
            reason_code: ReasonCode::UnsupportedPolicyShape,
            detail: detail.into(),
        }
    }
}

fn validate_supported_policy(
    policy: &ContainmentPolicy,
    cancelled: Option<&AtomicBool>,
) -> Result<(), PolicyValidationError> {
    validate_supported_common_policy(policy)?;
    for (rule_name, rule) in &policy.network_policies {
        if cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Err(PolicyValidationError::Cancelled);
        }
        validate_supported_network_rule(rule_name, rule, cancelled)?;
    }
    validate_no_cross_protocol_overlap(policy, cancelled)
}

fn validate_supported_common_policy(policy: &ContainmentPolicy) -> Result<(), UnsupportedFeature> {
    if let Some(reason) = execution::unsupported_reason(policy) {
        return Err(UnsupportedFeature::policy_shape(reason));
    }
    if !policy.network_middlewares.is_empty() {
        return Err(UnsupportedFeature::policy_shape(
            "uses network middleware controls",
        ));
    }
    Ok(())
}

fn validate_supported_network_rule(
    rule_name: &str,
    rule: &NetworkRule,
    cancelled: Option<&AtomicBool>,
) -> Result<(), PolicyValidationError> {
    for binary in &rule.binaries {
        if cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Err(PolicyValidationError::Cancelled);
        }
        validate_supported_binary(rule_name, binary)?;
    }
    for endpoint in &rule.endpoints {
        if cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Err(PolicyValidationError::Cancelled);
        }
        validate_supported_endpoint(rule_name, endpoint)?;
    }
    Ok(())
}

fn validate_supported_binary(rule_name: &str, binary: &Binary) -> Result<(), UnsupportedFeature> {
    if let Some(reason) = unsupported_network_literal(&binary.path) {
        return Err(UnsupportedFeature::policy_shape(format!(
            "rule '{rule_name}' binary path {reason}"
        )));
    }
    if binary.path.is_empty()
        || !is_canonical_pattern_path(&binary.path)
        || unsupported_glob(&binary.path)
    {
        return Err(UnsupportedFeature::policy_shape(format!(
            "rule '{rule_name}' uses an unsupported binary"
        )));
    }
    Ok(())
}

fn validate_supported_endpoint(
    rule_name: &str,
    endpoint: &Endpoint,
) -> Result<(), UnsupportedFeature> {
    let context = format!("rule '{rule_name}'");
    validate_shared_endpoint(&context, endpoint)?;
    validate_supported_endpoint_extensions(&context, endpoint)?;
    match validate_supported_protocol(&context, endpoint)? {
        Protocol::L4 => validate_supported_l4(&context, endpoint),
        Protocol::Rest => validate_supported_rest(&context, endpoint),
    }
}

fn validate_shared_endpoint(context: &str, endpoint: &Endpoint) -> Result<(), UnsupportedFeature> {
    if let Some(reason) = unsupported_network_literal(&endpoint.host) {
        return Err(UnsupportedFeature::policy_shape(format!(
            "{context} endpoint host {reason}"
        )));
    }
    if let Some(reason) = unsupported_network_literal(&endpoint.path) {
        return Err(UnsupportedFeature::policy_shape(format!(
            "{context} endpoint path {reason}"
        )));
    }
    if endpoint.host.is_empty()
        || endpoint.effective_ports().is_empty()
        || (endpoint.port != 0 && !endpoint.ports.is_empty())
    {
        return Err(UnsupportedFeature::policy_shape(format!(
            "{context} has no unambiguous host and port"
        )));
    }
    if unsupported_host_glob(&endpoint.host) {
        return Err(UnsupportedFeature::policy_shape(format!(
            "{context} endpoint host uses an unsupported pattern"
        )));
    }
    if unsupported_glob(&endpoint.path)
        || (!endpoint.path.is_empty() && !is_canonical_pattern_path(&endpoint.path))
    {
        return Err(UnsupportedFeature::policy_shape(format!(
            "{context} uses an unsupported glob"
        )));
    }
    if !endpoint.path.is_empty() && !endpoint.path.starts_with('/') {
        return Err(UnsupportedFeature::policy_shape(format!(
            "{context} uses a non-canonical endpoint path"
        )));
    }
    if endpoint.host.contains(':') {
        return Err(UnsupportedFeature::policy_shape(format!(
            "{context} uses an IP-literal shape outside the DNS host model"
        )));
    }
    Ok(())
}

fn validate_supported_endpoint_extensions(
    context: &str,
    endpoint: &Endpoint,
) -> Result<(), UnsupportedFeature> {
    if !matches!(endpoint.tls.as_str(), "" | "terminate" | "passthrough")
        || endpoint.allow_encoded_slash
        || endpoint.websocket_credential_rewrite
        || endpoint.request_body_credential_rewrite
        || endpoint.allow_uninspected_credentials
    {
        return unsupported_endpoint_extension(context);
    }
    if let Some(reason) = ip::unsupported_endpoint(endpoint) {
        return Err(UnsupportedFeature::policy_shape(format!(
            "{context} {reason}"
        )));
    }
    validate_supported_graphql(context, endpoint)?;
    validate_supported_credentials(context, endpoint)?;
    validate_supported_json_rpc(context, endpoint)?;
    validate_supported_mcp(context, endpoint)
}

fn unsupported_endpoint_extension(context: &str) -> Result<(), UnsupportedFeature> {
    Err(UnsupportedFeature::policy_shape(format!(
        "{context} uses authority outside the initial model"
    )))
}

fn validate_supported_graphql(
    context: &str,
    endpoint: &Endpoint,
) -> Result<(), UnsupportedFeature> {
    if !endpoint.persisted_queries.is_empty()
        || !endpoint.graphql_persisted_queries.is_empty()
        || endpoint.graphql_max_body_bytes != 0
    {
        return unsupported_endpoint_extension(context);
    }
    Ok(())
}

fn validate_supported_credentials(
    context: &str,
    endpoint: &Endpoint,
) -> Result<(), UnsupportedFeature> {
    if !endpoint.credential_signing.is_empty()
        || !endpoint.signing_service.is_empty()
        || !endpoint.signing_region.is_empty()
        || endpoint.credential_binding.is_some()
    {
        return unsupported_endpoint_extension(context);
    }
    Ok(())
}

fn validate_supported_json_rpc(
    context: &str,
    endpoint: &Endpoint,
) -> Result<(), UnsupportedFeature> {
    if endpoint.json_rpc.is_some() {
        return unsupported_endpoint_extension(context);
    }
    Ok(())
}

fn validate_supported_mcp(context: &str, endpoint: &Endpoint) -> Result<(), UnsupportedFeature> {
    if endpoint.mcp.is_some() {
        return unsupported_endpoint_extension(context);
    }
    Ok(())
}

fn validate_supported_protocol(
    context: &str,
    endpoint: &Endpoint,
) -> Result<Protocol, UnsupportedFeature> {
    match endpoint.protocol.to_ascii_lowercase().as_str() {
        "" | "tcp" => Ok(Protocol::L4),
        "rest" => Ok(Protocol::Rest),
        _ => Err(UnsupportedFeature::policy_shape(format!(
            "{context} uses protocol '{}'; only L4 TCP and REST are modeled",
            endpoint.protocol
        ))),
    }
}

fn validate_supported_l4(context: &str, endpoint: &Endpoint) -> Result<(), UnsupportedFeature> {
    if endpoint.protocol.eq_ignore_ascii_case("tcp") && endpoint.host.parse::<IpAddr>().is_ok() {
        return Err(UnsupportedFeature::policy_shape(format!(
            "{context} uses an IP literal with explicit TCP semantics"
        )));
    }
    if !endpoint.enforcement.is_empty()
        || !endpoint.access.is_empty()
        || !endpoint.path.is_empty()
        || !endpoint.rules.is_empty()
        || !endpoint.deny_rules.is_empty()
    {
        return Err(UnsupportedFeature::policy_shape(format!(
            "{context} mixes REST controls into L4 authority"
        )));
    }
    Ok(())
}

fn validate_supported_rest(context: &str, endpoint: &Endpoint) -> Result<(), UnsupportedFeature> {
    if endpoint.enforcement != "enforce" {
        return Err(UnsupportedFeature::policy_shape(format!(
            "{context} uses REST without enforced inspection"
        )));
    }
    if (!endpoint.access.is_empty() && !endpoint.rules.is_empty())
        || (endpoint.access.is_empty() && endpoint.rules.is_empty())
        || (!endpoint.access.is_empty() && AccessPreset::parse(&endpoint.access).is_none())
    {
        return Err(UnsupportedFeature::policy_shape(format!(
            "{context} has an unsupported REST allow shape"
        )));
    }
    for rule in &endpoint.rules {
        if let Some(reason) = unsupported_network_literal(&rule.allow.method) {
            return Err(UnsupportedFeature::policy_shape(format!(
                "{context} REST allow method {reason}"
            )));
        }
        if let Some(reason) = unsupported_network_literal(&rule.allow.path) {
            return Err(UnsupportedFeature::policy_shape(format!(
                "{context} REST allow path {reason}"
            )));
        }
        if unsupported_allow(&rule.allow) {
            return Err(UnsupportedFeature::policy_shape(format!(
                "{context} uses an unsupported REST allow rule"
            )));
        }
    }
    for rule in &endpoint.deny_rules {
        if let Some(reason) = unsupported_network_literal(&rule.method) {
            return Err(UnsupportedFeature::policy_shape(format!(
                "{context} REST deny method {reason}"
            )));
        }
        if let Some(reason) = unsupported_network_literal(&rule.path) {
            return Err(UnsupportedFeature::policy_shape(format!(
                "{context} REST deny path {reason}"
            )));
        }
        if unsupported_deny(rule) {
            return Err(UnsupportedFeature::policy_shape(format!(
                "{context} uses an unsupported REST deny rule"
            )));
        }
    }
    Ok(())
}

struct AttributeSummary<T> {
    first: Option<T>,
    mixed: bool,
}

impl<T: Clone + Eq> AttributeSummary<T> {
    fn conflicts(&self, value: &T) -> bool {
        self.mixed || self.first.as_ref().is_some_and(|first| first != value)
    }

    fn insert(&mut self, value: &T) {
        if let Some(first) = &self.first {
            self.mixed |= first != value;
        } else {
            self.first = Some(value.clone());
        }
    }
}

impl<T> Default for AttributeSummary<T> {
    fn default() -> Self {
        Self {
            first: None,
            mixed: false,
        }
    }
}

struct AuthorityAttributeIndex<T> {
    all: BTreeMap<u16, AttributeSummary<T>>,
    wildcards: BTreeMap<u16, AttributeSummary<T>>,
    exact: BTreeMap<String, BTreeMap<u16, AttributeSummary<T>>>,
}

impl<T> Default for AuthorityAttributeIndex<T> {
    fn default() -> Self {
        Self {
            all: BTreeMap::new(),
            wildcards: BTreeMap::new(),
            exact: BTreeMap::new(),
        }
    }
}

impl<T: Clone + Eq> AuthorityAttributeIndex<T> {
    fn overlaps_with_different(&self, host: &str, ports: &[u16], value: &T) -> bool {
        ports.iter().any(|port| {
            if host.contains('*') {
                self.all
                    .get(port)
                    .is_some_and(|summary| summary.conflicts(value))
            } else {
                self.wildcards
                    .get(port)
                    .is_some_and(|summary| summary.conflicts(value))
                    || self
                        .exact
                        .get(host)
                        .and_then(|ports_for_host| ports_for_host.get(port))
                        .is_some_and(|summary| summary.conflicts(value))
            }
        })
    }

    fn insert(&mut self, host: &str, ports: &[u16], value: &T) {
        for port in ports {
            self.all.entry(*port).or_default().insert(value);
            if host.contains('*') {
                self.wildcards.entry(*port).or_default().insert(value);
            } else {
                self.exact
                    .entry(host.to_owned())
                    .or_default()
                    .entry(*port)
                    .or_default()
                    .insert(value);
            }
        }
    }
}

fn validate_no_cross_protocol_overlap(
    policy: &ContainmentPolicy,
    cancelled: Option<&AtomicBool>,
) -> Result<(), PolicyValidationError> {
    let mut protocols = AuthorityAttributeIndex::default();
    let mut allowed_ips = AuthorityAttributeIndex::default();
    let mut different_allowed_ips_overlap = false;
    let mut different_protocols_overlap = false;
    for endpoint in policy
        .network_policies
        .values()
        .flat_map(|rule| &rule.endpoints)
    {
        if cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Err(PolicyValidationError::Cancelled);
        }
        let host = endpoint.host.to_ascii_lowercase();
        let ports = endpoint.effective_ports();
        let protocol = endpoint.protocol_kind();
        different_allowed_ips_overlap |=
            allowed_ips.overlaps_with_different(&host, &ports, &endpoint.allowed_ips);
        different_protocols_overlap |= protocols.overlaps_with_different(&host, &ports, &protocol);
        allowed_ips.insert(&host, &ports, &endpoint.allowed_ips);
        protocols.insert(&host, &ports, &protocol);
    }
    if different_allowed_ips_overlap {
        return Err(UnsupportedFeature::policy_shape(
            "has overlapping endpoints with different allowed_ips; runtime first-endpoint selection is not modeled",
        )
        .into());
    }
    let mut different_implicit_ip_modes_overlap = false;
    for rule in policy.network_policies.values() {
        let mut implicit_modes = AuthorityAttributeIndex::default();
        for endpoint in &rule.endpoints {
            if cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                return Err(PolicyValidationError::Cancelled);
            }
            if endpoint.allowed_ips.is_empty() {
                let host = endpoint.host.to_ascii_lowercase();
                let ports = endpoint.effective_ports();
                let wildcard = endpoint.host.contains('*');
                different_implicit_ip_modes_overlap |=
                    implicit_modes.overlaps_with_different(&host, &ports, &wildcard);
                implicit_modes.insert(&host, &ports, &wildcard);
            }
        }
    }
    if different_implicit_ip_modes_overlap {
        return Err(UnsupportedFeature::policy_shape(
            "has overlapping exact and wildcard endpoints with different implicit destination IP modes",
        )
        .into());
    }
    if different_protocols_overlap {
        return Err(UnsupportedFeature::policy_shape(
            "contains overlapping L4 and REST endpoints whose inspection selection is not modeled",
        )
        .into());
    }
    Ok(())
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
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
) -> Option<String> {
    let policies = [boundary, candidate];
    let rule_count = policies
        .iter()
        .map(|policy| policy.network_policies.len())
        .fold(0_usize, usize::saturating_add);
    if rule_count > MAX_RULES {
        return Some(resource_limit_detail("rules", rule_count, MAX_RULES));
    }

    let endpoint_count = policies
        .iter()
        .flat_map(|policy| policy.network_policies.values())
        .map(|rule| rule.endpoints.len())
        .fold(0_usize, usize::saturating_add);
    if endpoint_count > MAX_ENDPOINTS {
        return Some(resource_limit_detail(
            "endpoints",
            endpoint_count,
            MAX_ENDPOINTS,
        ));
    }

    let binary_count = policies
        .iter()
        .flat_map(|policy| policy.network_policies.values())
        .map(|rule| rule.binaries.len())
        .fold(0_usize, usize::saturating_add);
    if binary_count > MAX_BINARIES {
        return Some(resource_limit_detail(
            "binaries",
            binary_count,
            MAX_BINARIES,
        ));
    }

    let mut port_entry_count = 0_usize;
    let mut l7_count = 0_usize;
    let mut ip_range_count = 0_usize;
    let mut total_pattern_bytes = 0_usize;
    for policy in policies {
        for path in policy
            .filesystem_policy
            .read_only
            .iter()
            .chain(&policy.filesystem_policy.read_write)
        {
            if let Some(reason) = account_pattern_bytes(path, &mut total_pattern_bytes) {
                return Some(reason);
            }
        }
        for rule in policy.network_policies.values() {
            for binary in &rule.binaries {
                if let Some(reason) = account_pattern_bytes(&binary.path, &mut total_pattern_bytes)
                {
                    return Some(reason);
                }
            }
            for endpoint in &rule.endpoints {
                let endpoint_port_entries =
                    usize::from(endpoint.ports.is_empty() && endpoint.port != 0)
                        .max(endpoint.ports.len());
                port_entry_count = port_entry_count.saturating_add(endpoint_port_entries);
                if port_entry_count > MAX_PORT_ENTRIES {
                    return Some(resource_limit_detail(
                        "port_entries",
                        port_entry_count,
                        MAX_PORT_ENTRIES,
                    ));
                }

                l7_count = l7_count
                    .saturating_add(endpoint.rules.len())
                    .saturating_add(endpoint.deny_rules.len());
                if l7_count > MAX_L7_RULES {
                    return Some(resource_limit_detail("l7_rules", l7_count, MAX_L7_RULES));
                }

                ip_range_count = ip_range_count.saturating_add(endpoint.allowed_ips.len());
                if ip_range_count > MAX_IP_RANGES {
                    return Some(resource_limit_detail(
                        "ip_ranges",
                        ip_range_count,
                        MAX_IP_RANGES,
                    ));
                }

                for value in [&endpoint.host, &endpoint.path] {
                    if let Some(reason) = account_pattern_bytes(value, &mut total_pattern_bytes) {
                        return Some(reason);
                    }
                }
                for range in &endpoint.allowed_ips {
                    if let Some(reason) = account_pattern_bytes(range, &mut total_pattern_bytes) {
                        return Some(reason);
                    }
                }
                for rule in &endpoint.rules {
                    for value in [&rule.allow.path, &rule.allow.method] {
                        if let Some(reason) = account_pattern_bytes(value, &mut total_pattern_bytes)
                        {
                            return Some(reason);
                        }
                    }
                }
                for rule in &endpoint.deny_rules {
                    for value in [&rule.path, &rule.method] {
                        if let Some(reason) = account_pattern_bytes(value, &mut total_pattern_bytes)
                        {
                            return Some(reason);
                        }
                    }
                }
            }
        }
    }
    None
}

fn account_pattern_bytes(value: &str, total: &mut usize) -> Option<String> {
    if value.len() > MAX_PATTERN_BYTES {
        return Some(resource_limit_detail(
            "longest_pattern",
            value.len(),
            MAX_PATTERN_BYTES,
        ));
    }
    *total = total.saturating_add(value.len());
    (*total > MAX_TOTAL_PATTERN_BYTES)
        .then(|| resource_limit_detail("pattern_bytes", *total, MAX_TOTAL_PATTERN_BYTES))
}

fn resource_limit_detail(metric: &str, observed: usize, limit: usize) -> String {
    format!("containment model exceeds resource limit ({metric}={observed}, limit={limit})")
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
        || (!rule.path.is_empty() && !rule.path.starts_with('/'))
        || (!rule.path.is_empty() && !is_canonical_pattern_path(&rule.path))
        || unsupported_glob(&rule.path)
}

fn is_canonical_pattern_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains("//")
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
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
    use std::cell::Cell;
    use std::fmt::Write as _;

    fn parse(value: &str) -> ContainmentPolicy {
        parse_policy_str(value).expect("valid policy")
    }

    fn options() -> CheckOptions {
        CheckOptions::new(Duration::from_secs(10))
    }

    // Keep address permissions identical when testing hostname/binary logic:
    // an exact declaration without allowed_ips permits private addresses,
    // whereas a wildcard declaration without allowed_ips does not.
    fn fixed_test_ips(mut policy: ContainmentPolicy) -> ContainmentPolicy {
        for endpoint in policy
            .network_policies
            .values_mut()
            .flat_map(|rule| &mut rule.endpoints)
        {
            endpoint.allowed_ips = vec!["8.8.8.0/24".to_owned()];
        }
        policy
    }

    #[test]
    fn filesystem_containment_and_counterexample() {
        let boundary =
            parse("version: 1\nfilesystem_policy: { read_only: [/usr], read_write: [/tmp] }\n");
        let within = parse("version: 1\nfilesystem_policy: { read_only: [/usr, /tmp] }\n");
        let exceeds = parse("version: 1\nfilesystem_policy: { read_write: [/workspace] }\n");
        assert!(matches!(
            check_within_boundary(&boundary, &within, options()),
            CheckResult::Within(_)
        ));
        assert!(matches!(
            check_within_boundary(
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
            check_within_boundary(&explicit, &omitted, options()),
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
            check_within_boundary(&l4, &rest, options()),
            CheckResult::Within(_)
        ));
        assert!(matches!(
            check_within_boundary(&rest, &l4, options()),
            CheckResult::Exceeds(_)
        ));
    }

    #[test]
    fn network_containment_covers_disabled_binary_identity() {
        let boundary = parse("version: 1\n");
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: []\n",
        );
        let result = check_within_boundary(&boundary, &candidate, options());
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
            let result = check_within_boundary(&parse("version: 1\n"), &candidate, options());
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
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  boundary:\n    endpoints: [{ host: '*.example.com', port: 443 }]\n    binaries: []\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  candidate:\n    endpoints: [{ host: api_internal.example.com, port: 443 }]\n    binaries: []\n",
        );
        let boundary = fixed_test_ips(boundary);
        let candidate = fixed_test_ips(candidate);
        assert!(matches!(
            check_within_boundary(&boundary, &candidate, options()),
            CheckResult::Within(_)
        ));

        let exact_boundary = parse(
            "version: 1\nnetwork_policies:\n  boundary:\n    endpoints: [{ host: _service.example.com, port: 443, protocol: tcp }]\n    binaries: []\n",
        );
        let exact_candidate = parse(
            "version: 1\nnetwork_policies:\n  candidate:\n    endpoints: [{ host: _service.example.com, port: 443, protocol: tcp }]\n    binaries: []\n",
        );
        assert!(matches!(
            check_within_boundary(&exact_boundary, &exact_candidate, options()),
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
                check_within_boundary(&parse("version: 1\n"), &candidate, options()),
                CheckResult::Unsupported(ref evidence)
                    if evidence.reason_code() == ReasonCode::UnsupportedPolicyShape
                        && evidence.reason().contains("endpoint host")
            ));
        }
    }

    #[test]
    fn differing_binary_selectors_are_checked_when_identity_is_required() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/wget }]\n",
        );
        let result = check_within_boundary(&boundary, &candidate, options());
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
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: full\n        deny_rules: [{ method: DELETE, path: /** }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: DELETE, path: /private/resource } }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let result = check_within_boundary(&boundary, &candidate, options());
        assert!(matches!(result, CheckResult::Exceeds(_)), "{result:?}");
    }

    #[test]
    fn host_wildcard_zero_length_suffix_preserves_exact_deny() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: 'api*.example.com', port: 443, protocol: rest, enforcement: enforce, access: full }\n    binaries: [{ path: /usr/bin/curl }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: full\n        deny_rules: [{ method: GET, path: '/**' }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: 'api*.example.com', port: 443, protocol: rest, enforcement: enforce, access: full }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let result = check_within_boundary(&boundary, &candidate, options());
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
    fn ancestor_binary_can_supply_a_boundary_deny() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: /usr/bin/curl }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-only\n        deny_rules: [{ method: '*', path: '/**' }]\n    binaries: [{ path: /usr/bin/python3 }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: /usr/bin/curl }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-only\n        deny_rules: [{ method: '*', path: '/**' }]\n    binaries: [{ path: /usr/bin/node }]\n",
        );
        let result = check_within_boundary(&boundary, &candidate, options());
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
    fn exact_boundary_deny_under_candidate_glob_requires_image_resolution() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: '/**' }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-only\n        deny_rules: [{ method: '*', path: '/**' }]\n    binaries: [{ path: /venv/bin/python }]\n",
        );
        for pattern in ["/venv/bin/*", "/venv/bin/py**", "/venv/bin/**thon"] {
            let candidate = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: '/**' }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-only\n        deny_rules: [{ method: '*', path: '/**' }]\n    binaries: [{ path: 'BINARY_GLOB' }]\n".replace("BINARY_GLOB", pattern).as_str(),
        );
            assert!(matches!(
                check_within_boundary(&boundary, &candidate, options()),
                CheckResult::Unsupported(ref evidence)
                    if evidence.reason_code() == ReasonCode::UnresolvedBinaryPath
            ));
        }
    }

    #[test]
    fn definite_network_expansion_precedes_symlink_uncertainty() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: '/**' }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-only\n        deny_rules: [{ method: '*', path: '/**' }]\n    binaries: [{ path: /venv/bin/python }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: '/**' }]\n  extra:\n    endpoints: [{ host: extra.example.com, port: 443 }]\n    binaries: [{ path: '/**' }]\n  deny:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: read-only\n        deny_rules: [{ method: '*', path: '/**' }]\n    binaries: [{ path: '/venv/bin/*' }]\n",
        );
        assert!(matches!(
            check_within_boundary(&boundary, &candidate, options()),
            CheckResult::Exceeds(_)
        ));
    }

    #[test]
    fn overlapping_l4_and_rest_authority_is_unsupported() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - { host: api.example.com, port: 443 }\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_boundary(&boundary, &candidate, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnsupportedPolicyShape
        ));
    }

    #[test]
    fn methods_longer_than_sixty_four_bytes_are_in_the_action_domain() {
        let method = "X".repeat(65);
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, rules: [{ allow: { method: GET, path: '/**' } }] }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(&format!(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - {{ host: api.example.com, port: 443, protocol: rest, enforcement: enforce, rules: [{{ allow: {{ method: {method}, path: '/**' }} }}] }}\n    binaries: [{{ path: /usr/bin/curl }}]\n"
        ));
        let result = check_within_boundary(&boundary, &candidate, options());
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
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: GET, path: '/repos/**' } }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let narrower = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: GET, path: '/repos/NVIDIA/**' } }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let broader_method = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules: [{ allow: { method: POST, path: '/repos/NVIDIA/**' } }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let options = CheckOptions::new(Duration::from_secs(30));
        let result = check_within_boundary(&boundary, &narrower, options);
        assert!(matches!(result, CheckResult::Within(_)), "{result:?}");
        let result = check_within_boundary(&boundary, &broader_method, options);
        assert!(matches!(result, CheckResult::Exceeds(_)), "{result:?}");
    }

    #[test]
    fn structural_path_containment_requires_a_recursive_segment_boundary() {
        assert!(path_pattern_contains("/repos/**", "/repos/NVIDIA/**"));
        assert!(!path_pattern_contains("/repos/**", "/repository/NVIDIA/**"));
        assert!(!path_pattern_contains("/repos**", "/repos/NVIDIA/**"));
    }

    #[test]
    fn structural_fast_path_does_not_ignore_separate_boundary_denies() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, rules: [{ allow: { method: GET, path: '/repos/**' } }] }\n    binaries: [{ path: /usr/bin/curl }]\n  deny:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full, deny_rules: [{ method: GET, path: '/repos/private/**' }] }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  allow:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, rules: [{ allow: { method: GET, path: '/repos/private/**' } }] }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(!network_is_structurally_contained(
            &boundary, &candidate, true
        ));
    }

    #[test]
    fn unknown_and_environment_dependent_shapes_fail_closed() {
        assert!(parse_policy_str("version: 1\nfuture_authority: true\n").is_err());
        let workdir = parse("version: 1\nfilesystem_policy: { include_workdir: true }\n");
        let empty = parse("version: 1\nfilesystem_policy: {}\n");
        assert!(matches!(
            check_within_boundary(&empty, &workdir, options()),
            CheckResult::Unsupported(_)
        ));
        let boundary_workdir = parse("version: 1\nfilesystem_policy: { include_workdir: true }\n");
        let explicit = parse("version: 1\nfilesystem_policy: { read_write: [/workspace] }\n");
        assert!(matches!(
            check_within_boundary(&boundary_workdir, &explicit, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnresolvedWorkdir
        ));
    }

    #[test]
    fn mcp_authority_fails_closed_in_both_inputs() {
        let mcp = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: mcp\n        enforcement: enforce\n        access: full\n        mcp: {}\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let empty = parse("version: 1\n");
        for (boundary, candidate, side) in [(&mcp, &empty, "boundary"), (&empty, &mcp, "candidate")]
        {
            let result = check_within_boundary(boundary, candidate, options());
            assert!(
                matches!(
                    result,
                    CheckResult::Unsupported(ref evidence)
                        if evidence.reason_code() == ReasonCode::UnsupportedPolicyShape
                            && evidence.reason().contains(side)
                ),
                "side={side} result={result:?}"
            );
        }
    }

    #[test]
    fn exact_binary_under_a_boundary_glob_requires_image_resolution() {
        for pattern in ["/usr/bin/*3", "/usr/bin/py**", "/usr/bin/**3"] {
            let boundary = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: 'BINARY_GLOB' }]\n".replace("BINARY_GLOB", pattern).as_str(),
        );
            let candidate = parse(
                "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/python3 }]\n",
            );
            let result = check_within_boundary(&boundary, &candidate, options());
            assert!(
                matches!(
                    result,
                    CheckResult::Unsupported(ref evidence)
                        if evidence.reason_code() == ReasonCode::UnresolvedBinaryPath
                ),
                "{result:?}"
            );
        }
    }

    #[test]
    fn unrelated_boundary_glob_does_not_make_exact_containment_unsupported() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n  unrelated:\n    endpoints: [{ host: other.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_boundary(&boundary, &candidate, options()),
            CheckResult::Within(_)
        ));
    }

    #[test]
    fn redundant_boundary_glob_does_not_hide_equivalent_exact_containment() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n  glob:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let result = check_within_boundary(&boundary, &candidate, options());
        assert!(matches!(result, CheckResult::Within(_)), "{result:?}");
    }

    #[test]
    fn unrelated_universal_glob_does_not_hide_symlink_ambiguity() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  ambiguous:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n  unrelated:\n    endpoints: [{ host: unrelated.example.com, port: 80 }]\n    binaries: [{ path: '/**' }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_boundary(&boundary, &candidate, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnresolvedBinaryPath
        ));
    }

    #[test]
    fn shared_glob_does_not_hide_exact_binary_symlink_ambiguity() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  shared:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  shared:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }, { path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_boundary(&boundary, &candidate, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnresolvedBinaryPath
        ));
    }

    #[test]
    fn wildcard_endpoint_overlap_does_not_hide_symlink_ambiguity() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  shared:\n    endpoints: [{ host: '*.example.com', port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  shared:\n    endpoints: [{ host: '*.example.com', port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let boundary = fixed_test_ips(boundary);
        let candidate = fixed_test_ips(candidate);
        assert!(matches!(
            check_within_boundary(&boundary, &candidate, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnresolvedBinaryPath
        ));
    }

    #[test]
    fn ambiguity_check_preserves_shared_unrelated_globs() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n  ambiguous:\n    endpoints: [{ host: unrelated.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n  shared:\n    endpoints: [{ host: shared.example.com, port: 443 }, { host: mirror.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  exact:\n    endpoints: [{ host: api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n  shared:\n    endpoints: [{ host: mirror.example.com, port: 443 }, { host: shared.example.com, port: 443 }]\n    binaries: [{ path: '/usr/bin/*' }]\n",
        );
        assert!(matches!(
            check_within_boundary(&boundary, &candidate, options()),
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
        let reflexive = check_within_boundary(&first, &first, options());
        assert!(matches!(reflexive, CheckResult::Within(_)), "{reflexive:?}");
        assert!(matches!(
            check_within_boundary(&first, &second, options()),
            CheckResult::Within(_)
        ));
        assert!(matches!(
            check_within_boundary(&second, &first, options()),
            CheckResult::Within(_)
        ));
    }

    #[test]
    fn containment_is_transitive() {
        let broad = parse("version: 1\nfilesystem_policy: { read_write: [/workspace, /tmp] }\n");
        let middle = parse("version: 1\nfilesystem_policy: { read_write: [/workspace] }\n");
        let narrow = parse("version: 1\nfilesystem_policy: { read_only: [/workspace] }\n");
        assert!(matches!(
            check_within_boundary(&broad, &middle, options()),
            CheckResult::Within(_)
        ));
        assert!(matches!(
            check_within_boundary(&middle, &narrow, options()),
            CheckResult::Within(_)
        ));
        assert!(matches!(
            check_within_boundary(&broad, &narrow, options()),
            CheckResult::Within(_)
        ));
    }

    #[test]
    fn removed_binary_harness_field_is_invalid_input() {
        assert!(parse_policy_str(
            "version: 1\nnetwork_policies:\n  n:\n    binaries: [{ path: /usr/bin/curl, harness: true }]\n"
        ).is_err());
    }

    fn mixed_protocol_policy(endpoint_count: usize) -> ContainmentPolicy {
        let l4 = parse(
            "version: 1
network_policies:
  n:
    endpoints: [{ host: l4-0.example.com, port: 443 }]
",
        )
        .network_policies["n"]
            .endpoints[0]
            .clone();
        let rest = parse(
            "version: 1
network_policies:
  n:
    endpoints: [{ host: rest.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }]
",
        )
        .network_policies["n"]
            .endpoints[0]
            .clone();
        let l4_count = endpoint_count / 2;
        let mut endpoints = Vec::with_capacity(endpoint_count);
        for index in 0..l4_count {
            let mut endpoint = l4.clone();
            endpoint.host = format!("l4-{index}.example.com");
            endpoints.push(endpoint);
        }
        for index in l4_count..endpoint_count {
            let mut endpoint = rest.clone();
            endpoint.host = if index + 1 == endpoint_count {
                "l4-0.example.com".to_owned()
            } else {
                format!("rest-{index}.example.com")
            };
            endpoints.push(endpoint);
        }
        let mut policy = parse(
            "version: 1
",
        );
        policy.network_policies.insert(
            "mixed".to_owned(),
            NetworkRule {
                name: String::new(),
                endpoints,
                binaries: Vec::new(),
            },
        );
        policy
    }

    fn l4_policy(endpoint_count: usize, host_prefix: &str) -> ContainmentPolicy {
        let template = parse(
            "version: 1
network_policies:
  n:
    endpoints: [{ host: api.example.com, port: 443 }]
",
        )
        .network_policies["n"]
            .endpoints[0]
            .clone();
        let endpoints = (0..endpoint_count)
            .map(|index| {
                let mut endpoint = template.clone();
                endpoint.host = format!("{host_prefix}-{index}.example.com");
                endpoint
            })
            .collect();
        let mut policy = parse(
            "version: 1
",
        );
        policy.network_policies.insert(
            "l4".to_owned(),
            NetworkRule {
                name: String::new(),
                endpoints,
                binaries: Vec::new(),
            },
        );
        policy
    }

    #[test]
    fn resource_limits_precede_mixed_protocol_validation_for_either_input() {
        let empty = parse(
            "version: 1
",
        );
        let oversized = mixed_protocol_policy(MAX_ENDPOINTS + 1);

        assert!(matches!(
            validate_supported_policy(&oversized, None),
            Err(PolicyValidationError::Unsupported(_))
        ));
        for (boundary, candidate) in [(&oversized, &empty), (&empty, &oversized)] {
            let result =
                preflight_and_validate_policies(boundary, candidate, options(), None, |_| {
                    panic!("semantic validation must not run after failed preflight")
                });
            assert!(matches!(
                result,
                Some(CheckResult::Inconclusive(ref evidence))
                    if evidence.reason_code() == ReasonCode::ResourceLimit
            ));
            assert!(matches!(
                check_within_boundary(boundary, candidate, options()),
                CheckResult::Inconclusive(ref evidence)
                    if evidence.reason_code() == ReasonCode::ResourceLimit
            ));
        }
    }

    #[test]
    fn aggregate_resource_limit_skips_both_validators() {
        let boundary = l4_policy(MAX_ENDPOINTS / 2 + 1, "boundary");
        let candidate = l4_policy(MAX_ENDPOINTS / 2 + 1, "candidate");
        let empty = parse(
            "version: 1
",
        );
        assert!(resource_limit_reason(&boundary, &empty).is_none());
        assert!(resource_limit_reason(&empty, &candidate).is_none());

        let result =
            preflight_and_validate_policies(&boundary, &candidate, options(), None, |_| {
                panic!("semantic validation must not run after aggregate preflight failure")
            });
        assert!(matches!(
            result,
            Some(CheckResult::Inconclusive(ref evidence))
                if evidence.reason_code() == ReasonCode::ResourceLimit
        ));
    }

    #[test]
    fn permitted_preflight_invokes_both_validators() {
        let boundary = l4_policy(1, "boundary");
        let candidate = l4_policy(1, "candidate");
        let calls = Cell::new(0);
        let result =
            preflight_and_validate_policies(&boundary, &candidate, options(), None, |_| {
                calls.set(calls.get() + 1);
                Ok(())
            });
        assert!(result.is_none());
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn aggregate_endpoint_limit_accepts_exactly_the_limit() {
        let empty = parse(
            "version: 1
",
        );
        let at_limit = mixed_protocol_policy(MAX_ENDPOINTS);
        let over_limit = mixed_protocol_policy(MAX_ENDPOINTS + 1);
        assert!(resource_limit_reason(&empty, &at_limit).is_none());
        assert!(resource_limit_reason(&at_limit, &empty).is_none());
        assert_eq!(
            resource_limit_reason(&empty, &over_limit).as_deref(),
            Some("containment model exceeds resource limit (endpoints=4097, limit=4096)")
        );
        assert_eq!(
            resource_limit_reason(&over_limit, &empty).as_deref(),
            Some("containment model exceeds resource limit (endpoints=4097, limit=4096)")
        );
    }

    #[test]
    fn pattern_limit_diagnostic_reports_the_observed_count() {
        let empty = parse(
            "version: 1
",
        );
        let mut oversized = empty.clone();
        oversized
            .filesystem_policy
            .read_only
            .push("x".repeat(MAX_PATTERN_BYTES + 1));
        assert_eq!(
            resource_limit_reason(&empty, &oversized).as_deref(),
            Some("containment model exceeds resource limit (longest_pattern=4097, limit=4096)")
        );
    }

    #[test]
    fn cancellation_precedes_resource_limits_and_validation() {
        let empty = parse(
            "version: 1
",
        );
        let oversized = mixed_protocol_policy(MAX_ENDPOINTS + 1);
        let cancelled = AtomicBool::new(true);
        assert!(matches!(
            check_within_boundary_cancellable(&empty, &oversized, options(), &cancelled),
            CheckResult::Inconclusive(ref evidence)
                if evidence.reason_code() == ReasonCode::Cancelled
        ));
    }

    #[test]
    fn indexed_cross_protocol_overlap_matches_pairwise_reference() {
        fn pairwise(policy: &ContainmentPolicy) -> bool {
            let endpoints = policy
                .network_policies
                .values()
                .flat_map(|rule| &rule.endpoints)
                .collect::<Vec<_>>();
            endpoints.iter().enumerate().any(|(index, endpoint)| {
                endpoints[index + 1..].iter().any(|other| {
                    endpoint.protocol_kind() != other.protocol_kind()
                        && endpoint_authority_may_overlap(endpoint, other)
                })
            })
        }

        let policies = [
            "version: 1
network_policies:
  n:
    endpoints: [{ host: api.example.com, port: 443 }, { host: API.EXAMPLE.COM, port: 443, protocol: rest }]
",
            "version: 1
network_policies:
  n:
    endpoints: [{ host: '*.example.com', ports: [80, 443] }, { host: api.other.test, port: 443, protocol: rest }]
",
            "version: 1
network_policies:
  n:
    endpoints: [{ host: api.example.com, port: 80 }, { host: api.example.com, port: 443, protocol: rest }]
",
            "version: 1
network_policies:
  n:
    endpoints: [{ host: api.example.com, ports: [80, 443] }, { host: other.example.com, ports: [443, 8443], protocol: rest }]
",
            "version: 1
network_policies:
  a:
    endpoints: [{ host: api.example.com, port: 443 }]
  b:
    endpoints: [{ host: api.example.com, port: 443 }, { host: api.example.com, port: 443, protocol: rest }]
",
        ];
        for source in policies {
            let policy = parse(source);
            let indexed = validate_no_cross_protocol_overlap(&policy, None).is_err();
            assert_eq!(indexed, pairwise(&policy), "{source}");
        }
    }

    #[test]
    fn excessive_model_size_is_inconclusive() {
        let boundary = parse("version: 1\n");
        let mut candidate = parse("version: 1\n");
        for index in 0..=1_024 {
            candidate.network_policies.insert(
                format!("rule-{index}"),
                NetworkRule {
                    name: String::new(),
                    endpoints: Vec::new(),
                    binaries: Vec::new(),
                },
            );
        }
        assert!(matches!(
            check_within_boundary(&boundary, &candidate, options()),
            CheckResult::Inconclusive(ref evidence)
                if evidence.reason_code() == ReasonCode::ResourceLimit
        ));
    }

    #[test]
    fn shared_schema_preserves_filesystem_presence_and_json_inputs() {
        let absent = parse(r#"{"version":1}"#);
        let empty = parse(r#"{"version":1,"filesystem_policy":{}}"#);
        assert!(absent.filesystem_policy.include_workdir);
        assert!(!empty.filesystem_policy.include_workdir);
        assert!(matches!(
            check_within_boundary(&empty, &absent, options()),
            CheckResult::Unsupported(ref evidence)
                if evidence.reason_code() == ReasonCode::UnresolvedWorkdir
        ));
        let normalized = parse("version: 1\nfilesystem_policy: { read_only: ['/usr//./lib/'] }\n");
        assert_eq!(normalized.filesystem_policy.read_only, ["/usr/lib"]);
    }

    #[test]
    fn invalid_version_and_relative_path_are_input_errors() {
        assert!(parse_policy_str("version: 2\n").is_err());
        assert!(parse_policy_str("version: 1\nfilesystem_policy: { read_only: [tmp] }\n").is_err());
        assert!(parse_policy_str("version: 1\nversion: 1\n").is_err());
        let mut deep = String::from("version: 1\nfuture:\n");
        for depth in 0..=openshell_policy_schema::ParseLimits::default().max_depth {
            writeln!(deep, "{}level-{depth}:", "  ".repeat(depth + 1)).unwrap();
        }
        writeln!(
            deep,
            "{}true",
            "  ".repeat(openshell_policy_schema::ParseLimits::default().max_depth + 2)
        )
        .unwrap();
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
            check_within_boundary_cancellable(&policy, &policy, options(), &cancelled),
            CheckResult::Inconclusive(ref evidence)
                if evidence.reason_code() == ReasonCode::Cancelled
        ));
    }

    #[test]
    fn deprecated_tls_spelling_does_not_change_authority() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        tls: terminate\n        enforcement: enforce\n        access: read-only\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let candidate = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules:\n          - allow: { method: GET, path: '/v1/**' }\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_boundary(&boundary, &candidate, options()),
            CheckResult::Within(_)
        ));
    }

    #[test]
    fn host_wildcards_do_not_cross_or_elide_labels() {
        let boundary = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: '*.example.com', port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let nested = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: deep.api.example.com, port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        assert!(matches!(
            check_within_boundary(&boundary, &nested, options()),
            CheckResult::Exceeds(_)
        ));
        let recursive = parse(
            "version: 1\nnetwork_policies:\n  n:\n    endpoints: [{ host: '**.example.com', port: 443 }]\n    binaries: [{ path: /usr/bin/curl }]\n",
        );
        let recursive = fixed_test_ips(recursive);
        let nested = fixed_test_ips(nested);
        assert!(matches!(
            check_within_boundary(&recursive, &nested, options()),
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
            let boundary = parse(&format!(
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
                        check_within_boundary(&boundary, &candidate, options()),
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
                check_within_boundary(&boundary, &matching, options()),
                CheckResult::Within(_)
            ));
            let root = parse(&format!(
                "version: 1\nfilesystem_policy: {{ {access}: [/] }}\n"
            ));
            assert!(matches!(
                check_within_boundary(&root, &boundary, options()),
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
            for (boundary, candidate, label) in [
                (&policy, &empty, "boundary"),
                (&empty, &policy, "candidate"),
                (&policy, &policy, "boundary"),
            ] {
                let result = check_within_boundary(boundary, candidate, options());
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
        for (boundary, candidate, label) in [
            (&policy, &empty, "boundary"),
            (&empty, &policy, "candidate"),
            (&policy, &policy, "boundary"),
        ] {
            let result = check_within_boundary(boundary, candidate, options());
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
