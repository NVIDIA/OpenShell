// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Token-grant owner selection for Cedar sandboxes, compiled from provider
//! rules to Cedar.
//!
//! The gateway stamps each attached provider endpoint with the owner of its
//! token grants. A YAML sandbox admits owner O for a request when an
//! endpoint stamped with O matches the request and its own rules allow it,
//! and no deny rule of any provider endpoint fires. [`TokenGrantRules`]
//! compiles the provider rules into a Cedar policy set with that meaning and
//! evaluates it with the same `HttpRequest` request the sandbox's own Cedar
//! policy decides:
//!
//! - each allow rule of an owned endpoint becomes a `permit` annotated with
//!   `@token_grant_owner`, conditioned on its policy's binaries, the
//!   endpoint's host, ports, and path, and the rule's matchers;
//! - each deny rule of any endpoint becomes a `forbid`, as do the protocol
//!   denials of JSON-RPC and GraphQL endpoints, because a YAML deny admits no
//!   owner at all;
//! - an owner is admitted when one of its endpoints is admitted by every
//!   evaluation of the request (one per GraphQL operation), and within one
//!   evaluation by a single `permit` for every combination of repeated query
//!   values, as a YAML allow rule must match every value.
//!
//! Glob matchers are translated to delimited `like` patterns with the
//! semantics of the Rego `glob.match` they replace. A binary glob becomes a
//! `context.binary_globs.contains(pattern)` test, since the supervisor
//! matches the patterns [`TokenGrantRules::binary_glob_patterns`] lists
//! against the binary and its ancestors with the YAML matcher. A matcher
//! Cedar cannot express exactly never widens what is admitted: a `permit`
//! loses it (the rule admits nothing, or less), a `forbid` ignores it (the
//! rule denies more), and a pattern Rego could fail to evaluate admits no
//! owner at all. [`TokenGrantRules::untranslated`] lists each such case.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{self, Write as _};

use cedar_policy::{Policy, PolicyId, PolicySet, ValidationMode, Validator};

use crate::analysis::QueryKeys;
use crate::{CedarEngineError, Evaluator, HttpRequestInput, Principal, QueryCombinations};

/// Annotation naming the owner whose grant a `permit` admits.
pub const TOKEN_GRANT_OWNER_ANNOTATION: &str = "token_grant_owner";

/// Most `**` path components of one glob that may also match no component.
///
/// Each one doubles the patterns the glob is translated to.
const MAX_ZERO_COMPONENT_WILDCARDS: usize = 4;

/// One provider's network rule, as the YAML engine evaluates it.
///
/// Built from the normalized policy data: access presets expanded, aliases
/// normalized, and symlinked binaries listed with their targets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderPolicy {
    /// The rule's key, used to name generated policies.
    pub name: String,
    /// Binary paths and globs, including resolved symlink targets.
    pub binaries: Vec<String>,
    /// The rule's endpoints, in order.
    pub endpoints: Vec<ProviderEndpoint>,
}

/// One provider endpoint and its L7 rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderEndpoint {
    /// Host or host glob as authored; empty for none.
    pub host: String,
    /// Ports; an endpoint without ports matches nothing.
    pub ports: Vec<u16>,
    /// Endpoint path pattern; empty for every path.
    pub path: String,
    /// The endpoint has `allowed_ips`, which lets a host-less endpoint match
    /// every host.
    pub has_allowed_ips: bool,
    /// Canonical protocol (`rest`, `json-rpc`, `mcp`, `graphql`, ...), or
    /// empty.
    pub protocol: String,
    /// The owner the gateway stamped; empty for none.
    pub token_grant_owner: String,
    /// The MCP option allowing every available method.
    pub mcp_allow_all_known_methods: bool,
    /// Allow rules.
    pub rules: Vec<RuleMatcher>,
    /// Deny rules.
    pub deny_rules: Vec<RuleMatcher>,
}

/// The selectors of one allow or deny rule; `None` when absent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleMatcher {
    /// HTTP or JSON-RPC method.
    pub method: Option<String>,
    /// Request path glob.
    pub path: Option<String>,
    /// SQL command.
    pub command: Option<String>,
    /// GraphQL operation type.
    pub operation_type: Option<String>,
    /// GraphQL operation name glob.
    pub operation_name: Option<String>,
    /// GraphQL root field globs.
    pub fields: Vec<String>,
    /// Query parameter matchers by key.
    pub query: BTreeMap<String, ValueMatcher>,
    /// JSON-RPC params matchers by key.
    pub params: BTreeMap<String, ValueMatcher>,
}

/// A query or params value matcher: matches a value any of `globs` matches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValueMatcher {
    /// Globs with `.` as the delimiter.
    pub globs: Vec<String>,
}

/// Where an untranslated selector appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleLocation {
    /// The policy's binaries.
    Binaries,
    /// The endpoint's host, ports, or path.
    Endpoint,
    /// Allow rule `n`.
    Rule(usize),
    /// Deny rule `n`.
    DenyRule(usize),
    /// The denial a GraphQL or WebSocket endpoint applies to operations its
    /// rules do not allow.
    ProtocolDeny,
}

/// How an untranslated selector is compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handling {
    /// The `permit` admits less than the YAML rule.
    PermitNarrowed,
    /// The rule admits no owner.
    PermitDropped,
    /// The `forbid` fires where the YAML rule does and in more cases.
    ForbidWidened,
    /// No owner is admitted for any request.
    FailClosed,
}

impl fmt::Display for Handling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PermitNarrowed => "allow rule narrowed",
            Self::PermitDropped => "allow rule admits no owner",
            Self::ForbidWidened => "deny widened",
            Self::FailClosed => "no owner is admitted",
        })
    }
}

/// A provider selector Cedar cannot express exactly, and how it is compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntranslatedRule {
    /// The provider policy's name.
    pub policy: String,
    /// The endpoint's index, if the selector belongs to one.
    pub endpoint: Option<usize>,
    /// Where in the policy or endpoint it appears.
    pub location: RuleLocation,
    /// Why it cannot be translated exactly.
    pub reason: String,
    /// How it is compiled instead.
    pub handling: Handling,
}

impl fmt::Display for UntranslatedRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.policy)?;
        if let Some(endpoint) = self.endpoint {
            write!(f, ".endpoints[{endpoint}]")?;
        }
        match self.location {
            RuleLocation::Binaries => write!(f, ".binaries")?,
            RuleLocation::Endpoint => {}
            RuleLocation::Rule(rule) => write!(f, ".rules[{rule}]")?,
            RuleLocation::DenyRule(rule) => write!(f, ".deny_rules[{rule}]")?,
            RuleLocation::ProtocolDeny => write!(f, " (protocol deny)")?,
        }
        write!(f, ": {} ({})", self.reason, self.handling)
    }
}

/// Provider rules compiled to Cedar for token-grant owner selection.
#[derive(Debug)]
pub struct TokenGrantRules {
    evaluator: Evaluator,
    policies: PolicySet,
    /// The endpoint slot each owner-annotated `permit` admits.
    permit_slots: HashMap<PolicyId, usize>,
    /// The owner of each endpoint slot.
    owners: Vec<String>,
    query_keys: QueryKeys,
    /// The binary glob patterns the generated policies test.
    binary_globs: BTreeSet<String>,
    source: String,
    untranslated: Vec<UntranslatedRule>,
    fail_closed: Option<String>,
}

impl TokenGrantRules {
    /// Compiles provider rules and validates the result against the schema.
    ///
    /// Without a stamped owner the result admits no owner and holds no
    /// policies.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if the schema fails to load or a
    /// generated policy fails to parse or validate, which indicates a
    /// compiler defect rather than a policy error.
    pub fn compile(policies: &[ProviderPolicy]) -> Result<Self, CedarEngineError> {
        let evaluator = Evaluator::new()?;
        let mut compiler = Compiler::default();
        let owned = policies
            .iter()
            .flat_map(|policy| &policy.endpoints)
            .any(|endpoint| !endpoint.token_grant_owner.is_empty());
        if owned {
            for policy in policies {
                compiler.policy(policy);
            }
        }
        let source = compiler
            .sources
            .iter()
            .map(|(_, text)| text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let mut set = PolicySet::new();
        if compiler.fail_closed.is_none() {
            for (id, text) in &compiler.sources {
                let policy = Policy::parse(Some(PolicyId::new(id)), text)
                    .map_err(|e| CedarEngineError::PolicyParse(Box::new(e)))?;
                set.add(policy)
                    .map_err(|e| CedarEngineError::PolicySet(Box::new(e)))?;
            }
            let validation =
                Validator::new(evaluator.schema.clone()).validate(&set, ValidationMode::Strict);
            if !validation.validation_passed() {
                let reason = validation
                    .validation_errors()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(CedarEngineError::PolicyValidation { reason });
            }
        }
        Ok(Self {
            evaluator,
            policies: set,
            permit_slots: compiler
                .permit_slots
                .into_iter()
                .map(|(id, slot)| (PolicyId::new(id), slot))
                .collect(),
            owners: compiler.owners,
            query_keys: QueryKeys::Named(compiler.query_keys),
            binary_globs: compiler.binary_globs,
            source,
            untranslated: compiler.untranslated,
            fail_closed: compiler.fail_closed,
        })
    }

    /// Returns the generated Cedar policies.
    #[must_use]
    pub fn policy_text(&self) -> &str {
        &self.source
    }

    /// Returns the selectors compiled other than exactly.
    #[must_use]
    pub fn untranslated(&self) -> &[UntranslatedRule] {
        &self.untranslated
    }

    /// Returns the binary glob patterns the generated policies test with
    /// `context.binary_globs`, sorted.
    ///
    /// The caller lists in a request's `binary_globs` the ones that match
    /// its binary or an ancestor with the YAML binary glob matcher, as for
    /// `CedarEngine::binary_glob_patterns`.
    pub fn binary_glob_patterns(&self) -> impl Iterator<Item = &str> {
        self.binary_globs.iter().map(String::as_str)
    }

    /// Returns why no owner is ever admitted, if that is the case.
    #[must_use]
    pub fn fail_closed_reason(&self) -> Option<&str> {
        self.fail_closed.as_deref()
    }

    /// Returns the owners admitted for one request.
    ///
    /// `requests` are the request's evaluations, as the sandbox's own Cedar
    /// policy evaluated and allowed them: one per GraphQL operation, else
    /// one. An owner is admitted when one of its endpoints admits every
    /// evaluation and no `forbid` fires in any.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError::TooManyQueryCombinations`] when the query
    /// has too many combinations of the keys provider rules read, and
    /// another [`CedarEngineError`] when Cedar fails to evaluate a request.
    pub fn admitted_owners(
        &self,
        requests: &[HttpRequestInput],
    ) -> Result<BTreeSet<String>, CedarEngineError> {
        if self.fail_closed.is_some()
            || self.permit_slots.is_empty()
            || requests.is_empty()
            || requests.iter().any(|request| !comparable(request))
        {
            return Ok(BTreeSet::new());
        }
        let mut admitted: Option<BTreeSet<usize>> = None;
        for request in requests {
            let query = QueryCombinations::new(&request.query, &self.query_keys)?;
            let context = self.evaluator.l7_context(request);
            // The permits that allowed every combination so far.
            let mut permits: Option<Vec<PolicyId>> = None;
            for index in 0..query.count {
                let outcome = self.evaluator.authorize(
                    &self.policies,
                    &self.evaluator.uids.http_request,
                    &Principal {
                        user: &request.user,
                        group: &request.group,
                    },
                    &request.host,
                    request.port,
                    "",
                    context.clone(),
                    Some(self.evaluator.query_entity(query.combination(index))?),
                )?;
                // A denial, by a `forbid` or for want of a `permit`, admits
                // no owner for this evaluation and so for the request.
                if !outcome.allowed {
                    return Ok(BTreeSet::new());
                }
                let common = permits.get_or_insert_with(|| outcome.reasons.clone());
                common.retain(|id| outcome.reasons.contains(id));
            }
            let slots: BTreeSet<usize> = permits
                .unwrap_or_default()
                .iter()
                .filter_map(|id| self.permit_slots.get(id).copied())
                .collect();
            let slots = match admitted {
                Some(previous) => previous.intersection(&slots).copied().collect(),
                None => slots,
            };
            if slots.is_empty() {
                return Ok(BTreeSet::new());
            }
            admitted = Some(slots);
        }
        Ok(admitted
            .unwrap_or_default()
            .into_iter()
            .map(|slot| self.owners[slot].clone())
            .collect())
    }
}

/// Returns whether Cedar sees `request` as the Rego rules see it.
///
/// Cedar strips a trailing `.` from the host, which the Rego host comparison
/// keeps, and Rego fails to glob-match a string holding NUL.
fn comparable(request: &HttpRequestInput) -> bool {
    let no_nul = |value: &str| !value.contains('\0');
    !request.host.ends_with('.')
        && [
            &request.host,
            &request.binary_path,
            &request.method,
            &request.path,
            &request.jsonrpc_method,
            &request.mcp_tool,
            &request.graphql_operation_name,
        ]
        .into_iter()
        .all(|value| no_nul(value))
        && request.ancestors.iter().all(|value| no_nul(value))
        && request.graphql_fields.iter().all(|value| no_nul(value))
        && request
            .query
            .iter()
            .all(|(key, values)| no_nul(key) && values.iter().all(|value| no_nul(value)))
}

/// A generated condition.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Cond {
    /// Never holds.
    Never,
    /// Holds when every conjunct holds; empty for `true`.
    All(Vec<String>),
}

impl Cond {
    const TRUE: Self = Self::All(Vec::new());

    fn expr(text: impl Into<String>) -> Self {
        Self::All(vec![text.into()])
    }

    fn all(parts: impl IntoIterator<Item = Self>) -> Self {
        let mut conjuncts = Vec::new();
        for part in parts {
            match part {
                Self::Never => return Self::Never,
                Self::All(more) => conjuncts.extend(more),
            }
        }
        Self::All(conjuncts)
    }

    fn any(parts: impl IntoIterator<Item = Self>) -> Self {
        let mut disjuncts = Vec::new();
        for part in parts {
            match part {
                Self::Never => {}
                Self::All(conjuncts) if conjuncts.is_empty() => return Self::TRUE,
                part @ Self::All(_) => disjuncts.push(part),
            }
        }
        match disjuncts.len() {
            0 => Self::Never,
            1 => disjuncts.remove(0),
            _ => Self::expr(format!(
                "({})",
                disjuncts
                    .iter()
                    .map(Self::inline)
                    .collect::<Vec<_>>()
                    .join(" || ")
            )),
        }
    }

    fn not(self) -> Self {
        match self {
            Self::Never => Self::TRUE,
            Self::All(conjuncts) if conjuncts.is_empty() => Self::Never,
            Self::All(conjuncts) => Self::expr(format!("!({})", conjuncts.join(" && "))),
        }
    }

    fn inline(&self) -> String {
        match self {
            Self::Never => "false".to_string(),
            Self::All(conjuncts) => match conjuncts.len() {
                0 => "true".to_string(),
                1 => conjuncts[0].clone(),
                _ => format!("({})", conjuncts.join(" && ")),
            },
        }
    }
}

/// Which effect a condition is built for, which decides how an
/// untranslatable selector is approximated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Permit,
    Forbid,
}

/// The state of building one condition.
#[derive(Debug)]
struct Scope {
    side: Side,
    /// Why selectors were approximated.
    reasons: Vec<String>,
    /// Set when a pattern could fail Rego evaluation.
    fail: Option<String>,
    /// The query keys the condition reads.
    query_keys: BTreeSet<String>,
}

impl Scope {
    fn new(side: Side) -> Self {
        Self {
            side,
            reasons: Vec::new(),
            fail: None,
            query_keys: BTreeSet::new(),
        }
    }

    /// Approximates a selector Cedar cannot express: a `permit` loses it, a
    /// `forbid` ignores it.
    fn unsupported(&mut self, reason: impl Into<String>) -> Cond {
        self.reasons.push(reason.into());
        match self.side {
            Side::Permit => Cond::Never,
            Side::Forbid => Cond::TRUE,
        }
    }

    /// Records a pattern Rego could fail to evaluate.
    fn may_fail(&mut self, reason: String) -> Cond {
        self.fail.get_or_insert(reason);
        Cond::Never
    }

    /// Builds `target like pattern`, or `==` for a pattern without wildcards.
    fn glob(&mut self, target: &str, pattern: &str, delimiter: char) -> Cond {
        match translate_glob(pattern, delimiter) {
            Glob::Patterns(patterns) => Cond::any(patterns.into_iter().map(|pattern| {
                if pattern.contains('*') {
                    Cond::expr(format!(r#"{target} like("{pattern}", "{delimiter}")"#))
                } else {
                    Cond::expr(format!(r#"{target} == "{pattern}""#))
                }
            })),
            Glob::Unsupported(why) => self.unsupported(format!("glob {pattern:?}: {why}")),
            Glob::MayFail(why) => self.may_fail(format!("glob {pattern:?}: {why}")),
        }
    }

    /// Matches `target` against a query or params matcher.
    fn value(&mut self, target: &str, matcher: &ValueMatcher) -> Cond {
        let parts: Vec<Cond> = matcher
            .globs
            .iter()
            .map(|glob| self.glob(target, glob, '.'))
            .collect();
        Cond::any(parts)
    }
}

/// A glob translated to delimited `like` patterns.
#[derive(Debug, PartialEq, Eq)]
enum Glob {
    /// Patterns, escaped for a Cedar string, one of which must match.
    Patterns(Vec<String>),
    /// The glob uses a feature Cedar cannot express.
    Unsupported(&'static str),
    /// The glob may be invalid, which fails Rego evaluation.
    MayFail(&'static str),
}

/// Translates a Rego `glob.match` pattern with one delimiter.
///
/// Rego builds the glob with `globset` and a literal separator. `*` matches
/// within one segment and `**` spans segments only as a whole segment;
/// elsewhere it is `*`. With the `/` delimiter, a leading `**/` and an inner
/// `/**/` also match no segment, which a Cedar `**` does not, so each yields
/// one pattern with and one without it. With the `.` delimiter, Rego's
/// rewriting of `.` into `/./` makes the two agree.
fn translate_glob(pattern: &str, delimiter: char) -> Glob {
    if pattern
        .chars()
        .any(|c| matches!(c, '[' | ']' | '{' | '}' | '\\' | '\0'))
    {
        return Glob::MayFail("character classes, alternatives, and escapes are not supported");
    }
    if pattern.contains('?') {
        return Glob::Unsupported("`?` has no Cedar equivalent");
    }
    if pattern.contains("***") || pattern.contains(&format!("**{delimiter}**")) {
        return Glob::Unsupported("adjacent recursive wildcards are not supported");
    }
    let chars: Vec<char> = pattern.chars().collect();
    let mut variants = vec![String::new()];
    let mut zero_component = 0;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c != '*' {
            let escaped = escape_char(c);
            for v in &mut variants {
                v.push_str(&escaped);
            }
            i += 1;
            continue;
        }
        if chars.get(i + 1) != Some(&'*') {
            for v in &mut variants {
                v.push('*');
            }
            i += 1;
            continue;
        }
        let prev = i.checked_sub(1).map(|p| chars[p]);
        let next = chars.get(i + 2).copied();
        let whole_segment =
            prev.is_none_or(|p| p == delimiter) && next.is_none_or(|n| n == delimiter);
        if !whole_segment {
            for v in &mut variants {
                v.push('*');
            }
        } else if delimiter == '/' && next == Some('/') {
            zero_component += 1;
            if zero_component > MAX_ZERO_COMPONENT_WILDCARDS {
                return Glob::Unsupported("too many `**` components");
            }
            variants = variants
                .into_iter()
                .flat_map(|v| [format!("{v}**/"), v])
                .collect();
            i += 3;
            continue;
        } else {
            for v in &mut variants {
                v.push_str("**");
            }
        }
        i += 2;
    }
    variants.dedup();
    Glob::Patterns(variants)
}

/// Escapes one character for a Cedar string or pattern.
fn escape_char(c: char) -> String {
    match c {
        '"' => "\\\"".to_string(),
        '\\' => "\\\\".to_string(),
        c if c.is_control() => format!("\\u{{{:x}}}", u32::from(c)),
        c => c.to_string(),
    }
}

/// Quotes `value` as a Cedar string literal.
fn quote(value: &str) -> String {
    format!("\"{}\"", value.chars().map(escape_char).collect::<String>())
}

/// Quotes `value` as a literal Cedar `like` pattern, escaping `*`.
fn quote_literal_pattern(value: &str) -> String {
    quote(value).replace('*', "\\*")
}

/// The binary condition of one policy for each side, and why it is
/// approximated.
#[derive(Debug)]
struct Binaries {
    permit: Cond,
    permit_reasons: Vec<String>,
    forbid: Cond,
    forbid_reasons: Vec<String>,
}

/// Characters a binary glob may hold that Rego's matcher could fail to
/// compile, which fails the YAML evaluation and so admits no owner.
const MAY_FAIL_GLOB_CHARS: [char; 6] = ['[', ']', '{', '}', '\\', '\0'];

/// Accumulates generated policies.
#[derive(Debug, Default)]
struct Compiler {
    /// `(policy id, text)` in generation order.
    sources: Vec<(String, String)>,
    permit_slots: Vec<(String, usize)>,
    owners: Vec<String>,
    query_keys: BTreeSet<String>,
    binary_globs: BTreeSet<String>,
    untranslated: Vec<UntranslatedRule>,
    fail_closed: Option<String>,
}

impl Compiler {
    fn policy(&mut self, policy: &ProviderPolicy) {
        let binaries = self.binaries(policy);
        let mut noted = (false, false);
        for (index, endpoint) in policy.endpoints.iter().enumerate() {
            self.endpoint(policy, index, endpoint, &binaries, &mut noted);
        }
    }

    /// Builds a policy's binary condition: an exact path matches the binary
    /// or an ancestor, and a glob matches the binary or an ancestor through
    /// `context.binary_globs`, which the supervisor fills with the YAML
    /// matcher.
    fn binaries(&mut self, policy: &ProviderPolicy) -> Binaries {
        let mut globs = BTreeSet::new();
        let mut build = |side| {
            let mut scope = Scope::new(side);
            let parts: Vec<Cond> = policy
                .binaries
                .iter()
                .map(|binary| {
                    let path = quote(binary);
                    if !binary.contains('*') {
                        return Cond::expr(format!(
                            "(context.binary_path == {path} || context.ancestors.contains({path}))"
                        ));
                    }
                    if binary.contains(MAY_FAIL_GLOB_CHARS) {
                        return scope.may_fail(format!(
                            "binary glob {binary:?}: character classes, alternatives, and \
                             escapes are not supported"
                        ));
                    }
                    globs.insert(binary.clone());
                    Cond::expr(format!("context.binary_globs.contains({path})"))
                })
                .collect();
            (Cond::any(parts), scope)
        };
        let (permit, permit_scope) = build(Side::Permit);
        let (forbid, forbid_scope) = build(Side::Forbid);
        self.binary_globs.extend(globs);
        for fail in [permit_scope.fail, forbid_scope.fail].into_iter().flatten() {
            self.fail(&policy.name, None, RuleLocation::Binaries, fail);
        }
        Binaries {
            permit,
            permit_reasons: permit_scope.reasons,
            forbid,
            forbid_reasons: forbid_scope.reasons,
        }
    }

    fn fail(
        &mut self,
        policy: &str,
        endpoint: Option<usize>,
        location: RuleLocation,
        reason: String,
    ) {
        self.untranslated.push(UntranslatedRule {
            policy: policy.to_string(),
            endpoint,
            location,
            reason: reason.clone(),
            handling: Handling::FailClosed,
        });
        self.fail_closed
            .get_or_insert_with(|| format!("{policy}: {reason}"));
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one place lists every Rego allow and deny clause of an endpoint"
    )]
    fn endpoint(
        &mut self,
        policy: &ProviderPolicy,
        index: usize,
        endpoint: &ProviderEndpoint,
        binaries: &Binaries,
        noted: &mut (bool, bool),
    ) {
        let jsonrpc_family = matches!(endpoint.protocol.as_str(), "json-rpc" | "mcp");
        let mcp = endpoint.protocol == "mcp";
        let ctx = Ctx {
            policy,
            index,
            endpoint,
        };

        if !endpoint.token_grant_owner.is_empty() {
            let slot = self.owners.len();
            self.owners.push(endpoint.token_grant_owner.clone());
            for (rule_index, rule) in endpoint.rules.iter().enumerate() {
                let location = RuleLocation::Rule(rule_index);
                if rule.method.is_some() {
                    let label = format!("rules[{rule_index}]");
                    if jsonrpc_family {
                        self.emit(&ctx, binaries, noted, Some(slot), location, &label, |s| {
                            jsonrpc_cond(s, endpoint, rule, true)
                        });
                    } else {
                        self.emit(&ctx, binaries, noted, Some(slot), location, &label, |s| {
                            rest_cond(s, rule)
                        });
                    }
                }
                if rule.operation_type.is_some() {
                    let label = format!("rules[{rule_index}]/graphql");
                    self.emit(&ctx, binaries, noted, Some(slot), location, &label, |s| {
                        graphql_cond(s, rule, true)
                    });
                }
            }
            if mcp && endpoint.mcp_allow_all_known_methods {
                // The tool rules narrow `tools/call` instead.
                let narrowed = endpoint
                    .rules
                    .iter()
                    .any(|rule| rule.params.contains_key("name"));
                self.emit(
                    &ctx,
                    binaries,
                    noted,
                    Some(slot),
                    RuleLocation::Endpoint,
                    "mcp_allow_all_known_methods",
                    |_| {
                        Cond::all([
                            jsonrpc_call(),
                            Cond::expr("!context.jsonrpc_response"),
                            Cond::expr(r#"context.mcp_method_class == "available""#),
                            if narrowed {
                                Cond::expr(r#"context.jsonrpc_method != "tools/call""#)
                            } else {
                                Cond::TRUE
                            },
                        ])
                    },
                );
            }
            if mcp {
                // An MCP endpoint admits client response frames and its GET
                // receive stream.
                self.emit(
                    &ctx,
                    binaries,
                    noted,
                    Some(slot),
                    RuleLocation::Endpoint,
                    "mcp_response",
                    |_| Cond::expr("context.jsonrpc_response"),
                );
                self.emit(
                    &ctx,
                    binaries,
                    noted,
                    Some(slot),
                    RuleLocation::Endpoint,
                    "mcp_receive_stream",
                    |_| {
                        Cond::all([
                            Cond::expr(r#"context.method == "GET""#),
                            Cond::expr("context.jsonrpc_receive_stream"),
                            Cond::expr(r#"context.jsonrpc_method == """#),
                            Cond::expr("!context.jsonrpc_response"),
                        ])
                    },
                );
            }
        }

        for (rule_index, rule) in endpoint.deny_rules.iter().enumerate() {
            let location = RuleLocation::DenyRule(rule_index);
            if rule.method.is_some() {
                let label = format!("deny_rules[{rule_index}]");
                if jsonrpc_family {
                    self.emit(&ctx, binaries, noted, None, location, &label, |s| {
                        jsonrpc_cond(s, endpoint, rule, false)
                    });
                } else {
                    self.emit(&ctx, binaries, noted, None, location, &label, |s| {
                        rest_cond(s, rule)
                    });
                }
            }
            if rule.operation_type.is_some() {
                let label = format!("deny_rules[{rule_index}]/graphql");
                self.emit(&ctx, binaries, noted, None, location, &label, |s| {
                    graphql_cond(s, rule, false)
                });
            }
        }
        if endpoint.protocol == "json-rpc" {
            // A generic JSON-RPC endpoint denies client response frames.
            self.emit(
                &ctx,
                binaries,
                noted,
                None,
                RuleLocation::ProtocolDeny,
                "json_rpc_response",
                |_| Cond::expr("context.jsonrpc_response"),
            );
        }
        if matches!(endpoint.protocol.as_str(), "graphql" | "websocket") {
            // A GraphQL operation its rules do not allow is denied, even
            // when another endpoint's rules allow the request.
            self.emit(
                &ctx,
                binaries,
                noted,
                None,
                RuleLocation::ProtocolDeny,
                "graphql_operations",
                |s| {
                    let mut allow = Scope::new(Side::Permit);
                    let allowed: Vec<Cond> = endpoint
                        .rules
                        .iter()
                        .filter(|rule| rule.operation_type.is_some())
                        .map(|rule| graphql_cond(&mut allow, rule, true))
                        .collect();
                    s.reasons.extend(allow.reasons);
                    if let Some(fail) = allow.fail {
                        s.fail.get_or_insert(fail);
                    }
                    Cond::all([
                        Cond::expr(r#"context.graphql_operation_type != """#),
                        Cond::any(allowed).not(),
                    ])
                },
            );
        }
    }

    /// Generates one policy: a `permit` for `slot`, or a `forbid`.
    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments locate and annotate one generated policy"
    )]
    fn emit(
        &mut self,
        ctx: &Ctx<'_>,
        binaries: &Binaries,
        noted: &mut (bool, bool),
        slot: Option<usize>,
        location: RuleLocation,
        label: &str,
        build: impl FnOnce(&mut Scope) -> Cond,
    ) {
        let side = if slot.is_some() {
            Side::Permit
        } else {
            Side::Forbid
        };
        let mut scope = Scope::new(side);
        let matched = endpoint_cond(&mut scope, ctx.endpoint);
        let endpoint_reasons = std::mem::take(&mut scope.reasons);
        let rule = build(&mut scope);
        let binary = match side {
            Side::Permit => binaries.permit.clone(),
            Side::Forbid => binaries.forbid.clone(),
        };
        let cond = Cond::all([binary, matched, rule]);
        if let Some(fail) = scope.fail {
            self.fail(&ctx.policy.name, Some(ctx.index), location, fail);
            return;
        }
        let handling = match (side, &cond) {
            (Side::Permit, Cond::Never) => Handling::PermitDropped,
            (Side::Permit, _) => Handling::PermitNarrowed,
            (Side::Forbid, _) => Handling::ForbidWidened,
        };
        for (location, reason) in endpoint_reasons
            .into_iter()
            .map(|reason| (RuleLocation::Endpoint, reason))
            .chain(scope.reasons.into_iter().map(|reason| (location, reason)))
        {
            let note = UntranslatedRule {
                policy: ctx.policy.name.clone(),
                endpoint: Some(ctx.index),
                location,
                reason,
                handling,
            };
            if !self.untranslated.contains(&note) {
                self.untranslated.push(note);
            }
        }
        if cond == Cond::Never {
            return;
        }
        // Binary approximations are reported once per policy and side.
        let (seen, reasons, handling) = match side {
            Side::Permit => (
                &mut noted.0,
                &binaries.permit_reasons,
                Handling::PermitNarrowed,
            ),
            Side::Forbid => (
                &mut noted.1,
                &binaries.forbid_reasons,
                Handling::ForbidWidened,
            ),
        };
        if !*seen {
            *seen = true;
            for reason in reasons {
                self.untranslated.push(UntranslatedRule {
                    policy: ctx.policy.name.clone(),
                    endpoint: None,
                    location: RuleLocation::Binaries,
                    reason: reason.clone(),
                    handling,
                });
            }
        }
        self.query_keys.extend(scope.query_keys);

        let id = format!(
            "{}{}",
            if slot.is_some() { "grant" } else { "deny" },
            self.sources.len()
        );
        let mut text = format!(
            "@id({})\n",
            quote(&format!(
                "{}/endpoints[{}]/{label}",
                ctx.policy.name, ctx.index
            ))
        );
        if let Some(slot) = slot {
            let _ = writeln!(
                text,
                "@{TOKEN_GRANT_OWNER_ANNOTATION}({})",
                quote(&self.owners[slot])
            );
            self.permit_slots.push((id.clone(), slot));
        }
        let _ = write!(
            text,
            "{} (\n    principal,\n    action == Sandbox::Action::\"HttpRequest\",\n    resource is Sandbox::NetworkEndpoint\n)",
            if slot.is_some() { "permit" } else { "forbid" }
        );
        match cond {
            Cond::All(conjuncts) if !conjuncts.is_empty() => {
                let _ = write!(
                    text,
                    "\nwhen {{\n    {}\n}};\n",
                    conjuncts.join("\n    && ")
                );
            }
            _ => text.push_str(";\n"),
        }
        self.sources.push((id, text));
    }
}

/// The endpoint a generated policy belongs to.
struct Ctx<'a> {
    policy: &'a ProviderPolicy,
    index: usize,
    endpoint: &'a ProviderEndpoint,
}

/// Matches the request's host, port, and path against the endpoint's.
fn endpoint_cond(scope: &mut Scope, endpoint: &ProviderEndpoint) -> Cond {
    let host = if endpoint.host.is_empty() {
        // A host-less endpoint with `allowed_ips` matches any host.
        if endpoint.has_allowed_ips {
            Cond::TRUE
        } else {
            Cond::Never
        }
    } else if !endpoint.host.is_ascii() {
        scope.unsupported("a non-ASCII host is lowercased differently")
    } else {
        let host = endpoint.host.to_ascii_lowercase();
        if host.contains('*') {
            scope.glob("resource.host", &host, '.')
        } else {
            Cond::expr(format!("resource.host == {}", quote(&host)))
        }
    };
    let ports = match endpoint.ports.as_slice() {
        [] => Cond::Never,
        [port] => Cond::expr(format!("resource.port == {port}")),
        ports => Cond::expr(format!(
            "[{}].contains(resource.port)",
            ports
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    };
    Cond::all([host, ports, endpoint_path_cond(scope, &endpoint.path)])
}

/// Matches the request path against an endpoint path pattern, as
/// `openshell_core::endpoint_path::matches` does: empty, `**`, and `/**`
/// match every path, `P/**` matches `P` and below, and other patterns are
/// globs whose `*` also matches `/`.
fn endpoint_path_cond(scope: &mut Scope, path: &str) -> Cond {
    if path.is_empty() || path == "**" || path == "/**" {
        return Cond::TRUE;
    }
    if let Some(prefix) = path.strip_suffix("/**") {
        // The prefix is literal: its `*` are escaped in the pattern.
        let below = quote_literal_pattern(&format!("{prefix}/"));
        let below = format!("{}*\"", below.strip_suffix('"').unwrap_or(&below));
        return Cond::expr(format!(
            "(context.path == {} || context.path like {below})",
            quote(prefix)
        ));
    }
    if path.contains(['?', '[']) || path.contains("**") {
        return scope.unsupported(format!(
            "endpoint path {path:?}: only `*` wildcards and a `/**` suffix are supported"
        ));
    }
    if path.contains('*') {
        Cond::expr(format!("context.path like {}", quote(path)))
    } else {
        Cond::expr(format!("context.path == {}", quote(path)))
    }
}

/// A REST allow or deny rule: method, path, and query matchers.
fn rest_cond(scope: &mut Scope, rule: &RuleMatcher) -> Cond {
    let method = rule
        .method
        .as_deref()
        .map_or(Cond::Never, |method| method_cond(scope, method));
    let path = match rule.path.as_deref() {
        None => Cond::Never,
        Some("**") => Cond::TRUE,
        Some(path) => scope.glob("context.path", path, '/'),
    };
    let query: Vec<Cond> = rule
        .query
        .iter()
        .map(|(key, matcher)| {
            scope.query_keys.insert(key.clone());
            let key = quote(key);
            let value = scope.value(&format!("context.query.getTag({key})"), matcher);
            Cond::all([Cond::expr(format!("context.query.hasTag({key})")), value])
        })
        .collect();
    Cond::all([method, path, Cond::all(query)])
}

/// Matches an HTTP method case-insensitively, `GET` also matching `HEAD`.
///
/// A JSON-RPC call is evaluated with an empty method, and is always sent
/// with `POST`, so `POST` also matches an empty method.
fn method_cond(scope: &mut Scope, method: &str) -> Cond {
    if method == "*" {
        return Cond::TRUE;
    }
    if !method.is_ascii() {
        return scope.unsupported("a non-ASCII method is uppercased differently");
    }
    let method = method.to_ascii_uppercase();
    match method.as_str() {
        "" => Cond::Never,
        "GET" => Cond::expr(r#"["GET", "HEAD"].contains(context.method)"#),
        "POST" => Cond::expr(r#"["POST", ""].contains(context.method)"#),
        method => Cond::expr(format!("context.method == {}", quote(method))),
    }
}

/// A JSON-RPC call: the only evaluation with an empty method.
fn jsonrpc_call() -> Cond {
    Cond::all([
        Cond::expr(r#"context.method == """#),
        Cond::expr(r#"context.jsonrpc_method != """#),
    ])
}

/// A JSON-RPC or MCP allow or deny rule.
fn jsonrpc_cond(
    scope: &mut Scope,
    endpoint: &ProviderEndpoint,
    rule: &RuleMatcher,
    allow: bool,
) -> Cond {
    let mcp = endpoint.protocol == "mcp";
    let rule_method = rule.method.as_deref().unwrap_or_default();
    if rule_method.is_empty() {
        return Cond::Never;
    }
    let method = if mcp {
        scope.glob("context.jsonrpc_method", rule_method, '.')
    } else if rule_method == "*" {
        Cond::TRUE
    } else {
        Cond::expr(format!("context.jsonrpc_method == {}", quote(rule_method)))
    };
    // Only MCP rules match params, and a call exposes only `params.name`,
    // the tool of a `tools/call`.
    let params: Vec<Cond> = if mcp {
        rule.params
            .iter()
            .map(|(key, matcher)| {
                if key == "name" {
                    Cond::all([
                        Cond::expr(r#"context.jsonrpc_method == "tools/call""#),
                        scope.value("context.mcp_tool", matcher),
                    ])
                } else {
                    Cond::Never
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    // An extension method needs an exact rule.
    let class = if mcp && allow {
        Cond::any([
            Cond::expr(r#"context.mcp_method_class == "available""#),
            Cond::expr(format!(
                r#"(context.mcp_method_class == "extension" && context.jsonrpc_method == {})"#,
                quote(rule_method)
            )),
        ])
    } else {
        Cond::TRUE
    };
    let response = if allow {
        Cond::expr("!context.jsonrpc_response")
    } else {
        Cond::TRUE
    };
    Cond::all([jsonrpc_call(), response, method, Cond::all(params), class])
}

/// A GraphQL allow or deny rule, for one operation.
fn graphql_cond(scope: &mut Scope, rule: &RuleMatcher, allow: bool) -> Cond {
    let operation_type = match rule.operation_type.as_deref() {
        None => return Cond::Never,
        Some("*") => Cond::expr(r#"context.graphql_operation_type != """#),
        Some(kind) if !kind.is_ascii() => {
            return scope.unsupported("a non-ASCII operation type is lowercased differently");
        }
        Some(kind) => {
            let kind = kind.to_ascii_lowercase();
            if kind.is_empty() {
                return Cond::Never;
            }
            Cond::expr(format!(
                "context.graphql_operation_type == {}",
                quote(&kind)
            ))
        }
    };
    let name = match rule.operation_name.as_deref() {
        None | Some("") => Cond::TRUE,
        Some(name) => scope.glob("context.graphql_operation_name", name, '.'),
    };
    Cond::all([
        operation_type,
        name,
        fields_cond(scope, &rule.fields, allow),
    ])
}

/// Matches root fields: an allow rule needs every field to match a pattern,
/// a deny rule one. Only literal fields and `*` translate.
fn fields_cond(scope: &mut Scope, patterns: &[String], allow: bool) -> Cond {
    if patterns.is_empty() {
        return Cond::TRUE;
    }
    let any_field = Cond::expr("!context.graphql_fields.isEmpty()");
    // A GraphQL field name has no `.`, so a run of `*` matches every field.
    if patterns
        .iter()
        .any(|p| !p.is_empty() && p.chars().all(|c| c == '*'))
    {
        return any_field;
    }
    if let Some(pattern) = patterns.iter().find(|p| {
        p.chars()
            .any(|c| matches!(c, '[' | ']' | '{' | '}' | '\\' | '\0'))
    }) {
        return scope.may_fail(format!("field glob {pattern:?} may be invalid"));
    }
    let literals: Vec<String> = patterns
        .iter()
        .filter(|p| !p.contains(['*', '?']))
        .map(|p| quote(p))
        .collect();
    let globbed = literals.len() != patterns.len();
    let list = format!("[{}]", literals.join(", "));
    if allow {
        if globbed {
            scope
                .reasons
                .push("field globs need every field to match, which Cedar cannot test".into());
        }
        if literals.is_empty() {
            return Cond::Never;
        }
        Cond::all([
            any_field,
            Cond::expr(format!("{list}.containsAll(context.graphql_fields)")),
        ])
    } else if globbed {
        scope.reasons.push("field globs cannot be tested".into());
        any_field
    } else {
        Cond::expr(format!("context.graphql_fields.containsAny({list})"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "api.example.com";
    const CURL: &str = "/usr/bin/curl";

    fn rule(method: &str, path: &str) -> RuleMatcher {
        RuleMatcher {
            method: Some(method.to_string()),
            path: Some(path.to_string()),
            ..Default::default()
        }
    }

    fn endpoint(owner: &str, protocol: &str, rules: Vec<RuleMatcher>) -> ProviderEndpoint {
        ProviderEndpoint {
            host: HOST.to_string(),
            ports: vec![443],
            protocol: protocol.to_string(),
            token_grant_owner: owner.to_string(),
            rules,
            ..Default::default()
        }
    }

    fn policy(name: &str, endpoints: Vec<ProviderEndpoint>) -> ProviderPolicy {
        ProviderPolicy {
            name: name.to_string(),
            binaries: vec![CURL.to_string()],
            endpoints,
        }
    }

    fn rest(method: &str, path: &str) -> HttpRequestInput {
        HttpRequestInput {
            user: "sandbox".to_string(),
            group: "sandbox".to_string(),
            binary_path: CURL.to_string(),
            host: HOST.to_string(),
            port: 443,
            method: method.to_string(),
            path: path.to_string(),
            ..Default::default()
        }
    }

    fn with_query(mut request: HttpRequestInput, key: &str, values: &[&str]) -> HttpRequestInput {
        request.query.insert(
            key.to_string(),
            values.iter().map(ToString::to_string).collect(),
        );
        request
    }

    fn compile(policies: &[ProviderPolicy]) -> TokenGrantRules {
        TokenGrantRules::compile(policies).unwrap_or_else(|e| panic!("compiles: {e}"))
    }

    fn owners(rules: &TokenGrantRules, requests: &[HttpRequestInput]) -> Vec<String> {
        rules
            .admitted_owners(requests)
            .expect("evaluates")
            .into_iter()
            .collect()
    }

    fn single(path_rule: RuleMatcher) -> TokenGrantRules {
        compile(&[policy("p", vec![endpoint("o", "rest", vec![path_rule])])])
    }

    #[test]
    fn get_also_admits_head_and_methods_ignore_case() {
        let rules = single(rule("get", "**"));
        assert_eq!(owners(&rules, &[rest("GET", "/x")]), ["o"]);
        assert_eq!(owners(&rules, &[rest("HEAD", "/x")]), ["o"]);
        assert!(owners(&rules, &[rest("POST", "/x")]).is_empty());
        let rules = single(rule("POST", "**"));
        // A JSON-RPC call carries an empty method and was sent with POST.
        assert_eq!(owners(&rules, &[rest("", "/x")]), ["o"]);
        assert!(owners(&rules, &[rest("HEAD", "/x")]).is_empty());
        let rules = single(rule("*", "**"));
        assert_eq!(owners(&rules, &[rest("DELETE", "/x")]), ["o"]);
    }

    #[test]
    fn path_globs_follow_rego_glob_semantics() {
        let cases: &[(&str, &[(&str, bool)])] = &[
            ("/a/*", &[("/a/b", true), ("/a/b/c", false), ("/a/", true)]),
            ("/a/**", &[("/a/b/c", true), ("/a", false), ("/a/", true)]),
            ("/a**", &[("/abc", true), ("/a/b", false)]),
            ("/a/**b", &[("/a/xb", true), ("/a/x/b", false)]),
            (
                "/**/git-upload-pack",
                &[
                    ("/git-upload-pack", true),
                    ("/o/r/git-upload-pack", true),
                    ("/o/r/git-receive-pack", false),
                ],
            ),
            (
                "/a/**/b",
                &[("/a/b", true), ("/a/x/y/b", true), ("/ab", false)],
            ),
            ("**/b", &[("b", true), ("/b", true), ("/x/b", true)]),
            ("**", &[("/any/thing", true)]),
        ];
        for (pattern, paths) in cases {
            let rules = single(rule("GET", pattern));
            for (path, expected) in *paths {
                assert_eq!(
                    !owners(&rules, &[rest("GET", path)]).is_empty(),
                    *expected,
                    "{pattern} vs {path}"
                );
            }
        }
    }

    #[test]
    fn query_allow_needs_every_value_and_any_lists_alternatives() {
        let mut allow = rule("GET", "**");
        allow.query.insert(
            "env".to_string(),
            ValueMatcher {
                globs: vec!["prod-*".to_string(), "staging".to_string()],
            },
        );
        let rules = single(allow);
        let get = || rest("GET", "/x");
        assert_eq!(
            owners(&rules, &[with_query(get(), "env", &["prod-a"])]),
            ["o"]
        );
        assert_eq!(
            owners(&rules, &[with_query(get(), "env", &["prod-a", "staging"])]),
            ["o"]
        );
        assert!(owners(&rules, &[with_query(get(), "env", &["prod-a", "dev"])]).is_empty());
        assert!(owners(&rules, &[get()]).is_empty(), "missing key");
        // The `.` delimiter keeps `*` within one label.
        assert!(owners(&rules, &[with_query(get(), "env", &["prod-a.b"])]).is_empty());
    }

    #[test]
    fn deny_rules_are_global_and_fire_on_any_value() {
        let mut deny = rule("GET", "**");
        deny.query.insert(
            "force".to_string(),
            ValueMatcher {
                globs: vec!["true".to_string()],
            },
        );
        let mut denying = endpoint("", "rest", Vec::new());
        denying.deny_rules = vec![deny];
        let rules = compile(&[
            policy(
                "owned",
                vec![endpoint("o", "rest", vec![rule("GET", "**")])],
            ),
            policy("other", vec![denying]),
        ]);
        let get = || rest("GET", "/x");
        assert_eq!(owners(&rules, &[get()]), ["o"], "missing key never denies");
        assert!(owners(&rules, &[with_query(get(), "force", &["no", "true"])]).is_empty());
        assert_eq!(
            owners(&rules, &[with_query(get(), "force", &["no"])]),
            ["o"]
        );
    }

    #[test]
    fn owners_need_their_own_endpoint_and_binary() {
        let mut other = endpoint("narrow", "rest", vec![rule("POST", "/a/**")]);
        other.path = "/a/**".to_string();
        let rules = compile(&[
            policy(
                "p",
                vec![endpoint("broad", "rest", vec![rule("GET", "**")]), other],
            ),
            ProviderPolicy {
                name: "glob".to_string(),
                binaries: vec!["/opt/tools/*".to_string()],
                endpoints: vec![endpoint("tool", "rest", vec![rule("GET", "**")])],
            },
        ]);
        assert_eq!(owners(&rules, &[rest("GET", "/a/x")]), ["broad"]);
        assert_eq!(owners(&rules, &[rest("POST", "/a/x")]), ["narrow"]);
        assert!(
            owners(&rules, &[rest("POST", "/b")]).is_empty(),
            "endpoint path"
        );
        let mut ancestor = rest("GET", "/x");
        ancestor.binary_path = "/usr/bin/other".to_string();
        ancestor.ancestors = vec![CURL.to_string(), "/opt/tools/run".to_string()];
        // An exact binary matches an ancestor, and so does a glob: the
        // supervisor lists the patterns that match the binary or an ancestor
        // in `binary_globs`.
        assert_eq!(owners(&rules, &[ancestor.clone()]), ["broad"]);
        ancestor.binary_globs = vec!["/opt/tools/*".to_string()];
        assert_eq!(owners(&rules, &[ancestor]), ["broad", "tool"]);
        assert_eq!(
            rules.binary_glob_patterns().collect::<Vec<_>>(),
            ["/opt/tools/*"]
        );
        assert!(
            rules
                .untranslated()
                .iter()
                .all(|note| note.location != RuleLocation::Binaries),
            "{:?}",
            rules.untranslated()
        );
        let mut tool = rest("GET", "/x");
        tool.binary_path = "/opt/tools/run".to_string();
        assert!(
            owners(&rules, &[tool.clone()]).is_empty(),
            "no pattern matched"
        );
        tool.binary_globs = vec!["/opt/tools/*".to_string()];
        assert_eq!(owners(&rules, &[tool]), ["tool"]);
        // A glob Rego could fail to compile admits no owner at all.
        let failing = compile(&[ProviderPolicy {
            name: "glob".to_string(),
            binaries: vec!["/opt/{a,b}/*".to_string()],
            endpoints: vec![endpoint("tool", "rest", vec![rule("GET", "**")])],
        }]);
        assert!(failing.fail_closed_reason().is_some());
        assert_eq!(failing.binary_glob_patterns().count(), 0);
        let mut other_host = rest("GET", "/x");
        other_host.host = "other.example.com".to_string();
        assert!(owners(&rules, &[other_host]).is_empty());
    }

    #[test]
    fn host_globs_and_hostless_endpoints() {
        let mut glob = endpoint("glob", "rest", vec![rule("GET", "**")]);
        glob.host = "*.Example.com".to_string();
        let mut hostless = endpoint("hostless", "rest", vec![rule("GET", "**")]);
        hostless.host = String::new();
        hostless.has_allowed_ips = true;
        hostless.ports = vec![8443];
        let rules = compile(&[policy("p", vec![glob, hostless])]);
        assert_eq!(owners(&rules, &[rest("GET", "/")]), ["glob"]);
        let mut deep = rest("GET", "/");
        deep.host = "a.b.example.com".to_string();
        assert!(owners(&rules, &[deep]).is_empty());
        let mut anywhere = rest("GET", "/");
        anywhere.host = "else.test".to_string();
        anywhere.port = 8443;
        assert_eq!(owners(&rules, &[anywhere]), ["hostless"]);
        let mut dotted = rest("GET", "/");
        dotted.host = format!("{HOST}.");
        assert!(owners(&rules, &[dotted]).is_empty(), "trailing dot");
    }

    #[test]
    fn untranslatable_allow_is_dropped_and_deny_is_widened() {
        let rules = single(rule("GET", "/a/?"));
        assert!(owners(&rules, &[rest("GET", "/a/b")]).is_empty());
        assert_eq!(rules.untranslated()[0].handling, Handling::PermitDropped);

        let mut denying = endpoint("o", "rest", vec![rule("GET", "**")]);
        denying.deny_rules = vec![rule("GET", "/secret/?")];
        let rules = compile(&[policy("p", vec![denying])]);
        // The deny ignores its path, so it denies every GET.
        assert!(owners(&rules, &[rest("GET", "/public")]).is_empty());
        assert_eq!(rules.untranslated()[0].handling, Handling::ForbidWidened);

        let rules = single(rule("GET", "/a/[bc]"));
        assert!(rules.fail_closed_reason().is_some());
        assert!(owners(&rules, &[rest("GET", "/x")]).is_empty());
    }

    fn call(method: &str, tool: &str, class: &str) -> HttpRequestInput {
        HttpRequestInput {
            method: String::new(),
            jsonrpc_method: method.to_string(),
            mcp_tool: tool.to_string(),
            mcp_method_class: class.to_string(),
            ..rest("POST", "/mcp")
        }
    }

    #[test]
    fn mcp_rules_match_methods_tools_and_protocol_frames() {
        let mut tool_rule = RuleMatcher {
            method: Some("tools/call".to_string()),
            ..Default::default()
        };
        tool_rule.params.insert(
            "name".to_string(),
            ValueMatcher {
                globs: vec!["github.*".to_string()],
            },
        );
        let glob_rule = RuleMatcher {
            method: Some("resources/*".to_string()),
            ..Default::default()
        };
        let extension = RuleMatcher {
            method: Some("vendor/inspect".to_string()),
            ..Default::default()
        };
        let mut mcp = endpoint("o", "mcp", vec![tool_rule, glob_rule, extension]);
        mcp.path = "/mcp".to_string();
        let rules = compile(&[policy("p", vec![mcp.clone()])]);
        let available = "available";
        assert_eq!(
            owners(&rules, &[call("tools/call", "github.read", available)]),
            ["o"]
        );
        assert!(owners(&rules, &[call("tools/call", "other", available)]).is_empty());
        assert_eq!(
            owners(&rules, &[call("resources/read", "", available)]),
            ["o"]
        );
        assert!(owners(&rules, &[call("resources/x", "", "extension")]).is_empty());
        assert_eq!(
            owners(&rules, &[call("vendor/inspect", "", "extension")]),
            ["o"]
        );
        let response = HttpRequestInput {
            jsonrpc_response: true,
            ..rest("POST", "/mcp")
        };
        assert_eq!(owners(&rules, &[response]), ["o"]);
        let stream = HttpRequestInput {
            jsonrpc_receive_stream: true,
            ..rest("GET", "/mcp")
        };
        assert_eq!(owners(&rules, &[stream]), ["o"]);

        mcp.mcp_allow_all_known_methods = true;
        let rules = compile(&[policy("p", vec![mcp])]);
        assert_eq!(
            owners(&rules, &[call("prompts/list", "", available)]),
            ["o"]
        );
        // Tool rules still narrow `tools/call`.
        assert!(owners(&rules, &[call("tools/call", "other", available)]).is_empty());
    }

    #[test]
    fn jsonrpc_endpoints_deny_response_frames() {
        let rpc = endpoint(
            "o",
            "json-rpc",
            vec![RuleMatcher {
                method: Some("*".to_string()),
                ..Default::default()
            }],
        );
        let rest_owner = endpoint("r", "rest", vec![rule("POST", "**")]);
        let rules = compile(&[policy("p", vec![rpc, rest_owner])]);
        assert_eq!(owners(&rules, &[call("anything", "", "")]), ["o", "r"]);
        let response = HttpRequestInput {
            jsonrpc_response: true,
            ..rest("POST", "/rpc")
        };
        assert!(owners(&rules, &[response]).is_empty());
    }

    fn operation(kind: &str, name: &str, fields: &[&str]) -> HttpRequestInput {
        HttpRequestInput {
            graphql_operation_type: kind.to_string(),
            graphql_operation_name: name.to_string(),
            graphql_fields: fields.iter().map(ToString::to_string).collect(),
            ..rest("POST", "/graphql")
        }
    }

    #[test]
    fn graphql_rules_match_operations_and_deny_unlisted_ones() {
        let query = RuleMatcher {
            operation_type: Some("Query".to_string()),
            ..Default::default()
        };
        let named = RuleMatcher {
            operation_type: Some("mutation".to_string()),
            operation_name: Some("Create*".to_string()),
            fields: vec!["createIssue".to_string()],
            ..Default::default()
        };
        let globbed = RuleMatcher {
            operation_type: Some("mutation".to_string()),
            fields: vec!["delete*".to_string()],
            ..Default::default()
        };
        let mut graphql = endpoint("g", "graphql", vec![query, named, globbed]);
        graphql.path = "/graphql".to_string();
        let rest_owner = endpoint("r", "rest", vec![rule("POST", "**")]);
        let rules = compile(&[policy("p", vec![graphql, rest_owner])]);
        assert_eq!(
            owners(&rules, &[operation("query", "", &["viewer"])]),
            ["g", "r"]
        );
        assert_eq!(
            owners(
                &rules,
                &[operation("mutation", "CreateOne", &["createIssue"])]
            ),
            ["g", "r"]
        );
        // An operation the GraphQL endpoint does not allow denies every
        // owner, including the REST one.
        assert!(owners(&rules, &[operation("mutation", "Other", &["createIssue"])]).is_empty());
        assert!(
            owners(
                &rules,
                &[operation("mutation", "CreateOne", &["createIssue", "x"])]
            )
            .is_empty()
        );
        // Field globs are dropped from the allow rule, so the deny widens.
        assert!(owners(&rules, &[operation("mutation", "", &["deleteRepo"])]).is_empty());
        // Every operation must be admitted by the same endpoint.
        assert!(
            owners(
                &rules,
                &[
                    operation("query", "", &["viewer"]),
                    operation("subscription", "", &["x"])
                ]
            )
            .is_empty()
        );
        assert_eq!(
            owners(
                &rules,
                &[rest("POST", "/graphql"), operation("query", "", &["a"])]
            ),
            ["r"]
        );
    }

    #[test]
    fn generated_policies_are_readable_and_annotated() {
        let rules = single(rule("GET", "/repos/**"));
        let text = rules.policy_text();
        assert!(text.contains(r#"@id("p/endpoints[0]/rules[0]")"#), "{text}");
        assert!(text.contains(r#"@token_grant_owner("o")"#), "{text}");
        assert!(
            text.contains(r#"context.path like("/repos/**", "/")"#),
            "{text}"
        );
    }

    #[test]
    fn glob_translation() {
        assert_eq!(
            translate_glob("/a/**/b/**/c", '/'),
            Glob::Patterns(vec![
                "/a/**/b/**/c".to_string(),
                "/a/**/b/c".to_string(),
                "/a/b/**/c".to_string(),
                "/a/b/c".to_string(),
            ])
        );
        assert_eq!(
            translate_glob("**.example.com", '.'),
            Glob::Patterns(vec!["**.example.com".to_string()])
        );
        assert_eq!(
            translate_glob("a**b", '.'),
            Glob::Patterns(vec!["a*b".to_string()])
        );
        assert!(matches!(translate_glob("a?", '.'), Glob::Unsupported(_)));
        assert!(matches!(translate_glob("{a,b}", '.'), Glob::MayFail(_)));
    }

    #[test]
    fn no_owner_without_stamped_endpoints() {
        let rules = compile(&[policy(
            "p",
            vec![endpoint("", "rest", vec![rule("GET", "**")])],
        )]);
        assert!(rules.policy_text().is_empty());
        assert!(owners(&rules, &[rest("GET", "/")]).is_empty());
    }
}
