// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validation for endpoint selectors whose policy-derived behavior conflicts.

use openshell_core::net::parse_ip_net;
use openshell_core::proto::{
    NetworkEndpoint, NetworkEnforcementMode, NetworkTlsMode, SandboxPolicy,
};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashSet, VecDeque};
use std::fmt;

/// One pair of endpoints that can authorize the same request but disagree on
/// policy-derived behavior that must have a single deterministic value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointAmbiguity {
    pub left_policy: String,
    pub left_endpoint_index: usize,
    pub left_selector: String,
    pub right_policy: String,
    pub right_endpoint_index: usize,
    pub right_selector: String,
    pub overlapping_ports: Vec<u32>,
    pub conflicts: Vec<String>,
}

impl fmt::Display for EndpointAmbiguity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "network policies '{}' endpoint[{}] ({}) and '{}' endpoint[{}] ({}) overlap on port(s) {} with conflicting metadata: {}",
            self.left_policy,
            self.left_endpoint_index,
            self.left_selector,
            self.right_policy,
            self.right_endpoint_index,
            self.right_selector,
            self.overlapping_ports
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
            self.conflicts.join("; "),
        )
    }
}

struct EndpointRef<'a> {
    policy: &'a str,
    index: usize,
    endpoint: &'a NetworkEndpoint,
}

/// Reject endpoint metadata ambiguity before a policy generation is activated.
///
/// Request authorization rules (`access`, `rules`, and `deny_rules`) may be
/// contributed by multiple compatible endpoints. Metadata used to establish
/// or parse a connection must agree whenever equally specific endpoint host,
/// port, and (for request-specific metadata) path selectors can match the
/// same request. When a host-naming endpoint overlaps a hostless one, the
/// host-naming endpoint supplies that metadata and must be at least as
/// restrictive.
#[must_use]
pub fn find_endpoint_ambiguities(policy: &SandboxPolicy) -> Vec<EndpointAmbiguity> {
    let endpoints = policy
        .network_policies
        .iter()
        .flat_map(|(key, rule)| {
            let policy_name = if rule.name.is_empty() {
                key.as_str()
            } else {
                rule.name.as_str()
            };
            rule.endpoints
                .iter()
                .enumerate()
                .map(move |(index, endpoint)| EndpointRef {
                    policy: policy_name,
                    index,
                    endpoint,
                })
        })
        .collect::<Vec<_>>();

    let mut ambiguities = Vec::new();
    for left_index in 0..endpoints.len() {
        for right_index in (left_index + 1)..endpoints.len() {
            let left = &endpoints[left_index];
            let right = &endpoints[right_index];
            let overlapping_ports = overlapping_ports(left.endpoint, right.endpoint);
            if overlapping_ports.is_empty()
                || !host_patterns_overlap(&left.endpoint.host, &right.endpoint.host)
            {
                continue;
            }

            let conflicts = match host_selector_specificity(&left.endpoint.host)
                .cmp(&host_selector_specificity(&right.endpoint.host))
            {
                Ordering::Equal => {
                    let mut conflicts = connection_conflicts(left.endpoint, right.endpoint);
                    if endpoint_contributes_request_pipeline_metadata(left.endpoint)
                        && endpoint_contributes_request_pipeline_metadata(right.endpoint)
                        && path_patterns_overlap(&left.endpoint.path, &right.endpoint.path)
                    {
                        conflicts.extend(match path_selector_specificity(&left.endpoint.path)
                            .cmp(&path_selector_specificity(&right.endpoint.path))
                        {
                            Ordering::Equal => {
                                request_pipeline_conflicts(left.endpoint, right.endpoint)
                            }
                            Ordering::Greater => {
                                less_restrictive_conflicts(left.endpoint, right.endpoint)
                            }
                            Ordering::Less => {
                                less_restrictive_conflicts(right.endpoint, left.endpoint)
                            }
                        });
                    }
                    conflicts
                }
                Ordering::Greater => less_restrictive_conflicts(left.endpoint, right.endpoint),
                Ordering::Less => less_restrictive_conflicts(right.endpoint, left.endpoint),
            };
            if conflicts.is_empty() {
                continue;
            }

            ambiguities.push(EndpointAmbiguity {
                left_policy: left.policy.to_string(),
                left_endpoint_index: left.index,
                left_selector: endpoint_selector(left.endpoint),
                right_policy: right.policy.to_string(),
                right_endpoint_index: right.index,
                right_selector: endpoint_selector(right.endpoint),
                overlapping_ports,
                conflicts,
            });
        }
    }
    ambiguities
}

fn endpoint_selector(endpoint: &NetworkEndpoint) -> String {
    let host = if endpoint.host.is_empty() {
        "<any-host>"
    } else {
        &endpoint.host
    };
    let path = if endpoint.path.is_empty() {
        ""
    } else {
        endpoint.path.as_str()
    };
    format!("{host}:{}{}", display_ports(endpoint), path)
}

fn display_ports(endpoint: &NetworkEndpoint) -> String {
    effective_ports(endpoint)
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn effective_ports(endpoint: &NetworkEndpoint) -> BTreeSet<u32> {
    if endpoint.ports.is_empty() {
        (endpoint.port > 0)
            .then_some(endpoint.port)
            .into_iter()
            .collect()
    } else {
        endpoint
            .ports
            .iter()
            .copied()
            .filter(|port| *port > 0)
            .collect()
    }
}

fn overlapping_ports(left: &NetworkEndpoint, right: &NetworkEndpoint) -> Vec<u32> {
    effective_ports(left)
        .intersection(&effective_ports(right))
        .copied()
        .collect()
}

fn connection_conflicts(left: &NetworkEndpoint, right: &NetworkEndpoint) -> Vec<String> {
    let mut conflicts = Vec::new();
    push_conflict(
        &mut conflicts,
        "transparent_tcp_eligible",
        &is_explicit_tcp(&left.protocol),
        &is_explicit_tcp(&right.protocol),
    );
    push_conflict(
        &mut conflicts,
        "tls",
        &normalized_tls(left.tls),
        &normalized_tls(right.tls),
    );
    push_conflict(
        &mut conflicts,
        "allowed_ips",
        &normalized_strings(&left.allowed_ips),
        &normalized_strings(&right.allowed_ips),
    );
    conflicts
}

fn is_explicit_tcp(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("tcp")
}

fn is_l7_protocol(protocol: &str) -> bool {
    !protocol.is_empty() && !is_explicit_tcp(protocol)
}

/// A host-naming endpoint replaces an overlapping hostless `allowed_ips`
/// endpoint's connection and request-pipeline metadata for every request both
/// can match, so it must be at least as restrictive on each setting that has
/// a stricter direction. The same invariant applies to a more specific path.
/// Parser and credential transformation settings must agree because allow and
/// deny rules still combine across both endpoints at request time.
fn less_restrictive_conflicts(narrower: &NetworkEndpoint, broader: &NetworkEndpoint) -> Vec<String> {
    let mut conflicts = Vec::new();
    conflicts.extend(credential_transform_conflicts(narrower, broader));
    if narrower.allow_uninspected_credentials && !broader.allow_uninspected_credentials {
        push_looser(&mut conflicts, "allow_uninspected_credentials", &true, &false);
    }
    if is_explicit_tcp(&narrower.protocol) && !is_explicit_tcp(&broader.protocol) {
        push_looser(
            &mut conflicts,
            "protocol",
            &narrower.protocol,
            &broader.protocol,
        );
    }
    if normalized_tls(narrower.tls) == NetworkTlsMode::Skip as i32
        && normalized_tls(broader.tls) != NetworkTlsMode::Skip as i32
    {
        push_looser(&mut conflicts, "tls", &"skip", &"terminate");
    }
    if !allowed_ips_within(&narrower.allowed_ips, &broader.allowed_ips) {
        push_looser(
            &mut conflicts,
            "allowed_ips",
            &normalized_strings(&narrower.allowed_ips),
            &normalized_strings(&broader.allowed_ips),
        );
    }

    if !is_l7_protocol(&broader.protocol) {
        return conflicts;
    }
    if !is_l7_protocol(&narrower.protocol)
        || !narrower.protocol.eq_ignore_ascii_case(&broader.protocol)
    {
        push_looser(
            &mut conflicts,
            "protocol",
            &narrower.protocol,
            &broader.protocol,
        );
        return conflicts;
    }
    if normalized_enforcement(broader.enforcement) == NetworkEnforcementMode::Enforce as i32
        && normalized_enforcement(narrower.enforcement) != NetworkEnforcementMode::Enforce as i32
    {
        push_looser(&mut conflicts, "enforcement", &"audit", &"enforce");
    }
    if narrower.allow_encoded_slash && !broader.allow_encoded_slash {
        push_looser(
            &mut conflicts,
            "allow_encoded_slash",
            &narrower.allow_encoded_slash,
            &broader.allow_encoded_slash,
        );
    }
    if narrower.protocol.eq_ignore_ascii_case("websocket") {
        push_conflict(
            &mut conflicts,
            "websocket_graphql_policy",
            &websocket_graphql_policy(narrower),
            &websocket_graphql_policy(broader),
        );
    }
    conflicts.extend(parser_option_conflicts(narrower, broader));
    if narrower.protocol.eq_ignore_ascii_case("graphql")
        && normalized_body_limit(narrower.graphql_max_body_bytes)
            > normalized_body_limit(broader.graphql_max_body_bytes)
    {
        push_looser(
            &mut conflicts,
            "graphql_max_body_bytes",
            &normalized_body_limit(narrower.graphql_max_body_bytes),
            &normalized_body_limit(broader.graphql_max_body_bytes),
        );
    }
    if is_json_rpc_family(&narrower.protocol)
        && normalized_body_limit(narrower.json_rpc_max_body_bytes)
            > normalized_body_limit(broader.json_rpc_max_body_bytes)
    {
        push_looser(
            &mut conflicts,
            "json_rpc_max_body_bytes",
            &normalized_body_limit(narrower.json_rpc_max_body_bytes),
            &normalized_body_limit(broader.json_rpc_max_body_bytes),
        );
    }
    if narrower.protocol.eq_ignore_ascii_case("mcp")
        && normalized_mcp_strict_tool_names(broader)
        && !normalized_mcp_strict_tool_names(narrower)
    {
        push_looser(&mut conflicts, "mcp.strict_tool_names", &false, &true);
    }
    conflicts
}

fn push_looser<T: fmt::Debug + ?Sized>(
    conflicts: &mut Vec<String>,
    field: &str,
    narrower: &T,
    broader: &T,
) {
    conflicts.push(format!(
        "{field}={narrower:?} on the more selective endpoint is less restrictive than {broader:?} on the broader endpoint"
    ));
}

/// True when every address `inner` permits is also permitted by `outer`.
///
/// An empty list permits any public address, and runtime validation rejects
/// `allowed_ips` broad enough to cover all of them, so an empty `inner` is
/// never within a non-empty `outer`. Each `inner` network must sit inside a
/// single `outer` network; a network split across adjacent `outer` entries
/// is conservatively treated as not contained.
fn allowed_ips_within(inner: &[String], outer: &[String]) -> bool {
    if inner.is_empty() {
        return outer.is_empty();
    }
    let Some(outer) = outer
        .iter()
        .map(|entry| parse_ip_net(entry).ok())
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    inner.iter().all(|entry| {
        parse_ip_net(entry).is_ok_and(|net| outer.iter().any(|outer| outer.contains(&net)))
    })
}

/// Keep request-pipeline ambiguity checks aligned with Rego's
/// `endpoint_has_extended_config` predicate. Plain L4 endpoints authorize a
/// destination but do not participate in endpoint-config selection, so they
/// cannot compete with the single L7/connection-config endpoint selected for
/// that request.
fn endpoint_contributes_request_pipeline_metadata(endpoint: &NetworkEndpoint) -> bool {
    (!endpoint.protocol.is_empty() && !endpoint.protocol.eq_ignore_ascii_case("tcp"))
        || !endpoint.allowed_ips.is_empty()
        || endpoint.tls != NetworkTlsMode::Unspecified as i32
        || endpoint.credential_binding.is_some()
}

fn request_pipeline_conflicts(left: &NetworkEndpoint, right: &NetworkEndpoint) -> Vec<String> {
    let mut conflicts = Vec::new();
    push_conflict(
        &mut conflicts,
        "protocol",
        &normalized_request_protocol(&left.protocol),
        &normalized_request_protocol(&right.protocol),
    );
    push_conflict(
        &mut conflicts,
        "enforcement",
        &normalized_enforcement(left.enforcement),
        &normalized_enforcement(right.enforcement),
    );
    push_conflict(
        &mut conflicts,
        "allow_encoded_slash",
        &left.allow_encoded_slash,
        &right.allow_encoded_slash,
    );
    conflicts.extend(credential_transform_conflicts(left, right));
    conflicts.extend(parser_option_conflicts(left, right));
    push_conflict(
        &mut conflicts,
        "allow_uninspected_credentials",
        &left.allow_uninspected_credentials,
        &right.allow_uninspected_credentials,
    );
    if left.protocol.eq_ignore_ascii_case("websocket")
        && right.protocol.eq_ignore_ascii_case("websocket")
    {
        push_conflict(
            &mut conflicts,
            "websocket_graphql_policy",
            &websocket_graphql_policy(left),
            &websocket_graphql_policy(right),
        );
    }
    push_conflict(
        &mut conflicts,
        "credential_binding.provider",
        &left
            .credential_binding
            .as_ref()
            .map(|binding| binding.provider.as_str())
            .unwrap_or_default(),
        &right
            .credential_binding
            .as_ref()
            .map(|binding| binding.provider.as_str())
            .unwrap_or_default(),
    );

    if left.protocol.eq_ignore_ascii_case("graphql")
        && right.protocol.eq_ignore_ascii_case("graphql")
    {
        push_conflict(
            &mut conflicts,
            "graphql_max_body_bytes",
            &normalized_body_limit(left.graphql_max_body_bytes),
            &normalized_body_limit(right.graphql_max_body_bytes),
        );
    }
    if left.protocol.eq_ignore_ascii_case(&right.protocol) && is_json_rpc_family(&left.protocol) {
        push_conflict(
            &mut conflicts,
            "json_rpc_max_body_bytes",
            &normalized_body_limit(left.json_rpc_max_body_bytes),
            &normalized_body_limit(right.json_rpc_max_body_bytes),
        );
    }
    if left.protocol.eq_ignore_ascii_case("mcp") && right.protocol.eq_ignore_ascii_case("mcp") {
        push_conflict(
            &mut conflicts,
            "mcp.strict_tool_names",
            &normalized_mcp_strict_tool_names(left),
            &normalized_mcp_strict_tool_names(right),
        );
    }
    conflicts
}

/// Signing and rewrites apply to every forwarded request, including those
/// admitted only by another endpoint. Their settings must therefore agree.
fn credential_transform_conflicts(left: &NetworkEndpoint, right: &NetworkEndpoint) -> Vec<String> {
    let mut conflicts = Vec::new();
    push_conflict(
        &mut conflicts,
        "websocket_credential_rewrite",
        &left.websocket_credential_rewrite,
        &right.websocket_credential_rewrite,
    );
    push_conflict(
        &mut conflicts,
        "request_body_credential_rewrite",
        &left.request_body_credential_rewrite,
        &right.request_body_credential_rewrite,
    );
    push_conflict(
        &mut conflicts,
        "credential_signing",
        &left.credential_signing,
        &right.credential_signing,
    );
    push_conflict(
        &mut conflicts,
        "signing_service",
        &left.signing_service,
        &right.signing_service,
    );
    push_conflict(
        &mut conflicts,
        "signing_region",
        &left.signing_region,
        &right.signing_region,
    );
    conflicts
}

fn parser_option_conflicts(left: &NetworkEndpoint, right: &NetworkEndpoint) -> Vec<String> {
    let mut conflicts = Vec::new();
    if left.protocol.eq_ignore_ascii_case("mcp") && right.protocol.eq_ignore_ascii_case("mcp") {
        let versions = |endpoint: &NetworkEndpoint| {
            endpoint
                .mcp
                .as_ref()
                .filter(|options| !options.versions.is_empty())
                .map_or_else(
                    || vec![openshell_core::mcp::DEFAULT_MCP_PROTOCOL_VERSION.to_string()],
                    |options| normalized_strings(&options.versions),
                )
        };
        push_conflict(
            &mut conflicts,
            "mcp.versions",
            &versions(left),
            &versions(right),
        );
    }
    if left.protocol.eq_ignore_ascii_case(&right.protocol)
        && (left.protocol.eq_ignore_ascii_case("graphql")
            || left.protocol.eq_ignore_ascii_case("websocket"))
    {
        let mode = |endpoint: &NetworkEndpoint| {
            if endpoint.persisted_queries.is_empty() {
                "deny".to_string()
            } else {
                endpoint.persisted_queries.clone()
            }
        };
        push_conflict(&mut conflicts, "persisted_queries", &mode(left), &mode(right));
        push_conflict(
            &mut conflicts,
            "graphql_persisted_queries",
            &left.graphql_persisted_queries,
            &right.graphql_persisted_queries,
        );
    }
    conflicts
}

fn normalized_request_protocol(protocol: &str) -> String {
    if protocol.eq_ignore_ascii_case("tcp") {
        String::new()
    } else {
        protocol.to_ascii_lowercase()
    }
}

fn websocket_graphql_policy(endpoint: &NetworkEndpoint) -> bool {
    let allow_rule_has_graphql_fields = endpoint.rules.iter().any(|rule| {
        rule.allow.as_ref().is_some_and(|allow| {
            !allow.operation_type.is_empty()
                || !allow.operation_name.is_empty()
                || !allow.fields.is_empty()
        })
    });
    let deny_rule_has_graphql_fields = endpoint.deny_rules.iter().any(|deny| {
        !deny.operation_type.is_empty()
            || !deny.operation_name.is_empty()
            || !deny.fields.is_empty()
    });

    !endpoint.graphql_persisted_queries.is_empty()
        || (!endpoint.persisted_queries.is_empty() && endpoint.persisted_queries != "deny")
        || allow_rule_has_graphql_fields
        || deny_rule_has_graphql_fields
}

fn push_conflict<T: fmt::Debug + PartialEq>(
    conflicts: &mut Vec<String>,
    field: &str,
    left: &T,
    right: &T,
) {
    if left != right {
        conflicts.push(format!("{field}={left:?} vs {right:?}"));
    }
}

fn normalized_tls(value: i32) -> i32 {
    if value == NetworkTlsMode::Skip as i32 {
        NetworkTlsMode::Skip as i32
    } else if NetworkTlsMode::try_from(value).is_ok() {
        NetworkTlsMode::Unspecified as i32
    } else {
        value
    }
}

fn normalized_enforcement(value: i32) -> i32 {
    if value == NetworkEnforcementMode::Enforce as i32 {
        NetworkEnforcementMode::Enforce as i32
    } else if NetworkEnforcementMode::try_from(value).is_ok() {
        NetworkEnforcementMode::Audit as i32
    } else {
        value
    }
}

fn normalized_strings(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

const DEFAULT_BODY_LIMIT: u32 = 65_536;

fn normalized_body_limit(value: u32) -> u32 {
    if value == 0 {
        DEFAULT_BODY_LIMIT
    } else {
        value
    }
}

fn is_json_rpc_family(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("json-rpc") || protocol.eq_ignore_ascii_case("mcp")
}

fn normalized_mcp_strict_tool_names(endpoint: &NetworkEndpoint) -> bool {
    endpoint
        .mcp
        .as_ref()
        .and_then(|options| options.strict_tool_names)
        .unwrap_or(true)
}

fn host_patterns_overlap(left: &str, right: &str) -> bool {
    if left.is_empty() || right.is_empty() {
        return true;
    }
    glob_patterns_overlap(&left.to_ascii_lowercase(), &right.to_ascii_lowercase(), '.')
}

/// Match Rego's `matched_endpoint_config` host rank.
///
/// An endpoint that names a host (exactly or by glob) takes precedence over a
/// hostless `allowed_ips` endpoint for every request both can match, so the
/// two never compete for connection or request metadata; see
/// `less_restrictive_conflicts`. Endpoints of equal rank must agree.
fn host_selector_specificity(host: &str) -> usize {
    usize::from(!host.is_empty())
}

fn path_patterns_overlap(left: &str, right: &str) -> bool {
    if left.is_empty()
        || right.is_empty()
        || matches!(left, "**" | "/**")
        || matches!(right, "**" | "/**")
    {
        return true;
    }
    runtime_path_patterns_overlap(left, right)
}

/// Match the runtime route-selection rank used by `L7EndpointConfig`.
///
/// Overlapping endpoints with different ranks do not compete for request
/// metadata: the endpoint with the more-specific path wins. Equal-rank
/// overlaps must agree because iteration order would otherwise decide which
/// parser, credential handling, or enforcement behavior applies. Different-rank
/// overlaps must preserve the broader endpoint's restrictions as well.
fn path_selector_specificity(path: &str) -> usize {
    if path.is_empty() {
        0
    } else {
        path.chars().filter(|character| *character != '*').count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CharacterRange {
    start: char,
    end: char,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GlobToken {
    Literal(char),
    AnyChar,
    CharacterClass {
        ranges: Vec<CharacterRange>,
        negated: bool,
    },
    Star {
        crosses_delimiter: bool,
    },
}

fn tokenize_delimited_glob(pattern: &str) -> Vec<GlobToken> {
    let chars = pattern.chars().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '*' {
            tokens.push(GlobToken::Literal(chars[index]));
            index += 1;
            continue;
        }

        let start = index;
        while index < chars.len() && chars[index] == '*' {
            index += 1;
        }
        tokens.push(GlobToken::Star {
            crosses_delimiter: index - start >= 2,
        });
    }
    tokens
}

fn tokenize_runtime_path_glob(pattern: &str) -> Option<Vec<GlobToken>> {
    let chars = pattern.chars().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        match chars[index] {
            '?' => {
                tokens.push(GlobToken::AnyChar);
                index += 1;
            }
            '*' => {
                let start = index;
                while index < chars.len() && chars[index] == '*' {
                    index += 1;
                }
                let count = index - start;
                if count > 2 {
                    return None;
                }
                if count == 2 {
                    let starts_component = start == 0 || chars[start - 1] == '/';
                    let ends_component = index == chars.len() || chars[index] == '/';
                    if !starts_component || !ends_component {
                        return None;
                    }
                    if index < chars.len() && chars[index] == '/' {
                        index += 1;
                    }
                }
                // `glob::Pattern::matches` uses `require_literal_separator:
                // false`, so both `*` and `**` can consume `/`.
                tokens.push(GlobToken::Star {
                    crosses_delimiter: true,
                });
            }
            '[' => {
                let negated = chars.get(index + 1) == Some(&'!');
                let content_start = index + if negated { 2 } else { 1 };
                let close = chars[content_start..]
                    .iter()
                    .position(|character| *character == ']')
                    .map(|offset| content_start + offset)?;
                if close == content_start {
                    return None;
                }
                tokens.push(GlobToken::CharacterClass {
                    ranges: parse_character_ranges(&chars[content_start..close]),
                    negated,
                });
                index = close + 1;
            }
            literal => {
                tokens.push(GlobToken::Literal(literal));
                index += 1;
            }
        }
    }
    Some(tokens)
}

fn parse_character_ranges(characters: &[char]) -> Vec<CharacterRange> {
    let mut ranges = Vec::new();
    let mut index = 0;
    while index < characters.len() {
        if index + 2 < characters.len() && characters[index + 1] == '-' {
            ranges.push(CharacterRange {
                start: characters[index],
                end: characters[index + 2],
            });
            index += 3;
        } else {
            ranges.push(CharacterRange {
                start: characters[index],
                end: characters[index],
            });
            index += 1;
        }
    }
    ranges
}

fn runtime_path_patterns_overlap(left: &str, right: &str) -> bool {
    let (Some(left), Some(right)) = (
        tokenize_runtime_path_glob(left),
        tokenize_runtime_path_glob(right),
    ) else {
        // Invalid path globs are rejected by ordinary policy validation. Keep
        // ambiguity validation conservative if it is called independently.
        return true;
    };
    token_languages_overlap(&left, &right, '/')
}

/// Decide whether two delimiter-aware glob languages intersect.
///
/// This is a small product-NFA search. `*` consumes any character except the
/// delimiter and `**` consumes any character, including the delimiter. Star
/// epsilon transitions and self-loops make the state space finite.
fn glob_patterns_overlap(left: &str, right: &str, delimiter: char) -> bool {
    let left = tokenize_delimited_glob(left);
    let right = tokenize_delimited_glob(right);
    token_languages_overlap(&left, &right, delimiter)
}

fn token_languages_overlap(left: &[GlobToken], right: &[GlobToken], delimiter: char) -> bool {
    let mut queue = VecDeque::from([(0_usize, 0_usize)]);
    let mut seen = HashSet::new();

    while let Some((left_index, right_index)) = queue.pop_front() {
        if !seen.insert((left_index, right_index)) {
            continue;
        }
        if left_index == left.len() && right_index == right.len() {
            return true;
        }

        if matches!(left.get(left_index), Some(GlobToken::Star { .. })) {
            queue.push_back((left_index + 1, right_index));
        }
        if matches!(right.get(right_index), Some(GlobToken::Star { .. })) {
            queue.push_back((left_index, right_index + 1));
        }

        let Some(left_token) = left.get(left_index) else {
            continue;
        };
        let Some(right_token) = right.get(right_index) else {
            continue;
        };
        if tokens_share_character(left_token, right_token, delimiter) {
            let next_left = if matches!(left_token, GlobToken::Star { .. }) {
                left_index
            } else {
                left_index + 1
            };
            let next_right = if matches!(right_token, GlobToken::Star { .. }) {
                right_index
            } else {
                right_index + 1
            };
            queue.push_back((next_left, next_right));
        }
    }
    false
}

fn tokens_share_character(left: &GlobToken, right: &GlobToken, delimiter: char) -> bool {
    let left_ranges = token_character_ranges(left, delimiter);
    let right_ranges = token_character_ranges(right, delimiter);
    left_ranges.iter().any(|left| {
        right_ranges
            .iter()
            .any(|right| left.0 <= right.1 && right.0 <= left.1)
    })
}

fn token_character_ranges(token: &GlobToken, delimiter: char) -> Vec<(u32, u32)> {
    match token {
        GlobToken::Literal(value) => vec![(u32::from(*value), u32::from(*value))],
        GlobToken::AnyChar
        | GlobToken::Star {
            crosses_delimiter: true,
        } => unicode_scalar_ranges(),
        GlobToken::Star {
            crosses_delimiter: false,
        } => complement_ranges(&[(u32::from(delimiter), u32::from(delimiter))]),
        GlobToken::CharacterClass { ranges, negated } => {
            let ranges = normalize_ranges(
                ranges
                    .iter()
                    .filter(|range| range.start <= range.end)
                    .map(|range| (u32::from(range.start), u32::from(range.end)))
                    .collect(),
            );
            if *negated {
                complement_ranges(&ranges)
            } else {
                ranges
            }
        }
    }
}

fn unicode_scalar_ranges() -> Vec<(u32, u32)> {
    vec![(0, 0xD7FF), (0xE000, 0x0010_FFFF)]
}

fn normalize_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    ranges.sort_unstable();
    let mut normalized: Vec<(u32, u32)> = Vec::new();
    for (start, end) in ranges {
        for (start, end) in intersect_with_unicode_scalars(start, end) {
            if let Some(last) = normalized.last_mut()
                && start <= last.1.saturating_add(1)
            {
                last.1 = last.1.max(end);
            } else {
                normalized.push((start, end));
            }
        }
    }
    normalized
}

fn intersect_with_unicode_scalars(start: u32, end: u32) -> Vec<(u32, u32)> {
    unicode_scalar_ranges()
        .into_iter()
        .filter_map(|(scalar_start, scalar_end)| {
            let start = start.max(scalar_start);
            let end = end.min(scalar_end);
            (start <= end).then_some((start, end))
        })
        .collect()
}

fn complement_ranges(ranges: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let ranges = normalize_ranges(ranges.to_vec());
    let mut complement = Vec::new();
    for (universe_start, universe_end) in unicode_scalar_ranges() {
        let mut cursor = universe_start;
        for &(start, end) in &ranges {
            if end < universe_start || start > universe_end {
                continue;
            }
            let start = start.max(universe_start);
            let end = end.min(universe_end);
            if cursor < start {
                complement.push((cursor, start - 1));
            }
            cursor = end.saturating_add(1);
            if cursor > universe_end {
                break;
            }
        }
        if cursor <= universe_end {
            complement.push((cursor, universe_end));
        }
    }
    complement
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        L7Allow, L7Rule, NetworkAccessPreset, NetworkBinary, NetworkPolicyRule,
    };

    fn endpoint(host: &str, port: u32) -> NetworkEndpoint {
        NetworkEndpoint {
            host: host.to_string(),
            port,
            ..Default::default()
        }
    }

    fn policy_with(left: NetworkEndpoint, right: NetworkEndpoint) -> SandboxPolicy {
        let mut policy = SandboxPolicy::default();
        policy.network_policies.insert(
            "left".to_string(),
            NetworkPolicyRule {
                name: "left".to_string(),
                endpoints: vec![left],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/curl".to_string(),
                }],
            },
        );
        policy.network_policies.insert(
            "right".to_string(),
            NetworkPolicyRule {
                name: "right".to_string(),
                endpoints: vec![right],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/bash".to_string(),
                }],
            },
        );
        policy
    }

    #[test]
    fn exact_and_wildcard_hosts_overlap() {
        assert!(host_patterns_overlap("api.example.com", "*.example.com"));
        assert!(host_patterns_overlap(
            "us-aiplatform.googleapis.com",
            "*-aiplatform.googleapis.com"
        ));
        assert!(!host_patterns_overlap("api.example.com", "*.other.com"));
    }

    #[test]
    fn intersecting_wildcards_are_detected() {
        assert!(host_patterns_overlap("*.example.com", "api.*.com"));
        assert!(host_patterns_overlap("**.example.com", "api.example.com"));
        assert!(!host_patterns_overlap("*.example.com", "*.example.org"));
    }

    #[test]
    fn disjoint_ports_do_not_overlap() {
        let mut left = endpoint("api.example.com", 443);
        left.tls = NetworkTlsMode::Skip as i32;
        let right = endpoint("api.example.com", 8443);
        assert!(find_endpoint_ambiguities(&policy_with(left, right)).is_empty());
    }

    #[test]
    fn compatible_request_rules_may_overlap() {
        let mut left = endpoint("api.example.com", 443);
        left.protocol = "rest".to_string();
        left.tls = NetworkTlsMode::Skip as i32;
        let mut right = left.clone();
        left.access = NetworkAccessPreset::ReadOnly as i32;
        right.access = NetworkAccessPreset::ReadWrite as i32;

        assert!(find_endpoint_ambiguities(&policy_with(left, right)).is_empty());
    }

    #[test]
    fn advisor_provenance_does_not_make_endpoints_ambiguous() {
        let explicit = endpoint("api.example.com", 443);
        let mut proposed = explicit.clone();
        proposed.advisor_proposed = true;

        assert!(find_endpoint_ambiguities(&policy_with(explicit, proposed)).is_empty());
    }

    #[test]
    fn plain_l4_endpoint_does_not_compete_with_l7_endpoint_metadata() {
        let left = endpoint("api.example.com", 443);
        let mut right = endpoint("api.example.com", 443);
        right.protocol = "rest".to_string();
        right.enforcement = NetworkEnforcementMode::Enforce as i32;

        assert!(find_endpoint_ambiguities(&policy_with(left, right)).is_empty());
    }

    #[test]
    fn disjoint_path_specific_protocols_may_overlap() {
        let mut left = endpoint("api.example.com", 443);
        left.path = "/graphql".to_string();
        left.protocol = "graphql".to_string();
        let mut right = endpoint("api.example.com", 443);
        right.path = "/repos/**".to_string();
        right.protocol = "rest".to_string();

        assert!(find_endpoint_ambiguities(&policy_with(left, right)).is_empty());
    }

    #[test]
    fn question_mark_path_overlap_is_detected() {
        let mut left = endpoint("api.example.com", 443);
        left.path = "/v?".to_string();
        left.protocol = "rest".to_string();
        let mut right = endpoint("api.example.com", 443);
        right.path = "/v1".to_string();
        right.protocol = "graphql".to_string();

        let ambiguities = find_endpoint_ambiguities(&policy_with(left, right));
        assert_eq!(ambiguities.len(), 1);
        assert!(
            ambiguities[0]
                .conflicts
                .iter()
                .any(|field| field.contains("protocol"))
        );
    }

    #[test]
    fn overlapping_character_class_paths_are_detected() {
        let mut left = endpoint("api.example.com", 443);
        left.path = "/v[12]".to_string();
        left.protocol = "rest".to_string();
        let mut right = endpoint("api.example.com", 443);
        right.path = "/v[23]".to_string();
        right.protocol = "graphql".to_string();

        assert_eq!(
            find_endpoint_ambiguities(&policy_with(left, right)).len(),
            1
        );
    }

    #[test]
    fn disjoint_character_class_paths_may_overlap_by_host_and_port() {
        let mut left = endpoint("api.example.com", 443);
        left.path = "/v[12]".to_string();
        left.protocol = "rest".to_string();
        let mut right = endpoint("api.example.com", 443);
        right.path = "/v[34]".to_string();
        right.protocol = "graphql".to_string();

        assert!(find_endpoint_ambiguities(&policy_with(left, right)).is_empty());
    }

    #[test]
    fn negated_character_class_paths_follow_runtime_glob_semantics() {
        assert!(runtime_path_patterns_overlap("/v[!0]", "/v1"));
        assert!(!runtime_path_patterns_overlap("/v[!0]", "/v0"));
    }

    #[test]
    fn more_specific_path_cannot_change_the_broader_parser() {
        let mut left = endpoint("api.example.com", 443);
        left.protocol = "rest".to_string();
        left.enforcement = NetworkEnforcementMode::Enforce as i32;
        let mut right = endpoint("api.example.com", 443);
        right.path = "/graphql".to_string();
        right.protocol = "graphql".to_string();
        right.enforcement = NetworkEnforcementMode::Enforce as i32;

        assert_less_restrictive(right, left, "protocol");
    }

    #[test]
    fn exact_wildcard_tls_conflict_is_rejected() {
        let mut left = endpoint("*.example.com", 443);
        left.tls = NetworkTlsMode::Skip as i32;
        let right = endpoint("api.example.com", 443);
        let ambiguities = find_endpoint_ambiguities(&policy_with(left, right));

        assert_eq!(ambiguities.len(), 1);
        assert!(ambiguities[0].conflicts[0].contains("tls"));
        assert!(ambiguities[0].to_string().contains("left"));
        assert!(ambiguities[0].to_string().contains("right"));
    }

    #[test]
    fn allowed_ip_conflict_is_rejected_regardless_of_order() {
        let mut left = endpoint("api.example.com", 443);
        left.allowed_ips = vec!["10.0.1.0/24".to_string(), "10.0.0.0/24".to_string()];
        let mut compatible = endpoint("api.example.com", 443);
        compatible.allowed_ips = vec!["10.0.0.0/24".to_string(), "10.0.1.0/24".to_string()];
        assert!(find_endpoint_ambiguities(&policy_with(left.clone(), compatible)).is_empty());

        let mut conflicting = endpoint("api.example.com", 443);
        conflicting.allowed_ips = vec!["10.0.2.0/24".to_string()];
        let ambiguities = find_endpoint_ambiguities(&policy_with(left, conflicting));
        assert!(
            ambiguities[0]
                .conflicts
                .iter()
                .any(|field| field.contains("allowed_ips"))
        );
    }

    #[test]
    fn credential_and_parser_conflicts_are_rejected_on_same_path() {
        let mut left = endpoint("api.example.com", 443);
        left.protocol = "rest".to_string();
        left.credential_signing = "sigv4".to_string();
        left.signing_service = "execute-api".to_string();
        let mut right = left.clone();
        right.signing_service = "bedrock".to_string();
        right.allow_encoded_slash = true;

        let ambiguities = find_endpoint_ambiguities(&policy_with(left, right));
        assert!(
            ambiguities[0]
                .conflicts
                .iter()
                .any(|field| field.contains("signing_service"))
        );
        assert!(
            ambiguities[0]
                .conflicts
                .iter()
                .any(|field| field.contains("allow_encoded_slash"))
        );
    }

    #[test]
    fn credential_binding_conflicts_are_rejected_on_same_endpoint() {
        let mut left = endpoint("api.example.com", 443);
        left.credential_binding = Some(openshell_core::proto::NetworkCredentialBinding {
            provider: "provider-a".to_string(),
        });
        let mut right = endpoint("api.example.com", 443);
        right.credential_binding = Some(openshell_core::proto::NetworkCredentialBinding {
            provider: "provider-b".to_string(),
        });

        let ambiguities = find_endpoint_ambiguities(&policy_with(left, right));
        assert_eq!(ambiguities.len(), 1);
        assert!(
            ambiguities[0]
                .conflicts
                .iter()
                .any(|field| field.contains("credential_binding.provider"))
        );
    }

    #[test]
    fn json_rpc_body_limit_is_compared_only_within_the_same_protocol() {
        let mut json_rpc = endpoint("api.example.com", 443);
        json_rpc.protocol = "json-rpc".to_string();
        json_rpc.json_rpc_max_body_bytes = 1_024;

        let mut mcp = endpoint("api.example.com", 443);
        mcp.protocol = "mcp".to_string();
        mcp.json_rpc_max_body_bytes = 2_048;

        let mixed_protocol = find_endpoint_ambiguities(&policy_with(json_rpc, mcp.clone()));
        assert_eq!(mixed_protocol.len(), 1);
        assert!(
            mixed_protocol[0]
                .conflicts
                .iter()
                .any(|field| field.contains("protocol"))
        );
        assert!(
            !mixed_protocol[0]
                .conflicts
                .iter()
                .any(|field| field.contains("json_rpc_max_body_bytes"))
        );

        let mut other_mcp = mcp.clone();
        other_mcp.json_rpc_max_body_bytes = 4_096;
        let same_protocol = find_endpoint_ambiguities(&policy_with(mcp, other_mcp));
        assert_eq!(same_protocol.len(), 1);
        assert!(
            same_protocol[0]
                .conflicts
                .iter()
                .any(|field| field.contains("json_rpc_max_body_bytes"))
        );
    }

    #[test]
    fn websocket_graphql_classification_conflict_is_rejected() {
        let mut graphql = endpoint("api.example.com", 443);
        graphql.protocol = "websocket".to_string();
        graphql.rules.push(L7Rule {
            allow: Some(L7Allow {
                operation_type: "subscription".to_string(),
                ..Default::default()
            }),
        });
        let mut transport = endpoint("api.example.com", 443);
        transport.protocol = "websocket".to_string();
        transport.rules.push(L7Rule {
            allow: Some(L7Allow {
                method: "WEBSOCKET_TEXT".to_string(),
                ..Default::default()
            }),
        });

        let ambiguities = find_endpoint_ambiguities(&policy_with(graphql, transport));
        assert_eq!(ambiguities.len(), 1);
        assert!(
            ambiguities[0]
                .conflicts
                .iter()
                .any(|field| field.contains("websocket_graphql_policy"))
        );
    }

    #[test]
    fn matching_websocket_graphql_classification_is_compatible() {
        let mut left = endpoint("api.example.com", 443);
        left.protocol = "websocket".to_string();
        left.persisted_queries = "allow_registered".to_string();
        let mut right = left.clone();
        right.rules.push(L7Rule {
            allow: Some(L7Allow {
                operation_name: "Events".to_string(),
                ..Default::default()
            }),
        });

        assert!(find_endpoint_ambiguities(&policy_with(left, right)).is_empty());
    }

    #[test]
    fn different_binary_lists_do_not_hide_endpoint_ambiguity() {
        let mut left = endpoint("api.example.com", 443);
        left.tls = NetworkTlsMode::Skip as i32;
        let right = endpoint("api.example.com", 443);

        assert_eq!(
            find_endpoint_ambiguities(&policy_with(left, right)).len(),
            1
        );
    }

    fn hostless(port: u32, allowed_ips: &[&str]) -> NetworkEndpoint {
        NetworkEndpoint {
            port,
            allowed_ips: allowed_ips.iter().map(ToString::to_string).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn hosted_endpoint_takes_precedence_over_hostless_connection_metadata() {
        let open_web = hostless(443, &["172.0.0.0/6", "192.0.0.0/2"]);
        let mut pinned = endpoint("example.com", 443);
        pinned.allowed_ips = vec!["172.66.147.243".to_string()];
        pinned.protocol = "rest".to_string();
        pinned.path = "/v1/**".to_string();

        assert!(
            find_endpoint_ambiguities(&policy_with(open_web.clone(), pinned.clone())).is_empty()
        );
        assert!(find_endpoint_ambiguities(&policy_with(pinned, open_web)).is_empty());
    }

    fn assert_less_restrictive(
        hosted: NetworkEndpoint,
        hostless: NetworkEndpoint,
        field: &str,
    ) {
        for policy in [
            policy_with(hosted.clone(), hostless.clone()),
            policy_with(hostless, hosted),
        ] {
            let ambiguities = find_endpoint_ambiguities(&policy);
            assert_eq!(ambiguities.len(), 1, "{ambiguities:?}");
            assert!(
                ambiguities[0]
                    .conflicts
                    .iter()
                    .any(|conflict| conflict.starts_with(&format!("{field}="))
                        && conflict.contains("less restrictive")),
                "{ambiguities:?}"
            );
        }
    }

    #[test]
    fn hosted_endpoint_without_allowed_ips_is_looser_than_hostless_endpoint() {
        assert_less_restrictive(
            endpoint("github.com", 443),
            hostless(443, &["172.0.0.0/6", "192.0.0.0/2"]),
            "allowed_ips",
        );
    }

    #[test]
    fn hosted_allowed_ips_must_sit_within_hostless_allowed_ips() {
        let mut hosted = endpoint("example.com", 443);
        hosted.allowed_ips = vec!["10.0.0.5".to_string()];
        assert_less_restrictive(
            hosted,
            hostless(443, &["172.0.0.0/6", "192.0.0.0/2"]),
            "allowed_ips",
        );

        let mut broader = endpoint("example.com", 443);
        broader.allowed_ips = vec!["172.0.0.0/5".to_string()];
        assert_less_restrictive(broader, hostless(443, &["172.0.0.0/6"]), "allowed_ips");
    }

    #[test]
    fn hosted_endpoint_must_inspect_when_hostless_endpoint_inspects() {
        let mut open_web = hostless(443, &["172.0.0.0/6", "192.0.0.0/2"]);
        open_web.protocol = "rest".to_string();
        let mut github = endpoint("github.com", 443);
        github.allowed_ips = vec!["192.0.2.0/24".to_string()];

        assert_less_restrictive(github, open_web, "protocol");
    }

    #[test]
    fn hosted_tls_skip_is_looser_than_hostless_tls_termination() {
        let mut wildcard = endpoint("*.example.com", 443);
        wildcard.allowed_ips = vec!["8.8.8.0/24".to_string()];
        wildcard.tls = NetworkTlsMode::Skip as i32;

        assert_less_restrictive(wildcard, hostless(443, &["8.0.0.0/8"]), "tls");
    }

    #[test]
    fn hosted_raw_tcp_is_looser_than_hostless_endpoint() {
        let mut database = endpoint("db.example.com", 443);
        database.allowed_ips = vec!["8.8.8.8".to_string()];
        database.protocol = "tcp".to_string();

        assert_less_restrictive(database, hostless(443, &["8.0.0.0/8"]), "protocol");
    }

    #[test]
    fn hosted_audit_is_looser_than_hostless_enforcement() {
        let mut open_web = hostless(443, &["8.0.0.0/8"]);
        open_web.protocol = "rest".to_string();
        open_web.enforcement = NetworkEnforcementMode::Enforce as i32;
        let mut provider = endpoint("example.com", 443);
        provider.allowed_ips = vec!["8.8.8.8".to_string()];
        provider.protocol = "rest".to_string();
        provider.enforcement = NetworkEnforcementMode::Audit as i32;

        assert_less_restrictive(provider, open_web, "enforcement");
    }

    #[test]
    fn stricter_hosted_endpoint_preserves_the_broader_parser() {
        let mut open_web = hostless(443, &["8.0.0.0/8"]);
        open_web.protocol = "rest".to_string();
        open_web.tls = NetworkTlsMode::Skip as i32;
        let mut provider = endpoint("example.com", 443);
        provider.allowed_ips = vec!["8.8.8.8".to_string()];
        provider.protocol = "rest".to_string();
        provider.enforcement = NetworkEnforcementMode::Enforce as i32;
        provider.credential_binding = Some(openshell_core::proto::NetworkCredentialBinding {
            provider: "example".to_string(),
        });

        assert!(
            find_endpoint_ambiguities(&policy_with(open_web.clone(), provider.clone())).is_empty()
        );
        assert!(find_endpoint_ambiguities(&policy_with(provider, open_web)).is_empty());
    }

    /// Check each restriction under both host and path precedence, in both
    /// endpoint orders. Binary selectors deliberately differ in policy_with.
    fn assert_override_conflict(broader: NetworkEndpoint, narrower: NetworkEndpoint, field: &str) {
        for path_precedence in [false, true] {
            let mut broader = broader.clone();
            let mut narrower = narrower.clone();
            if path_precedence {
                broader.host = narrower.host.clone();
                broader.allowed_ips = narrower.allowed_ips.clone();
                narrower.path = "/v1/**".into();
            }
            for policy in [
                policy_with(broader.clone(), narrower.clone()),
                policy_with(narrower, broader),
            ] {
                let ambiguities = find_endpoint_ambiguities(&policy);
                assert_eq!(ambiguities.len(), 1, "{field}: {ambiguities:?}");
                assert!(
                    ambiguities[0]
                        .conflicts
                        .iter()
                        .any(|value| value.starts_with(&format!("{field}="))),
                    "{ambiguities:?}"
                );
            }
        }
    }

    fn inspected_pair(protocol: &str) -> (NetworkEndpoint, NetworkEndpoint) {
        let mut broader = hostless(443, &["8.0.0.0/8"]);
        broader.protocol = protocol.into();
        let mut narrower = broader.clone();
        narrower.host = "api.example.com".into();
        narrower.allowed_ips = vec!["8.8.8.8".into()];
        (broader, narrower)
    }

    #[test]
    fn more_selective_endpoints_cannot_drop_inspection_or_protocol_denies() {
        for protocol in ["mcp", "json-rpc", "graphql", "rest", "websocket"] {
            for replacement in ["", "tcp", "sql", "rest"] {
                if protocol == replacement {
                    continue;
                }
                let (mut broader, mut narrower) = inspected_pair(protocol);
                broader.deny_rules.push(openshell_core::proto::L7DenyRule {
                    method: "tools/call".into(),
                    ..Default::default()
                });
                narrower.protocol = replacement.into();
                assert_override_conflict(broader, narrower, "protocol");
            }
        }
    }

    #[test]
    fn more_selective_endpoints_cannot_change_credential_transformations() {
        for field in [
            "credential_signing",
            "signing_service",
            "signing_region",
            "request_body_credential_rewrite",
            "websocket_credential_rewrite",
        ] {
            let (broader, mut narrower) = inspected_pair("rest");
            match field {
                "credential_signing" => narrower.credential_signing = "sigv4".into(),
                "signing_service" => narrower.signing_service = "bedrock".into(),
                "signing_region" => narrower.signing_region = "us-west-2".into(),
                "request_body_credential_rewrite" => {
                    narrower.request_body_credential_rewrite = true;
                }
                "websocket_credential_rewrite" => narrower.websocket_credential_rewrite = true,
                _ => unreachable!(),
            }
            assert_override_conflict(broader, narrower, field);
        }
    }

    #[test]
    fn more_selective_endpoints_preserve_parser_options_and_credential_guards() {
        let (mut broader, narrower) = inspected_pair("websocket");
        broader.deny_rules.push(openshell_core::proto::L7DenyRule {
            operation_type: "mutation".into(),
            ..Default::default()
        });
        assert_override_conflict(broader, narrower, "websocket_graphql_policy");

        let (broader, mut narrower) = inspected_pair("rest");
        narrower.allow_uninspected_credentials = true;
        assert_override_conflict(broader, narrower, "allow_uninspected_credentials");

        let (broader, mut narrower) = inspected_pair("mcp");
        narrower.mcp = Some(openshell_core::proto::McpOptions {
            versions: vec!["2025-03-26".into()],
            ..Default::default()
        });
        assert_override_conflict(broader, narrower, "mcp.versions");

        let (broader, mut narrower) = inspected_pair("graphql");
        narrower.persisted_queries = "allow_registered".into();
        assert_override_conflict(broader, narrower, "persisted_queries");

        let (broader, mut narrower) = inspected_pair("graphql");
        narrower.graphql_persisted_queries.insert(
            "hash".into(),
            openshell_core::proto::GraphqlOperation {
                operation_type: "query".into(),
                ..Default::default()
            },
        );
        assert_override_conflict(broader, narrower, "graphql_persisted_queries");
    }

    #[test]
    fn more_selective_endpoints_may_strengthen_restrictions() {
        for protocol in ["rest", "graphql", "mcp"] {
            let (mut broader, mut narrower) = inspected_pair(protocol);
            broader.enforcement = NetworkEnforcementMode::Audit as i32;
            broader.allow_encoded_slash = true;
            broader.allow_uninspected_credentials = true;
            narrower.enforcement = NetworkEnforcementMode::Enforce as i32;
            narrower.graphql_max_body_bytes = 1024;
            narrower.json_rpc_max_body_bytes = 1024;
            for path_precedence in [false, true] {
                let mut broader = broader.clone();
                let mut narrower = narrower.clone();
                if path_precedence {
                    broader.host = narrower.host.clone();
                    broader.allowed_ips = narrower.allowed_ips.clone();
                    narrower.path = "/v1/**".into();
                }
                for policy in [
                policy_with(broader.clone(), narrower.clone()),
                policy_with(narrower, broader),
            ] {
                    assert!(find_endpoint_ambiguities(&policy).is_empty());
                }
            }
        }
    }

    #[test]
    fn more_selective_endpoints_cannot_relax_request_hardening() {
        for (protocol, field) in [
            ("rest", "enforcement"),
            ("rest", "allow_encoded_slash"),
            ("graphql", "graphql_max_body_bytes"),
            ("json-rpc", "json_rpc_max_body_bytes"),
            ("mcp", "mcp.strict_tool_names"),
        ] {
            let (mut broader, mut narrower) = inspected_pair(protocol);
            match field {
                "enforcement" => {
                    broader.enforcement = NetworkEnforcementMode::Enforce as i32;
                }
                "allow_encoded_slash" => narrower.allow_encoded_slash = true,
                "graphql_max_body_bytes" => narrower.graphql_max_body_bytes = 131_072,
                "json_rpc_max_body_bytes" => narrower.json_rpc_max_body_bytes = 131_072,
                "mcp.strict_tool_names" => {
                    narrower.mcp = Some(openshell_core::proto::McpOptions {
                        strict_tool_names: Some(false),
                        ..Default::default()
                    });
                }
                _ => unreachable!(),
            }
            assert_override_conflict(broader, narrower, field);
        }
    }

    #[test]
    fn equally_specific_endpoints_must_agree_on_uninspected_credentials() {
        let (mut left, mut right) = inspected_pair("rest");
        left.host = right.host.clone();
        left.allowed_ips = right.allowed_ips.clone();
        right.allow_uninspected_credentials = true;
        let ambiguities = find_endpoint_ambiguities(&policy_with(left, right));
        assert_eq!(ambiguities.len(), 1);
        assert!(
            ambiguities[0]
                .conflicts
                .iter()
                .any(|conflict| conflict.starts_with("allow_uninspected_credentials="))
        );
    }

    #[test]
    fn hostless_endpoints_must_still_agree_with_each_other() {
        let ambiguities = find_endpoint_ambiguities(&policy_with(
            hostless(443, &["10.0.0.0/8"]),
            hostless(443, &["192.168.0.0/16"]),
        ));

        assert_eq!(ambiguities.len(), 1);
        assert!(
            ambiguities[0]
                .conflicts
                .iter()
                .any(|conflict| conflict.contains("allowed_ips"))
        );
    }

    #[test]
    fn explicit_tcp_and_omitted_protocol_are_ambiguous_for_native_tcp_eligibility() {
        let mut explicit_tcp = endpoint("api.example.com", 443);
        explicit_tcp.protocol = "tcp".to_string();
        explicit_tcp.tls = NetworkTlsMode::Skip as i32;
        let mut omitted = endpoint("api.example.com", 443);
        omitted.tls = NetworkTlsMode::Skip as i32;

        let ambiguities = find_endpoint_ambiguities(&policy_with(explicit_tcp, omitted));
        assert_eq!(ambiguities.len(), 1);
        assert!(
            ambiguities[0]
                .conflicts
                .iter()
                .any(|conflict| conflict.contains("transparent_tcp_eligible"))
        );
    }
}
