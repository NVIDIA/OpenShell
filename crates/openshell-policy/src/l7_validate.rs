// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared L7 endpoint semantic validation.
//!
//! Both profile lint (`openshell-providers`) and the runtime policy
//! validator (`openshell-supervisor-network`) call
//! [`validate_l7_endpoint_semantics`] to enforce the same constraints on
//! L7 endpoint field combinations, preventing drift between lint-time
//! and runtime checks.

/// Known L7 inspection protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L7Protocol {
    Rest,
    Websocket,
    Graphql,
    Sql,
    JsonRpc,
    Mcp,
}

impl L7Protocol {
    /// Parse a protocol string into a known variant.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "rest" => Some(Self::Rest),
            "websocket" => Some(Self::Websocket),
            "graphql" => Some(Self::Graphql),
            "sql" => Some(Self::Sql),
            "json-rpc" => Some(Self::JsonRpc),
            "mcp" => Some(Self::Mcp),
            _ => None,
        }
    }

    /// Returns `true` for protocols in the JSON-RPC family (`json-rpc`,
    /// `mcp`).
    pub fn is_jsonrpc_family(self) -> bool {
        matches!(self, Self::JsonRpc | Self::Mcp)
    }
}

/// Returns whether the authored protocol explicitly selects L4 TCP handling.
///
/// `tcp` is intentionally not an [`L7Protocol`]. It is the explicit spelling
/// of the existing L4 behavior and does not enable request inspection.
pub fn is_explicit_tcp_protocol(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("tcp")
}

/// Reject transport choices that an in-sandbox agent must not grant itself.
///
/// An omitted protocol remains allowed: it uses the established explicit
/// proxy, which canonicalizes forward HTTP authorities and terminates TLS by
/// default. Native transparent TCP and `tls: skip` bypass those application
/// authority checks, so only an administrator may author them directly.
pub fn agent_authored_transport_rejection(protocol: &str, tls: &str) -> Option<&'static str> {
    if is_explicit_tcp_protocol(protocol) {
        return Some(
            "agent-authored proposals cannot request protocol tcp; ask an administrator to add native TCP access explicitly",
        );
    }
    if tls.eq_ignore_ascii_case("skip") {
        return Some(
            "agent-authored proposals cannot request tls: skip; ask an administrator to add raw TLS access explicitly",
        );
    }
    None
}

/// Reject additional L7-only fields represented outside
/// [`L7EndpointFields`] by the runtime and provider-profile schemas.
///
/// Callers pass only authored fields with a non-default value. Keeping the
/// diagnostic construction here ensures both activation paths use the same
/// explicit-TCP contract.
pub fn validate_explicit_tcp_additional_fields(
    protocol: &str,
    present_fields: &[&str],
) -> Vec<String> {
    if !is_explicit_tcp_protocol(protocol) || present_fields.is_empty() {
        return Vec::new();
    }

    vec![format!(
        "protocol tcp does not support L7-only fields: {}; remove those fields",
        present_fields.join(", ")
    )]
}

#[cfg(test)]
mod agent_transport_tests {
    use super::agent_authored_transport_rejection;

    #[test]
    fn omitted_protocol_with_default_tls_remains_available_to_agents() {
        assert_eq!(agent_authored_transport_rejection("", ""), None);
    }

    #[test]
    fn agent_cannot_request_native_tcp_or_skip_tls_inspection() {
        assert!(agent_authored_transport_rejection("tcp", "").is_some());
        assert!(agent_authored_transport_rejection("TCP", "terminate").is_some());
        assert!(agent_authored_transport_rejection("", "skip").is_some());
        assert!(agent_authored_transport_rejection("rest", "SKIP").is_some());
    }
}

/// Fields extracted from an endpoint definition needed for L7 semantic
/// validation. Both profile lint and the runtime validator construct this
/// from their own data representation.
#[allow(clippy::struct_excessive_bools)]
pub struct L7EndpointFields<'a> {
    /// Protocol string as authored (e.g. `"rest"`, `"mcp"`). Empty
    /// string means no L7 protocol was specified.
    pub protocol: &'a str,

    /// Access preset string (e.g. `"read-only"`, `"full"`). Empty string
    /// means no access preset.
    pub access: &'a str,

    /// `true` when the endpoint has a non-empty rules list.
    pub has_rules: bool,

    /// `true` when the endpoint has a non-empty `deny_rules` list.
    pub has_deny_rules: bool,

    /// `true` when rules are present (non-empty) but would deny all
    /// traffic because every entry lacks an allow clause.
    pub rules_would_deny_all: bool,

    /// Value of `mcp.allow_all_known_mcp_methods` (defaults to `false`).
    pub allow_all_known_mcp_methods: bool,
}

/// Validate the semantic consistency of an L7 endpoint's field
/// combination.
///
/// Returns a list of error message strings. An empty list means the
/// endpoint passes validation. Messages are bare — callers prepend
/// their own location context.
pub fn validate_l7_endpoint_semantics(ep: &L7EndpointFields<'_>) -> Vec<String> {
    let mut errors = Vec::new();
    let protocol = ep.protocol;
    let l7_protocol = L7Protocol::parse(protocol);
    let explicit_tcp = is_explicit_tcp_protocol(protocol);
    let jsonrpc_family = l7_protocol.is_some_and(L7Protocol::is_jsonrpc_family);
    let is_mcp = matches!(l7_protocol, Some(L7Protocol::Mcp));
    let is_jsonrpc = matches!(l7_protocol, Some(L7Protocol::JsonRpc));

    // 1. Unknown protocol
    if !protocol.is_empty() && l7_protocol.is_none() && !explicit_tcp {
        errors.push(format!(
            "unknown protocol '{protocol}' (expected tcp, rest, websocket, graphql, sql, json-rpc, or mcp)"
        ));
    }

    // Explicit TCP is an L4 marker, not an inspection protocol. Reject L7
    // policy fields instead of silently ignoring them.
    if explicit_tcp && (!ep.access.is_empty() || ep.has_rules || ep.has_deny_rules) {
        errors.push(
            "protocol tcp does not support access, rules, or deny_rules; remove those L7 fields"
                .to_string(),
        );
    }

    // 2. rules + access mutually exclusive
    if ep.has_rules && !ep.access.is_empty() {
        errors.push("rules and access are mutually exclusive".to_string());
    }

    // 3. JSON-RPC family cannot use access presets
    if jsonrpc_family && !ep.access.is_empty() {
        if is_mcp {
            errors.push(format!(
                "protocol {protocol} does not support access presets; \
                 use rules/deny_rules or set mcp.allow_all_known_mcp_methods: true \
                 for an allow-all MCP policy"
            ));
        } else {
            errors.push(format!(
                "protocol {protocol} does not support access presets; \
                 use explicit rules with allow.method such as \"*\""
            ));
        }
    }

    // 4. json-rpc requires explicit rules
    if is_jsonrpc && !ep.has_rules && ep.access.is_empty() {
        errors.push(format!(
            "protocol {protocol} requires explicit rules with allow.method"
        ));
    }

    // 5. Non-MCP, non-JSON-RPC protocol requires rules or access (JSON-RPC's
    // dedicated message is emitted by rule 4).
    if l7_protocol.is_some() && !is_mcp && !is_jsonrpc && !ep.has_rules && ep.access.is_empty() {
        errors.push("protocol requires rules or access to define allowed traffic".to_string());
    }

    // 6. MCP requires rules when allow_all_known_mcp_methods is false
    if is_mcp && !ep.has_rules && ep.access.is_empty() && !ep.allow_all_known_mcp_methods {
        errors.push(
            "protocol mcp requires rules when mcp.allow_all_known_mcp_methods is false".to_string(),
        );
    }

    // 7. Rules would deny all traffic (MCP with allow_all_known_mcp_methods
    // is excluded because normalization supplies method: "*").
    if ep.rules_would_deny_all && !(is_mcp && ep.allow_all_known_mcp_methods) {
        errors.push(
            "rules would deny all traffic (no allow clause found). \
             Use `access: full` or add allow clauses to rules."
                .to_string(),
        );
    }

    // 8. deny_rules require protocol
    if ep.has_deny_rules && l7_protocol.is_none() {
        errors.push("deny_rules require protocol (L7 inspection must be enabled)".to_string());
    }

    // 9. deny_rules require base allow set
    if ep.has_deny_rules && !is_mcp && !ep.has_rules && ep.access.is_empty() {
        errors.push("deny_rules require rules or access to define the base allow set".to_string());
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_rest_endpoint() -> L7EndpointFields<'static> {
        L7EndpointFields {
            protocol: "rest",
            access: "read-only",
            has_rules: false,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        }
    }

    #[test]
    fn valid_endpoint_produces_no_errors() {
        let errors = validate_l7_endpoint_semantics(&valid_rest_endpoint());
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    #[test]
    fn rejects_unknown_protocol() {
        let ep = L7EndpointFields {
            protocol: "ftp",
            access: "",
            has_rules: false,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(errors.iter().any(|e| e.contains("unknown protocol")));
    }

    #[test]
    fn rejects_rules_and_access_together() {
        let ep = L7EndpointFields {
            protocol: "rest",
            access: "full",
            has_rules: true,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(errors.iter().any(|e| e.contains("mutually exclusive")));
    }

    #[test]
    fn rejects_jsonrpc_with_access_presets() {
        let ep = L7EndpointFields {
            protocol: "json-rpc",
            access: "full",
            has_rules: false,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("does not support access presets"))
        );
    }

    #[test]
    fn rejects_mcp_with_access_presets() {
        let ep = L7EndpointFields {
            protocol: "mcp",
            access: "full",
            has_rules: false,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("allow_all_known_mcp_methods"))
        );
    }

    #[test]
    fn rejects_jsonrpc_without_rules() {
        let ep = L7EndpointFields {
            protocol: "json-rpc",
            access: "",
            has_rules: false,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(errors.iter().any(|e| e.contains("requires explicit rules")));
    }

    #[test]
    fn rejects_protocol_without_rules_or_access() {
        let ep = L7EndpointFields {
            protocol: "rest",
            access: "",
            has_rules: false,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("protocol requires rules or access"))
        );
    }

    #[test]
    fn rejects_mcp_without_rules_when_allow_all_false() {
        let ep = L7EndpointFields {
            protocol: "mcp",
            access: "",
            has_rules: false,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(errors.iter().any(|e| e.contains("mcp requires rules when")));
    }

    #[test]
    fn accepts_mcp_with_allow_all_true() {
        let ep = L7EndpointFields {
            protocol: "mcp",
            access: "",
            has_rules: false,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: true,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    #[test]
    fn rejects_rules_that_deny_all() {
        let ep = L7EndpointFields {
            protocol: "rest",
            access: "",
            has_rules: true,
            has_deny_rules: false,
            rules_would_deny_all: true,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(errors.iter().any(|e| e.contains("would deny all traffic")));
    }

    #[test]
    fn mcp_allow_all_with_empty_allow_not_rejected() {
        let ep = L7EndpointFields {
            protocol: "mcp",
            access: "",
            has_rules: true,
            has_deny_rules: false,
            rules_would_deny_all: true,
            allow_all_known_mcp_methods: true,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(
            !errors.iter().any(|e| e.contains("would deny all traffic")),
            "MCP with allow_all_known_mcp_methods should not reject empty allow rules: {errors:?}"
        );
    }

    #[test]
    fn rejects_deny_rules_without_protocol() {
        let ep = L7EndpointFields {
            protocol: "",
            access: "",
            has_rules: false,
            has_deny_rules: true,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("deny_rules require protocol"))
        );
    }

    #[test]
    fn rejects_deny_rules_without_allow_base() {
        let ep = L7EndpointFields {
            protocol: "rest",
            access: "",
            has_rules: false,
            has_deny_rules: true,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("deny_rules require rules or access"))
        );
    }

    #[test]
    fn no_protocol_no_errors() {
        let ep = L7EndpointFields {
            protocol: "",
            access: "",
            has_rules: false,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    #[test]
    fn explicit_tcp_is_valid_without_l7_fields() {
        let ep = L7EndpointFields {
            protocol: "tcp",
            access: "",
            has_rules: false,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
        assert!(is_explicit_tcp_protocol("TCP"));
        assert_eq!(L7Protocol::parse("tcp"), None);
    }

    #[test]
    fn explicit_tcp_rejects_l7_fields() {
        let ep = L7EndpointFields {
            protocol: "tcp",
            access: "full",
            has_rules: false,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert_eq!(
            errors,
            vec![
                "protocol tcp does not support access, rules, or deny_rules; remove those L7 fields"
            ]
        );
    }

    #[test]
    fn explicit_tcp_rejects_additional_l7_fields() {
        let errors =
            validate_explicit_tcp_additional_fields("tcp", &["enforcement", "credential_signing"]);

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("enforcement, credential_signing"));
        assert!(validate_explicit_tcp_additional_fields("rest", &["enforcement"]).is_empty());
    }

    #[test]
    fn l7_protocol_parse_known_variants() {
        assert_eq!(L7Protocol::parse("rest"), Some(L7Protocol::Rest));
        assert_eq!(L7Protocol::parse("websocket"), Some(L7Protocol::Websocket));
        assert_eq!(L7Protocol::parse("graphql"), Some(L7Protocol::Graphql));
        assert_eq!(L7Protocol::parse("sql"), Some(L7Protocol::Sql));
        assert_eq!(L7Protocol::parse("json-rpc"), Some(L7Protocol::JsonRpc));
        assert_eq!(L7Protocol::parse("mcp"), Some(L7Protocol::Mcp));
        assert_eq!(L7Protocol::parse("unknown"), None);
        assert_eq!(L7Protocol::parse(""), None);
        assert_eq!(L7Protocol::parse("REST"), Some(L7Protocol::Rest));
        assert_eq!(L7Protocol::parse("Mcp"), Some(L7Protocol::Mcp));
        assert_eq!(L7Protocol::parse("JSON-RPC"), Some(L7Protocol::JsonRpc));
    }

    #[test]
    fn jsonrpc_with_access_emits_single_diagnostic() {
        let ep = L7EndpointFields {
            protocol: "json-rpc",
            access: "full",
            has_rules: false,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert_eq!(
            errors,
            vec![
                "protocol json-rpc does not support access presets; \
                 use explicit rules with allow.method such as \"*\""
            ],
            "should emit only the access-preset error, not the redundant missing-rules error"
        );
    }

    #[test]
    fn jsonrpc_without_rules_or_access_emits_single_diagnostic() {
        let ep = L7EndpointFields {
            protocol: "json-rpc",
            access: "",
            has_rules: false,
            has_deny_rules: false,
            rules_would_deny_all: false,
            allow_all_known_mcp_methods: false,
        };
        let errors = validate_l7_endpoint_semantics(&ep);
        assert_eq!(
            errors,
            vec!["protocol json-rpc requires explicit rules with allow.method"],
            "should emit only the missing-rules error"
        );
    }

    #[test]
    fn l7_protocol_jsonrpc_family() {
        assert!(L7Protocol::JsonRpc.is_jsonrpc_family());
        assert!(L7Protocol::Mcp.is_jsonrpc_family());
        assert!(!L7Protocol::Rest.is_jsonrpc_family());
        assert!(!L7Protocol::Websocket.is_jsonrpc_family());
        assert!(!L7Protocol::Graphql.is_jsonrpc_family());
        assert!(!L7Protocol::Sql.is_jsonrpc_family());
    }
}
