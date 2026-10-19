// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Load-time checks that an authored policy set is enforced exactly as written.
//!
//! Cedar evaluates `NetworkConnect` and `HttpRequest` at request time, so any
//! condition an author writes on those actions is enforced by Cedar itself.
//! Three things are *not* decided by Cedar at request time, and are instead
//! derived from the policy text once, here:
//!
//! - **Landlock grants.** Landlock is a flat allow-list of path subtrees
//!   applied at sandbox start. Only filesystem policies whose meaning is
//!   exactly "this process may read/write these subtrees" are accepted:
//!   `permit`, an action scope of `ReadFile`/`WriteFile` only, an
//!   unconstrained principal, and paths named either as
//!   `resource in Sandbox::FilesystemPath::"/p"` in the scope, or as a `when`
//!   clause that is only an `||` of such `resource in` tests. Anything else
//!   (`forbid`, other conditions, `resource ==`, a principal constraint) is
//!   rejected, because Landlock would grant more than the policy says. A
//!   Landlock read-write grant includes read, so a permit that lists
//!   `WriteFile` without `ReadFile` is rejected too: it would grant reads
//!   the policy does not say.
//! - **L7 inspection routing.** The proxy must decide at CONNECT time whether
//!   to inspect a connection per request. Every policy that can apply to
//!   `HttpRequest` must therefore name its endpoint: literally in the scope,
//!   or as a host glob written with a `.` delimiter and a port, as exactly
//!   one `resource.host like("*.example.com", ".")` and one
//!   `resource.port == <port>` top-level `when` conjunct, in the shapes
//!   policy DNS accepts (see DNS eligibility below). Every endpoint so named
//!   is inspected, and a glob inspects every host it matches, as a YAML
//!   wildcard endpoint with request rules does. An `HttpRequest` policy the
//!   proxy could not route would otherwise be silently skipped. Entries that
//!   can select one host (an exact host and the globs matching it, or
//!   overlapping globs) must inspect equally specific overlapping paths the
//!   same way, as YAML rejects such ambiguous endpoints. A `@path`
//!   annotation attaches a policy to one request path pattern of its
//!   endpoint, so one `host:port` can be inspected with a different protocol
//!   and enforcement per path, as YAML endpoints sharing a `host:port` are.
//!   `@path` selects inspection only: every policy still applies to every
//!   request on its endpoint, so conditions on `context.path` decide which
//!   requests a policy allows. An `@enforcement("audit")` annotation marks an
//!   `HttpRequest` policy as audit: an inspected path whose policies are all
//!   audit logs denials instead of enforcing them, like a YAML
//!   `enforcement: audit` endpoint. Audit policies still decide requests
//!   routed to every path of their `host:port`, as YAML applies the rules of
//!   every matching endpoint while the selected endpoint's enforcement
//!   decides whether a denial blocks; so, as in YAML, the routed path's mode
//!   decides whether a denial blocks, even a denial by an enforced policy
//!   attached to another path of the same `host:port`. Such an audit path
//!   beside enforced policies is reported as an [`AnalysisWarning`]. An
//!   `@enforcement("staged")` annotation marks a policy as staged: it never
//!   changes a path's mode and never takes part in a decision; requests whose
//!   decision it would change are logged. A permit attached to a
//!   `websocket-graphql` path that could allow a client message without a
//!   GraphQL condition is rejected, as YAML rejects a generic
//!   `WEBSOCKET_TEXT` rule there. For a request parsed as GraphQL, on a
//!   `graphql` or `websocket-graphql` path, permits attached to another path
//!   of the endpoint that neither read a `graphql_*` field nor test
//!   `resource.protocol` are left out of the decision, as a YAML GraphQL
//!   endpoint is authoritative for the requests it parses.
//! - **DNS eligibility.** A `NetworkConnect` `permit` makes a host eligible
//!   for policy DNS when it names the endpoint in its scope, or when its
//!   `when` conditions require both `resource.host` and `resource.port`: the
//!   host as an exact string or as a host glob written with a `.` delimiter
//!   (`resource.host like("*.example.com", ".")`), and the port as a number.
//!   `resource.host_port == "host:port"`, or
//!   `["host:port"].contains(resource.host_port)` with one element, names
//!   both at once, and its literal passes the checks a scope literal does.
//!   Host globs follow the same shape rules as YAML wildcard hosts. Hosts
//!   matched any other way, such as an undelimited `like` or a `host_port`
//!   set with several elements, are not eligible, which fails closed.
//! - **Native TCP.** A `@transport("tcp")` annotation on a `NetworkConnect`
//!   `permit` marks its endpoint for native transparent TCP, like a YAML
//!   `protocol: tcp` endpoint, and its policy DNS record carries
//!   `protocol: tcp`. As in YAML, the endpoint must be a DNS host or host
//!   glob with a port, never an IP literal or a hostless form, it is never
//!   inspected per request, and no other `NetworkConnect` permit may name an
//!   overlapping host and port without the annotation. A permit without the
//!   annotation whose host cannot be derived (no `resource.host` conjunct, a
//!   wildcard top-level domain, an undelimited `like`, or hosts joined with
//!   `||`) may allow any host, so it is rejected whenever a native TCP permit
//!   shares a port it may allow, or exists at all when it names no port.
//!
//! - **Destination addresses.** A `NetworkConnect` permit may require
//!   `context.destination_ip`, the resolved address, to lie in fixed ranges,
//!   like a YAML endpoint's `allowed_ips`. Such a condition must be a
//!   top-level `when` conjunct that is `context has destination_ip` or an
//!   `||` of `context.destination_ip.isInRange(ip("..."))` tests, so the
//!   ranges are known exactly: the proxy enforces them on resolved addresses
//!   and policy DNS filters answers with them. Ranges overlapping loopback,
//!   link-local, or unspecified addresses are rejected, as YAML rejects such
//!   `allowed_ips`. A connection is first decided without
//!   `destination_ip`, with each such permit's address conjuncts removed,
//!   then again for each resolved address with every policy. A `forbid` may
//!   read `destination_ip` in any form and takes part in both decisions as
//!   written: strict validation requires a `context has destination_ip`
//!   guard, which is false before resolution, so only its other conditions
//!   can deny then, and its address conditions apply per address after.
//! - **Binary aliases.** `context.binary_aliases` holds the binary paths
//!   policies name that are symlinks in the sandbox resolving to the calling
//!   binary or an ancestor, the way YAML expands a symlinked binary path. The
//!   supervisor resolves only the paths collected here, so a policy may test
//!   the set only with `.contains`, `.containsAny`, or `.containsAll` and
//!   literal absolute paths without `*` (YAML never resolves a glob).
//! - **Binary globs.** `context.binary_globs` holds the binary glob patterns
//!   policies name that match the calling binary or an ancestor with the
//!   YAML binary glob matcher, since Cedar cannot apply `like` across the
//!   `context.ancestors` set. The supervisor matches only the patterns
//!   collected here, in the same forms as binary aliases, with literal
//!   absolute patterns that contain `*` and compile as globs.
//! - **Delimited patterns.** A delimited `like` pattern with `**` next to a
//!   character other than the delimiter is rejected: YAML reads such a `**`
//!   as `*`, within one segment, while Cedar's crosses segments.
//!
//! Before any of that, the policy set is validated against the schema in
//! strict mode, so a typo such as `context.binray_path` is a load error
//! rather than a policy Cedar silently skips at request time. The validator
//! accepts a `has` test of an attribute the schema does not declare, which
//! typechecks to `false`, so such a test is a load error here too:
//! `principal has workdir` or `context has method` on `NetworkConnect` could
//! never hold, and the policy would never match.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::net::IpAddr;

use cedar_policy::{
    ActionConstraint, Effect, EntityUid, Policy, PolicyId, PolicySet, PrincipalConstraint,
    ResourceConstraint, Schema, ValidationMode, Validator,
};
use ipnet::IpNet;
use openshell_core::host_pattern::HostPattern;
use openshell_policy_cedar_schema::{
    DeclaredAttributes, actions, context_fields, endpoint_fields, entity_types,
};
use serde_json::Value;

use crate::{AuthorizedNetworkEndpoint, CedarEngineError, FilesystemGrants};

/// Annotation that declares the wire protocol of an `HttpRequest` endpoint.
///
/// Read only from policies that can apply to `HttpRequest`; see
/// [`L7Protocol`] for accepted values.
const PROTOCOL_ANNOTATION: &str = "protocol";

/// Annotation that attaches an `HttpRequest` policy to one request path
/// pattern of its endpoint, with the YAML endpoint `path` grammar.
const PATH_ANNOTATION: &str = "path";

/// Annotation that marks an `HttpRequest` policy as audit or staged.
///
/// See [`EnforcementAnnotation`] for accepted values.
const ENFORCEMENT_ANNOTATION: &str = "enforcement";

/// The method a WebSocket client text message is evaluated with.
const WEBSOCKET_TEXT_METHOD: &str = "WEBSOCKET_TEXT";

/// Prefix of the `HttpRequest` context fields that carry a GraphQL operation.
const GRAPHQL_FIELD_PREFIX: &str = "graphql_";

/// Annotation that marks a `NetworkConnect` permit's endpoint for native TCP.
///
/// See [`NetworkTransport`] for accepted values.
const TRANSPORT_ANNOTATION: &str = "transport";

/// Annotation whose value, when present, names a policy in error messages.
///
/// Cedar assigns positional ids (`policy0`, `policy1`, ...) to policies
/// parsed from text, which are hard to map back to the source.
const ID_ANNOTATION: &str = "id";

/// Wire protocol the proxy parses on an L7-inspected endpoint.
///
/// Only protocols whose per-request fields the `HttpRequest` context carries
/// are accepted. SQL has no request inspection in the proxy, so it is
/// rejected at load instead of being relayed without enforcement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum L7Protocol {
    /// HTTP/1.1 REST requests, matched on `context.method`/`context.path`.
    #[default]
    Rest,
    /// JSON-RPC requests, matched on `context.jsonrpc_method`.
    JsonRpc,
    /// MCP requests, matched on `context.jsonrpc_method`, `context.mcp_tool`,
    /// and `context.mcp_method_class`.
    Mcp,
    /// GraphQL operations, matched on `context.graphql_operation_type`,
    /// `context.graphql_operation_name`, and `context.graphql_fields`.
    Graphql,
    /// WebSocket: the upgrade is a `GET` request, and each client text
    /// message is evaluated with method `WEBSOCKET_TEXT` and the upgrade path.
    Websocket,
    /// WebSocket whose client messages carry GraphQL operations: the upgrade
    /// is a `GET` request, and each operation message is evaluated with
    /// method `WEBSOCKET_TEXT`, the upgrade path, and the `graphql_*` fields.
    /// Control messages pass without evaluation, and messages that are not
    /// valid GraphQL-over-WebSocket client messages are denied.
    WebsocketGraphql,
}

impl L7Protocol {
    /// Returns the label `@protocol` accepts, also the endpoint's
    /// `resource.protocol` for requests inspected with this protocol.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rest => "rest",
            Self::JsonRpc => "json-rpc",
            Self::Mcp => "mcp",
            Self::Graphql => "graphql",
            Self::Websocket => "websocket",
            Self::WebsocketGraphql => "websocket-graphql",
        }
    }

    /// Returns the protocol label the proxy's L7 config parser expects.
    ///
    /// Both WebSocket variants are `websocket`;
    /// [`Self::websocket_graphql_messages`] tells them apart.
    #[must_use]
    pub fn config_label(self) -> &'static str {
        match self {
            Self::WebsocketGraphql => Self::Websocket.as_str(),
            other => other.as_str(),
        }
    }

    /// Returns whether the relay applies GraphQL message policy to client
    /// WebSocket messages.
    #[must_use]
    pub fn websocket_graphql_messages(self) -> bool {
        self == Self::WebsocketGraphql
    }

    fn from_annotation(value: &str) -> Option<Self> {
        match value {
            "rest" => Some(Self::Rest),
            "json-rpc" => Some(Self::JsonRpc),
            "mcp" => Some(Self::Mcp),
            "graphql" => Some(Self::Graphql),
            "websocket" => Some(Self::Websocket),
            "websocket-graphql" => Some(Self::WebsocketGraphql),
            _ => None,
        }
    }
}

impl fmt::Display for L7Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How connections to a `NetworkConnect` endpoint are carried.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkTransport {
    /// No `@transport` annotation: the default connection handling.
    #[default]
    Default,
    /// `@transport("tcp")`: native transparent TCP, like a YAML endpoint with
    /// `protocol: tcp`.
    Tcp,
}

impl NetworkTransport {
    /// Returns the YAML endpoint `protocol` this transport corresponds to, if
    /// any; `"tcp"` for [`Self::Tcp`].
    #[must_use]
    pub fn protocol(self) -> Option<&'static str> {
        match self {
            Self::Default => None,
            Self::Tcp => Some("tcp"),
        }
    }

    fn from_annotation(value: &str) -> Option<Self> {
        (value == "tcp").then_some(Self::Tcp)
    }
}

/// Whether the proxy blocks requests an endpoint's policies deny.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum L7Enforcement {
    /// Denied requests are blocked.
    #[default]
    Enforce,
    /// Denied requests are logged and forwarded.
    Audit,
}

impl L7Enforcement {
    /// Returns the enforcement label the proxy's L7 config parser expects.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Audit => "audit",
        }
    }
}

/// The value of an `@enforcement` annotation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum EnforcementAnnotation {
    /// The default: the policy decides requests and enforces its path.
    #[default]
    Enforce,
    /// The policy decides requests; a path whose policies are all audit
    /// logs denials instead of blocking them.
    Audit,
    /// The policy never decides a request and never changes a path's mode;
    /// requests whose decision it would change are logged.
    Staged,
}

impl EnforcementAnnotation {
    /// The label of [`Self::Staged`].
    const STAGED: &'static str = "staged";

    fn from_annotation(value: &str) -> Option<Self> {
        match value {
            "enforce" => Some(Self::Enforce),
            "audit" => Some(Self::Audit),
            Self::STAGED => Some(Self::Staged),
            _ => None,
        }
    }
}

/// How the proxy inspects requests routed to one path of an endpoint named
/// by `HttpRequest` policies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct L7Endpoint {
    /// Wire protocol parsed per request.
    pub protocol: L7Protocol,
    /// [`L7Enforcement::Audit`] when every deciding `HttpRequest` policy
    /// attached to the path is audit; staged policies do not count.
    pub enforcement: L7Enforcement,
    /// True when some policy of the path's `host:port` is staged, so the
    /// decision staged policies would make is compared for logging.
    pub(crate) staged: bool,
}

impl L7Endpoint {
    /// Returns whether two paths inspect requests the same way.
    fn same_inspection(self, other: Self) -> bool {
        self.protocol == other.protocol && self.enforcement == other.enforcement
    }
}

/// Returns whether a policy is annotated `@enforcement("staged")`.
pub fn is_staged(policy: &Policy) -> bool {
    policy.annotation(ENFORCEMENT_ANNOTATION) == Some(EnforcementAnnotation::STAGED)
}

/// `HttpRequest` policies seen for one inspected `host:port` while analyzing,
/// by `@path`.
#[derive(Default)]
struct DeclaredEndpoint {
    paths: BTreeMap<String, DeclaredPath>,
}

impl DeclaredEndpoint {
    /// Returns the inspection of each path, each decided by its own
    /// policies, and warns of an audit path beside enforced policies.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError::GenericWebsocketGraphqlPermit`] for a
    /// permit on a `websocket-graphql` path that could allow a client
    /// message without a GraphQL condition.
    fn finish(
        self,
        host: &str,
        port: u16,
        warnings: &mut Vec<AnalysisWarning>,
    ) -> Result<BTreeMap<String, L7Endpoint>, CedarEngineError> {
        let endpoint_enforced = self.paths.values().any(|path| path.enforced_policies > 0);
        let staged = self.paths.values().any(|path| path.staged_policies > 0);
        self.paths
            .into_iter()
            .map(|(path, declared)| {
                if let Some(policy_id) = declared.generic_websocket_permit() {
                    return Err(CedarEngineError::GenericWebsocketGraphqlPermit {
                        policy_id,
                        path,
                    });
                }
                let endpoint = declared.finish(staged);
                if endpoint.enforcement == L7Enforcement::Audit && endpoint_enforced {
                    warnings.push(AnalysisWarning::AuditPathOnEnforcedEndpoint {
                        endpoint: format!("{host}:{port}"),
                        path: path.clone(),
                    });
                }
                Ok((path, endpoint))
            })
            .collect()
    }
}

/// `HttpRequest` policies seen for one inspected endpoint path.
#[derive(Default)]
struct DeclaredPath {
    protocol: Option<L7Protocol>,
    enforced_policies: usize,
    audit_policies: usize,
    staged_policies: usize,
    /// Permits whose conditions can hold for a `WEBSOCKET_TEXT` request
    /// through no condition on a `graphql_*` field, in policy order.
    generic_permits: Vec<String>,
}

impl DeclaredPath {
    fn finish(self, staged: bool) -> L7Endpoint {
        let audit_only = self.audit_policies > 0 && self.enforced_policies == 0;
        L7Endpoint {
            protocol: self.protocol.unwrap_or_default(),
            enforcement: if audit_only {
                L7Enforcement::Audit
            } else {
                L7Enforcement::Enforce
            },
            staged,
        }
    }

    /// Returns the first permit that could allow a GraphQL-over-WebSocket
    /// client message without a GraphQL condition, if the path carries
    /// such messages.
    fn generic_websocket_permit(&self) -> Option<String> {
        (self.protocol == Some(L7Protocol::WebsocketGraphql))
            .then(|| self.generic_permits.first().cloned())
            .flatten()
    }
}

/// A policy set that loads but is likely not what its author meant.
///
/// Warnings never change how a policy set is enforced; they are reported to
/// the author when the policy is validated or loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnalysisWarning {
    /// Every deciding `HttpRequest` policy attached to one `@path` is audit
    /// while the same `host:port` has enforced `HttpRequest` policies on
    /// other paths or without `@path`. Requests routed to the path are logged
    /// and forwarded even when an enforced policy denies them, as YAML audits
    /// a request routed to an `enforcement: audit` endpoint.
    AuditPathOnEnforcedEndpoint {
        /// The endpoint, as `"host:port"`.
        endpoint: String,
        /// The audit-only `@path`; empty for the path-less endpoint.
        path: String,
    },
}

impl fmt::Display for AnalysisWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuditPathOnEnforcedEndpoint { endpoint, path } => {
                let path = if path.is_empty() {
                    "the path-less endpoint".to_string()
                } else {
                    format!("path `{path}`")
                };
                write!(
                    f,
                    "{path} of {endpoint} is audit-only: requests routed to it are logged and \
                     forwarded even when an enforced policy denies them; to try a policy \
                     without changing the path's mode or any decision, annotate it \
                     @enforcement(\"staged\") instead"
                )
            }
        }
    }
}

/// A `NetworkConnect` permit without `@transport("tcp")` whose host cannot
/// be derived, so it may allow a connection to any host.
struct HostlessPermit {
    policy_id: String,
    /// The port its conditions require, if exactly one is named.
    port: Option<u16>,
}

/// Everything derived from an authored policy set at load time.
#[derive(Debug, Clone, Default)]
pub struct PolicyAnalysis {
    /// Landlock path grants.
    pub(crate) filesystem: FilesystemGrants,
    /// Exact `NetworkConnect` endpoints eligible for policy DNS, by host.
    pub(crate) dns_endpoints: Vec<AuthorizedNetworkEndpoint>,
    /// Endpoints routed into L7 inspection, keyed by `(host, port)`, with
    /// the inspection of each declared path. The host is an exact host or a
    /// host glob in policy DNS syntax. The empty path is the endpoint
    /// declared by policies without `@path`.
    pub(crate) l7_endpoints: BTreeMap<(String, u16), BTreeMap<String, L7Endpoint>>,
    /// The keys of [`Self::l7_endpoints`] whose host is a glob, compiled
    /// with the matcher policy DNS and YAML endpoints use, in key order.
    pub(crate) l7_host_patterns: Vec<L7HostPattern>,
    /// The query keys deciding policies can read.
    pub(crate) query_keys: QueryKeys,
    /// The query keys all policies, including staged policies, can read.
    pub(crate) staged_query_keys: QueryKeys,
    /// What each `NetworkConnect` permit requires of a connection, by id.
    pub(crate) network_permits: HashMap<PolicyId, NetworkPermit>,
    /// Each permit that reads `destination_ip`, without its address
    /// conjuncts, as it takes part in the decision made before resolution.
    /// Every other policy, forbids included, takes part as written.
    pub(crate) unresolved: HashMap<PolicyId, Policy>,
    /// The binary paths policies test in `context.binary_aliases`.
    pub(crate) binary_alias_paths: BTreeSet<String>,
    /// The binary glob patterns policies test in `context.binary_globs`.
    pub(crate) binary_glob_patterns: BTreeSet<String>,
    /// Where each `HttpRequest` permit is attached and whether it is aware
    /// of GraphQL, by id.
    pub(crate) http_permits: HashMap<PolicyId, HttpPermit>,
    /// Shapes that load but are likely not what the author meant.
    pub(crate) warnings: Vec<AnalysisWarning>,
}

/// One inspected endpoint whose host is a glob.
#[derive(Debug, Clone)]
pub struct L7HostPattern {
    /// The glob, as keyed in [`PolicyAnalysis::l7_endpoints`].
    pub(crate) host: String,
    pub(crate) port: u16,
    /// The glob compiled with the YAML endpoint host matcher.
    pub(crate) pattern: HostPattern,
}

impl PolicyAnalysis {
    /// Returns the inspected endpoint entries that select `host:port`, the
    /// exact entry first and then each glob entry the host matches, each as
    /// its key host with the inspection of its paths.
    ///
    /// `host` must be normalized (lowercase, no trailing dot). When several
    /// entries select a host, their paths are inspected together: a request
    /// is routed to the most specific matching path of any entry, which the
    /// load-time ambiguity check makes well defined.
    pub(crate) fn l7_selecting(
        &self,
        host: &str,
        port: u16,
    ) -> impl Iterator<Item = (&str, &BTreeMap<String, L7Endpoint>)> {
        let exact = self
            .l7_endpoints
            .get_key_value(&(host.to_string(), port))
            .map(|((key, _), paths)| (key.as_str(), paths));
        let globs = self
            .l7_host_patterns
            .iter()
            .filter(move |entry| entry.port == port && entry.pattern.matches(host))
            .filter_map(move |entry| {
                self.l7_endpoints
                    .get_key_value(&(entry.host.clone(), port))
                    .map(|((key, _), paths)| (key.as_str(), paths))
            });
        exact.into_iter().chain(globs)
    }
}

/// Where one `HttpRequest` permit is attached and what it is aware of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPermit {
    /// The endpoint it names, as `(host, port)`; the host may be a glob.
    pub(crate) endpoint: (String, u16),
    /// Its `@path`, or empty without one.
    pub(crate) path: String,
    /// It reads a `graphql_*` context field or tests `resource.protocol`,
    /// so it means to apply to requests parsed as GraphQL.
    pub(crate) graphql_aware: bool,
}

/// What one `NetworkConnect` permit requires of a connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkPermit {
    /// The host and port the permit names exactly, if any; never a glob.
    pub(crate) endpoint: Option<(String, u16)>,
    /// The ranges its `destination_ip` condition admits; empty when the
    /// permit has no such condition.
    pub(crate) allowed_ips: Vec<IpNet>,
}

/// Which `HttpRequest` query keys policies can read through
/// `context.query`.
///
/// A key no policy reads cannot change a decision, so leaving it out of the
/// `HttpQuery` entity keeps its repeated values from multiplying the
/// evaluations of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryKeys {
    /// Every `hasTag` and `getTag` names one of these keys literally.
    Named(BTreeSet<String>),
    /// Some policy computes a tag key, so every key may be read.
    Any,
}

impl Default for QueryKeys {
    fn default() -> Self {
        Self::Named(BTreeSet::new())
    }
}

impl QueryKeys {
    /// Returns whether a policy can read `key`.
    pub fn includes(&self, key: &str) -> bool {
        match self {
            Self::Named(keys) => keys.contains(key),
            Self::Any => true,
        }
    }

    /// Adds the tag keys `policy`'s conditions read.
    fn add_policy(&mut self, policy: &Policy) {
        let Ok(json) = policy.to_json() else {
            // Without the policy's JSON form its keys are unknown.
            *self = Self::Any;
            return;
        };
        if let Some(conditions) = json.get("conditions") {
            self.add_expr(conditions);
        }
    }

    /// Adds the tag keys of every `hasTag` and `getTag` call within `expr`.
    fn add_expr(&mut self, expr: &Value) {
        match expr {
            Value::Object(fields) => {
                for (name, value) in fields {
                    if name == "hasTag" || name == "getTag" {
                        let key = value
                            .get("right")
                            .and_then(|right| right.get("Value"))
                            .and_then(Value::as_str);
                        match (key, &mut *self) {
                            (Some(key), Self::Named(keys)) => {
                                keys.insert(key.to_string());
                            }
                            (Some(_), Self::Any) => {}
                            (None, _) => *self = Self::Any,
                        }
                    }
                    self.add_expr(value);
                }
            }
            Value::Array(values) => {
                for value in values {
                    self.add_expr(value);
                }
            }
            _ => {}
        }
    }
}

/// Validates `policies` against `schema` and derives a [`PolicyAnalysis`].
///
/// # Errors
///
/// Returns [`CedarEngineError`] if the policy set fails strict schema
/// validation, contains templates, or contains a policy whose meaning this
/// crate cannot enforce exactly (see the module docs).
pub fn analyze(schema: &Schema, policies: &PolicySet) -> Result<PolicyAnalysis, CedarEngineError> {
    let validation = Validator::new(schema.clone()).validate(policies, ValidationMode::Strict);
    if !validation.validation_passed() {
        let reason = validation
            .validation_errors()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(CedarEngineError::PolicyValidation { reason });
    }
    if let Some(template) = policies.templates().next() {
        return Err(CedarEngineError::UnsupportedPolicy {
            policy_id: template.id().to_string(),
            reason: "policy templates are not supported".to_string(),
        });
    }

    let declared = openshell_policy_cedar_schema::declared_attributes()?;
    let mut read_only = BTreeSet::new();
    let mut read_write = BTreeSet::new();
    let mut dns_ports: BTreeMap<(String, NetworkTransport, Vec<IpNet>), BTreeSet<u16>> =
        BTreeMap::new();
    let mut network_permits = HashMap::new();
    let mut unresolved = HashMap::new();
    let mut l7_declared: BTreeMap<(String, u16), DeclaredEndpoint> = BTreeMap::new();
    let mut hostless_permits = Vec::new();
    let mut query_keys = QueryKeys::default();
    let mut staged_query_keys = QueryKeys::default();
    let mut binary_alias_paths = BTreeSet::new();
    let mut binary_glob_patterns = BTreeSet::new();
    let mut http_permits = HashMap::new();

    for policy in policies.policies() {
        let policy_id = display_id(policy);
        staged_query_keys.add_policy(policy);
        if !is_staged(policy) {
            query_keys.add_policy(policy);
        }
        let json = policy
            .to_json()
            .map_err(|_| CedarEngineError::UnsupportedPolicy {
                policy_id: policy_id.clone(),
                reason: "the policy has no JSON form to inspect".to_string(),
            })?;
        let conditions = json.get("conditions").unwrap_or(&Value::Null);
        collect_binary_set_literals(
            conditions,
            BinarySet::Aliases,
            &policy_id,
            &mut binary_alias_paths,
        )?;
        collect_binary_set_literals(
            conditions,
            BinarySet::Globs,
            &policy_id,
            &mut binary_glob_patterns,
        )?;
        check_delimited_patterns(conditions, &policy_id)?;
        let scope = ActionScope::of(policy);
        check_has_tests(conditions, policy, &policy_id, &scope, schema, &declared)?;
        let touches_filesystem = (scope.includes(actions::READ_FILE)
            || scope.includes(actions::WRITE_FILE))
            && resource_may_be(policy, entity_types::FILESYSTEM_PATH);
        let touches_http_request = scope.includes(actions::HTTP_REQUEST)
            && resource_may_be(policy, entity_types::NETWORK_ENDPOINT);
        let touches_network_connect = scope.includes(actions::NETWORK_CONNECT)
            && resource_may_be(policy, entity_types::NETWORK_ENDPOINT);

        let protocol_annotation = policy.annotation(PROTOCOL_ANNOTATION);
        if protocol_annotation.is_some() && !touches_http_request {
            return Err(CedarEngineError::UnsupportedPolicy {
                policy_id,
                reason: "@protocol only applies to policies on the HttpRequest action".to_string(),
            });
        }
        let path_annotation = policy.annotation(PATH_ANNOTATION);
        if path_annotation.is_some() && !touches_http_request {
            return Err(CedarEngineError::UnsupportedPolicy {
                policy_id,
                reason: "@path only applies to policies on the HttpRequest action".to_string(),
            });
        }
        let enforcement = policy
            .annotation(ENFORCEMENT_ANNOTATION)
            .map(|value| {
                EnforcementAnnotation::from_annotation(value).ok_or_else(|| {
                    CedarEngineError::UnsupportedEnforcement {
                        policy_id: policy_id.clone(),
                        enforcement: value.to_string(),
                    }
                })
            })
            .transpose()?
            .unwrap_or_default();
        if enforcement != EnforcementAnnotation::Enforce
            && !(touches_http_request && scope.is_only(actions::HTTP_REQUEST))
        {
            // Audit and staged policies describe per-request enforcement, and
            // staged policies are left out of every decision, so they may
            // only name the HttpRequest action. `@enforcement("enforce")` is
            // the default and allowed anywhere.
            return Err(CedarEngineError::UnsupportedPolicy {
                policy_id,
                reason: "@enforcement(\"audit\") and @enforcement(\"staged\") only apply to \
                         policies whose action scope is exactly the HttpRequest action"
                    .to_string(),
            });
        }

        let transport = policy
            .annotation(TRANSPORT_ANNOTATION)
            .map(|value| {
                NetworkTransport::from_annotation(value).ok_or_else(|| {
                    CedarEngineError::UnsupportedTransport {
                        policy_id: policy_id.clone(),
                        transport: value.to_string(),
                    }
                })
            })
            .transpose()?;
        if transport.is_some()
            && !(touches_network_connect
                && policy.effect() == Effect::Permit
                && scope.is_only(actions::NETWORK_CONNECT))
        {
            return Err(CedarEngineError::UnsupportedPolicy {
                policy_id,
                reason: "@transport only applies to permit policies whose action scope is \
                         exactly the NetworkConnect action"
                    .to_string(),
            });
        }

        let destination = if touches_network_connect {
            destination_ip_use(policy, &policy_id, &scope)?
        } else {
            DestinationIpUse::None
        };
        let allowed_ips = match destination {
            DestinationIpUse::None | DestinationIpUse::Forbid => Vec::new(),
            DestinationIpUse::Permit {
                allowed_ips,
                unresolved: stripped,
            } => {
                unresolved.insert(policy.id().clone(), *stripped);
                allowed_ips
            }
        };

        if touches_filesystem {
            let grant = filesystem_grant(policy, &policy_id, &scope)?;
            let target = if grant.writes {
                &mut read_write
            } else {
                &mut read_only
            };
            target.extend(grant.paths);
        }

        if touches_http_request {
            let key = match scope_endpoint(policy) {
                Some(endpoint) => parse_endpoint(&policy_id, &endpoint)?,
                None => condition_host_glob(policy, &policy_id)?.ok_or_else(|| {
                    CedarEngineError::UnsupportedPolicy {
                        policy_id: policy_id.clone(),
                        reason: "a policy on the HttpRequest action must name its endpoint, in \
                                 the scope (resource == Sandbox::NetworkEndpoint::\"host:port\") \
                                 or as exactly one `.`-delimited host glob \
                                 (`resource.host like(\"*.example.com\", \".\")`) and one \
                                 `resource.port == <port>` top-level `when` conjunct, so the \
                                 proxy knows which connections to inspect"
                            .to_string(),
                    }
                })?,
            };
            let endpoint = format!("{}:{}", key.0, key.1);
            let path = path_annotation
                .map(|path| validate_path(&policy_id, path))
                .transpose()?
                .unwrap_or_default();
            let protocol = protocol_annotation
                .map(|value| {
                    L7Protocol::from_annotation(value).ok_or_else(|| {
                        CedarEngineError::UnsupportedL7Protocol {
                            policy_id: policy_id.clone(),
                            protocol: value.to_string(),
                        }
                    })
                })
                .transpose()?;
            let declared = l7_declared
                .entry(key.clone())
                .or_default()
                .paths
                .entry(path.clone())
                .or_default();
            match (declared.protocol, protocol) {
                (Some(first), Some(second)) if first != second => {
                    return Err(CedarEngineError::ConflictingL7Protocol {
                        endpoint: format!("{endpoint}{path}"),
                        first: first.to_string(),
                        second: second.to_string(),
                    });
                }
                (None, Some(protocol)) => declared.protocol = Some(protocol),
                _ => {}
            }
            match enforcement {
                EnforcementAnnotation::Enforce => declared.enforced_policies += 1,
                EnforcementAnnotation::Audit => declared.audit_policies += 1,
                EnforcementAnnotation::Staged => declared.staged_policies += 1,
            }
            if policy.effect() == Effect::Permit {
                let reads_graphql =
                    reads_context_attr(conditions, |attr| attr.starts_with(GRAPHQL_FIELD_PREFIX));
                if permits_method_without_graphql(&json, WEBSOCKET_TEXT_METHOD) {
                    declared.generic_permits.push(policy_id.clone());
                }
                http_permits.insert(
                    policy.id().clone(),
                    HttpPermit {
                        endpoint: key,
                        path,
                        graphql_aware: reads_graphql
                            || mentions_resource_attr(conditions, endpoint_fields::PROTOCOL),
                    },
                );
            }
        }

        if touches_network_connect && policy.effect() == Effect::Permit {
            let endpoint = match scope_endpoint(policy) {
                Some(endpoint) => Some(parse_endpoint(&policy_id, &endpoint)?),
                None => condition_endpoint(policy, &policy_id)?,
            };
            if transport == Some(NetworkTransport::Tcp)
                && let Some((host, _)) = &endpoint
                && !host.contains('*')
            {
                check_tcp_host(&policy_id, host)?;
            }
            network_permits.insert(
                policy.id().clone(),
                NetworkPermit {
                    endpoint: endpoint.clone().filter(|(host, _)| !host.contains('*')),
                    allowed_ips: allowed_ips.clone(),
                },
            );
            match endpoint {
                Some((host, port)) => {
                    dns_ports
                        .entry((host, transport.unwrap_or_default(), allowed_ips))
                        .or_default()
                        .insert(port);
                }
                None if transport.is_some() => {
                    return Err(CedarEngineError::UnsupportedPolicy {
                        policy_id,
                        reason: "a @transport(\"tcp\") permit must name one DNS host and port, \
                                 in its scope (resource == Sandbox::NetworkEndpoint::\"host:port\") \
                                 or as `resource.host` and `resource.port` conditions; native TCP \
                                 has no hostless form"
                            .to_string(),
                    });
                }
                None => hostless_permits.push(HostlessPermit {
                    policy_id,
                    port: condition_port(policy),
                }),
            }
        }
    }

    let dns_endpoints: Vec<AuthorizedNetworkEndpoint> = dns_ports
        .into_iter()
        .map(
            |((host, transport, allowed_ips), ports)| AuthorizedNetworkEndpoint {
                host,
                ports: ports.into_iter().collect(),
                transport,
                allowed_ips,
            },
        )
        .collect();
    check_tcp_endpoints(&dns_endpoints, l7_declared.keys(), &hostless_permits)?;

    let mut l7_endpoints = BTreeMap::new();
    let mut l7_host_patterns = Vec::new();
    let mut warnings = Vec::new();
    for ((host, port), declared) in l7_declared {
        let paths = declared.finish(&host, port, &mut warnings)?;
        check_unambiguous_paths(&host, port, &paths)?;
        if host.contains('*') {
            // `host_glob` only produces patterns the YAML matcher compiles.
            let pattern =
                HostPattern::new(&host).map_err(|reason| CedarEngineError::UnsupportedPolicy {
                    policy_id: format!("{host}:{port}"),
                    reason: format!("host glob cannot be matched: {reason}"),
                })?;
            l7_host_patterns.push(L7HostPattern {
                host: host.clone(),
                port,
                pattern,
            });
        }
        l7_endpoints.insert((host, port), paths);
    }
    check_unambiguous_hosts(&l7_endpoints)?;

    Ok(PolicyAnalysis {
        filesystem: FilesystemGrants {
            read_only: read_only.into_iter().collect(),
            read_write: read_write.into_iter().collect(),
        },
        dns_endpoints,
        l7_endpoints,
        l7_host_patterns,
        query_keys,
        staged_query_keys,
        network_permits,
        unresolved,
        binary_alias_paths,
        binary_glob_patterns,
        http_permits,
        warnings,
    })
}

/// A `Set<String>` context field holding binary identities the supervisor
/// computes from the literals policies test it with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinarySet {
    /// `context.binary_aliases`: exact paths resolved as symlinks.
    Aliases,
    /// `context.binary_globs`: glob patterns matched against the binary and
    /// its ancestors.
    Globs,
}

impl BinarySet {
    fn field(self) -> &'static str {
        match self {
            Self::Aliases => context_fields::BINARY_ALIASES,
            Self::Globs => context_fields::BINARY_GLOBS,
        }
    }

    /// The accepted forms of a test on the set, for errors.
    fn forms(self) -> String {
        format!(
            "{} may only be tested with `.contains(\"{}\")`, `.containsAny([...])`, or \
             `.containsAll([...])` with literal {}",
            self.field(),
            match self {
                Self::Aliases => "/path",
                Self::Globs => "/pattern/*",
            },
            match self {
                Self::Aliases => "paths",
                Self::Globs => "glob patterns",
            }
        )
    }

    fn error(self, policy_id: &str, reason: String) -> CedarEngineError {
        let policy_id = policy_id.to_string();
        match self {
            Self::Aliases => CedarEngineError::InvalidBinaryAlias { policy_id, reason },
            Self::Globs => CedarEngineError::InvalidBinaryGlob { policy_id, reason },
        }
    }

    /// Checks one literal the set is tested with.
    fn check_literal(self, literal: &str) -> Result<(), String> {
        match self {
            Self::Aliases => {
                if !literal.starts_with('/') || literal.contains('*') {
                    return Err(format!(
                        "{literal:?} is not an absolute binary path without `*`; YAML \
                         resolves only exact binary paths"
                    ));
                }
            }
            Self::Globs => {
                if !literal.starts_with('/') || !literal.contains('*') {
                    return Err(format!(
                        "{literal:?} is not an absolute binary glob pattern with `*`; test \
                         an exact path with binary_path, ancestors, and binary_aliases"
                    ));
                }
                // The supervisor matches the pattern as the Rego rules match a
                // YAML binary glob: `globset` with a literal `/` separator.
                globset::GlobBuilder::new(literal)
                    .literal_separator(true)
                    .build()
                    .map_err(|error| format!("{literal:?} is not a valid glob: {error}"))?;
            }
        }
        Ok(())
    }
}

/// Collects the literals `conditions` tests `set` with; see the module docs
/// for the accepted forms.
///
/// # Errors
///
/// Returns [`CedarEngineError::InvalidBinaryAlias`] or
/// [`CedarEngineError::InvalidBinaryGlob`] for a form whose literals cannot
/// be collected exactly.
fn collect_binary_set_literals(
    conditions: &Value,
    set: BinarySet,
    policy_id: &str,
    literals: &mut BTreeSet<String>,
) -> Result<(), CedarEngineError> {
    binary_set_literals_in(conditions, set, literals).map_err(|reason| set.error(policy_id, reason))
}

/// Adds the literals of every test of `set` within `expr`.
///
/// Returns why a use of the set, or of the whole `context` record, which
/// includes it, is not one of the accepted forms.
fn binary_set_literals_in(
    expr: &Value,
    set: BinarySet,
    literals: &mut BTreeSet<String>,
) -> Result<(), String> {
    match expr {
        Value::Object(fields) => {
            for (name, value) in fields {
                if name == "Var" && value.as_str() == Some("context") {
                    return Err(format!(
                        "the whole `context` record includes {}; read its attributes instead",
                        set.field()
                    ));
                }
                if (name == "." || name == "has")
                    && let Some(attr) = context_attr(value)
                {
                    if name == "." && attr == set.field() {
                        return Err(set.forms());
                    }
                    continue;
                }
                if matches!(name.as_str(), "contains" | "containsAny" | "containsAll")
                    && value
                        .get("left")
                        .and_then(|left| left.get("."))
                        .and_then(context_attr)
                        == Some(set.field())
                {
                    let right = value.get("right").unwrap_or(&Value::Null);
                    let elements = if name == "contains" {
                        vec![right]
                    } else {
                        right
                            .get("Set")
                            .and_then(Value::as_array)
                            .map(|elements| elements.iter().collect())
                            .ok_or_else(|| set.forms())?
                    };
                    for element in elements {
                        let literal = element
                            .get("Value")
                            .and_then(Value::as_str)
                            .ok_or_else(|| set.forms())?;
                        set.check_literal(literal)?;
                        literals.insert(literal.to_string());
                    }
                    continue;
                }
                binary_set_literals_in(value, set, literals)?;
            }
            Ok(())
        }
        Value::Array(values) => values
            .iter()
            .try_for_each(|value| binary_set_literals_in(value, set, literals)),
        _ => Ok(()),
    }
}

/// Rejects `has` tests on `principal`, `resource`, or `context` of an
/// attribute the schema does not declare for a request the policy can
/// apply to; see the module docs.
///
/// Each request environment of the schema whose action is in the policy's
/// scope and whose resource type its resource scope admits is checked, so a
/// policy on both network actions that tests `context has method` is
/// rejected for `NetworkConnect`, as a read of `context.method` is.
///
/// # Errors
///
/// Returns [`CedarEngineError::PolicyValidation`] for the first such test.
fn check_has_tests(
    conditions: &Value,
    policy: &Policy,
    policy_id: &str,
    scope: &ActionScope,
    schema: &Schema,
    declared: &DeclaredAttributes,
) -> Result<(), CedarEngineError> {
    let mut tests = Vec::new();
    collect_var_has_tests(conditions, &mut tests);
    for (variable, attr) in tests {
        for env in schema.request_envs() {
            let action = env.action().id().unescaped();
            if !scope.includes(action) {
                continue;
            }
            let (subject, attributes) = match variable {
                "context" => (format!("action {action}"), declared.context(action)),
                "principal" => (
                    env.principal().to_string(),
                    declared.entity(&env.principal().to_string()),
                ),
                _ => {
                    let resource = env.resource().to_string();
                    if !resource_may_be(policy, &resource) {
                        continue;
                    }
                    (resource.clone(), declared.entity(&resource))
                }
            };
            if !attributes.contains(attr) {
                return Err(CedarEngineError::PolicyValidation {
                    reason: format!(
                        "policy {policy_id:?} tests `{variable} has {attr}`, but the schema \
                         declares no attribute {attr:?} on {subject}, so the test can never hold"
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Collects the `(variable, attribute)` of every `has` node within `expr`
/// whose left operand is `principal`, `resource`, or `context`.
fn collect_var_has_tests<'a>(expr: &'a Value, tests: &mut Vec<(&'a str, &'a str)>) {
    match expr {
        Value::Object(fields) => {
            for (name, value) in fields {
                if name == "has"
                    && let Some(variable) = value
                        .get("left")
                        .and_then(|left| left.get("Var"))
                        .and_then(Value::as_str)
                    && let Some(attr) = value.get("attr").and_then(Value::as_str)
                    && matches!(variable, "principal" | "resource" | "context")
                {
                    tests.push((variable, attr));
                }
                collect_var_has_tests(value, tests);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_var_has_tests(value, tests);
            }
        }
        _ => {}
    }
}

/// Rejects delimited `like` patterns within `expr` whose `**` is next to a
/// character other than the delimiter; see the module docs.
///
/// # Errors
///
/// Returns [`CedarEngineError::AmbiguousRecursiveWildcard`] for the first
/// such pattern.
fn check_delimited_patterns(expr: &Value, policy_id: &str) -> Result<(), CedarEngineError> {
    match expr {
        Value::Object(fields) => {
            for (name, value) in fields {
                if name == "like"
                    && let Some(delimiter) = value.get("delim").and_then(Value::as_str)
                    && let Some(elements) = value.get("pattern").and_then(Value::as_array)
                    && let Some(pattern) = ambiguous_recursive_wildcard(elements, delimiter)
                {
                    return Err(CedarEngineError::AmbiguousRecursiveWildcard {
                        policy_id: policy_id.to_string(),
                        pattern,
                        delimiter: delimiter.to_string(),
                    });
                }
                check_delimited_patterns(value, policy_id)?;
            }
            Ok(())
        }
        Value::Array(values) => values
            .iter()
            .try_for_each(|value| check_delimited_patterns(value, policy_id)),
        _ => Ok(()),
    }
}

/// Returns the pattern's text when a `MultiWildcard` in `elements` is next
/// to anything other than `delimiter` or the pattern's ends.
///
/// Rego's glob matcher reads a `**` that is not a whole segment as `*`,
/// while Cedar's `**` always crosses segments, so such a pattern cannot mean
/// the same in both.
fn ambiguous_recursive_wildcard(elements: &[Value], delimiter: &str) -> Option<String> {
    // Each element as its text, with `*` and `**` for wildcards; an escaped
    // `*` in a literal is written `\*`.
    let texts: Vec<String> = elements
        .iter()
        .map(|element| match element {
            Value::String(kind) if kind == "Wildcard" => "*".to_string(),
            Value::String(kind) if kind == "MultiWildcard" => "**".to_string(),
            Value::Object(literal) => literal
                .get("Literal")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .replace('*', "\\*"),
            _ => String::new(),
        })
        .collect();
    let adjacent_to_text = |neighbor: Option<&String>, from_end: bool| {
        neighbor.is_some_and(|text| {
            if text == "*" || text == "**" {
                return true;
            }
            let boundary = if from_end {
                text.chars().next_back()
            } else {
                text.chars().next()
            };
            boundary.is_some_and(|c| !delimiter.starts_with(c))
        })
    };
    let ambiguous = texts.iter().enumerate().any(|(index, text)| {
        text == "**"
            && (adjacent_to_text(index.checked_sub(1).and_then(|i| texts.get(i)), true)
                || adjacent_to_text(texts.get(index + 1), false))
    });
    ambiguous.then(|| texts.concat())
}

/// True if a `.` or `has` node within `expr` reads a `context` attribute
/// `accept` accepts, or the whole `context` record, which includes them.
fn reads_context_attr(expr: &Value, accept: impl Fn(&str) -> bool + Copy) -> bool {
    match expr {
        Value::Object(fields) => fields.iter().any(|(name, value)| {
            if name == "Var" && value.as_str() == Some("context") {
                return true;
            }
            if (name == "." || name == "has")
                && let Some(attr) = context_attr(value)
            {
                return accept(attr);
            }
            reads_context_attr(value, accept)
        }),
        Value::Array(values) => values.iter().any(|value| reads_context_attr(value, accept)),
        _ => false,
    }
}

/// True if `expr` reads or tests `resource.<attr>`.
fn mentions_resource_attr(expr: &Value, attr: &str) -> bool {
    match expr {
        Value::Object(fields) => fields.iter().any(|(name, value)| {
            if (name == "." || name == "has")
                && value
                    .get("left")
                    .and_then(|left| left.get("Var"))
                    .and_then(Value::as_str)
                    == Some("resource")
            {
                return value.get("attr").and_then(Value::as_str) == Some(attr);
            }
            mentions_resource_attr(value, attr)
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| mentions_resource_attr(value, attr)),
        _ => false,
    }
}

/// What a permit's conditions can be for a GraphQL-over-WebSocket client
/// message, abstracted over everything but the method and the GraphQL
/// fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageTruth {
    /// Always true for such a message.
    True,
    /// Never true for such a message.
    False,
    /// May be true, depending on fields other than `graphql_*`.
    Maybe,
    /// Can only be true through a condition on a `graphql_*` field.
    Graphql,
}

impl MessageTruth {
    fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            other => other,
        }
    }

    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::Graphql, _) | (_, Self::Graphql) => Self::Graphql,
            (Self::Maybe, _) | (_, Self::Maybe) => Self::Maybe,
            (Self::True, Self::True) => Self::True,
        }
    }

    fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::Maybe, _) | (_, Self::Maybe) => Self::Maybe,
            (Self::Graphql, _) | (_, Self::Graphql) => Self::Graphql,
            (Self::False, Self::False) => Self::False,
        }
    }

    /// Whether the conditions can hold without a condition on a `graphql_*`
    /// field.
    fn satisfiable_without_graphql(self) -> bool {
        matches!(self, Self::True | Self::Maybe)
    }
}

/// Returns whether the policy's conditions can hold for a request with
/// `method` through no condition on a `graphql_*` field.
///
/// Evaluates the `when` and `unless` bodies in [`MessageTruth`]: a test of
/// `context.method` against literals is decided for `method`, a test that
/// reads a `graphql_*` field is [`MessageTruth::Graphql`], and any other
/// test may hold. So a permit whose conditions are `GET || WEBSOCKET_TEXT ||
/// (WEBSOCKET_TEXT && graphql...)` can, while one with `GET ||
/// (WEBSOCKET_TEXT && graphql...)` cannot.
fn permits_method_without_graphql(json: &Value, method: &str) -> bool {
    let conditions = json
        .get("conditions")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    conditions
        .iter()
        .fold(MessageTruth::True, |truth, condition| {
            let body = condition.get("body").unwrap_or(&Value::Null);
            let body = message_truth(body, method);
            truth.and(
                if condition.get("kind").and_then(Value::as_str) == Some("unless") {
                    body.not()
                } else {
                    body
                },
            )
        })
        .satisfiable_without_graphql()
}

/// The string of a `Value` literal node.
fn string_literal(node: &Value) -> Option<&str> {
    node.get("Value").and_then(Value::as_str)
}

/// Evaluates `expr` in [`MessageTruth`] for a request with `method`.
fn message_truth(expr: &Value, method: &str) -> MessageTruth {
    let Some(fields) = expr.as_object() else {
        return MessageTruth::Maybe;
    };
    let Some((name, value)) = fields.iter().next() else {
        return MessageTruth::Maybe;
    };
    let operands = |node: &Value| {
        node.get("left")
            .zip(node.get("right"))
            .map(|(left, right)| (message_truth(left, method), message_truth(right, method)))
    };
    let is_method = |node: &Value| {
        node.get(".")
            .and_then(context_attr)
            .is_some_and(|attr| attr == context_fields::METHOD)
    };
    match name.as_str() {
        "Value" => match value {
            Value::Bool(true) => MessageTruth::True,
            Value::Bool(false) => MessageTruth::False,
            _ => MessageTruth::Maybe,
        },
        "&&" => operands(value).map_or(MessageTruth::Maybe, |(left, right)| left.and(right)),
        "||" => operands(value).map_or(MessageTruth::Maybe, |(left, right)| left.or(right)),
        "!" => message_truth(value.get("arg").unwrap_or(&Value::Null), method).not(),
        "if-then-else" => {
            let condition = message_truth(value.get("if").unwrap_or(&Value::Null), method);
            let then = message_truth(value.get("then").unwrap_or(&Value::Null), method);
            let otherwise = message_truth(value.get("else").unwrap_or(&Value::Null), method);
            condition.and(then).or(condition.not().and(otherwise))
        }
        "==" | "!=" => {
            let (Some(left), Some(right)) = (value.get("left"), value.get("right")) else {
                return MessageTruth::Maybe;
            };
            let compared = if is_method(left) {
                string_literal(right)
            } else if is_method(right) {
                string_literal(left)
            } else {
                None
            };
            let truth = match compared {
                Some(compared) if compared == method => MessageTruth::True,
                Some(_) => MessageTruth::False,
                None if reads_context_attr(expr, |attr| attr.starts_with(GRAPHQL_FIELD_PREFIX)) => {
                    MessageTruth::Graphql
                }
                None => MessageTruth::Maybe,
            };
            if name == "!=" { truth.not() } else { truth }
        }
        "contains"
            if value.get("right").is_some_and(is_method)
                && let Some(elements) = value
                    .get("left")
                    .and_then(|left| left.get("Set"))
                    .and_then(Value::as_array) =>
        {
            if elements
                .iter()
                .any(|element| string_literal(element) == Some(method))
            {
                MessageTruth::True
            } else if elements
                .iter()
                .all(|element| string_literal(element).is_some())
            {
                MessageTruth::False
            } else {
                MessageTruth::Maybe
            }
        }
        _ if reads_context_attr(expr, |attr| attr.starts_with(GRAPHQL_FIELD_PREFIX)) => {
            MessageTruth::Graphql
        }
        _ => MessageTruth::Maybe,
    }
}

/// The attribute an `attr` or `has` node reads from `context`, if it reads
/// one from `context` directly.
fn context_attr(access: &Value) -> Option<&str> {
    let reads_context = access
        .get("left")
        .and_then(|left| left.get("Var"))
        .and_then(Value::as_str)
        == Some("context");
    reads_context
        .then(|| access.get("attr").and_then(Value::as_str))
        .flatten()
}

/// How a `NetworkConnect` policy reads `context.destination_ip`.
enum DestinationIpUse {
    /// It does not.
    None,
    /// A `forbid` reads it, in any form. It takes part in every decision as
    /// written: before resolution with the address absent, so its guarded
    /// address conditions are false, and once per resolved address after.
    Forbid,
    /// A `permit` requires the address to lie in `allowed_ips`.
    Permit {
        allowed_ips: Vec<IpNet>,
        /// The permit without its address conjuncts.
        unresolved: Box<Policy>,
    },
}

/// Classifies how a policy that can apply to `NetworkConnect` reads
/// `context.destination_ip`; see the module docs for the accepted forms.
///
/// # Errors
///
/// Returns [`CedarEngineError::InvalidDestinationIp`] for a form whose
/// ranges cannot be derived exactly.
fn destination_ip_use(
    policy: &Policy,
    policy_id: &str,
    scope: &ActionScope,
) -> Result<DestinationIpUse, CedarEngineError> {
    let invalid = |reason: &str| CedarEngineError::InvalidDestinationIp {
        policy_id: policy_id.to_string(),
        reason: reason.to_string(),
    };
    let Ok(mut json) = policy.to_json() else {
        return Err(invalid("the policy has no JSON form to inspect"));
    };
    let conditions = json
        .get("conditions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !conditions.iter().any(reads_destination_ip) {
        return Ok(DestinationIpUse::None);
    }
    if !scope.is_only(actions::NETWORK_CONNECT) {
        return Err(invalid(
            "a policy that reads destination_ip must have exactly the NetworkConnect action in \
             its scope",
        ));
    }
    if policy.effect() == Effect::Forbid {
        return Ok(DestinationIpUse::Forbid);
    }

    let mut allowed_ips: Option<Vec<IpNet>> = None;
    let mut stripped_conditions = Vec::with_capacity(conditions.len());
    for condition in &conditions {
        let body = condition.get("body").unwrap_or(&Value::Null);
        if condition.get("kind").and_then(Value::as_str) != Some("when") {
            if reads_destination_ip(body) {
                return Err(invalid(
                    "a permit may read destination_ip only in `when` conditions",
                ));
            }
            stripped_conditions.push(condition.clone());
            continue;
        }
        let mut conjuncts = Vec::new();
        collect_conjuncts(body, &mut conjuncts);
        let mut kept = Vec::new();
        for conjunct in conjuncts {
            if !reads_destination_ip(conjunct) {
                kept.push(conjunct.clone());
                continue;
            }
            if is_destination_ip_guard(conjunct) {
                continue;
            }
            let mut literals = Vec::new();
            if !range_disjunction(conjunct, &mut literals) {
                return Err(invalid(
                    "each `when` conjunct that reads destination_ip must be \
                     `context has destination_ip` or an `||` of \
                     `context.destination_ip.isInRange(ip(\"...\"))` tests",
                ));
            }
            let ranges = literals
                .iter()
                .map(|literal| parse_range(literal).map_err(|reason| invalid(&reason)))
                .collect::<Result<Vec<_>, _>>()?;
            allowed_ips = Some(match allowed_ips {
                None => normalize_ranges(ranges),
                Some(previous) => intersect_ranges(&previous, &ranges),
            });
        }
        let mut stripped = condition.clone();
        stripped["body"] = kept
            .into_iter()
            .reduce(|left, right| serde_json::json!({ "&&": { "left": left, "right": right } }))
            .unwrap_or_else(|| serde_json::json!({ "Value": true }));
        stripped_conditions.push(stripped);
    }
    let Some(allowed_ips) = allowed_ips else {
        return Err(invalid(
            "a permit that reads destination_ip must require it to be in a range with \
             `context.destination_ip.isInRange(ip(\"...\"))`",
        ));
    };
    if allowed_ips.is_empty() {
        return Err(invalid("the destination_ip ranges admit no address"));
    }
    json["conditions"] = Value::Array(stripped_conditions);
    let unresolved = Policy::from_json(Some(policy.id().clone()), json)
        .map_err(|e| invalid(&format!("the policy without its address conditions: {e}")))?;
    Ok(DestinationIpUse::Permit {
        allowed_ips,
        unresolved: Box::new(unresolved),
    })
}

/// True if `expr` reads `context.destination_ip`, tests for it, or uses the
/// whole `context` record, which includes it.
fn reads_destination_ip(expr: &Value) -> bool {
    match expr {
        Value::Object(fields) => fields.iter().any(|(name, value)| {
            // A variable reference; a record key named `Var` holds an
            // expression instead, which is inspected below.
            if name == "Var"
                && let Some(variable) = value.as_str()
            {
                return variable == "context";
            }
            if (name == "." || name == "has")
                && value
                    .get("left")
                    .and_then(|left| left.get("Var"))
                    .and_then(Value::as_str)
                    == Some("context")
            {
                return value.get("attr").and_then(Value::as_str)
                    == Some(context_fields::DESTINATION_IP);
            }
            reads_destination_ip(value)
        }),
        Value::Array(values) => values.iter().any(reads_destination_ip),
        _ => false,
    }
}

/// True if `expr` is `context has destination_ip`.
fn is_destination_ip_guard(expr: &Value) -> bool {
    expr.get("has").is_some_and(|has| {
        has.get("left")
            .and_then(|left| left.get("Var"))
            .and_then(Value::as_str)
            == Some("context")
            && has.get("attr").and_then(Value::as_str) == Some(context_fields::DESTINATION_IP)
    })
}

/// Collects the `ip("...")` literals of an `||` of
/// `context.destination_ip.isInRange(ip("..."))` tests.
///
/// Returns `false` if any node has another form.
fn range_disjunction(expr: &Value, literals: &mut Vec<String>) -> bool {
    if let Some(or) = expr.get("||") {
        return match (or.get("left"), or.get("right")) {
            (Some(left), Some(right)) => {
                range_disjunction(left, literals) && range_disjunction(right, literals)
            }
            _ => false,
        };
    }
    let Some([address, range]) = expr
        .get("isInRange")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
    else {
        return false;
    };
    let reads_address = address.get(".").is_some_and(|access| {
        access
            .get("left")
            .and_then(|left| left.get("Var"))
            .and_then(Value::as_str)
            == Some("context")
            && access.get("attr").and_then(Value::as_str) == Some(context_fields::DESTINATION_IP)
    });
    let literal =
        range
            .get("ip")
            .and_then(Value::as_array)
            .and_then(|args| match args.as_slice() {
                [arg] => arg.get("Value").and_then(Value::as_str),
                _ => None,
            });
    match literal {
        Some(literal) if reads_address => {
            literals.push(literal.to_string());
            true
        }
        _ => false,
    }
}

/// Parses an `ip("...")` literal as a range, a bare address being a single
/// host, and rejects ranges the proxy always blocks.
fn parse_range(literal: &str) -> Result<IpNet, String> {
    let range = literal
        .parse::<IpNet>()
        .or_else(|_| literal.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| format!("ip({literal:?}) is not an address or CIDR range"))?;
    if openshell_core::net::is_always_blocked_net(range) {
        return Err(format!(
            "ip({literal:?}) overlaps loopback, link-local, or unspecified addresses, which \
             are blocked regardless of policy"
        ));
    }
    Ok(range)
}

/// Sorts `ranges` and drops any range inside another.
fn normalize_ranges(mut ranges: Vec<IpNet>) -> Vec<IpNet> {
    ranges.sort();
    ranges.dedup();
    let all = ranges.clone();
    ranges.retain(|range| {
        !all.iter()
            .any(|other| other != range && other.contains(range))
    });
    ranges
}

/// Returns the addresses in both unions of ranges, as ranges.
///
/// Two CIDR ranges either nest or are disjoint, so the intersection of two
/// unions is a union of ranges from either side.
fn intersect_ranges(left: &[IpNet], right: &[IpNet]) -> Vec<IpNet> {
    let mut both = Vec::new();
    for a in left {
        for b in right {
            if a.contains(b) {
                both.push(*b);
            } else if b.contains(a) {
                both.push(*a);
            }
        }
    }
    normalize_ranges(both)
}

/// Longest DNS label, in octets.
const MAX_DNS_LABEL_LEN: usize = 63;

/// Longest DNS name, in octets, without the root dot.
const MAX_DNS_NAME_LEN: usize = 253;

/// Checks that a native TCP endpoint names a DNS host, as YAML requires of a
/// `protocol: tcp` endpoint.
///
/// # Errors
///
/// Returns [`CedarEngineError::InvalidTcpHost`] for an IP literal or a host
/// that is not a valid DNS name.
fn check_tcp_host(policy_id: &str, host: &str) -> Result<(), CedarEngineError> {
    let invalid = |reason: &str| CedarEngineError::InvalidTcpHost {
        policy_id: policy_id.to_string(),
        host: host.to_string(),
        reason: reason.to_string(),
    };
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    if unbracketed.parse::<IpAddr>().is_ok() {
        return Err(invalid(
            "native TCP reaches hosts through policy DNS, so it cannot name an IP address",
        ));
    }
    let valid = exact_host(host).is_some()
        && host.len() <= MAX_DNS_NAME_LEN
        && host
            .split('.')
            .all(|label| label.len() <= MAX_DNS_LABEL_LEN);
    if !valid {
        return Err(invalid("not a valid DNS host name"));
    }
    Ok(())
}

/// Rejects a native TCP endpoint that another endpoint can also select.
///
/// YAML rejects a `protocol: tcp` endpoint that overlaps, on a host and
/// port, an endpoint without it or an inspected endpoint, because whether a
/// destination is native TCP must not depend on which endpoint matched. A
/// permit whose host cannot be derived may allow any host, so it overlaps
/// every native TCP endpoint on a port it may allow.
///
/// # Errors
///
/// Returns [`CedarEngineError::ConflictingTransport`] for the first overlap.
fn check_tcp_endpoints<'a>(
    endpoints: &[AuthorizedNetworkEndpoint],
    inspected: impl Iterator<Item = &'a (String, u16)> + Clone,
    hostless_permits: &[HostlessPermit],
) -> Result<(), CedarEngineError> {
    let conflict = |tcp_host: &str, other_host: &str, port: u16, reason: &str| {
        CedarEngineError::ConflictingTransport {
            tcp_endpoint: format!("{tcp_host}:{port}"),
            other_endpoint: format!("{other_host}:{port}"),
            reason: reason.to_string(),
        }
    };
    for tcp in endpoints
        .iter()
        .filter(|endpoint| endpoint.transport == NetworkTransport::Tcp)
    {
        for permit in hostless_permits {
            // A permit naming no port may allow every port of the endpoint.
            let shared = permit.port.map_or_else(
                || tcp.ports.first().copied(),
                |port| tcp.ports.contains(&port).then_some(port),
            );
            if let Some(port) = shared {
                return Err(CedarEngineError::ConflictingTransport {
                    tcp_endpoint: format!("{}:{port}", tcp.host),
                    other_endpoint: permit
                        .port
                        .map_or_else(|| "*:*".to_string(), |port| format!("*:{port}")),
                    reason: format!(
                        "which NetworkConnect permit {:?} may allow without @transport(\"tcp\"): \
                         its host cannot be derived from its conditions, so name the host with \
                         `resource.host == \"...\"` or a `.`-delimited `resource.host like`, \
                         with `resource.port`, as one top-level `when` conjunct each",
                        permit.policy_id
                    ),
                });
            }
        }
        for (host, port) in inspected.clone() {
            if tcp.ports.contains(port) && host_patterns_overlap(&tcp.host, host) {
                return Err(conflict(
                    &tcp.host,
                    host,
                    *port,
                    "which HttpRequest policies inspect; native TCP is never inspected per request",
                ));
            }
        }
        for other in endpoints
            .iter()
            .filter(|endpoint| endpoint.transport != NetworkTransport::Tcp)
        {
            let shared = tcp.ports.iter().find(|port| other.ports.contains(port));
            if let Some(port) = shared
                && host_patterns_overlap(&tcp.host, &other.host)
            {
                return Err(conflict(
                    &tcp.host,
                    &other.host,
                    *port,
                    "which a NetworkConnect permit names without @transport(\"tcp\")",
                ));
            }
        }
    }
    Ok(())
}

/// One element of a host pattern, for [`host_patterns_overlap`].
#[derive(Clone, Copy)]
enum HostToken {
    Literal(char),
    /// `*` (within one label) or `**` (across labels).
    Star {
        crosses_labels: bool,
    },
}

fn host_tokens(pattern: &str) -> Vec<HostToken> {
    let mut tokens = Vec::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '*' {
            let crosses_labels = chars.next_if_eq(&'*').is_some();
            while chars.next_if_eq(&'*').is_some() {}
            tokens.push(HostToken::Star { crosses_labels });
        } else {
            tokens.push(HostToken::Literal(c));
        }
    }
    tokens
}

/// Returns whether some host matches both host patterns, each an exact
/// host or a host glob in policy DNS syntax.
pub fn host_patterns_overlap(left: &str, right: &str) -> bool {
    if !left.contains('*') && !right.contains('*') {
        return left == right;
    }
    // Authored selectors are bounded at load time. Keep this public helper
    // conservative for oversized callers too: an unknown overlap must not
    // bypass checks for conflicting inspection modes.
    if left.len() > MAX_DNS_NAME_LEN || right.len() > MAX_DNS_NAME_LEN {
        return true;
    }
    let (left, right) = (host_tokens(left), host_tokens(right));
    let accepts = |token: HostToken, c: char| match token {
        HostToken::Literal(literal) => literal == c,
        HostToken::Star { crosses_labels } => crosses_labels || c != '.',
    };
    // Every transition advances at least one pattern position. Keep only
    // the current and next row of reachable states, rather than a matrix.
    let mut current = vec![false; right.len() + 1];
    let mut next = vec![false; right.len() + 1];
    current[0] = true;
    for i in 0..=left.len() {
        for j in 0..=right.len() {
            if !current[j] {
                continue;
            }
            if i == left.len() && j == right.len() {
                return true;
            }
            let (l, r) = (left.get(i).copied(), right.get(j).copied());
            if let Some(HostToken::Star { .. }) = l {
                next[j] = true;
            }
            if let Some(HostToken::Star { .. }) = r {
                current[j + 1] = true;
            }
            match (l, r) {
                (Some(HostToken::Literal(a)), Some(HostToken::Literal(b))) if a == b => {
                    next[j + 1] = true;
                }
                (Some(HostToken::Literal(c)), Some(star @ HostToken::Star { .. }))
                    if accepts(star, c) =>
                {
                    next[j] = true;
                }
                (Some(star @ HostToken::Star { .. }), Some(HostToken::Literal(c)))
                    if accepts(star, c) =>
                {
                    current[j + 1] = true;
                }
                _ => {}
            }
        }
        std::mem::swap(&mut current, &mut next);
        next.fill(false);
    }
    false
}

/// Checks an `@path` value against the YAML endpoint `path` grammar.
///
/// # Errors
///
/// Returns [`CedarEngineError::InvalidL7Path`] if the value is empty or
/// neither starts with `/` nor is `**`.
fn validate_path(policy_id: &str, path: &str) -> Result<String, CedarEngineError> {
    let invalid = |reason: &str| CedarEngineError::InvalidL7Path {
        policy_id: policy_id.to_string(),
        path: path.to_string(),
        reason: reason.to_string(),
    };
    if path.is_empty() {
        return Err(invalid(
            "must not be empty; omit @path for the endpoint's path-less inspection",
        ));
    }
    if !path.starts_with('/') && path != "**" {
        return Err(invalid("must start with '/' or be '**'"));
    }
    Ok(path.to_string())
}

/// Ranks a path as the relay ranks endpoint paths when selecting one for a
/// request: the matching path with the most characters other than `*` wins.
fn path_specificity(path: &str) -> usize {
    path.chars().filter(|c| *c != '*').count()
}

/// Rejects two paths of one endpoint that the relay could not order.
///
/// The relay selects the matching path with the highest
/// [`path_specificity`]; between equally specific paths it would fall back
/// to their order. Such paths must inspect the same way when a request can
/// match both, as YAML requires of endpoints sharing a `host:port`.
///
/// # Errors
///
/// Returns [`CedarEngineError::AmbiguousL7Paths`] for the first such pair.
fn check_unambiguous_paths(
    host: &str,
    port: u16,
    paths: &BTreeMap<String, L7Endpoint>,
) -> Result<(), CedarEngineError> {
    for (index, first) in paths.iter().enumerate() {
        if let Some((first, second)) = paths
            .iter()
            .skip(index + 1)
            .find_map(|second| ambiguous_path_pair(first, second))
        {
            return Err(CedarEngineError::AmbiguousL7Paths {
                endpoint: format!("{host}:{port}"),
                first: first.to_string(),
                second: second.to_string(),
            });
        }
    }
    Ok(())
}

/// Returns the two paths if the relay could not order them: equally
/// specific, able to match one request, and inspected differently.
fn ambiguous_path_pair<'a>(
    (first, first_endpoint): (&'a String, &L7Endpoint),
    (second, second_endpoint): (&'a String, &L7Endpoint),
) -> Option<(&'a str, &'a str)> {
    (path_specificity(first) == path_specificity(second)
        && !first_endpoint.same_inspection(*second_endpoint)
        && paths_may_overlap(first, second))
    .then_some((first.as_str(), second.as_str()))
}

/// Rejects two inspected endpoints that can select one host but inspect an
/// equally specific overlapping path differently.
///
/// A host matched by an exact entry and a glob, or by two globs, is routed
/// to the most specific matching path of every entry selecting it, so the
/// paths of such entries must agree where [`check_unambiguous_paths`] would
/// require it of one entry. YAML rejects endpoints whose hosts and ports
/// overlap with the same conflict.
///
/// # Errors
///
/// Returns [`CedarEngineError::AmbiguousL7Hosts`] for the first such pair.
fn check_unambiguous_hosts(
    endpoints: &BTreeMap<(String, u16), BTreeMap<String, L7Endpoint>>,
) -> Result<(), CedarEngineError> {
    for (index, ((first_host, port), first_paths)) in endpoints.iter().enumerate() {
        for ((second_host, second_port), second_paths) in endpoints.iter().skip(index + 1) {
            if port != second_port || !host_patterns_overlap(first_host, second_host) {
                continue;
            }
            let conflict = first_paths.iter().find_map(|first| {
                second_paths
                    .iter()
                    .find_map(|second| ambiguous_path_pair(first, second))
            });
            if let Some((first_path, second_path)) = conflict {
                return Err(CedarEngineError::AmbiguousL7Hosts {
                    first: format!("{first_host}:{port}"),
                    second: format!("{second_host}:{port}"),
                    first_path: first_path.to_string(),
                    second_path: second_path.to_string(),
                });
            }
        }
    }
    Ok(())
}

/// An endpoint path pattern in the shapes [`paths_may_overlap`] compares exactly.
enum PathShape<'a> {
    /// Matches every path.
    Any,
    /// Matches exactly this path.
    Literal(&'a str),
    /// Matches this path and its descendants.
    Subtree(&'a str),
    /// Any other glob.
    Glob,
}

impl<'a> PathShape<'a> {
    fn of(path: &'a str) -> Self {
        let has_glob = |text: &str| text.contains(['*', '?', '[', ']', '{', '}']);
        if path.is_empty() || path == "**" || path == "/**" {
            Self::Any
        } else if let Some(prefix) = path.strip_suffix("/**")
            && !has_glob(prefix)
        {
            Self::Subtree(prefix)
        } else if has_glob(path) {
            Self::Glob
        } else {
            Self::Literal(path)
        }
    }
}

/// Returns whether some request path could match both patterns.
///
/// Exact for literal paths and `/prefix/**` subtrees with literal prefixes;
/// any other glob is assumed to overlap, which only rejects more policies.
fn paths_may_overlap(first: &str, second: &str) -> bool {
    let under = |path: &str, prefix: &str| {
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    };
    match (PathShape::of(first), PathShape::of(second)) {
        (PathShape::Literal(left), PathShape::Literal(right)) => left == right,
        (PathShape::Literal(path), PathShape::Subtree(prefix))
        | (PathShape::Subtree(prefix), PathShape::Literal(path)) => under(path, prefix),
        (PathShape::Subtree(left), PathShape::Subtree(right)) => {
            under(left, right) || under(right, left)
        }
        _ => true,
    }
}

/// Which `Sandbox::Action`s a policy's action scope can match.
enum ActionScope {
    /// Unconstrained `action`: every action in the schema.
    Any,
    /// The listed action ids.
    Listed(BTreeSet<String>),
}

impl ActionScope {
    fn of(policy: &Policy) -> Self {
        let ids = |uids: &[EntityUid]| {
            uids.iter()
                .filter(|uid| uid.type_name().to_string() == actions::ACTION_TYPE)
                .map(|uid| uid.id().unescaped().to_string())
                .collect()
        };
        match policy.action_constraint() {
            ActionConstraint::Any => Self::Any,
            ActionConstraint::Eq(uid) => Self::Listed(ids(&[uid])),
            ActionConstraint::In(uids) => Self::Listed(ids(&uids)),
        }
    }

    fn includes(&self, action: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Listed(ids) => ids.contains(action),
        }
    }

    /// True if the scope lists exactly `action`.
    fn is_only(&self, action: &str) -> bool {
        matches!(self, Self::Listed(ids) if ids.len() == 1 && ids.contains(action))
    }

    /// True if every action in scope is `ReadFile` or `WriteFile`.
    fn is_filesystem_only(&self) -> bool {
        match self {
            Self::Any => false,
            Self::Listed(ids) => ids
                .iter()
                .all(|id| id == actions::READ_FILE || id == actions::WRITE_FILE),
        }
    }
}

/// True if the policy's resource scope can match an entity of `type_name`.
fn resource_may_be(policy: &Policy, type_name: &str) -> bool {
    match policy.resource_constraint() {
        ResourceConstraint::Any => true,
        ResourceConstraint::Is(entity_type) | ResourceConstraint::IsIn(entity_type, _) => {
            entity_type.to_string() == type_name
        }
        ResourceConstraint::Eq(uid) | ResourceConstraint::In(uid) => {
            uid.type_name().to_string() == type_name
        }
    }
}

/// Returns the `NetworkEndpoint` id named in the policy's resource scope.
///
/// `NetworkEndpoint` has no parent types, so `resource in E` matches exactly
/// `E`, the same as `resource == E`.
fn scope_endpoint(policy: &Policy) -> Option<String> {
    match policy.resource_constraint() {
        ResourceConstraint::Eq(uid)
        | ResourceConstraint::In(uid)
        | ResourceConstraint::IsIn(_, uid)
            if uid.type_name().to_string() == entity_types::NETWORK_ENDPOINT =>
        {
            Some(uid.id().unescaped().to_string())
        }
        _ => None,
    }
}

/// Splits a `"host:port"` endpoint id into a lowercase host and a port.
fn parse_endpoint(policy_id: &str, endpoint: &str) -> Result<(String, u16), CedarEngineError> {
    let invalid = |reason: &str| CedarEngineError::InvalidEndpoint {
        policy_id: policy_id.to_string(),
        endpoint: endpoint.to_string(),
        reason: reason.to_string(),
    };
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| invalid("expected \"host:port\""))?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid("port must be in 1..=65535"))?;
    if host.is_empty() {
        return Err(invalid("host must not be empty"));
    }
    if host.len() > MAX_DNS_NAME_LEN {
        return Err(invalid("host selector must not exceed 253 bytes"));
    }
    if host.ends_with('.') {
        return Err(invalid("host must not end with '.'"));
    }
    if host != host.to_ascii_lowercase() {
        // Requests are matched against the lowercased host, so an uppercase
        // literal could never match.
        return Err(invalid("host must be lowercase"));
    }
    if host.contains('*') {
        // An entity id matches only itself, so `*` here is a literal star that
        // no host contains, while policy DNS would read it as a wildcard.
        return Err(invalid(
            "host must not contain '*'; match hosts with \
             `resource.host like(\"*.example.com\", \".\")` in a `when` clause",
        ));
    }
    Ok((host.to_string(), port))
}

/// Delimiter that makes a `like` on `resource.host` a DNS-label host glob.
const HOST_LABEL_DELIMITER: &str = ".";

/// Returns the host and port a `permit`'s `when` conditions require.
///
/// Every top-level `&&` operand of a `when` condition is necessary for the
/// policy to apply, so a host and port found there bound every endpoint the
/// policy can allow, the same over-approximation YAML eligibility makes by
/// ignoring binaries. Returns `None`, so the policy grants no eligibility,
/// unless exactly one operand constrains the host and one the port, both in a
/// recognised form. A `resource.host_port` literal constrains both, so it
/// counts as the host operand and the port operand.
///
/// # Errors
///
/// Returns [`CedarEngineError::InvalidEndpoint`] for a `host_port` literal
/// that could never match a request's endpoint, as for a scope literal.
fn condition_endpoint(
    policy: &Policy,
    policy_id: &str,
) -> Result<Option<(String, u16)>, CedarEngineError> {
    let Some(json) = policy.to_json().ok() else {
        return Ok(None);
    };
    let Some(operands) = when_conjuncts(&json) else {
        return Ok(None);
    };
    let mut hosts = operands.iter().filter_map(|expr| required_host(expr));
    let Some(host) = hosts.next() else {
        return Ok(None);
    };
    if hosts.next().is_some() {
        return Ok(None);
    }
    let port = match &host {
        // `host_port` names the port too; another port operand would make
        // two, which the exactly-one rule rejects.
        HostConstraint::Endpoint(_)
            if operands.iter().any(|expr| required_port(expr).is_some()) =>
        {
            return Ok(None);
        }
        HostConstraint::Endpoint(literal) => {
            return parse_endpoint(policy_id, literal).map(Some);
        }
        HostConstraint::Eligible(_) | HostConstraint::Ineligible => single_port(&operands),
    };
    Ok(match (host, port) {
        (HostConstraint::Eligible(host), Some(port)) => {
            if host.len() > MAX_DNS_NAME_LEN {
                return Err(CedarEngineError::InvalidEndpoint {
                    policy_id: policy_id.to_string(),
                    endpoint: format!("{host}:{port}"),
                    reason: "host selector must not exceed 253 bytes".to_string(),
                });
            }
            Some((host, port))
        }
        _ => None,
    })
}

/// Returns the host glob and port an `HttpRequest` policy's `when`
/// conditions require, in the forms [`condition_endpoint`] accepts.
///
/// Only a glob counts: an exact host belongs in the policy's scope, where
/// `parse_endpoint` validates it. A glob here inspects every host it
/// matches, since the conditions hold for no other host.
///
/// # Errors
///
/// Returns [`CedarEngineError::InvalidEndpoint`] as [`condition_endpoint`]
/// does.
fn condition_host_glob(
    policy: &Policy,
    policy_id: &str,
) -> Result<Option<(String, u16)>, CedarEngineError> {
    Ok(condition_endpoint(policy, policy_id)?.filter(|(host, _)| host.contains('*')))
}

/// Returns the port a `permit`'s `when` conditions require, if exactly one
/// top-level `&&` operand constrains `resource.port`, whatever they say of
/// the host.
fn condition_port(policy: &Policy) -> Option<u16> {
    let json = policy.to_json().ok()?;
    single_port(&when_conjuncts(&json)?)
}

/// Returns the port named by exactly one `resource.port == <port>` operand.
fn single_port(operands: &[&Value]) -> Option<u16> {
    let mut ports = operands.iter().filter_map(|expr| required_port(expr));
    let port = ports.next()?;
    ports.next().is_none().then_some(port)
}

/// Flattens the top-level `&&` operands of every `when` condition of a
/// policy's JSON form.
fn when_conjuncts(json: &Value) -> Option<Vec<&Value>> {
    let mut operands = Vec::new();
    for condition in json.get("conditions")?.as_array()? {
        if condition.get("kind")?.as_str()? == "when" {
            collect_conjuncts(condition.get("body")?, &mut operands);
        }
    }
    Some(operands)
}

/// Flattens an `&&` tree into its operands.
fn collect_conjuncts<'a>(expr: &'a Value, operands: &mut Vec<&'a Value>) {
    if let Some(and) = expr.get("&&")
        && let (Some(left), Some(right)) = (and.get("left"), and.get("right"))
    {
        collect_conjuncts(left, operands);
        collect_conjuncts(right, operands);
    } else {
        operands.push(expr);
    }
}

/// True if `expr` is `resource.<attr>`.
fn is_resource_attr(expr: &Value, attr: &str) -> bool {
    expr.get(".").is_some_and(|access| {
        access
            .get("left")
            .and_then(|left| left.get("Var"))
            .and_then(Value::as_str)
            == Some("resource")
            && access.get("attr").and_then(Value::as_str) == Some(attr)
    })
}

/// Returns the operand of `resource.<attr> == <literal>`, in either order.
fn equality_with_resource_attr<'a>(expr: &'a Value, attr: &str) -> Option<&'a Value> {
    let eq = expr.get("==")?;
    let (left, right) = (eq.get("left")?, eq.get("right")?);
    let literal = if is_resource_attr(left, attr) {
        right
    } else if is_resource_attr(right, attr) {
        left
    } else {
        return None;
    };
    literal.get("Value")
}

/// A `when` operand that constrains `resource.host` or `resource.host_port`.
enum HostConstraint {
    /// An exact host or host glob policy DNS can match exactly.
    Eligible(String),
    /// A `resource.host_port` literal, as written, naming the host and the
    /// port together; `parse_endpoint` validates it.
    Endpoint(String),
    /// A host constraint in a form that grants no eligibility.
    Ineligible,
}

impl From<Option<String>> for HostConstraint {
    fn from(host: Option<String>) -> Self {
        host.map_or(Self::Ineligible, Self::Eligible)
    }
}

/// Classifies an operand, returning `None` if it does not constrain the host.
///
/// `resource.host_port == "h:p"` and `["h:p"].contains(resource.host_port)`
/// with exactly one element are [`HostConstraint::Endpoint`]; any other test
/// of `host_port`, such as a set with several elements or a `like`, is
/// [`HostConstraint::Ineligible`], since it does not name one endpoint.
fn required_host(expr: &Value) -> Option<HostConstraint> {
    if let Some(value) = equality_with_resource_attr(expr, endpoint_fields::HOST) {
        return Some(value.as_str().and_then(exact_host).into());
    }
    if let Some(value) = equality_with_resource_attr(expr, endpoint_fields::HOST_PORT) {
        return Some(
            value
                .as_str()
                .map_or(HostConstraint::Ineligible, |literal| {
                    HostConstraint::Endpoint(literal.to_string())
                }),
        );
    }
    if let Some(contains) = expr.get("contains")
        && contains
            .get("right")
            .is_some_and(|right| is_resource_attr(right, endpoint_fields::HOST_PORT))
    {
        let elements = contains
            .get("left")
            .and_then(|left| left.get("Set"))
            .and_then(Value::as_array);
        return Some(match elements.map(Vec::as_slice) {
            Some([element]) => string_literal(element)
                .map_or(HostConstraint::Ineligible, |literal| {
                    HostConstraint::Endpoint(literal.to_string())
                }),
            _ => HostConstraint::Ineligible,
        });
    }
    let like = expr.get("like")?;
    let subject = like.get("left")?;
    if is_resource_attr(subject, endpoint_fields::HOST_PORT) {
        // A glob over "host:port" names no one endpoint.
        return Some(HostConstraint::Ineligible);
    }
    if !is_resource_attr(subject, endpoint_fields::HOST) {
        return None;
    }
    if like.get("delim").and_then(Value::as_str) != Some(HOST_LABEL_DELIMITER) {
        return Some(HostConstraint::Ineligible);
    }
    Some(
        like.get("pattern")
            .and_then(Value::as_array)
            .and_then(|elems| host_glob(elems))
            .into(),
    )
}

/// Returns the port of a `resource.port == <port>` operand.
fn required_port(expr: &Value) -> Option<u16> {
    equality_with_resource_attr(expr, "port")?
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
}

/// Accepts a lowercase host without wildcards or empty labels.
fn exact_host(host: &str) -> Option<String> {
    let valid = !host.is_empty()
        && host == host.to_ascii_lowercase()
        && !host.split('.').any(str::is_empty)
        && host.chars().all(|c| c == '.' || is_host_char(c));
    valid.then(|| host.to_string())
}

/// Characters a host label may contain. Excludes glob metacharacters, so a
/// literal in a Cedar pattern can never be read as a wildcard by policy DNS.
fn is_host_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'
}

/// One element of a delimited `like` pattern on `resource.host`.
#[derive(Clone, Copy)]
enum PatternChar {
    Literal(char),
    /// `*`: any run of characters within one label.
    Wildcard,
    /// `**`: any run of characters, across labels.
    MultiWildcard,
}

/// One `.`-separated label of a delimited host pattern.
enum HostLabel {
    /// Literal characters, with `*` standing for a Cedar `Wildcard`.
    Glob(String),
    /// A whole-label Cedar `MultiWildcard`, written `**`.
    Recursive,
}

/// Converts a delimited `like` pattern on `resource.host` into the host glob
/// policy DNS matches, if both mean the same thing.
///
/// Cedar's delimited `*` stays within one label and its `**` crosses labels,
/// as policy DNS does for YAML wildcard hosts. The two agree on every valid
/// host when the pattern also satisfies YAML's wildcard host rules: `**` only
/// as the whole first label, `*` within the first label or as a whole later
/// label, and no wildcard top-level domain such as `*.com`.
fn host_glob(elems: &[Value]) -> Option<String> {
    let mut labels = vec![Vec::new()];
    for elem in elems {
        match elem {
            Value::String(kind) if kind == "Wildcard" => {
                labels.last_mut()?.push(PatternChar::Wildcard);
            }
            Value::String(kind) if kind == "MultiWildcard" => {
                labels.last_mut()?.push(PatternChar::MultiWildcard);
            }
            Value::Object(literal) => {
                for c in literal.get("Literal")?.as_str()?.chars() {
                    if c == '.' {
                        labels.push(Vec::new());
                    } else if is_host_char(c) {
                        labels.last_mut()?.push(PatternChar::Literal(c));
                    } else {
                        return None;
                    }
                }
            }
            _ => return None,
        }
    }
    let labels = labels
        .into_iter()
        .map(|label| match label.as_slice() {
            [] => None,
            [PatternChar::MultiWildcard] => Some(HostLabel::Recursive),
            _ => {
                let mut glob = String::new();
                for elem in &label {
                    match *elem {
                        // Adjacent `*`s within a label match the same text as one.
                        PatternChar::Wildcard if glob.ends_with('*') => {}
                        PatternChar::Wildcard => glob.push('*'),
                        PatternChar::Literal(c) => glob.push(c),
                        PatternChar::MultiWildcard => return None,
                    }
                }
                Some(HostLabel::Glob(glob))
            }
        })
        .collect::<Option<Vec<_>>>()?;

    let (first, rest) = labels.split_first()?;
    let later_labels_valid = rest.iter().all(|label| match label {
        HostLabel::Recursive => false,
        HostLabel::Glob(glob) => glob == "*" || !glob.contains('*'),
    });
    let whole_first_wildcard =
        matches!(first, HostLabel::Recursive) || matches!(first, HostLabel::Glob(g) if g == "*");
    let tld_wildcard = whole_first_wildcard && labels.len() <= 2;
    if !later_labels_valid || tld_wildcard {
        return None;
    }
    Some(
        labels
            .iter()
            .map(|label| match label {
                HostLabel::Recursive => "**",
                HostLabel::Glob(glob) => glob.as_str(),
            })
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Paths and access level granted by one filesystem `permit`.
struct FilesystemGrant {
    paths: Vec<String>,
    writes: bool,
}

/// Converts one filesystem-touching policy into a Landlock grant.
///
/// # Errors
///
/// Returns [`CedarEngineError`] if the policy's meaning cannot be expressed
/// exactly as a Landlock allow-list entry.
fn filesystem_grant(
    policy: &Policy,
    policy_id: &str,
    scope: &ActionScope,
) -> Result<FilesystemGrant, CedarEngineError> {
    let unsupported = |reason: &str| CedarEngineError::UnsupportedPolicy {
        policy_id: policy_id.to_string(),
        reason: reason.to_string(),
    };
    if policy.effect() == Effect::Forbid {
        return Err(CedarEngineError::FilesystemForbidUnsupported {
            policy_id: policy_id.to_string(),
        });
    }
    if !scope.is_filesystem_only() {
        return Err(unsupported(
            "a policy that can apply to files must list only ReadFile and/or WriteFile \
             in its action scope",
        ));
    }
    let principal_unconstrained = match policy.principal_constraint() {
        PrincipalConstraint::Any => true,
        PrincipalConstraint::Is(entity_type) => entity_type.to_string() == entity_types::PROCESS,
        _ => false,
    };
    if !principal_unconstrained {
        return Err(unsupported(
            "filesystem grants apply to every sandbox process; use `principal` or \
             `principal is Sandbox::Process`",
        ));
    }

    let paths = match policy.resource_constraint() {
        ResourceConstraint::In(uid) | ResourceConstraint::IsIn(_, uid)
            if !policy.has_non_scope_constraint() =>
        {
            vec![uid.id().unescaped().to_string()]
        }
        ResourceConstraint::Eq(_) => {
            return Err(unsupported(
                "`resource ==` names one exact path, but Landlock grants the whole \
                 subtree; use `resource in Sandbox::FilesystemPath::\"/path\"`",
            ));
        }
        ResourceConstraint::Any | ResourceConstraint::Is(_) => when_clause_paths(policy)
            .ok_or_else(|| {
                unsupported(
                    "name paths in the scope (`resource in Sandbox::FilesystemPath::\"/path\"`) \
                     or in a single `when` clause that only ORs `resource in` tests",
                )
            })?,
        ResourceConstraint::In(_) | ResourceConstraint::IsIn(..) => {
            return Err(unsupported(
                "`when`/`unless` conditions on a filesystem policy cannot be enforced by \
                 Landlock",
            ));
        }
    };

    let writes = scope.includes(actions::WRITE_FILE);
    if writes && !scope.includes(actions::READ_FILE) {
        return Err(unsupported(
            "Landlock read-write grants include read; list both ReadFile and WriteFile",
        ));
    }
    Ok(FilesystemGrant { paths, writes })
}

/// Returns the paths of a `when { resource in P1 || resource in P2 ... }` body.
///
/// Returns `None` unless the policy has exactly one condition, it is `when`,
/// and its body consists only of `||` over `resource in` tests against
/// `FilesystemPath` literals.
fn when_clause_paths(policy: &Policy) -> Option<Vec<String>> {
    let json = policy.to_json().ok()?;
    let conditions = json.get("conditions")?.as_array()?;
    let [condition] = conditions.as_slice() else {
        return None;
    };
    if condition.get("kind")?.as_str()? != "when" {
        return None;
    }
    let mut paths = Vec::new();
    collect_resource_in_paths(condition.get("body")?, &mut paths).then_some(paths)
}

/// Collects `resource in FilesystemPath::"..."` paths from an `||` tree.
///
/// Returns `false` if any node is not `||` or such a `resource in` test.
fn collect_resource_in_paths(expr: &Value, paths: &mut Vec<String>) -> bool {
    if let Some(or) = expr.get("||") {
        return match (or.get("left"), or.get("right")) {
            (Some(left), Some(right)) => {
                collect_resource_in_paths(left, paths) && collect_resource_in_paths(right, paths)
            }
            _ => false,
        };
    }
    let Some(test) = expr.get("in") else {
        return false;
    };
    let is_resource = test
        .get("left")
        .and_then(|left| left.get("Var"))
        .and_then(Value::as_str)
        == Some("resource");
    let entity = test
        .get("right")
        .and_then(|right| right.get("Value"))
        .and_then(|value| value.get("__entity"));
    let Some(entity) = entity else {
        return false;
    };
    let is_path = entity.get("type").and_then(Value::as_str) == Some(entity_types::FILESYSTEM_PATH);
    match entity.get("id").and_then(Value::as_str) {
        Some(id) if is_resource && is_path => {
            paths.push(id.to_string());
            true
        }
        _ => false,
    }
}

/// Returns the policy's `@id` annotation, or its Cedar-assigned id.
pub fn display_id(policy: &Policy) -> String {
    policy
        .annotation(ID_ANNOTATION)
        .map_or_else(|| policy.id().to_string(), ToString::to_string)
}

#[cfg(test)]
mod overlap_tests {
    use super::host_patterns_overlap;

    #[test]
    fn literal_and_glob_boundaries() {
        for (left, right, overlaps) in [
            ("api.example.com", "api.example.com", true),
            ("api.example.com", "other.example.com", false),
            ("*.example.com", "api.example.com", true),
            ("*.example.com", "deep.api.example.com", false),
            ("**.example.com", "deep.api.example.com", true),
            ("a*.example.com", "*b.example.com", true),
            ("*.example.com", "*.example.org", false),
        ] {
            assert_eq!(
                host_patterns_overlap(left, right),
                overlaps,
                "{left} vs {right}"
            );
            assert_eq!(
                host_patterns_overlap(right, left),
                overlaps,
                "{right} vs {left}"
            );
        }
        let huge = "a".repeat(100_000);
        assert!(host_patterns_overlap(&huge, &huge));
        assert!(!host_patterns_overlap(&huge, "other.example.com"));
        assert!(host_patterns_overlap(&format!("*.{huge}"), "*.example.com"));
    }
}
