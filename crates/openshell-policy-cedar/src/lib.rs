// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cedar policy evaluation for `OpenShell` sandboxes.
//!
//! [`CedarEngine`] is the authoritative policy engine for a sandbox
//! whose policy is authored in Cedar (`SandboxPolicy.cedar_policy_source`).
//! It evaluates `NetworkConnect` and per-request `HttpRequest` decisions at
//! request time, and derives Landlock grants, L7 inspection routing, and DNS
//! eligibility from the policy text once, at construction. Construction
//! rejects any policy whose meaning those derived artifacts could not
//! enforce exactly; see [`analysis`](crate::analysis) for the accepted
//! shapes.
//!
//! The schema itself lives in `openshell-policy-cedar-schema`, the single
//! source of truth for Cedar entity/action names across every Cedar-aware
//! consumer.

mod analysis;
mod error;
mod limits;
mod token_grants;

pub use analysis::{AnalysisWarning, L7Endpoint, L7Enforcement, L7Protocol, NetworkTransport};
pub use error::CedarEngineError;
pub use limits::{
    MAX_POLICY_EXPRESSION_DEPTH, MAX_POLICY_NESTING, MAX_POLICY_SOURCE_BYTES,
    MAX_REQUEST_FIELD_BYTES,
};
pub use token_grants::{
    Handling, ProviderEndpoint, ProviderPolicy, RuleLocation, RuleMatcher,
    TOKEN_GRANT_OWNER_ANNOTATION, TokenGrantRules, UntranslatedRule, ValueMatcher,
};

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use cedar_policy::{
    AuthorizationError, Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicyId, PolicySet, Request, RestrictedExpression, Schema,
};
use openshell_policy_cedar_schema::{actions, context_fields, endpoint_fields, entity_types};

use analysis::{HttpPermit, PolicyAnalysis, QueryKeys};
pub use ipnet::IpNet;
use limits::SourceShape;

/// Most evaluations one `HttpRequest` gets for the combinations of its
/// repeated query values.
///
/// A policy set of more than 4 policies gets fewer; see
/// [`MAX_QUERY_POLICY_EVALUATIONS`]. A request over the cap is not
/// evaluated; see [`CedarEngineError::TooManyQueryCombinations`].
pub const MAX_QUERY_COMBINATIONS: usize = 4096;

/// Most policy evaluations one `HttpRequest` gets for the combinations of
/// its repeated query values: the combinations times the policies of the
/// evaluated set.
///
/// Each combination evaluates every policy, so the combinations are capped
/// at this divided by the number of policies, or [`MAX_QUERY_COMBINATIONS`]
/// when that is smaller, and one combination is always evaluated: 81 for a
/// set of 201 policies.
pub const MAX_QUERY_POLICY_EVALUATIONS: usize = 16_384;

/// Synthetic id for the single `Process` entity built per request.
///
/// Each request is evaluated on its own and never cross-references other
/// processes, so a fixed id is sufficient.
const CURRENT_PROCESS: &str = "current";

/// Synthetic id for the single `HttpQuery` entity built per evaluation.
const CURRENT_QUERY: &str = "current";

/// `Process` attribute holding the process's `User` entity.
const PROCESS_USER_ATTR: &str = "user";

/// `Process` attribute holding the process's `Group` entity.
const PROCESS_GROUP_ATTR: &str = "group";

/// The input to one `Sandbox::Action::"NetworkConnect"` authorization.
///
/// Mirrors the fields `openshell_supervisor_network::policy_types::NetworkInput`
/// supplies to a policy engine. No request has been read at CONNECT time, so
/// the `NetworkConnect` context has no `method`, `path`, or `command`; a
/// policy that reads them on this action fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConnectRequest {
    /// Sandbox process user identity (`Sandbox::User` entity id).
    pub user: String,
    /// Sandbox process group identity (`Sandbox::Group` entity id).
    pub group: String,
    /// Destination host.
    pub host: String,
    /// Destination port.
    pub port: u16,
    /// Absolute path of the binary making the connection.
    pub binary_path: String,
    /// Absolute paths of the calling process's ancestors (parent,
    /// grandparent, ...). Excludes cmdline/argv0, which is spoofable.
    pub ancestors: Vec<String>,
    /// The paths of [`CedarEngine::binary_alias_paths`] that resolve, as
    /// symlinks in the sandbox, to `binary_path` or one of `ancestors`.
    pub binary_aliases: Vec<String>,
    /// The patterns of [`CedarEngine::binary_glob_patterns`] that match
    /// `binary_path` or one of `ancestors` with the YAML binary glob matcher.
    pub binary_globs: Vec<String>,
    /// One resolved address of the destination, or `None` before the host
    /// is resolved; see [`CedarEngine::authorize_network`].
    pub destination_ip: Option<IpAddr>,
}

/// Outcome of [`CedarEngine::authorize_network`], with what the allowing
/// permits require of the destination address.
///
/// The address fields describe the determining permits of an allow and are
/// empty or `false` for a deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEvaluation {
    /// The decision.
    pub decision: Decision,
    /// The `destination_ip` ranges of each determining permit that has a
    /// `destination_ip` condition, one list per permit.
    pub address_conditions: Vec<Vec<IpNet>>,
    /// A determining permit has no `destination_ip` condition.
    pub unconstrained_permit: bool,
    /// A determining permit names the request's host and port exactly: in
    /// its scope, or as `resource.host == "..."` and `resource.port == ...`
    /// conditions. A host glob never counts.
    pub names_endpoint: bool,
}

/// Outcome of evaluating a request against a Cedar policy set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// A `permit` policy matched and no `forbid` overrode it.
    Allow {
        /// Policies that contributed to the decision, by `@id` annotation or
        /// Cedar-assigned id.
        matched_policies: Vec<String>,
    },
    /// No `permit` matched, or a `forbid` matched.
    Deny {
        /// Policies that contributed to the decision, by `@id` annotation or
        /// Cedar-assigned id.
        matched_policies: Vec<String>,
    },
}

impl Decision {
    /// Returns `true` for [`Decision::Allow`].
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}

/// Outcome of evaluating one `HttpRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L7Evaluation {
    /// The decision of the endpoint's deciding policies: every policy but
    /// the staged ones.
    ///
    /// On an [`L7Enforcement::Audit`] path the proxy logs a deny instead of
    /// blocking it.
    pub decision: Decision,
    /// The decision with the endpoint's staged policies included, present
    /// only when it differs from [`Self::decision`].
    pub staged: Option<Decision>,
}

impl L7Evaluation {
    /// Returns `true` if [`Self::decision`] allows the request.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        self.decision.is_allow()
    }
}

/// The input to one `Sandbox::Action::"HttpRequest"` authorization.
///
/// Evaluated per request within a connection that `NetworkConnect` already
/// permitted.
/// Mirrors the fields `openshell_supervisor_network::l7::relay::L7EvalContext`
/// / `L7RequestInfo` supply, narrowed to what the `Sandbox::HttpRequest`
/// Cedar action declares in its schema. Fields that do not apply to a
/// request's protocol keep their default (`""`, `false`, or empty).
#[derive(Debug, Clone, Default)]
pub struct HttpRequestInput {
    /// Sandbox process user identity (`Sandbox::User` entity id), same as
    /// the connection's `NetworkConnect` request. Identity doesn't change
    /// within a connection, but policies may still guard every action
    /// (including `HttpRequest`) on it, e.g. a top-level identity `forbid`.
    pub user: String,
    /// Sandbox process group identity (`Sandbox::Group` entity id).
    pub group: String,
    /// Absolute path of the binary that owns this connection.
    pub binary_path: String,
    /// Absolute paths of the connection-owning process's ancestors.
    pub ancestors: Vec<String>,
    /// The paths of [`CedarEngine::binary_alias_paths`] that resolve, as
    /// symlinks in the sandbox, to `binary_path` or one of `ancestors`.
    pub binary_aliases: Vec<String>,
    /// The patterns of [`CedarEngine::binary_glob_patterns`] that match
    /// `binary_path` or one of `ancestors` with the YAML binary glob matcher.
    pub binary_globs: Vec<String>,
    /// Destination host (same endpoint the `NetworkConnect` matched).
    pub host: String,
    /// Destination port.
    pub port: u16,
    /// HTTP method, when known; empty string when not applicable.
    pub method: String,
    /// REST request path, when known; empty string when not applicable.
    pub path: String,
    /// SQL command verb, when known; empty string when not applicable.
    pub command: String,
    /// JSON-RPC method name, when known; empty string when not applicable.
    pub jsonrpc_method: String,
    /// An MCP GET that opens the server-to-client stream.
    pub jsonrpc_receive_stream: bool,
    /// The body carries client-to-server JSON-RPC response frames.
    pub jsonrpc_response: bool,
    /// MCP `tools/call` tool name; empty string when not applicable.
    pub mcp_tool: String,
    /// MCP method classification (`"available"` or `"extension"`); empty
    /// string for non-MCP requests.
    pub mcp_method_class: String,
    /// GraphQL operation type; empty string for a hash-only persisted query
    /// or a non-GraphQL request.
    pub graphql_operation_type: String,
    /// GraphQL operation name; empty string when anonymous.
    pub graphql_operation_name: String,
    /// The GraphQL operation's top-level fields.
    pub graphql_fields: Vec<String>,
    /// The proxy parsed this request as GraphQL: an operation of a `graphql`
    /// path, or a GraphQL-over-WebSocket client message. On such a request
    /// the routed path is authoritative; see [`CedarEngine::evaluate_l7`].
    pub graphql_request: bool,
    /// The `@path` of the inspected endpoint path the proxy routed this
    /// request to, which selects its protocol and enforcement; empty for the
    /// endpoint declared by policies without `@path`.
    pub endpoint_path: String,
    /// The decoded query parameters: every value of each key, in request
    /// order. Policies read one value per key as a tag of
    /// `context.query`; see [`CedarEngine::evaluate_l7`] for repeated keys.
    pub query: BTreeMap<String, Vec<String>>,
}

/// Landlock path grants derived from a Cedar policy set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilesystemGrants {
    /// Path subtrees granted read-only access.
    pub read_only: Vec<String>,
    /// Path subtrees granted read-write access.
    pub read_write: Vec<String>,
}

/// One host a Cedar policy set permits `NetworkConnect` to, with its ports
/// and transport.
///
/// Used for DNS eligibility, not CONNECT-time matching. Includes endpoints
/// named in a `permit` scope, and hosts and host globs a `permit`'s `when`
/// conditions require together with a port (see the `analysis` module). A
/// host matched any other way, such as `resource.host like "*.example.com"`
/// without a delimiter, is not included, so DNS resolution for it fails
/// closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedNetworkEndpoint {
    /// Destination host, lowercased, or a host glob in policy DNS syntax: `*`
    /// within one DNS label, and `**` as a whole first label spanning one or
    /// more labels.
    pub host: String,
    /// Ports this host is permitted on.
    pub ports: Vec<u16>,
    /// How connections to these ports are carried. A host with native TCP
    /// ports and other ports has one entry for each.
    pub transport: NetworkTransport,
    /// The `destination_ip` ranges of the permits behind this entry, like a
    /// YAML endpoint's `allowed_ips`; empty when they have no such
    /// condition. Permits with different ranges get separate entries.
    pub allowed_ips: Vec<IpNet>,
}

/// Entity type names and ids every request needs, built once per engine.
#[derive(Debug, Clone)]
pub(crate) struct RequestUids {
    user_type: EntityTypeName,
    group_type: EntityTypeName,
    endpoint_type: EntityTypeName,
    process: EntityUid,
    query: EntityUid,
    network_connect: EntityUid,
    pub(crate) http_request: EntityUid,
}

impl RequestUids {
    fn new() -> Result<Self, CedarEngineError> {
        Ok(Self {
            user_type: entity_type(entity_types::USER)?,
            group_type: entity_type(entity_types::GROUP)?,
            endpoint_type: entity_type(entity_types::NETWORK_ENDPOINT)?,
            process: entity_uid(entity_types::PROCESS, CURRENT_PROCESS)?,
            query: entity_uid(entity_types::HTTP_QUERY, CURRENT_QUERY)?,
            network_connect: entity_uid(actions::ACTION_TYPE, actions::NETWORK_CONNECT)?,
            http_request: entity_uid(actions::ACTION_TYPE, actions::HTTP_REQUEST)?,
        })
    }
}

/// Cedar-backed sandbox policy evaluator.
///
/// Loads a Cedar schema and policy set once, validates and analyzes them,
/// then evaluates [`NetworkConnectRequest`]s and [`HttpRequestInput`]s against them.
pub struct CedarEngine {
    evaluator: Evaluator,
    /// Every authored policy, including staged ones.
    policies: PolicySet,
    /// The policies that decide requests: every policy except staged ones.
    deciding_policies: PolicySet,
    /// The policies that decide a connection before its host is resolved:
    /// the deciding policies, with permits stripped of their
    /// `destination_ip` conditions. Forbids are kept as written; with the
    /// address absent, their `context has destination_ip` guards are false.
    unresolved_policies: PolicySet,
    /// For each `graphql` or `websocket-graphql` path with permits attached
    /// to other paths of its endpoint that are not GraphQL-aware, the
    /// permits its GraphQL requests are decided without, keyed by `(host,
    /// port, path)`.
    graphql_exclusions: HashMap<(String, u16, String), GraphqlExclusion>,
    analysis: PolicyAnalysis,
    /// The shape of the policy text, which sizes the stack evaluation needs.
    shape: SourceShape,
}

// Summarizes the engine: a derived `Debug` would recurse once per expression
// level of every policy, outside the stack `limits::with_stack` grows for it.
impl std::fmt::Debug for CedarEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CedarEngine")
            .field("policies", &self.policies.policies().count())
            .field(
                "deciding_policies",
                &self.deciding_policies.policies().count(),
            )
            .field("l7_endpoints", &self.analysis.l7_endpoints.len())
            .field("shape", &self.shape)
            .finish_non_exhaustive()
    }
}

/// The permits a request parsed as GraphQL on one path is decided without:
/// the permits of the path's endpoint, or of another entry that can select
/// a host with it, attached to another path and not aware of GraphQL.
///
/// Requests are evaluated against the whole policy set and these permits
/// are then disregarded, which decides as the set without them would:
/// forbids are never excluded, and an excluded permit neither allows a
/// request nor fails it with an evaluation error.
#[derive(Debug)]
struct GraphqlExclusion {
    /// The hosts of `HttpRequest` permits on [`Self::port`] that overlap the
    /// path's endpoint host, shared by the paths of one endpoint.
    hosts: Arc<HashSet<String>>,
    port: u16,
    path: String,
}

impl GraphqlExclusion {
    /// Returns whether the policy `id` is one of the excluded permits.
    fn excludes(&self, permits: &HashMap<PolicyId, HttpPermit>, id: &PolicyId) -> bool {
        permits.get(id).is_some_and(|permit| {
            permit.endpoint.1 == self.port
                && self.hosts.contains(&permit.endpoint.0)
                && permit.path != self.path
                && !permit.graphql_aware
        })
    }
}

impl CedarEngine {
    /// Parses and validates a policy set against the canonical sandbox schema.
    ///
    /// The schema is [`openshell_policy_cedar_schema::SANDBOX_SCHEMA_SRC`].
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if the policy set is over
    /// [`MAX_POLICY_SOURCE_BYTES`], [`MAX_POLICY_NESTING`], or
    /// [`MAX_POLICY_EXPRESSION_DEPTH`], fails to parse, fails strict schema
    /// validation, or uses a shape this crate cannot enforce exactly.
    pub fn from_policy_str(policy_src: &str) -> Result<Self, CedarEngineError> {
        // Bounded before parsing, so every recursion below fits the stack
        // sized from the bound, which is grown when the caller's is smaller.
        let shape = limits::check_policy_source(policy_src)?;
        limits::with_stack(shape.load_stack(), || Self::load(policy_src, shape))
    }

    fn load(policy_src: &str, shape: SourceShape) -> Result<Self, CedarEngineError> {
        let evaluator = Evaluator::new()?;
        let policies = PolicySet::from_str(policy_src)
            .map_err(|e| CedarEngineError::PolicyParse(Box::new(e)))?;
        let analysis = analysis::analyze(&evaluator.schema, &policies)?;
        let deciding_policies = PolicySet::from_policies(
            policies
                .policies()
                .filter(|policy| !analysis::is_staged(policy))
                .cloned(),
        )
        .map_err(|e| CedarEngineError::PolicySet(Box::new(e)))?;
        let unresolved_policies =
            PolicySet::from_policies(deciding_policies.policies().map(|policy| {
                analysis
                    .unresolved
                    .get(policy.id())
                    .map_or_else(|| policy.clone(), Clone::clone)
            }))
            .map_err(|e| CedarEngineError::PolicySet(Box::new(e)))?;
        let graphql_exclusions = graphql_exclusions(&analysis);
        Ok(Self {
            evaluator,
            policies,
            deciding_policies,
            unresolved_policies,
            graphql_exclusions,
            analysis,
            shape,
        })
    }

    /// Returns the Landlock path grants this policy set authorizes.
    #[must_use]
    pub fn filesystem_grants(&self) -> &FilesystemGrants {
        &self.analysis.filesystem
    }

    /// Returns the shapes in this policy set that load but are likely not
    /// what the author meant; see [`AnalysisWarning`].
    ///
    /// Warnings never change enforcement. Callers that validate or load a
    /// policy should show them to its author.
    #[must_use]
    pub fn warnings(&self) -> &[AnalysisWarning] {
        &self.analysis.warnings
    }

    /// Whether any policy can permit `NetworkConnect`, the Cedar counterpart
    /// of a YAML policy with network rules.
    #[must_use]
    pub fn has_network_permits(&self) -> bool {
        !self.analysis.network_permits.is_empty()
    }

    /// Returns the `NetworkConnect` hosts and host globs eligible for policy DNS.
    #[must_use]
    pub fn dns_endpoints(&self) -> &[AuthorizedNetworkEndpoint] {
        &self.analysis.dns_endpoints
    }

    /// Returns the exact binary paths policies test with
    /// `context.binary_aliases`, sorted.
    ///
    /// The caller resolves each one inside the sandbox, as YAML resolves a
    /// symlinked binary path, and lists in a request's `binary_aliases` the
    /// paths that resolve to its binary or one of its ancestors.
    pub fn binary_alias_paths(&self) -> impl Iterator<Item = &str> {
        self.analysis.binary_alias_paths.iter().map(String::as_str)
    }

    /// Returns the binary glob patterns policies test with
    /// `context.binary_globs`, sorted.
    ///
    /// The caller matches each one against a request's binary and ancestors
    /// with the YAML binary glob matcher (`*` within one path segment, `**`
    /// as a whole segment across segments), and lists the matching patterns
    /// in the request's `binary_globs`.
    pub fn binary_glob_patterns(&self) -> impl Iterator<Item = &str> {
        self.analysis
            .binary_glob_patterns
            .iter()
            .map(String::as_str)
    }

    /// Returns the L7 protocol policies without `@path` declare for
    /// `host:port`, if any.
    ///
    /// `None` means no `HttpRequest` policy without `@path` names this
    /// endpoint. See [`Self::l7_endpoints`] for every inspected path.
    #[must_use]
    pub fn l7_protocol(&self, host: &str, port: u16) -> Option<L7Protocol> {
        self.l7_endpoint(host, port)
            .map(|endpoint| endpoint.protocol)
    }

    /// Returns how the proxy inspects `host:port` for policies without
    /// `@path`, if any names it.
    #[must_use]
    pub fn l7_endpoint(&self, host: &str, port: u16) -> Option<L7Endpoint> {
        self.l7_endpoint_at(host, port, "")
    }

    /// Returns how the proxy inspects requests to `host:port` routed to
    /// `path`, an `@path` pattern, or `""` for policies without `@path`.
    ///
    /// The host is selected by the endpoint named exactly, or else by the
    /// host globs it matches; see [`Self::l7_endpoints`].
    #[must_use]
    pub fn l7_endpoint_at(&self, host: &str, port: u16, path: &str) -> Option<L7Endpoint> {
        self.analysis
            .l7_selecting(&normalize_host(host), port)
            .find_map(|(_, paths)| paths.get(path))
            .copied()
    }

    /// Returns every inspected path of `host:port` with its inspection,
    /// ordered by path.
    ///
    /// Empty means no `HttpRequest` policy names this endpoint, so an
    /// allowed connection to it is relayed without per-request checks. The
    /// empty path is the endpoint declared by policies without `@path`.
    ///
    /// A host is inspected by the endpoint that names it exactly and by
    /// every endpoint whose host glob matches it, with the matcher YAML
    /// endpoints and policy DNS use; their paths are inspected together,
    /// and the exact endpoint's declaration of a path takes precedence.
    /// Load-time analysis rejects entries that would inspect a request
    /// differently, so the merge is well defined.
    pub fn l7_endpoints(
        &self,
        host: &str,
        port: u16,
    ) -> impl Iterator<Item = (String, L7Endpoint)> {
        let mut merged: BTreeMap<String, L7Endpoint> = BTreeMap::new();
        // `l7_selecting` yields the exact entry first; inserting it last
        // lets it win where another entry declares the same path.
        let selecting: Vec<_> = self
            .analysis
            .l7_selecting(&normalize_host(host), port)
            .collect();
        for (_, paths) in selecting.into_iter().rev() {
            merged.extend(
                paths
                    .iter()
                    .map(|(path, endpoint)| (path.clone(), *endpoint)),
            );
        }
        merged.into_iter()
    }

    /// Returns configured endpoint selectors and paths without expanding host globs.
    pub fn configured_l7_endpoints(
        &self,
    ) -> impl Iterator<Item = (String, u16, String, L7Endpoint)> {
        self.analysis
            .l7_endpoints
            .iter()
            .flat_map(|((host, port), paths)| {
                paths
                    .iter()
                    .map(move |(path, endpoint)| (host.clone(), *port, path.clone(), *endpoint))
            })
    }

    /// Evaluates one network-connect request against the loaded policy set.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] as [`Self::authorize_network`] does.
    pub fn evaluate_network(
        &self,
        request: &NetworkConnectRequest,
    ) -> Result<Decision, CedarEngineError> {
        Ok(self.authorize_network(request)?.decision)
    }

    /// Evaluates one network-connect request, reporting what the allowing
    /// permits require of the destination address.
    ///
    /// Without `destination_ip` the request is decided as before its host is
    /// resolved: permits are evaluated without their `destination_ip`
    /// conditions, so an allow means some resolved address may be allowed,
    /// and forbids are evaluated as written with the address absent, so a
    /// forbid's other conditions still deny and its guarded address
    /// conditions are false. With `destination_ip` every enforced policy
    /// decides the request for that address. A host with an empty DNS
    /// label, such as `a..example.com`, is denied without evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError::RequestFieldTooLong`] if a request string
    /// is over [`MAX_REQUEST_FIELD_BYTES`], and another [`CedarEngineError`]
    /// if the request cannot be represented in the loaded schema, or if Cedar
    /// reports an error while evaluating any policy.
    pub fn authorize_network(
        &self,
        request: &NetworkConnectRequest,
    ) -> Result<NetworkEvaluation, CedarEngineError> {
        let longest = limits::check_network_request(request)?;
        if has_empty_label(&request.host) {
            return Ok(NetworkEvaluation {
                decision: Decision::Deny {
                    matched_policies: Vec::new(),
                },
                address_conditions: Vec::new(),
                unconstrained_permit: false,
                names_endpoint: false,
            });
        }
        limits::with_stack(self.shape.eval_stack(longest), || {
            self.authorize_network_unchecked(request)
        })
    }

    fn authorize_network_unchecked(
        &self,
        request: &NetworkConnectRequest,
    ) -> Result<NetworkEvaluation, CedarEngineError> {
        let protocol = self
            .l7_endpoint(&request.host, request.port)
            .map_or("", |endpoint| endpoint.protocol.as_str());
        let mut context = vec![
            (context_fields::BINARY_PATH, string(&request.binary_path)),
            (context_fields::ANCESTORS, string_set(&request.ancestors)),
            (
                context_fields::BINARY_ALIASES,
                string_set(&request.binary_aliases),
            ),
            (
                context_fields::BINARY_GLOBS,
                string_set(&request.binary_globs),
            ),
        ];
        if let Some(ip) = request.destination_ip {
            context.push((
                context_fields::DESTINATION_IP,
                RestrictedExpression::new_ip(ip.to_string()),
            ));
        }
        let policies = if request.destination_ip.is_some() {
            &self.deciding_policies
        } else {
            &self.unresolved_policies
        };
        let outcome = self.evaluator.authorize(
            policies,
            &self.evaluator.uids.network_connect,
            &Subject {
                principal: Principal {
                    user: &request.user,
                    group: &request.group,
                },
                host: &request.host,
                port: request.port,
                protocol,
            },
            context,
            None,
            &|_| false,
        )?;
        let mut evaluation = NetworkEvaluation {
            decision: Decision::Deny {
                matched_policies: Vec::new(),
            },
            address_conditions: Vec::new(),
            unconstrained_permit: false,
            names_endpoint: false,
        };
        if outcome.allowed {
            let host = normalize_host(&request.host);
            for id in &outcome.reasons {
                let permit = self.analysis.network_permits.get(id);
                match permit.map(|permit| &permit.allowed_ips) {
                    Some(ranges) if !ranges.is_empty() => {
                        evaluation.address_conditions.push(ranges.clone());
                    }
                    _ => evaluation.unconstrained_permit = true,
                }
                if permit
                    .and_then(|permit| permit.endpoint.as_ref())
                    .is_some_and(|(named, port)| *named == host && *port == request.port)
                {
                    evaluation.names_endpoint = true;
                }
            }
        }
        evaluation.decision = outcome.into_decision(policies);
        Ok(evaluation)
    }

    /// Evaluates one per-request `HttpRequest` within a permitted connection.
    ///
    /// `context.query` holds one value per query key. When keys repeat, the
    /// request is evaluated once per combination of their values, and it is
    /// allowed only if no evaluation is denied and one `permit` allows every
    /// evaluation. This matches YAML query matchers: an allow rule must match
    /// every value of each key it names, and a deny rule fires when each of
    /// its keys has one matching value. Keys no policy reads are left out,
    /// so their values do not multiply evaluations. The same combined
    /// decision is computed for the deciding policies (every policy but the
    /// staged ones) and, when the endpoint has staged policies, with them.
    ///
    /// A request the proxy parsed as GraphQL (`graphql_request`) on a
    /// `graphql` or `websocket-graphql` path is decided without the permits
    /// attached to other paths of the endpoint that neither read a
    /// `graphql_*` field nor test `resource.protocol`, as a YAML GraphQL
    /// endpoint is authoritative for the requests it parses. Forbids always
    /// apply. A host with an empty DNS label is denied without evaluation,
    /// as in [`Self::authorize_network`].
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError::RequestFieldTooLong`] if a request string
    /// is over [`MAX_REQUEST_FIELD_BYTES`],
    /// [`CedarEngineError::TooManyQueryCombinations`] if the query has more
    /// value combinations than [`MAX_QUERY_COMBINATIONS`] or, for a larger
    /// policy set, [`MAX_QUERY_POLICY_EVALUATIONS`] allow, and another
    /// [`CedarEngineError`] if the request cannot be represented in the
    /// loaded schema, or if Cedar reports an error while evaluating any
    /// deciding policy. Errors in the staged comparison are logged without
    /// changing the enforced decision.
    pub fn evaluate_l7(
        &self,
        request: &HttpRequestInput,
    ) -> Result<L7Evaluation, CedarEngineError> {
        let longest = limits::check_http_request(request)?;
        if has_empty_label(&request.host) {
            return Ok(L7Evaluation {
                decision: Decision::Deny {
                    matched_policies: Vec::new(),
                },
                staged: None,
            });
        }
        limits::with_stack(self.shape.eval_stack(longest), || {
            self.evaluate_l7_unchecked(request)
        })
    }

    fn evaluate_l7_unchecked(
        &self,
        request: &HttpRequestInput,
    ) -> Result<L7Evaluation, CedarEngineError> {
        let endpoint = self.l7_endpoint_at(&request.host, request.port, &request.endpoint_path);
        let protocol = endpoint.map_or("", |endpoint| endpoint.protocol.as_str());
        let query = QueryCombinations::new(
            &request.query,
            &self.analysis.query_keys,
            self.deciding_policies.num_of_policies(),
        )?;
        // Any entry selecting the host that declares the routed path works:
        // its exclusion set covers every entry that can select the host.
        let graphql = request
            .graphql_request
            .then(|| {
                self.analysis
                    .l7_selecting(&normalize_host(&request.host), request.port)
                    .find_map(|(key, _)| {
                        self.graphql_exclusions.get(&(
                            key.to_string(),
                            request.port,
                            request.endpoint_path.clone(),
                        ))
                    })
            })
            .flatten();
        let excluded = |id: &PolicyId| {
            graphql.is_some_and(|exclusion| exclusion.excludes(&self.analysis.http_permits, id))
        };
        let decision = self.decide_l7(
            &self.deciding_policies,
            request,
            protocol,
            &query,
            &excluded,
        )?;
        // Compare decisions, not the staged set's decision alone: Cedar denies
        // by default, so a set of only staged `forbid`s denies every request
        // whether or not one of them matched.
        let staged = if endpoint.is_some_and(|endpoint| endpoint.staged) {
            QueryCombinations::new(
                &request.query,
                &self.analysis.staged_query_keys,
                self.policies.num_of_policies(),
            )
            .and_then(|query| self.decide_l7(&self.policies, request, protocol, &query, &excluded))
            .map_or_else(
                |_| {
                    // Never include authored expressions or request query values.
                    tracing::debug!("staged Cedar evaluation failed; retaining enforced decision");
                    None
                },
                |staged| (staged.is_allow() != decision.is_allow()).then_some(staged),
            )
        } else {
            None
        };
        Ok(L7Evaluation { decision, staged })
    }

    /// Decides one `HttpRequest` with `policies`, without the `excluded`
    /// permits, over every combination of its query values; see
    /// [`Self::evaluate_l7`].
    ///
    /// A denied combination denies the request with its determining
    /// policies. When every combination is allowed but no single `permit`
    /// allows them all, the request is denied with no determining policy.
    fn decide_l7(
        &self,
        policies: &PolicySet,
        request: &HttpRequestInput,
        protocol: &str,
        query: &QueryCombinations<'_>,
        excluded: &dyn Fn(&PolicyId) -> bool,
    ) -> Result<Decision, CedarEngineError> {
        let context = self.evaluator.l7_context(request);
        // The permits that allowed every combination so far.
        let mut common_permits: Option<Vec<PolicyId>> = None;
        for index in 0..query.count {
            let tags = query.combination(index);
            let query_entity = self.evaluator.query_entity(tags)?;
            let outcome = self.evaluator.authorize(
                policies,
                &self.evaluator.uids.http_request,
                &Subject {
                    principal: Principal {
                        user: &request.user,
                        group: &request.group,
                    },
                    host: &request.host,
                    port: request.port,
                    protocol,
                },
                context.clone(),
                Some(query_entity),
                excluded,
            )?;
            if !outcome.allowed {
                return Ok(outcome.into_decision(policies));
            }
            let permits = common_permits.get_or_insert_with(|| outcome.reasons.clone());
            permits.retain(|id| outcome.reasons.contains(id));
            if permits.is_empty() {
                break;
            }
        }
        // No combination at all (a key without values) also denies.
        Ok(match common_permits {
            Some(permits) if !permits.is_empty() => Outcome {
                allowed: true,
                reasons: permits,
            }
            .into_decision(policies),
            _ => Decision::Deny {
                matched_policies: Vec::new(),
            },
        })
    }
}

/// Builds [`CedarEngine::graphql_exclusions`].
///
/// A GraphQL path excludes the permits of other paths of its endpoint, or of
/// another entry that can select a host with it, that do not mean to apply
/// to GraphQL requests. A permit of an entry that does not select the
/// request's host cannot fire for it, so leaving it out over-approximates
/// safely. Paths with no permit to exclude get no entry.
fn graphql_exclusions(
    analysis: &PolicyAnalysis,
) -> HashMap<(String, u16, String), GraphqlExclusion> {
    // The hosts of the `HttpRequest` permits, by port.
    let mut permit_hosts: BTreeMap<u16, BTreeSet<&str>> = BTreeMap::new();
    for permit in analysis.http_permits.values() {
        permit_hosts
            .entry(permit.endpoint.1)
            .or_default()
            .insert(&permit.endpoint.0);
    }
    let mut exclusions = HashMap::new();
    for ((host, port), paths) in &analysis.l7_endpoints {
        let mut endpoint: Option<(Arc<HashSet<String>>, BTreeSet<&str>)> = None;
        for (path, inspection) in paths {
            if !matches!(
                inspection.protocol,
                L7Protocol::Graphql | L7Protocol::WebsocketGraphql
            ) {
                continue;
            }
            // Computed once per endpoint: the overlapping permit hosts, and
            // the paths of the permits that may be excluded.
            let (hosts, permit_paths) = endpoint.get_or_insert_with(|| {
                let hosts: Arc<HashSet<String>> = Arc::new(
                    permit_hosts
                        .get(port)
                        .into_iter()
                        .flatten()
                        .filter(|permit_host| analysis::host_patterns_overlap(permit_host, host))
                        .map(|permit_host| (*permit_host).to_string())
                        .collect(),
                );
                let permit_paths = analysis
                    .http_permits
                    .values()
                    .filter(|permit| {
                        permit.endpoint.1 == *port
                            && hosts.contains(&permit.endpoint.0)
                            && !permit.graphql_aware
                    })
                    .map(|permit| permit.path.as_str())
                    .collect();
                (hosts, permit_paths)
            });
            if permit_paths.iter().all(|permit_path| permit_path == path) {
                continue;
            }
            exclusions.insert(
                (host.clone(), *port, path.clone()),
                GraphqlExclusion {
                    hosts: Arc::clone(hosts),
                    port: *port,
                    path: path.clone(),
                },
            );
        }
    }
    exclusions
}

/// The schema, authorizer, and entity ids every evaluation needs.
#[derive(Debug)]
pub(crate) struct Evaluator {
    pub(crate) schema: Schema,
    authorizer: Authorizer,
    pub(crate) uids: RequestUids,
}

impl Evaluator {
    /// Loads the canonical schema.
    pub(crate) fn new() -> Result<Self, CedarEngineError> {
        Ok(Self {
            schema: openshell_policy_cedar_schema::load_schema()?,
            authorizer: Authorizer::new(),
            uids: RequestUids::new()?,
        })
    }

    /// Builds the `HttpRequest` context of `request`, whose `query` is the
    /// per-evaluation `HttpQuery` entity.
    pub(crate) fn l7_context(
        &self,
        request: &HttpRequestInput,
    ) -> Vec<(&'static str, RestrictedExpression)> {
        vec![
            (context_fields::BINARY_PATH, string(&request.binary_path)),
            (context_fields::ANCESTORS, string_set(&request.ancestors)),
            (
                context_fields::BINARY_ALIASES,
                string_set(&request.binary_aliases),
            ),
            (
                context_fields::BINARY_GLOBS,
                string_set(&request.binary_globs),
            ),
            (context_fields::METHOD, string(&request.method)),
            (context_fields::PATH, string(&request.path)),
            (context_fields::COMMAND, string(&request.command)),
            (
                context_fields::JSONRPC_METHOD,
                string(&request.jsonrpc_method),
            ),
            (
                context_fields::JSONRPC_RECEIVE_STREAM,
                RestrictedExpression::new_bool(request.jsonrpc_receive_stream),
            ),
            (
                context_fields::JSONRPC_RESPONSE,
                RestrictedExpression::new_bool(request.jsonrpc_response),
            ),
            (context_fields::MCP_TOOL, string(&request.mcp_tool)),
            (
                context_fields::MCP_METHOD_CLASS,
                string(&request.mcp_method_class),
            ),
            (
                context_fields::GRAPHQL_OPERATION_TYPE,
                string(&request.graphql_operation_type),
            ),
            (
                context_fields::GRAPHQL_OPERATION_NAME,
                string(&request.graphql_operation_name),
            ),
            (
                context_fields::GRAPHQL_FIELDS,
                string_set(&request.graphql_fields),
            ),
            (
                context_fields::QUERY,
                RestrictedExpression::new_entity_uid(self.uids.query.clone()),
            ),
        ]
    }

    /// Builds the `HttpQuery` entity holding one value per query key.
    pub(crate) fn query_entity<'a>(
        &self,
        tags: impl Iterator<Item = (&'a str, &'a str)>,
    ) -> Result<Entity, CedarEngineError> {
        Entity::new_with_tags(
            self.uids.query.clone(),
            [],
            [],
            tags.map(|(key, value)| (key.to_string(), string(value))),
        )
        .map_err(|e| CedarEngineError::EntityBuild(Box::new(e)))
    }

    /// Runs one authorization query for `subject`.
    ///
    /// The `excluded` permits are disregarded: they neither allow the
    /// request nor fail it with an evaluation error, so the outcome is that
    /// of `policies` without them. Only permits may be excluded.
    pub(crate) fn authorize(
        &self,
        policies: &PolicySet,
        action: &EntityUid,
        subject: &Subject<'_>,
        context: Vec<(&str, RestrictedExpression)>,
        query: Option<Entity>,
        excluded: &dyn Fn(&PolicyId) -> bool,
    ) -> Result<Outcome, CedarEngineError> {
        let Subject {
            principal,
            host,
            port,
            protocol,
        } = subject;
        let host = normalize_host(host);
        let host_port = format!("{host}:{port}");

        let user_uid = EntityUid::from_type_name_and_id(
            self.uids.user_type.clone(),
            entity_id(principal.user),
        );
        let group_uid = EntityUid::from_type_name_and_id(
            self.uids.group_type.clone(),
            entity_id(principal.group),
        );
        let endpoint_uid = EntityUid::from_type_name_and_id(
            self.uids.endpoint_type.clone(),
            entity_id(&host_port),
        );

        let process = Entity::new(
            self.uids.process.clone(),
            HashMap::from([
                (
                    PROCESS_USER_ATTR.to_string(),
                    RestrictedExpression::new_entity_uid(user_uid.clone()),
                ),
                (
                    PROCESS_GROUP_ATTR.to_string(),
                    RestrictedExpression::new_entity_uid(group_uid.clone()),
                ),
            ]),
            HashSet::new(),
        )
        .map_err(|e| CedarEngineError::EntityBuild(Box::new(e)))?;
        let user = Entity::new_no_attrs(user_uid, HashSet::new());
        let group = Entity::new_no_attrs(group_uid, HashSet::new());
        let endpoint = Entity::new(
            endpoint_uid.clone(),
            HashMap::from([
                (
                    endpoint_fields::HOST.to_string(),
                    RestrictedExpression::new_string(host),
                ),
                (
                    endpoint_fields::PORT.to_string(),
                    RestrictedExpression::new_long(i64::from(*port)),
                ),
                (
                    endpoint_fields::PROTOCOL.to_string(),
                    RestrictedExpression::new_string(protocol.to_string()),
                ),
                (
                    endpoint_fields::HOST_PORT.to_string(),
                    RestrictedExpression::new_string(host_port),
                ),
            ]),
            HashSet::new(),
        )
        .map_err(|e| CedarEngineError::EntityBuild(Box::new(e)))?;

        let entities = Entities::from_entities(
            [process, user, group, endpoint].into_iter().chain(query),
            Some(&self.schema),
        )
        .map_err(|e| CedarEngineError::EntitiesBuild(Box::new(e)))?;
        let context = Context::from_pairs(
            context
                .into_iter()
                .map(|(field, value)| (field.to_string(), value)),
        )
        .map_err(|e| CedarEngineError::ContextBuild(Box::new(e)))?;
        let request = Request::new(
            self.uids.process.clone(),
            action.clone(),
            endpoint_uid,
            context,
            Some(&self.schema),
        )
        .map_err(|e| CedarEngineError::RequestBuild(Box::new(e)))?;

        let response = self.authorizer.is_authorized(&request, policies, &entities);
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .filter(|error| match error {
                AuthorizationError::PolicyEvaluationError(error) => !excluded(error.policy_id()),
            })
            .map(ToString::to_string)
            .collect();
        if !errors.is_empty() {
            return Err(CedarEngineError::Evaluation {
                reason: errors.join("; "),
            });
        }
        // An allow's reasons are its satisfied permits; with every one of
        // them excluded, no permit allows the request. A deny's reasons are
        // forbids, which are never excluded.
        let reasons: Vec<PolicyId> = response
            .diagnostics()
            .reason()
            .filter(|id| !excluded(id))
            .cloned()
            .collect();
        Ok(Outcome {
            allowed: response.decision() == cedar_policy::Decision::Allow && !reasons.is_empty(),
            reasons,
        })
    }
}

/// The result of one authorization query.
pub(crate) struct Outcome {
    pub(crate) allowed: bool,
    /// The determining policies: the satisfied `permit`s of an allow, or
    /// the satisfied `forbid`s of a deny (none when no `permit` matched).
    pub(crate) reasons: Vec<PolicyId>,
}

impl Outcome {
    /// Converts to a [`Decision`], naming policies by their display ids.
    fn into_decision(self, policies: &PolicySet) -> Decision {
        let matched_policies = self
            .reasons
            .iter()
            .map(|id| {
                policies
                    .policy(id)
                    .map_or_else(|| id.to_string(), analysis::display_id)
            })
            .collect();
        if self.allowed {
            Decision::Allow { matched_policies }
        } else {
            Decision::Deny { matched_policies }
        }
    }
}

/// The value combinations of a request's query keys that policies read.
pub(crate) struct QueryCombinations<'a> {
    /// The readable keys with their values, ordered by key.
    keys: Vec<(&'a str, &'a [String])>,
    /// The number of combinations: the product of the value counts, which is
    /// 1 for a query without readable keys and 0 when a key has no values.
    pub(crate) count: usize,
}

impl<'a> QueryCombinations<'a> {
    /// Selects the keys of `query` that `readable` includes, for a set of
    /// `policies` policies.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError::TooManyQueryCombinations`] when there are
    /// more combinations than [`MAX_QUERY_COMBINATIONS`] or, for a larger
    /// set, [`MAX_QUERY_POLICY_EVALUATIONS`] allow.
    pub(crate) fn new(
        query: &'a BTreeMap<String, Vec<String>>,
        readable: &QueryKeys,
        policies: usize,
    ) -> Result<Self, CedarEngineError> {
        let keys: Vec<_> = query
            .iter()
            .filter(|(key, _)| readable.includes(key))
            .map(|(key, values)| (key.as_str(), values.as_slice()))
            .collect();
        let count = keys.iter().fold(1_usize, |count, (_, values)| {
            count.saturating_mul(values.len())
        });
        let limit =
            (MAX_QUERY_POLICY_EVALUATIONS / policies.max(1)).clamp(1, MAX_QUERY_COMBINATIONS);
        if count > limit {
            return Err(CedarEngineError::TooManyQueryCombinations {
                combinations: count,
                limit,
            });
        }
        Ok(Self { keys, count })
    }

    /// Returns combination `index` (below [`Self::count`]): one value per key.
    pub(crate) fn combination(
        &self,
        index: usize,
    ) -> impl Iterator<Item = (&'a str, &'a str)> + '_ {
        let mut rest = index;
        self.keys.iter().map(move |(key, values)| {
            // `count` is nonzero, so every key has a value.
            let value = values[rest % values.len()].as_str();
            rest /= values.len();
            (*key, value)
        })
    }
}

/// The user and group a request is evaluated as.
pub(crate) struct Principal<'a> {
    pub(crate) user: &'a str,
    pub(crate) group: &'a str,
}

/// Who makes one authorization query, and the endpoint it is for.
pub(crate) struct Subject<'a> {
    pub(crate) principal: Principal<'a>,
    pub(crate) host: &'a str,
    pub(crate) port: u16,
    /// The endpoint's `resource.protocol`: the inspection protocol of the
    /// request's routed path, or `""` when not inspected.
    pub(crate) protocol: &'a str,
}

fn string(value: &str) -> RestrictedExpression {
    RestrictedExpression::new_string(value.to_string())
}

fn string_set(values: &[String]) -> RestrictedExpression {
    RestrictedExpression::new_set(values.iter().map(|value| string(value)))
}

/// Lowercases `host` and strips one trailing `.`.
///
/// DNS-resolved hostnames (as published by `policy_dns` and read back via
/// `ResolvedEndpointStore::lookup`) are absolute FQDNs with a trailing dot
/// (see `NormalizedName::parse`); authored Cedar policy host literals never
/// have one. Without this, every request whose host came from a DNS
/// resolution would fail to match an otherwise-identical policy host.
/// Lowercasing is ASCII-only, matching how endpoint literals are checked at
/// load.
#[must_use]
pub fn normalize_host(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// Returns whether `host`, after [`normalize_host`] strips one trailing
/// `.`, has an empty DNS label, as in `.example.com` or `a..example.com`.
///
/// Cedar's delimited `*` and `**` match empty labels, while the host
/// matcher that selects inspection rejects such hosts, so a request to one
/// is denied without evaluation: a host glob permit would otherwise allow a
/// connection that no `HttpRequest` policy inspects.
fn has_empty_label(host: &str) -> bool {
    host.strip_suffix('.')
        .unwrap_or(host)
        .split('.')
        .any(str::is_empty)
}

fn entity_type(type_name: &str) -> Result<EntityTypeName, CedarEngineError> {
    EntityTypeName::from_str(type_name).map_err(|e| CedarEngineError::EntityTypeParse(Box::new(e)))
}

fn entity_id(id: &str) -> EntityId {
    // `EntityId::from_str` is infallible: any string is a valid entity id.
    EntityId::from_str(id).unwrap_or_else(|never| match never {})
}

/// Builds an [`EntityUid`] from a Cedar entity type name and id.
fn entity_uid(type_name: &str, id: &str) -> Result<EntityUid, CedarEngineError> {
    Ok(EntityUid::from_type_name_and_id(
        entity_type(type_name)?,
        entity_id(id),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    /// The policy sets earlier versions built for one GraphQL path: copies
    /// of the engine's sets without the excluded permits.
    struct CopiedSets {
        deciding: PolicySet,
        all: PolicySet,
    }

    /// Builds the per-path copies as the engine once did.
    fn copied_sets(engine: &CedarEngine) -> HashMap<(String, u16, String), CopiedSets> {
        let analysis = &engine.analysis;
        let policy_set = |keep: &dyn Fn(&cedar_policy::Policy) -> bool| {
            PolicySet::from_policies(
                engine
                    .policies
                    .policies()
                    .filter(|policy| keep(policy))
                    .cloned(),
            )
            .unwrap()
        };
        let mut sets = HashMap::new();
        for ((host, port), paths) in &analysis.l7_endpoints {
            for (path, endpoint) in paths {
                if !matches!(
                    endpoint.protocol,
                    L7Protocol::Graphql | L7Protocol::WebsocketGraphql
                ) {
                    continue;
                }
                let excluded = |policy: &cedar_policy::Policy| {
                    analysis
                        .http_permits
                        .get(policy.id())
                        .is_some_and(|permit| {
                            permit.endpoint.1 == *port
                                && analysis::host_patterns_overlap(&permit.endpoint.0, host)
                                && permit.path != *path
                                && !permit.graphql_aware
                        })
                };
                if !engine.policies.policies().any(excluded) {
                    continue;
                }
                sets.insert(
                    (host.clone(), *port, path.clone()),
                    CopiedSets {
                        deciding: policy_set(&|policy| {
                            !analysis::is_staged(policy) && !excluded(policy)
                        }),
                        all: policy_set(&|policy| !excluded(policy)),
                    },
                );
            }
        }
        sets
    }

    /// Evaluates `request` against the per-path copies, as
    /// [`CedarEngine::evaluate_l7`] once did.
    fn evaluate_with_copies(
        engine: &CedarEngine,
        copies: &HashMap<(String, u16, String), CopiedSets>,
        request: &HttpRequestInput,
    ) -> Result<L7Evaluation, CedarEngineError> {
        let endpoint = engine.l7_endpoint_at(&request.host, request.port, &request.endpoint_path);
        let protocol = endpoint.map_or("", |endpoint| endpoint.protocol.as_str());
        let query = QueryCombinations::new(
            &request.query,
            &engine.analysis.query_keys,
            engine.deciding_policies.num_of_policies(),
        )?;
        let sets = request
            .graphql_request
            .then(|| {
                engine
                    .analysis
                    .l7_selecting(&normalize_host(&request.host), request.port)
                    .find_map(|(key, _)| {
                        copies.get(&(key.to_string(), request.port, request.endpoint_path.clone()))
                    })
            })
            .flatten();
        let (deciding, all) = sets.map_or((&engine.deciding_policies, &engine.policies), |sets| {
            (&sets.deciding, &sets.all)
        });
        let decision = engine.decide_l7(deciding, request, protocol, &query, &|_| false)?;
        let staged = if endpoint.is_some_and(|endpoint| endpoint.staged) {
            QueryCombinations::new(
                &request.query,
                &engine.analysis.staged_query_keys,
                engine.policies.num_of_policies(),
            )
            .and_then(|query| engine.decide_l7(all, request, protocol, &query, &|_| false))
            .map_or(None, |staged| {
                (staged.is_allow() != decision.is_allow()).then_some(staged)
            })
        } else {
            None
        };
        Ok(L7Evaluation { decision, staged })
    }

    /// An `HttpRequest` policy on `endpoint`.
    fn http_policy(endpoint: &str, annotations: &str, effect: &str, condition: &str) -> String {
        format!(
            r#"{annotations}
{effect} (principal, action == Sandbox::Action::"HttpRequest", resource == Sandbox::NetworkEndpoint::"{endpoint}")
when {{ {condition} }};
"#
        )
    }

    const API: &str = "api.example.com:443";

    /// Representative policy sets: several GraphQL paths, REST paths with
    /// and without GraphQL awareness, audit and staged policies, forbids,
    /// a host glob entry that selects the GraphQL host, a permit that
    /// fails to evaluate, and an unrelated host.
    fn policies() -> Vec<String> {
        vec![
            [
                http_policy(
                    API,
                    r#"@path("/**") @id("rest")"#,
                    "permit",
                    r#"context.method == "GET" && context.path like("/**", "/")"#,
                ),
                http_policy(
                    API,
                    r#"@path("/graphql") @protocol("graphql") @id("graphql")"#,
                    "permit",
                    r#"context.path == "/graphql" && context.graphql_operation_type == "query""#,
                ),
                http_policy(
                    API,
                    r#"@path("/**") @id("no-delete")"#,
                    "forbid",
                    r#"context.graphql_fields.contains("deleteRepository")"#,
                ),
            ]
            .concat(),
            [
                http_policy(
                    API,
                    r#"@path("/api/**") @id("api")"#,
                    "permit",
                    r#"["GET", "POST", "WEBSOCKET_TEXT"].contains(context.method)"#,
                ),
                http_policy(
                    API,
                    r#"@path("/api/**") @id("aware")"#,
                    "permit",
                    r#"context.method == "POST" && resource.protocol != "sql""#,
                ),
                http_policy(
                    API,
                    r#"@path("/audit/**") @enforcement("audit") @id("audit")"#,
                    "permit",
                    r#"context.method == "POST""#,
                ),
                http_policy(
                    API,
                    r#"@path("/g1") @protocol("graphql") @id("g1")"#,
                    "permit",
                    r#"context.graphql_operation_type == "query""#,
                ),
                http_policy(
                    API,
                    r#"@path("/g2") @protocol("graphql") @enforcement("audit") @id("g2")"#,
                    "permit",
                    r#"context.graphql_operation_type == "mutation""#,
                ),
                http_policy(
                    API,
                    r#"@path("/ws") @protocol("websocket-graphql") @id("ws")"#,
                    "permit",
                    r#"context.method == "GET" || context.graphql_operation_type == "subscription""#,
                ),
                http_policy(
                    API,
                    r#"@path("/api/**") @enforcement("staged") @id("staged-permit")"#,
                    "permit",
                    r#"context.method == "WEBSOCKET_TEXT""#,
                ),
                http_policy(
                    API,
                    r#"@path("/g1") @enforcement("staged") @id("staged-forbid")"#,
                    "forbid",
                    r#"context.graphql_fields.contains("secret")"#,
                ),
                http_policy(
                    API,
                    r#"@path("/api/**") @id("no-delete")"#,
                    "forbid",
                    r#"context.graphql_fields.contains("deleteRepository")"#,
                ),
                r#"@path("/glob/**") @id("glob")
permit (principal, action == Sandbox::Action::"HttpRequest", resource is Sandbox::NetworkEndpoint)
when { resource.host like("*.example.com", ".") && resource.port == 443 && context.method == "POST" };
"#
                .to_string(),
                http_policy(
                    "other.com:443",
                    r#"@path("/**") @id("other")"#,
                    "permit",
                    "true",
                ),
            ]
            .concat(),
            [
                http_policy(
                    API,
                    r#"@path("/**") @id("fails")"#,
                    "permit",
                    r#"context.method == "POST" && 9223372036854775807 + 1 > 0"#,
                ),
                http_policy(
                    API,
                    r#"@path("/graphql") @protocol("graphql") @id("graphql")"#,
                    "permit",
                    r#"context.graphql_operation_type == "query""#,
                ),
                http_policy(
                    API,
                    r#"@path("/graphql") @id("fails-forbid")"#,
                    "forbid",
                    r#"context.graphql_operation_type == "subscription" && 9223372036854775807 + 1 > 0"#,
                ),
            ]
            .concat(),
        ]
    }

    /// `evaluation` with its matched policies sorted, since Cedar reports
    /// them in no particular order.
    fn sorted(evaluation: &L7Evaluation) -> L7Evaluation {
        let sort = |decision: &Decision| match decision {
            Decision::Allow { matched_policies } => Decision::Allow {
                matched_policies: matched_policies
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            },
            Decision::Deny { matched_policies } => Decision::Deny {
                matched_policies: matched_policies
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            },
        };
        L7Evaluation {
            decision: sort(&evaluation.decision),
            staged: evaluation.staged.as_ref().map(sort),
        }
    }

    /// GraphQL paths share their endpoint's host set instead of holding
    /// policy set copies, so memory stays linear in the number of paths.
    #[test]
    fn graphql_exclusions_share_one_host_set_per_endpoint() {
        let paths = 50;
        let mut policy = String::from(
            r#"@path("/**")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.method == "POST" };
"#,
        );
        for index in 0..paths {
            let _ = write!(
                policy,
                r#"@path("/g{index}") @protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {{ context.graphql_operation_type == "query" }};
"#
            );
        }
        let engine = CedarEngine::from_policy_str(&policy).expect("policy loads");
        assert_eq!(engine.graphql_exclusions.len(), paths);
        let hosts: Vec<_> = engine
            .graphql_exclusions
            .values()
            .map(|exclusion| &exclusion.hosts)
            .collect();
        assert!(hosts.iter().all(|set| Arc::ptr_eq(set, hosts[0])));
        assert_eq!(Arc::strong_count(hosts[0]), paths);
    }

    #[test]
    fn graphql_exclusions_decide_as_the_copied_policy_sets() {
        let mut compared = 0;
        for policy in policies() {
            let engine = CedarEngine::from_policy_str(&policy)
                .unwrap_or_else(|error| panic!("{error}\n{policy}"));
            let copies = copied_sets(&engine);
            assert!(!copies.is_empty(), "{policy}");
            assert_eq!(
                copies.keys().collect::<HashSet<_>>(),
                engine.graphql_exclusions.keys().collect::<HashSet<_>>()
            );
            for host in ["api.example.com", "x.example.com", "other.com"] {
                let paths: Vec<String> = engine
                    .l7_endpoints(host, 443)
                    .map(|(path, _)| path)
                    .chain(["/unknown".to_string()])
                    .collect();
                for endpoint_path in &paths {
                    for graphql_request in [true, false] {
                        for method in ["GET", "POST", "WEBSOCKET_TEXT"] {
                            for operation in ["query", "mutation", "subscription", ""] {
                                for fields in [&[][..], &["deleteRepository"], &["secret"]] {
                                    let request = HttpRequestInput {
                                        user: "sandbox".to_string(),
                                        group: "sandbox".to_string(),
                                        binary_path: "/usr/bin/curl".to_string(),
                                        host: host.to_string(),
                                        port: 443,
                                        method: method.to_string(),
                                        path: "/graphql".to_string(),
                                        graphql_operation_type: operation.to_string(),
                                        graphql_fields: fields
                                            .iter()
                                            .map(ToString::to_string)
                                            .collect(),
                                        graphql_request,
                                        endpoint_path: endpoint_path.clone(),
                                        ..Default::default()
                                    };
                                    let expected = evaluate_with_copies(&engine, &copies, &request);
                                    let actual = engine.evaluate_l7(&request);
                                    match (&expected, &actual) {
                                        (Ok(expected), Ok(actual)) => {
                                            assert_eq!(
                                                sorted(expected),
                                                sorted(actual),
                                                "{request:?}"
                                            );
                                        }
                                        (
                                            Err(CedarEngineError::Evaluation { .. }),
                                            Err(CedarEngineError::Evaluation { .. }),
                                        ) => {}
                                        _ => panic!("{request:?}: {expected:?} != {actual:?}"),
                                    }
                                    compared += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(compared > 1000, "{compared}");
    }
}
