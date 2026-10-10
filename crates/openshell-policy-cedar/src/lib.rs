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

pub use analysis::{L7Endpoint, L7Enforcement, L7Protocol, NetworkTransport};
pub use error::CedarEngineError;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicyId,
    PolicySet, Request, RestrictedExpression, Schema,
};
use openshell_policy_cedar_schema::{actions, context_fields, endpoint_fields, entity_types};

use analysis::{PolicyAnalysis, QueryKeys};
pub use ipnet::IpNet;

/// Most evaluations one `HttpRequest` gets for the combinations of its
/// repeated query values.
///
/// A request over the cap is not evaluated; see
/// [`CedarEngineError::TooManyQueryCombinations`].
pub const MAX_QUERY_COMBINATIONS: usize = 64;

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

/// One network-connect authorization request.
///
/// Mirrors the fields `openshell_supervisor_network::opa::NetworkInput`
/// supplies to the Rego engine. The schema's `method`, `path`, and `command`
/// context fields are always `""` for `NetworkConnect`, since no request has
/// been read at CONNECT time, so they are not part of this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRequest {
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
    /// The decision of the endpoint's policies.
    ///
    /// On an [`L7Enforcement::Audit`] endpoint every policy is audit-only, so
    /// this is evaluated with all of them and the proxy logs a deny instead
    /// of blocking it. On an enforced endpoint it is evaluated without the
    /// audit-only policies.
    pub decision: Decision,
    /// The decision with the endpoint's staged audit-only policies included,
    /// present only when it differs from [`Self::decision`].
    pub staged: Option<Decision>,
}

impl L7Evaluation {
    /// Returns `true` if [`Self::decision`] allows the request.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        self.decision.is_allow()
    }
}

/// One per-request L7 evaluation within an already-permitted connection.
///
/// Mirrors the fields `openshell_supervisor_network::l7::relay::L7EvalContext`
/// / `L7RequestInfo` supply, narrowed to what the `Sandbox::HttpRequest`
/// Cedar action declares in its schema. Fields that do not apply to a
/// request's protocol keep their default (`""`, `false`, or empty).
#[derive(Debug, Clone, Default)]
pub struct L7Request {
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
struct RequestUids {
    user_type: EntityTypeName,
    group_type: EntityTypeName,
    endpoint_type: EntityTypeName,
    process: EntityUid,
    query: EntityUid,
    network_connect: EntityUid,
    http_request: EntityUid,
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
/// then evaluates [`NetworkRequest`]s and [`L7Request`]s against them.
#[derive(Debug)]
pub struct CedarEngine {
    schema: Schema,
    /// Every authored policy, including audit-only ones.
    policies: PolicySet,
    /// The policies that decide requests: every policy except audit-only ones.
    enforced_policies: PolicySet,
    /// The policies that decide a connection before its host is resolved:
    /// the enforced policies, with permits stripped of their
    /// `destination_ip` conditions and forbids that read it left out.
    unresolved_policies: PolicySet,
    authorizer: Authorizer,
    analysis: PolicyAnalysis,
    uids: RequestUids,
}

impl CedarEngine {
    /// Parses and validates a policy set against the canonical sandbox schema.
    ///
    /// The schema is [`openshell_policy_cedar_schema::SANDBOX_SCHEMA_SRC`].
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if the policy set fails to parse, fails
    /// strict schema validation, or uses a shape this crate cannot enforce
    /// exactly.
    pub fn from_policy_str(policy_src: &str) -> Result<Self, CedarEngineError> {
        let schema = openshell_policy_cedar_schema::load_schema()?;
        let policies = PolicySet::from_str(policy_src)
            .map_err(|e| CedarEngineError::PolicyParse(Box::new(e)))?;
        let analysis = analysis::analyze(&schema, &policies)?;
        let enforced_policies = PolicySet::from_policies(
            policies
                .policies()
                .filter(|policy| !analysis::is_audit_only(policy))
                .cloned(),
        )
        .map_err(|e| CedarEngineError::PolicySet(Box::new(e)))?;
        let unresolved_policies =
            PolicySet::from_policies(enforced_policies.policies().filter_map(|policy| {
                analysis
                    .unresolved
                    .get(policy.id())
                    .map_or_else(|| Some(policy.clone()), Clone::clone)
            }))
            .map_err(|e| CedarEngineError::PolicySet(Box::new(e)))?;
        Ok(Self {
            schema,
            policies,
            enforced_policies,
            unresolved_policies,
            authorizer: Authorizer::new(),
            analysis,
            uids: RequestUids::new()?,
        })
    }

    /// Returns the Landlock path grants this policy set authorizes.
    #[must_use]
    pub fn filesystem_grants(&self) -> &FilesystemGrants {
        &self.analysis.filesystem
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
    #[must_use]
    pub fn l7_endpoint_at(&self, host: &str, port: u16, path: &str) -> Option<L7Endpoint> {
        self.analysis
            .l7_endpoints
            .get(&(normalize_host(host), port))
            .and_then(|paths| paths.get(path))
            .copied()
    }

    /// Returns every inspected path of `host:port` with its inspection,
    /// ordered by path.
    ///
    /// Empty means no `HttpRequest` policy names this endpoint, so an
    /// allowed connection to it is relayed without per-request checks. The
    /// empty path is the endpoint declared by policies without `@path`.
    pub fn l7_endpoints(&self, host: &str, port: u16) -> impl Iterator<Item = (&str, L7Endpoint)> {
        self.analysis
            .l7_endpoints
            .get(&(normalize_host(host), port))
            .into_iter()
            .flatten()
            .map(|(path, endpoint)| (path.as_str(), *endpoint))
    }

    /// Evaluates one network-connect request against the loaded policy set.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if the request cannot be represented in
    /// the loaded schema, or if Cedar reports an error while evaluating any
    /// policy.
    pub fn evaluate_network(&self, request: &NetworkRequest) -> Result<Decision, CedarEngineError> {
        Ok(self.authorize_network(request)?.decision)
    }

    /// Evaluates one network-connect request, reporting what the allowing
    /// permits require of the destination address.
    ///
    /// Without `destination_ip` the request is decided as before its host is
    /// resolved: permits are evaluated without their `destination_ip`
    /// conditions and forbids that read `destination_ip` are left out, so an
    /// allow means some resolved address may be allowed. With
    /// `destination_ip` every enforced policy decides the request for that
    /// address.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError`] if the request cannot be represented in
    /// the loaded schema, or if Cedar reports an error while evaluating any
    /// policy.
    pub fn authorize_network(
        &self,
        request: &NetworkRequest,
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
            (context_fields::METHOD, string("")),
            (context_fields::PATH, string("")),
            (context_fields::COMMAND, string("")),
        ];
        if let Some(ip) = request.destination_ip {
            context.push((
                context_fields::DESTINATION_IP,
                RestrictedExpression::new_ip(ip.to_string()),
            ));
        }
        let policies = if request.destination_ip.is_some() {
            &self.enforced_policies
        } else {
            &self.unresolved_policies
        };
        let outcome = self.authorize(
            policies,
            &self.uids.network_connect,
            &Principal {
                user: &request.user,
                group: &request.group,
            },
            &request.host,
            request.port,
            protocol,
            context,
            None,
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
    /// decision is computed for the enforced policies and, when staged, with
    /// the audit-only policies.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError::TooManyQueryCombinations`] if the query
    /// has more than [`MAX_QUERY_COMBINATIONS`] value combinations, and
    /// another [`CedarEngineError`] if the request cannot be represented in
    /// the loaded schema, or if Cedar reports an error while evaluating any
    /// policy.
    pub fn evaluate_l7(&self, request: &L7Request) -> Result<L7Evaluation, CedarEngineError> {
        let endpoint = self.l7_endpoint_at(&request.host, request.port, &request.endpoint_path);
        let protocol = endpoint.map_or("", |endpoint| endpoint.protocol.as_str());
        let audit_endpoint =
            endpoint.is_some_and(|endpoint| endpoint.enforcement == L7Enforcement::Audit);
        let query = QueryCombinations::new(&request.query, &self.analysis.query_keys)?;
        let evaluate = |policies: &PolicySet| self.decide_l7(policies, request, protocol, &query);
        if audit_endpoint {
            return Ok(L7Evaluation {
                decision: evaluate(&self.policies)?,
                staged: None,
            });
        }
        let decision = evaluate(&self.enforced_policies)?;
        // Compare decisions, not the staged set's decision alone: Cedar denies
        // by default, so a set of only audit-only `forbid`s denies every
        // request whether or not one of them matched.
        let staged = if endpoint.is_some_and(|endpoint| endpoint.staged_audit) {
            let staged = evaluate(&self.policies)?;
            (staged.is_allow() != decision.is_allow()).then_some(staged)
        } else {
            None
        };
        Ok(L7Evaluation { decision, staged })
    }

    /// Decides one `HttpRequest` with `policies` over every combination of
    /// its query values; see [`Self::evaluate_l7`].
    ///
    /// A denied combination denies the request with its determining
    /// policies. When every combination is allowed but no single `permit`
    /// allows them all, the request is denied with no determining policy.
    fn decide_l7(
        &self,
        policies: &PolicySet,
        request: &L7Request,
        protocol: &str,
        query: &QueryCombinations<'_>,
    ) -> Result<Decision, CedarEngineError> {
        let context = vec![
            (context_fields::BINARY_PATH, string(&request.binary_path)),
            (context_fields::ANCESTORS, string_set(&request.ancestors)),
            (
                context_fields::BINARY_ALIASES,
                string_set(&request.binary_aliases),
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
        ];
        // The permits that allowed every combination so far.
        let mut common_permits: Option<Vec<PolicyId>> = None;
        for index in 0..query.count {
            let tags = query
                .combination(index)
                .map(|(key, value)| (key.to_string(), string(value)));
            let query_entity = Entity::new_with_tags(self.uids.query.clone(), [], [], tags)
                .map_err(|e| CedarEngineError::EntityBuild(Box::new(e)))?;
            let outcome = self.authorize(
                policies,
                &self.uids.http_request,
                &Principal {
                    user: &request.user,
                    group: &request.group,
                },
                &request.host,
                request.port,
                protocol,
                context.clone(),
                Some(query_entity),
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

    /// Runs one authorization query.
    ///
    /// `protocol` is the endpoint's `resource.protocol`: the inspection
    /// protocol of the request's routed path, or `""` when not inspected.
    #[expect(
        clippy::too_many_arguments,
        reason = "one call per action; the arguments are the request's distinct parts"
    )]
    fn authorize(
        &self,
        policies: &PolicySet,
        action: &EntityUid,
        principal: &Principal<'_>,
        host: &str,
        port: u16,
        protocol: &str,
        context: Vec<(&str, RestrictedExpression)>,
        query: Option<Entity>,
    ) -> Result<Outcome, CedarEngineError> {
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
                    RestrictedExpression::new_long(i64::from(port)),
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
            .map(ToString::to_string)
            .collect();
        if !errors.is_empty() {
            return Err(CedarEngineError::Evaluation {
                reason: errors.join("; "),
            });
        }
        Ok(Outcome {
            allowed: response.decision() == cedar_policy::Decision::Allow,
            reasons: response.diagnostics().reason().cloned().collect(),
        })
    }
}

/// The result of one authorization query.
struct Outcome {
    allowed: bool,
    /// The determining policies: the satisfied `permit`s of an allow, or
    /// the satisfied `forbid`s of a deny (none when no `permit` matched).
    reasons: Vec<PolicyId>,
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
struct QueryCombinations<'a> {
    /// The readable keys with their values, ordered by key.
    keys: Vec<(&'a str, &'a [String])>,
    /// The number of combinations: the product of the value counts, which is
    /// 1 for a query without readable keys and 0 when a key has no values.
    count: usize,
}

impl<'a> QueryCombinations<'a> {
    /// Selects the keys of `query` that `readable` includes.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEngineError::TooManyQueryCombinations`] when there are
    /// more than [`MAX_QUERY_COMBINATIONS`] combinations.
    fn new(
        query: &'a BTreeMap<String, Vec<String>>,
        readable: &QueryKeys,
    ) -> Result<Self, CedarEngineError> {
        let keys: Vec<_> = query
            .iter()
            .filter(|(key, _)| readable.includes(key))
            .map(|(key, values)| (key.as_str(), values.as_slice()))
            .collect();
        let count = keys.iter().fold(1_usize, |count, (_, values)| {
            count.saturating_mul(values.len())
        });
        if count > MAX_QUERY_COMBINATIONS {
            return Err(CedarEngineError::TooManyQueryCombinations {
                combinations: count,
                limit: MAX_QUERY_COMBINATIONS,
            });
        }
        Ok(Self { keys, count })
    }

    /// Returns combination `index` (below [`Self::count`]): one value per key.
    fn combination(&self, index: usize) -> impl Iterator<Item = (&'a str, &'a str)> + '_ {
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
struct Principal<'a> {
    user: &'a str,
    group: &'a str,
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
