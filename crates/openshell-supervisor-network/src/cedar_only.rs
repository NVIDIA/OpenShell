// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cedar as the sole, authoritative network policy engine for a sandbox.
//!
//! [`CedarOnlyEngine`] evaluates an authored `.cedar` policy directly. It is
//! selected instead of [`crate::opa::OpaEngine`], never alongside it:
//! a sandbox's `SandboxPolicy.cedar_policy_source` being non-empty is what
//! makes a sandbox use this engine instead of OPA, decided once at policy
//! load (see `crates/openshell-supervisor/src/lib.rs::load_policy`).
//!
//! CONNECT-time matching (host/binary/ancestor) is covered directly by
//! [`openshell_policy_cedar::CedarEngine::evaluate_network`].
//! Per-request L7 enforcement is covered by
//! [`openshell_policy_cedar::CedarEngine::evaluate_l7`] via
//! [`CedarL7TunnelEngine`], the handle each inspected tunnel's
//! [`crate::policy_engine::TunnelPolicyEngine`] delegates to. [`l7_endpoint_configs_for`] populates
//! `EgressAuthorization::endpoint_configs` for every endpoint an
//! `HttpRequest` policy names, exactly in its scope or as a host glob in its
//! conditions, so the proxy routes an allowed CONNECT into L7 inspection
//! instead of unconditional passthrough. A host glob inspects every host it
//! matches, selected with the host matcher YAML endpoints and policy DNS
//! use. The Cedar engine rejects at load any `HttpRequest` policy it could
//! not route this way.
//! DNS eligibility is covered by
//! [`CedarOnlyEngine::policy_dns_eligibility_snapshot`], one record per host
//! and transport, named by its index under the policy name `cedar`. An
//! endpoint a `@transport("tcp")` permit names is native TCP, and its record
//! carries `protocol: tcp`, as a YAML `protocol: tcp` endpoint's does.
//! `EgressAuthorization::matched_endpoints` lists the records that cover an
//! allowed connection's host and port, with the same indices, so the
//! transparent TCP listener can correlate a decision with the policy DNS
//! mapping it dialed, as it does for YAML.
//!
//! Provider credentials work the same way as for YAML sandboxes, except that
//! providers never grant access: the gateway delivers attached providers'
//! rules in `SandboxPolicy.provider_credential_rules`, and for a connection
//! Cedar allows, each matching provider endpoint contributes its credential
//! settings (credential marker, rewrite options, request signing) to
//! `endpoint_configs` and to the credential guard. Whether the connection is
//! inspected per request is still Cedar's decision.
//!
//! Endpoint settings that are configuration rather than access control
//! (`tls: skip`, `allow_encoded_slash`, body limits, MCP revisions, and
//! GraphQL persisted queries) come from `SandboxPolicy.endpoint_settings`,
//! authored in the middleware file. They are merged into the endpoint
//! configs of connections Cedar allows (see
//! [`LoadedPolicy::endpoint_configs`]), and hash-only GraphQL persisted
//! queries are resolved through their registry before Cedar evaluates them,
//! as the Rego rules do.
//!
//! `@path` gives one `host:port` a different protocol and enforcement per
//! path. Each inspected path gets its own endpoint config, and each request
//! is evaluated with the inspection of the config the relay selects for it
//! (see [`LoadedPolicy::route_request`]). WebSocket messages arrive as
//! `WEBSOCKET_TEXT` requests on their upgrade path; for a
//! `websocket-graphql` endpoint the relay classifies them first and supplies
//! their GraphQL operations.
//!
//! Token grants follow the YAML rule too: an owner's grant is admitted only
//! for a request Cedar allows and the owner's own provider endpoint admits
//! under its own rules. The provider rules are compiled to Cedar (see
//! `crate::cedar_provider_rules`) and evaluated with the same request, so
//! no Rego is involved (see
//! [`CedarL7TunnelEngine::admitted_token_grant_owners`]).
//!
//! Destination addresses follow YAML `allowed_ips`: a permit may require
//! `context.destination_ip` to lie in fixed ranges. A connection is allowed
//! at CONNECT time when Cedar allows it for some address, and the decision
//! carries a [`CedarDestination`] that the proxy applies to each resolved
//! address (see `proxy::destination`). Policy DNS records carry each
//! permit's ranges as `allowed_ips`, so answers are filtered as YAML filters
//! them. Provider endpoints grant no access, so their `allowed_ips` only
//! narrow: each matching provider endpoint's ranges must also admit every
//! resolved address, as they restrict a YAML provider endpoint's
//! connections, but they never admit a private address Cedar's own rules
//! reject. A host-less provider endpoint, which YAML matches by its
//! `allowed_ips` alone, matches no connection.
//!
//! Every read of the generation counter happens under the engine lock, and
//! [`CedarOnlyEngine::commit`] advances it under the write lock, so a
//! decision is always reported against the generation of the policy that
//! made it.
//!
//! Network middleware is selected without Rego: the engine owns a
//! `MiddlewareState` holding the policy's `network_middlewares`, the
//! connected service registry, and a middleware generation of its own (see
//! `crate::network_middleware`). [`CedarOnlyEngine::commit_configuration`]
//! publishes the Cedar policy, the middleware, and the caller's provider
//! credentials together, or nothing, so a Cedar sandbox needs no OPA engine
//! at all. A quarantine advances both generations, so the configuration
//! guard the policy poll loop pins becomes stale as it does for YAML.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use miette::Result;
use openshell_core::policy_identity::deterministic_policy_hash;
use openshell_core::proto::{NetworkPolicyRule, SandboxPolicy as ProtoSandboxPolicy};
use openshell_ocsf::{
    ActionId, ActivityId, ConfigStateChangeBuilder, DispositionId, Endpoint, HttpActivityBuilder,
    HttpRequest, SeverityId, StateId, StatusId, Url as OcsfUrl, ocsf_emit,
};
use openshell_policy_cedar::{
    AuthorizedNetworkEndpoint, CedarEngine, CedarEngineError, Decision, HttpRequestInput, IpNet,
    L7Endpoint, L7Protocol, NetworkConnectRequest, NetworkEvaluation, TokenGrantRules,
    normalize_host,
};
use tokio::sync::watch;

use crate::network_middleware::{MiddlewareConfigs, MiddlewareState};
use crate::policy_types::{
    DnsRecord, EgressAuthorization, EndpointConfig, EndpointProtocol, EnforcementSetting,
    GraphqlPersistedQuery, MatchedEndpoint, NetworkAction, NetworkInput,
    PolicyDnsEligibilitySnapshot, PolicyGenerationGuard, TlsSetting, generation_guard_for,
};
use openshell_supervisor_middleware::MiddlewareRegistry;

/// User and group entity id sent with every Cedar request.
///
/// Process identity is fixed per sandbox and enforced by the runtime, not
/// by network policy, so requests carry a constant identity that satisfies
/// the schema's `Process` shape. Policies that test `principal.user` see
/// this value.
const PLACEHOLDER_IDENTITY: &str = "sandbox";

/// Policy name of every Cedar policy DNS record and matched endpoint.
///
/// Cedar policies have no YAML-style names, so records are told apart by
/// their index alone.
const CEDAR_POLICY_NAME: &str = "cedar";

/// Builds the Cedar CONNECT request for one egress attempt.
fn network_request_from_input(input: &NetworkInput) -> NetworkConnectRequest {
    NetworkConnectRequest {
        user: PLACEHOLDER_IDENTITY.to_string(),
        group: PLACEHOLDER_IDENTITY.to_string(),
        host: input.host.clone(),
        port: input.port,
        binary_path: input.binary_path.to_string_lossy().into_owned(),
        ancestors: input
            .ancestors
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        // Filled from the loaded policy's aliases and globs; see
        // `BinaryAliases` and `BinaryGlobs`.
        binary_aliases: Vec::new(),
        binary_globs: Vec::new(),
        destination_ip: None,
    }
}

/// The active Cedar policy and the provider settings delivered with it.
///
/// Swapped as one unit on reload so a decision never pairs one revision's
/// Cedar policy with another revision's provider settings.
struct LoadedPolicy {
    mcp_endpoints: Vec<openshell_core::proto::NetworkEndpoint>,
    /// Shared with the [`CedarDestination`] of each decision it makes.
    cedar: Arc<CedarEngine>,
    /// Hash of the canonical policy, stamped on every endpoint config so
    /// token-grant reporting binds each request to the policy it was
    /// selected under, as the YAML engine's endpoint data does.
    policy_hash: String,
    providers: Vec<ProviderEndpoint>,
    settings: Vec<EndpointSetting>,
    /// The provider rules compiled to Cedar, used only to select token-grant
    /// owners. `None` when no provider endpoint carries an owner.
    token_grants: Option<TokenGrantRules>,
    /// The policy binary paths that are symlinks in the sandbox.
    binary_aliases: BinaryAliases,
    /// The binary glob patterns the Cedar policy and the provider rules
    /// test, compiled with the YAML matcher.
    binary_globs: BinaryGlobs,
    /// The entrypoint process whose root filesystem `binary_aliases` and
    /// `token_grants` were resolved in; 0 before it is known.
    entrypoint_pid: u32,
    /// Test-only: makes the next binary resolution fail, standing in for a
    /// provider rule set that compiles for one entrypoint process but not
    /// another.
    #[cfg(test)]
    fail_resolution: bool,
}

impl std::fmt::Debug for LoadedPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedPolicy")
            .field("cedar", &self.cedar)
            .field("policy_hash", &self.policy_hash)
            .field("providers", &self.providers)
            .field("settings", &self.settings)
            .field("token_grants", &self.token_grants.is_some())
            .field("binary_aliases", &self.binary_aliases)
            .field("binary_globs", &self.binary_globs)
            .field("entrypoint_pid", &self.entrypoint_pid)
            .finish()
    }
}

impl LoadedPolicy {
    /// Loads `policy`, resolving its binary paths in the root filesystem of
    /// `entrypoint_pid` (none when it is 0), as YAML does.
    fn from_proto(policy: &ProtoSandboxPolicy, entrypoint_pid: u32) -> Result<Self> {
        let cedar = Arc::new(
            CedarEngine::from_policy_str(&policy.cedar_policy_source)
                .map_err(|e| miette::miette!("{e}"))?,
        );
        // The CLI prints these when the file is submitted; the sandbox logs
        // them so operators see them too.
        for warning in cedar.warnings() {
            tracing::warn!(%warning, "Cedar policy loaded with a warning");
            ocsf_emit!(
                ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(SeverityId::Low)
                    .status(StatusId::Success)
                    .state(StateId::Enabled, "cedar policy loaded")
                    .message(format!("CONFIG:CEDAR policy warning: {warning}"))
                    .build()
            );
        }
        let mut providers = Vec::new();
        for rule in policy.provider_credential_rules.values() {
            for endpoint in &rule.endpoints {
                providers.push(ProviderEndpoint::from_proto(endpoint));
            }
        }
        let token_grants = crate::cedar_provider_rules::compile(
            &policy.provider_credential_rules,
            entrypoint_pid,
        )?;
        Ok(Self {
            mcp_endpoints: openshell_policy::endpoint_status::cedar_mcp_endpoints(policy, &cedar),
            binary_aliases: BinaryAliases::resolve(cedar.binary_alias_paths(), entrypoint_pid),
            binary_globs: BinaryGlobs::compile(&cedar, token_grants.as_ref()),
            cedar,
            policy_hash: deterministic_policy_hash(policy),
            providers,
            settings: policy
                .endpoint_settings
                .iter()
                .map(EndpointSetting::from_proto)
                .collect(),
            token_grants,
            entrypoint_pid,
            #[cfg(test)]
            fail_resolution: false,
        })
    }

    /// Returns this policy with its binary paths resolved again, for
    /// `entrypoint_pid`.
    ///
    /// `rules` are the provider rules the policy was loaded with. The copy
    /// shares the Cedar engine; only `binary_aliases`, `binary_globs`,
    /// `token_grants`, and `entrypoint_pid` differ. Does no locking, so a caller can resolve the
    /// active policy's copy outside the engine lock and swap it in later.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider rules fail to compile for
    /// `entrypoint_pid`.
    fn resolved_for(
        &self,
        rules: &HashMap<String, NetworkPolicyRule>,
        entrypoint_pid: u32,
    ) -> Result<Self> {
        #[cfg(test)]
        if self.fail_resolution {
            return Err(miette::miette!(
                "provider credential rules failed to compile: injected test failure"
            ));
        }
        let token_grants = crate::cedar_provider_rules::compile(rules, entrypoint_pid)?;
        Ok(Self {
            mcp_endpoints: self.mcp_endpoints.clone(),
            cedar: Arc::clone(&self.cedar),
            policy_hash: self.policy_hash.clone(),
            providers: self.providers.clone(),
            settings: self.settings.clone(),
            binary_aliases: BinaryAliases::resolve(self.cedar.binary_alias_paths(), entrypoint_pid),
            binary_globs: BinaryGlobs::compile(&self.cedar, token_grants.as_ref()),
            token_grants,
            entrypoint_pid,
            #[cfg(test)]
            fail_resolution: false,
        })
    }

    /// Returns whether `other` resolved to a different entrypoint process or
    /// different aliases or glob patterns than this policy.
    fn resolution_differs(&self, other: &Self) -> bool {
        self.entrypoint_pid != other.entrypoint_pid
            || self.binary_aliases != other.binary_aliases
            || self.binary_globs != other.binary_globs
    }

    /// Builds the endpoint configs for an allowed connection to `host:port`.
    ///
    /// Cedar inspects each path its `HttpRequest` policies declare with
    /// `@path` (and, for policies without `@path`, every path) with that
    /// path's protocol and enforcement; each gets a config with that `path`,
    /// so the relay's most-specific-path selection picks protocol and
    /// enforcement as it does for YAML endpoints sharing a `host:port`.
    ///
    /// Each matching provider endpoint contributes its settings, with its
    /// own L7 rules removed and its protocol replaced by the inspection
    /// Cedar declares for its path (see [`RoutePlan`]). A Cedar path whose
    /// config no provider endpoint supplies gets a config of its own.
    ///
    /// Matching endpoint settings without a path apply to every config.
    /// Settings with a path apply to the config with that path, which is
    /// added with Cedar's inspection when absent and Cedar inspects that
    /// path. Without inspection, only a path-less `tls` setting has an
    /// effect, so a config carrying it is added when no other config exists.
    fn endpoint_configs(&self, host: &str, port: u16) -> Vec<EndpointConfig> {
        let plan = self.route_plan(host, port);
        plan.routes.iter().map(|route| plan.build(route)).collect()
    }

    /// Plans the endpoint configs for `host:port`, in the order
    /// [`Self::endpoint_configs`] returns them.
    fn route_plan(&self, host: &str, port: u16) -> RoutePlan<'_> {
        let host = normalize_host(host);
        // Selected by the exact endpoint and every host glob the host
        // matches, with the matcher endpoint settings and providers use.
        let inspections: Vec<(String, L7Endpoint)> = self.cedar.l7_endpoints(&host, port).collect();
        let settings: Vec<&EndpointSetting> = self
            .settings
            .iter()
            .filter(|setting| setting.matches(&host, port))
            .collect();
        let mut routes: Vec<Route<'_>> = self
            .providers
            .iter()
            .filter(|endpoint| endpoint.matches(&host, port))
            .map(|endpoint| {
                let path = endpoint.config.path.clone();
                Route {
                    provider: Some(endpoint),
                    inspection: inspection_for(&inspections, &path),
                    path,
                }
            })
            .collect();

        if inspections.is_empty() {
            let tls_only = routes.is_empty()
                && settings
                    .iter()
                    .any(|setting| setting.path.is_empty() && setting.fields.tls.is_some());
            if tls_only {
                routes.push(Route {
                    provider: None,
                    path: String::new(),
                    inspection: None,
                });
            }
            return RoutePlan {
                routes,
                settings,
                policy_hash: &self.policy_hash,
                host,
                port,
                mcp_endpoints: &self.mcp_endpoints,
            };
        }

        for (path, endpoint) in &inspections {
            if !routes.iter().any(|route| route.path == *path) {
                routes.push(Route {
                    provider: None,
                    path: path.clone(),
                    inspection: Some((path.clone(), *endpoint)),
                });
            }
        }
        for setting in &settings {
            if setting.path.is_empty() || routes.iter().any(|route| route.path == setting.path) {
                continue;
            }
            // A setting for a path Cedar does not inspect has no effect.
            if let Some(inspection) = inspection_for(&inspections, &setting.path) {
                routes.push(Route {
                    provider: None,
                    path: setting.path.clone(),
                    inspection: Some(inspection),
                });
            }
        }
        RoutePlan {
            routes,
            settings,
            policy_hash: &self.policy_hash,
            host,
            port,
            mcp_endpoints: &self.mcp_endpoints,
        }
    }

    /// Returns how the relay routes a request for `path` to `host:port`.
    ///
    /// Selected as the relay selects it: among the configs it inspects with,
    /// the one whose path matches with the highest specificity, the last
    /// such config on a tie.
    fn route_request(&self, host: &str, port: u16, path: &str) -> RequestRoute {
        let plan = self.route_plan(host, port);
        match plan.select(path) {
            Some(route) => RequestRoute::Routed {
                endpoint_path: route
                    .inspection
                    .as_ref()
                    .map(|(endpoint_path, _)| endpoint_path.clone())
                    .unwrap_or_default(),
            },
            None if plan.routes.iter().any(Route::is_inspected) => RequestRoute::Unmatched,
            None => RequestRoute::Uninspected,
        }
    }

    /// Returns the endpoint config the relay selects for a request to `path`.
    fn request_config(&self, host: &str, port: u16, path: &str) -> Option<EndpointConfig> {
        let plan = self.route_plan(host, port);
        plan.select(path).map(|route| plan.build(route))
    }

    /// Returns the `allowed_ips` of each provider endpoint matching
    /// `host:port` that has them.
    ///
    /// Each such endpoint supplies credential settings to the connection, so
    /// each one's ranges must admit every address it reaches, as a YAML
    /// provider endpoint's `allowed_ips` restrict its connections.
    fn provider_ranges(&self, host: &str, port: u16) -> Vec<ProviderRanges> {
        let host = normalize_host(host);
        self.providers
            .iter()
            .filter(|endpoint| endpoint.matches(&host, port))
            .filter(|endpoint| !matches!(&endpoint.allowed_ips, Ok(ranges) if ranges.is_empty()))
            .map(|endpoint| endpoint.allowed_ips.clone())
            .collect()
    }
}

/// How the relay routes one request on a connection Cedar allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestRoute {
    /// Cedar does not inspect the connection.
    Uninspected,
    /// Cedar inspects the connection, but no inspected path matches the
    /// request, so the relay denies it before evaluation.
    Unmatched,
    /// The request is inspected as the Cedar path `endpoint_path` declares.
    Routed { endpoint_path: String },
}

/// The deny reason for a request no inspected path matches, the same reason
/// the relay reports.
const UNMATCHED_PATH: &str = "no L7 endpoint path matched request";

/// The endpoint configs of one allowed connection, before they are built.
struct RoutePlan<'a> {
    host: String,
    port: u16,
    mcp_endpoints: &'a [openshell_core::proto::NetworkEndpoint],
    routes: Vec<Route<'a>>,
    /// The endpoint settings matching the connection, in order.
    settings: Vec<&'a EndpointSetting>,
    /// The hash every built config carries; see [`LoadedPolicy::policy_hash`].
    policy_hash: &'a str,
}

/// One endpoint config of a [`RoutePlan`].
struct Route<'a> {
    /// The provider endpoint supplying the config, if any.
    provider: Option<&'a ProviderEndpoint>,
    /// The config's `path`; empty for none.
    path: String,
    /// The Cedar path whose inspection the config carries, with that
    /// inspection; `None` leaves the config uninspected.
    inspection: Option<(String, L7Endpoint)>,
}

impl Route<'_> {
    /// Returns whether the relay inspects requests with this config: only a
    /// config with a protocol is an L7 config.
    fn is_inspected(&self) -> bool {
        self.inspection.is_some()
    }
}

impl RoutePlan<'_> {
    /// Selects the route for a request to `path` as the relay selects a
    /// config: the most specific matching path, the last one on a tie.
    fn select(&self, path: &str) -> Option<&Route<'_>> {
        self.routes
            .iter()
            .filter(|route| route.is_inspected())
            .filter(|route| crate::l7::endpoint_path_matches(&route.path, path))
            .max_by_key(|route| route.path.chars().filter(|c| *c != '*').count())
    }

    /// Builds the endpoint config for `route`.
    fn build(&self, route: &Route<'_>) -> EndpointConfig {
        let inspection = route.inspection.as_ref().map(|(_, endpoint)| *endpoint);
        let protocol = inspection.map(|inspection| inspection.protocol);
        let mut config = route.provider.map_or_else(
            || EndpointConfig {
                path: route.path.clone(),
                ..EndpointConfig::default()
            },
            |endpoint| endpoint.config.clone(),
        );
        if let Some(inspection) = inspection {
            apply_inspection(&mut config, inspection);
        }
        // Every inspected protocol binds grant reporting to the policy
        // selected before credential acquisition, as the YAML engine does.
        config.policy_hash = self.policy_hash.to_string();
        let host_wide: Vec<&EndpointSetting> = self
            .settings
            .iter()
            .copied()
            .filter(|setting| setting.path.is_empty())
            .collect();
        apply_settings(&mut config, &host_wide, protocol);
        if !route.path.is_empty() {
            let scoped: Vec<&EndpointSetting> = self
                .settings
                .iter()
                .copied()
                .filter(|setting| setting.path == route.path)
                .collect();
            apply_settings(&mut config, &scoped, protocol);
        }
        if protocol == Some(L7Protocol::Mcp) {
            // A provider keeps its configured selector and complete effective
            // port set. Other routes select a configured Cedar/settings
            // descriptor; an observed host must never replace a host glob.
            config.endpoint_id = route.provider.map_or_else(
                || {
                    self.mcp_endpoints
                        .iter()
                        .filter(|endpoint| endpoint.path == route.path)
                        .filter(|endpoint| {
                            let ports = if endpoint.ports.is_empty() {
                                std::slice::from_ref(&endpoint.port)
                            } else {
                                &endpoint.ports
                            };
                            ports.contains(&u32::from(self.port))
                                && openshell_core::host_pattern::host_matches(
                                    &endpoint.host,
                                    &self.host,
                                )
                                .unwrap_or(false)
                        })
                        .max_by_key(|endpoint| {
                            (
                                endpoint.host == self.host,
                                endpoint.host.chars().filter(|c| *c != '*').count(),
                            )
                        })
                        .map(openshell_core::endpoint_status::endpoint_id)
                        .unwrap_or_default()
                },
                |endpoint| endpoint.config.endpoint_id.clone(),
            );
        } else {
            config.endpoint_id.clear();
        }
        config
    }
}

/// Returns the Cedar inspection for a config with endpoint path `path`.
///
/// The Cedar path declared as exactly `path`, or else the one the relay
/// would select for a request whose path is the text of `path`: for
/// example, a provider endpoint at `/api/**` takes the inspection of a Cedar
/// path `/api/**` or, failing that, of the path-less Cedar endpoint.
fn inspection_for(
    inspections: &[(String, L7Endpoint)],
    path: &str,
) -> Option<(String, L7Endpoint)> {
    inspections
        .iter()
        .find(|(declared, _)| declared == path)
        .or_else(|| {
            inspections
                .iter()
                .filter(|(declared, _)| crate::l7::endpoint_path_matches(declared, path))
                .max_by_key(|(declared, _)| declared.chars().filter(|c| *c != '*').count())
        })
        .cloned()
}

impl LoadedPolicy {
    /// Returns the policy DNS records, in the order
    /// [`CedarOnlyEngine::policy_dns_eligibility_snapshot`] publishes them;
    /// a record's position is its endpoint index.
    fn dns_records(&self) -> Vec<MatchedEndpoint> {
        self.cedar
            .dns_endpoints()
            .iter()
            .enumerate()
            .map(|(endpoint_index, authorized)| dns_record(endpoint_index, authorized))
            .collect()
    }

    /// Returns the policy DNS records that cover `host:port`, with the
    /// indices the DNS snapshot publishes.
    ///
    /// Matched as policy DNS matches a name against a record, so a
    /// transparent connection whose mapping came from one of these records
    /// correlates with the decision.
    fn matched_endpoints(&self, host: &str, port: u16) -> Vec<MatchedEndpoint> {
        let host = normalize_host(host);
        self.cedar
            .dns_endpoints()
            .iter()
            .enumerate()
            .filter(|(_, authorized)| {
                authorized.ports.contains(&port)
                    && openshell_core::host_pattern::HostSelector::new(
                        std::slice::from_ref(&authorized.host),
                        &[],
                    )
                    .is_ok_and(|selector| selector.matches(&host))
            })
            .map(|(endpoint_index, authorized)| dns_record(endpoint_index, authorized))
            .collect()
    }
}

/// Builds the policy DNS record for one Cedar endpoint, in the shape of a
/// YAML endpoint: `host`, `ports`, `protocol: tcp` for native TCP, and the
/// permits' `destination_ip` ranges as `allowed_ips`, so policy DNS filters
/// answers as it does for that YAML endpoint.
fn dns_record(endpoint_index: usize, authorized: &AuthorizedNetworkEndpoint) -> MatchedEndpoint {
    let endpoint = DnsRecord {
        host: authorized.host.clone(),
        ports: authorized.ports.clone(),
        protocol: authorized
            .transport
            .protocol()
            .map_or(EndpointProtocol::None, EndpointProtocol::from),
        allowed_ips: authorized
            .allowed_ips
            .iter()
            .map(ToString::to_string)
            .collect(),
    };
    MatchedEndpoint {
        policy_name: CEDAR_POLICY_NAME.to_string(),
        endpoint_index,
        endpoint,
    }
}

/// The binary paths a Cedar policy tests in `context.binary_aliases` that
/// are symlinks in the sandbox, with the targets they resolve to.
///
/// YAML adds the target of a symlinked binary path as another binary entry
/// of its policy, which the Rego rules match like any entry: exactly against
/// the process's binary and ancestors, or as a glob when the target contains
/// `*`. A request's aliases are the paths whose targets match it that way,
/// so `context.binary_aliases.contains(P)` holds exactly when that added
/// entry would match.
#[derive(Debug, Default, PartialEq)]
struct BinaryAliases(Vec<(String, AliasTarget)>);

/// The resolved target of one policy binary path.
#[derive(Debug)]
enum AliasTarget {
    /// A target without `*`, compared exactly.
    Exact(String),
    /// A target containing `*`, which the Rego rules match as a glob.
    Glob(String, globset::GlobMatcher),
    /// A target containing `*` that is not a valid glob, which fails Rego
    /// evaluation.
    InvalidGlob(String),
}

impl AliasTarget {
    /// The resolved path.
    fn text(&self) -> &str {
        match self {
            Self::Exact(target) | Self::Glob(target, _) | Self::InvalidGlob(target) => target,
        }
    }
}

/// Targets are equal when they resolved to the same path.
impl PartialEq for AliasTarget {
    fn eq(&self, other: &Self) -> bool {
        self.text() == other.text()
    }
}

impl AliasTarget {
    fn new(target: String) -> Self {
        if !target.contains('*') {
            return Self::Exact(target);
        }
        crate::binary_resolution::compile_binary_glob(&target).map_or_else(
            |_| Self::InvalidGlob(target.clone()),
            |glob| Self::Glob(target.clone(), glob),
        )
    }
}

impl BinaryAliases {
    /// Resolves `paths` in the root filesystem of `entrypoint_pid`, keeping
    /// the symlinks; none when `entrypoint_pid` is 0.
    fn resolve<'a>(paths: impl Iterator<Item = &'a str>, entrypoint_pid: u32) -> Self {
        Self(
            paths
                .filter_map(|path| {
                    let target =
                        crate::binary_resolution::resolve_policy_binary(path, entrypoint_pid)?;
                    Some((path.to_string(), AliasTarget::new(target)))
                })
                .collect(),
        )
    }

    /// Returns the policy binary paths whose targets match `binary_path` or
    /// one of `ancestors`.
    ///
    /// # Errors
    ///
    /// Returns an error when a target is an invalid glob, as Rego evaluation
    /// fails for one. Callers deny the request.
    fn matching(&self, binary_path: &str, ancestors: &[String]) -> Result<Vec<String>> {
        let mut aliases = Vec::new();
        for (path, target) in &self.0 {
            let matched = match target {
                AliasTarget::Exact(target) => {
                    target == binary_path || ancestors.iter().any(|ancestor| ancestor == target)
                }
                AliasTarget::Glob(_, glob) => {
                    glob.is_match(binary_path)
                        || ancestors.iter().any(|ancestor| glob.is_match(ancestor))
                }
                AliasTarget::InvalidGlob(target) => {
                    return Err(miette::miette!(
                        "policy binary {path:?} resolves to {target:?}, which is not a valid glob"
                    ));
                }
            };
            if matched {
                aliases.push(path.clone());
            }
        }
        Ok(aliases)
    }
}

/// The binary glob patterns a Cedar policy and its provider rules test in
/// `context.binary_globs`, compiled with the YAML matcher.
///
/// A YAML binary glob matches the process's binary or any ancestor with
/// `glob.match(pattern, ["/"], path)`. Cedar cannot apply a glob across the
/// `context.ancestors` set, so a request's `binary_globs` lists the patterns
/// that match it that way, and `context.binary_globs.contains(P)` holds
/// exactly when the YAML glob `P` would match.
#[derive(Debug, Default)]
struct BinaryGlobs(Vec<(String, Result<globset::GlobMatcher, String>)>);

/// Sets are equal when they hold the same patterns.
impl PartialEq for BinaryGlobs {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(&other.0)
                .all(|((left, _), (right, _))| left == right)
    }
}

impl BinaryGlobs {
    /// Compiles the patterns `cedar` tests, and those `token_grants` test.
    ///
    /// Analysis rejects a Cedar pattern that does not compile, and the
    /// token-grant compiler fails closed on one that might not, so a failure
    /// here stands in for a Rego evaluation failure and denies the request.
    fn compile(cedar: &CedarEngine, token_grants: Option<&TokenGrantRules>) -> Self {
        let patterns: std::collections::BTreeSet<&str> = cedar
            .binary_glob_patterns()
            .chain(
                token_grants
                    .into_iter()
                    .flat_map(TokenGrantRules::binary_glob_patterns),
            )
            .collect();
        Self(
            patterns
                .into_iter()
                .map(|pattern| {
                    let glob = crate::binary_resolution::compile_binary_glob(pattern)
                        .map_err(|error| error.to_string());
                    (pattern.to_string(), glob)
                })
                .collect(),
        )
    }

    /// Returns the patterns that match `binary_path` or one of `ancestors`.
    ///
    /// # Errors
    ///
    /// Returns an error when a pattern is an invalid glob, as Rego
    /// evaluation fails for one. Callers deny the request.
    fn matching(&self, binary_path: &str, ancestors: &[String]) -> Result<Vec<String>> {
        let mut globs = Vec::new();
        for (pattern, glob) in &self.0 {
            let glob = glob.as_ref().map_err(|error| {
                miette::miette!("policy binary glob {pattern:?} is not a valid glob: {error}")
            })?;
            if glob.is_match(binary_path)
                || ancestors.iter().any(|ancestor| glob.is_match(ancestor))
            {
                globs.push(pattern.clone());
            }
        }
        Ok(globs)
    }
}

/// One attached provider endpoint, used for its credential settings and to
/// narrow the addresses a connection carrying its credentials may reach.
#[derive(Debug, Clone)]
struct ProviderEndpoint {
    /// Lowercased host or host glob; empty for a host-less `allowed_ips`
    /// endpoint, which matches no connection.
    host: String,
    ports: Vec<u16>,
    /// The endpoint's `allowed_ips`, empty for none, or why one is invalid.
    allowed_ips: ProviderRanges,
    /// The endpoint's credential settings, as the L7 config parser reads
    /// them (see [`provider_config`]).
    config: EndpointConfig,
}

/// A provider endpoint's parsed `allowed_ips`, or why an entry is invalid.
pub(crate) type ProviderRanges = std::result::Result<Vec<IpNet>, String>;

/// Parses provider `allowed_ips` entries, each a CIDR range or a bare
/// address, as the proxy parses YAML `allowed_ips`.
fn parse_provider_allowed_ips(entries: &[String]) -> ProviderRanges {
    entries
        .iter()
        .map(|entry| {
            entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| format!("invalid CIDR/IP in provider allowed_ips: {entry}"))
        })
        .collect()
}

impl ProviderEndpoint {
    fn from_proto(endpoint: &openshell_core::proto::NetworkEndpoint) -> Self {
        let ports = if endpoint.ports.is_empty() {
            vec![endpoint.port]
        } else {
            endpoint.ports.clone()
        };
        Self {
            host: endpoint.host.to_ascii_lowercase(),
            ports: ports
                .into_iter()
                .filter_map(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .collect(),
            allowed_ips: parse_provider_allowed_ips(&endpoint.allowed_ips),
            config: provider_config(endpoint),
        }
    }

    /// Matches like the Rego `endpoint_matches_request` rule, except that a
    /// host-less endpoint matches nothing.
    ///
    /// YAML matches a host-less endpoint by its `allowed_ips`, which also
    /// restrict the connection's addresses. Providers grant no access on a
    /// Cedar sandbox, so such an endpoint would lend its credentials to every
    /// host on its ports.
    fn matches(&self, host: &str, port: u16) -> bool {
        if !self.ports.contains(&port) || self.host.is_empty() {
            return false;
        }
        if self.host.contains('*') {
            openshell_core::host_pattern::host_matches(&self.host, host).unwrap_or(false)
        } else {
            self.host == host
        }
    }
}

/// One `endpoint_settings` entry: an endpoint selector and its settings.
#[derive(Debug, Clone)]
struct EndpointSetting {
    /// Lowercased host or host glob.
    host: String,
    ports: Vec<u16>,
    /// Endpoint path glob; empty for every path.
    path: String,
    /// The settings the entry sets.
    fields: SettingFields,
}

/// The endpoint config settings an `endpoint_settings` entry can set; `None`
/// leaves a config's value alone.
///
/// Settings the proto leaves at its default are not set, as the YAML
/// endpoint conversion omits them.
#[derive(Debug, Clone, Default)]
struct SettingFields {
    tls: Option<TlsSetting>,
    allow_encoded_slash: Option<bool>,
    json_rpc_max_body_bytes: Option<u64>,
    graphql_max_body_bytes: Option<u64>,
    mcp_strict_tool_names: Option<bool>,
    persisted_queries: Option<String>,
    graphql_persisted_queries: Option<std::collections::BTreeMap<String, GraphqlPersistedQuery>>,
    mcp_versions: Option<Vec<String>>,
}

impl EndpointSetting {
    fn from_proto(setting: &openshell_core::proto::NetworkEndpoint) -> Self {
        let ports = if setting.ports.is_empty() {
            vec![setting.port]
        } else {
            setting.ports.clone()
        };
        // Only the settings the gateway accepts in `endpoint_settings`, set
        // as the YAML endpoint conversion sets them.
        let mcp = setting.mcp.as_ref();
        let fields = SettingFields {
            tls: (setting.tls != 0).then(|| TlsSetting::from_proto(setting.tls)),
            allow_encoded_slash: setting.allow_encoded_slash.then_some(true),
            json_rpc_max_body_bytes: (setting.json_rpc_max_body_bytes > 0)
                .then_some(u64::from(setting.json_rpc_max_body_bytes)),
            graphql_max_body_bytes: (setting.graphql_max_body_bytes > 0)
                .then_some(u64::from(setting.graphql_max_body_bytes)),
            mcp_strict_tool_names: mcp.and_then(|mcp| mcp.strict_tool_names),
            persisted_queries: (!setting.persisted_queries.is_empty())
                .then(|| setting.persisted_queries.clone()),
            graphql_persisted_queries: (!setting.graphql_persisted_queries.is_empty())
                .then(|| graphql_persisted_queries(&setting.graphql_persisted_queries)),
            // The YAML conversion emits MCP revisions only for an MCP
            // endpoint; a setting carries no protocol.
            mcp_versions: mcp.filter(|mcp| !mcp.versions.is_empty()).map(|mcp| {
                let mut versions = mcp.versions.clone();
                openshell_core::mcp::canonicalize_mcp_versions(&mut versions);
                versions
            }),
        };
        Self {
            host: setting.host.to_ascii_lowercase(),
            ports: ports
                .into_iter()
                .filter_map(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .collect(),
            path: setting.path.clone(),
            fields,
        }
    }

    /// Matches like the Rego `endpoint_matches_request` rule.
    fn matches(&self, host: &str, port: u16) -> bool {
        if !self.ports.contains(&port) || self.host.is_empty() {
            return false;
        }
        if self.host.contains('*') {
            openshell_core::host_pattern::host_matches(&self.host, host).unwrap_or(false)
        } else {
            self.host == host
        }
    }
}

/// Converts proto `graphql_persisted_queries` into the typed registry.
fn graphql_persisted_queries(
    queries: &HashMap<String, openshell_core::proto::GraphqlOperation>,
) -> std::collections::BTreeMap<String, GraphqlPersistedQuery> {
    queries
        .iter()
        .map(|(key, op)| {
            (
                key.clone(),
                GraphqlPersistedQuery {
                    operation_type: op.operation_type.clone(),
                    operation_name: op.operation_name.clone(),
                    fields: op.fields.clone(),
                },
            )
        })
        .collect()
}

/// Copies `settings` into `config`, later entries overriding earlier ones.
///
/// Protocol options apply only where Cedar selects that protocol, as YAML
/// rejects or ignores them on other endpoints. A plain WebSocket endpoint
/// takes no GraphQL option: a persisted-query setting would turn on the
/// GraphQL message policy Cedar did not declare.
fn apply_settings(
    config: &mut EndpointConfig,
    settings: &[&EndpointSetting],
    protocol: Option<L7Protocol>,
) {
    let jsonrpc_family = matches!(protocol, Some(L7Protocol::JsonRpc | L7Protocol::Mcp));
    let mcp = protocol == Some(L7Protocol::Mcp);
    let graphql = matches!(
        protocol,
        Some(L7Protocol::Graphql | L7Protocol::WebsocketGraphql)
    );
    for setting in settings {
        let fields = &setting.fields;
        if let Some(tls) = fields.tls {
            config.tls = tls;
        }
        if let Some(allow) = fields.allow_encoded_slash {
            config.allow_encoded_slash = allow;
        }
        if jsonrpc_family && let Some(bytes) = fields.json_rpc_max_body_bytes {
            config.json_rpc_max_body_bytes = bytes;
        }
        if mcp {
            if let Some(strict) = fields.mcp_strict_tool_names {
                config.mcp_strict_tool_names = Some(strict);
            }
            if let Some(versions) = &fields.mcp_versions {
                config.mcp_versions.clone_from(versions);
            }
        }
        if graphql {
            if let Some(bytes) = fields.graphql_max_body_bytes {
                config.graphql_max_body_bytes = bytes;
            }
            if let Some(mode) = &fields.persisted_queries {
                config.persisted_queries.clone_from(mode);
            }
            if let Some(queries) = &fields.graphql_persisted_queries {
                config.graphql_persisted_queries.clone_from(queries);
            }
        }
    }
}

/// Builds a provider endpoint's config: its credential settings only.
///
/// Settings that describe access, per-request rules, or inspection mode
/// (`allowed_ips`, `protocol`, `enforcement`, `access`, rules, persisted
/// queries and MCP options) are left unset: on a Cedar
/// sandbox, Cedar's `HttpRequest` policies are the per-request rules and
/// decide inspection, and the proxy checks addresses with the connection's
/// [`CedarDestination`], which carries provider `allowed_ips` separately so
/// they can only narrow what Cedar admits.
fn provider_config(endpoint: &openshell_core::proto::NetworkEndpoint) -> EndpointConfig {
    let ports = if endpoint.ports.is_empty() {
        (endpoint.port > 0)
            .then_some(endpoint.port)
            .into_iter()
            .collect()
    } else {
        endpoint.ports.clone()
    };
    EndpointConfig {
        endpoint_id: openshell_core::endpoint_status::endpoint_id(endpoint),
        host: endpoint.host.clone(),
        ports: ports
            .into_iter()
            .filter_map(|port| u16::try_from(port).ok())
            .collect(),
        path: endpoint.path.clone(),
        tls: TlsSetting::from_proto(endpoint.tls),
        allow_encoded_slash: endpoint.allow_encoded_slash,
        websocket_credential_rewrite: endpoint.websocket_credential_rewrite,
        request_body_credential_rewrite: endpoint.request_body_credential_rewrite,
        allow_uninspected_credentials: endpoint.allow_uninspected_credentials,
        provider_credentialed: endpoint.provider_credentialed,
        credential_signing: endpoint.credential_signing.clone(),
        signing_service: endpoint.signing_service.clone(),
        signing_region: endpoint.signing_region.clone(),
        graphql_max_body_bytes: u64::from(endpoint.graphql_max_body_bytes),
        json_rpc_max_body_bytes: u64::from(endpoint.json_rpc_max_body_bytes),
        ..EndpointConfig::default()
    }
}

/// Sets how the relay inspects requests with `config`.
///
/// MCP endpoints also carry the MCP revision list the relay requires, set to
/// the same default a YAML MCP endpoint without `mcp.versions` gets. An
/// endpoint setting with `mcp.versions` replaces it. A `websocket-graphql`
/// endpoint is a `websocket` endpoint with `websocket_graphql_policy` set,
/// which a YAML endpoint gets from its GraphQL operation rules.
fn apply_inspection(config: &mut EndpointConfig, inspection: L7Endpoint) {
    config.protocol = EndpointProtocol::from(inspection.protocol.config_label());
    config.websocket_graphql_policy = inspection.protocol.websocket_graphql_messages();
    config.enforcement = EnforcementSetting::from(inspection.enforcement.as_str());
    if inspection.protocol == L7Protocol::Mcp {
        config.mcp_versions = vec![
            openshell_policy_schema::DEFAULT_MCP_PROTOCOL_VERSION
                .as_str()
                .to_string(),
        ];
    }
}

/// The Cedar text, provider rules, and endpoint settings a [`LoadedPolicy`]
/// was built from.
///
/// Compared on reload so an unchanged policy keeps the current generation.
#[derive(Debug, Clone, PartialEq)]
struct PolicyInputs {
    source: String,
    /// Provider rules sorted by key; protobuf maps have no stable order.
    provider_rules: Vec<(String, NetworkPolicyRule)>,
    /// Endpoint settings, in order: a later entry overrides an earlier one.
    endpoint_settings: Vec<openshell_core::proto::NetworkEndpoint>,
}

impl PolicyInputs {
    /// The provider rules, keyed as the policy delivered them.
    fn provider_rule_map(&self) -> HashMap<String, NetworkPolicyRule> {
        self.provider_rules.iter().cloned().collect()
    }

    fn from_proto(policy: &ProtoSandboxPolicy) -> Self {
        let mut provider_rules: Vec<_> = policy
            .provider_credential_rules
            .iter()
            .map(|(key, rule)| (key.clone(), rule.clone()))
            .collect();
        provider_rules.sort_by(|left, right| left.0.cmp(&right.0));
        Self {
            source: policy.cedar_policy_source.clone(),
            provider_rules,
            endpoint_settings: policy.endpoint_settings.clone(),
        }
    }
}

/// Builds a policy holding only Cedar text, for callers without provider rules.
fn policy_from_source(policy_src: &str) -> ProtoSandboxPolicy {
    ProtoSandboxPolicy {
        cedar_policy_source: policy_src.to_string(),
        ..Default::default()
    }
}

/// Cedar-backed, fully authoritative network policy evaluator.
///
/// No hidden fallback to OPA: a sandbox either uses this engine for every
/// network decision, or [`crate::opa::OpaEngine`] for every network
/// decision, chosen once at policy load.
#[derive(Debug)]
pub struct CedarOnlyEngine {
    /// Sandbox-wide admission survives policy reloads and is shared by forward
    /// requests and CONNECT tunnels.
    websocket_assembly_budget: crate::l7::websocket::WebSocketAssemblyBudget,
    /// Shared with every [`CedarL7TunnelEngine`] handed out by
    /// [`Self::l7_handle`].
    engine: Arc<RwLock<LoadedPolicy>>,
    /// What the active policy was built from, so a reload with unchanged
    /// inputs keeps the generation. Advancing it would close every inspected
    /// tunnel on each policy-poll reconciliation, even one unrelated to this
    /// sandbox's policy (for example a middleware registry change).
    inputs: RwLock<PolicyInputs>,
    generation: Arc<AtomicU64>,
    generation_tx: watch::Sender<u64>,
    /// Set while a fail-closed quarantine is active: every connection is
    /// denied with this reason, and no name is eligible for policy DNS.
    /// Changed only while the engine write lock is held.
    fail_closed_reason: RwLock<Option<String>>,
    /// The policy's `network_middlewares` and the connected services, with
    /// a generation independent of the policy generation.
    middleware: MiddlewareState,
}

impl CedarOnlyEngine {
    /// Builds the engine from a policy's Cedar text, provider rules,
    /// endpoint settings, and network middlewares.
    ///
    /// The engine starts with no middleware services connected; see
    /// [`crate::policy_engine::PolicyEngine::replace_middleware_registry`].
    ///
    /// The policy gets the validation every gateway-delivered policy gets
    /// (see [`crate::policy_validation::validate_sandbox_policy`]), as
    /// `OpaEngine::from_proto` validates a YAML policy, and the engine is
    /// built from the canonical form the validator returns.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy fails validation, or its Cedar text
    /// fails to parse, fails schema validation, or uses a policy shape Cedar
    /// cannot enforce exactly.
    pub fn from_proto(policy: &ProtoSandboxPolicy) -> Result<Self> {
        let policy = crate::policy_validation::validate_sandbox_policy(policy)?;
        let loaded = LoadedPolicy::from_proto(&policy, 0)?;
        let (generation_tx, _) = watch::channel(0);
        Ok(Self {
            websocket_assembly_budget: crate::l7::websocket::WebSocketAssemblyBudget::default(),
            engine: Arc::new(RwLock::new(loaded)),
            inputs: RwLock::new(PolicyInputs::from_proto(&policy)),
            generation: Arc::new(AtomicU64::new(0)),
            generation_tx,
            fail_closed_reason: RwLock::new(None),
            middleware: MiddlewareState::new(MiddlewareConfigs::from_proto(&policy)),
        })
    }

    /// Builds the engine from Cedar text alone, with no provider rules.
    ///
    /// # Errors
    ///
    /// Returns an error if `policy_src` fails to load (see [`Self::from_proto`]).
    pub fn from_policy_str(policy_src: &str) -> Result<Self> {
        Self::from_proto(&policy_from_source(policy_src))
    }

    /// Returns the active policy generation, advanced by each committed reload.
    #[must_use]
    pub fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(crate) fn websocket_assembly_budget(
        &self,
    ) -> crate::l7::websocket::WebSocketAssemblyBudget {
        self.websocket_assembly_budget.clone()
    }

    /// Returns the sandbox's middleware configs, services, and generation.
    pub(crate) fn middleware(&self) -> &MiddlewareState {
        &self.middleware
    }

    /// Builds the L7 decision handle for a tunnel pinned at `captured_generation`.
    pub(crate) fn l7_handle(&self, captured_generation: u64) -> CedarL7TunnelEngine {
        CedarL7TunnelEngine {
            engine: Arc::clone(&self.engine),
            generation: Arc::clone(&self.generation),
            captured_generation,
        }
    }

    /// Pins `expected_generation` for a long-lived operation.
    ///
    /// # Errors
    ///
    /// Returns an error if `expected_generation` is already stale.
    pub fn generation_guard(&self, expected_generation: u64) -> Result<PolicyGenerationGuard> {
        generation_guard_for(
            expected_generation,
            self.current_generation(),
            &self.generation,
            &self.generation_tx,
        )
    }

    /// Runs `operation` only while `expected_generation` is current.
    ///
    /// Holds the engine read lock across the check and `operation`, so no
    /// reload can commit between them. `operation` must not block.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn with_current_generation<T>(
        &self,
        expected_generation: u64,
        operation: impl FnOnce(u64) -> T,
    ) -> Result<Option<T>> {
        let _engine = self.read_engine()?;
        let current_generation = self.current_generation();
        if current_generation != expected_generation {
            return Ok(None);
        }
        Ok(Some(operation(current_generation)))
    }

    fn read_engine(&self) -> Result<std::sync::RwLockReadGuard<'_, LoadedPolicy>> {
        self.engine
            .read()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))
    }

    /// Test-only: the analysis warnings the active policy loaded with.
    ///
    /// # Panics
    ///
    /// Panics if the engine lock is poisoned.
    #[cfg(test)]
    fn warnings_for_tests(&self) -> Vec<openshell_policy_cedar::AnalysisWarning> {
        self.read_engine()
            .expect("engine lock")
            .cedar
            .warnings()
            .to_vec()
    }

    /// Rebuilds the engine from a freshly reloaded policy and advances the
    /// generation counter. Call this directly alongside wherever
    /// `OpaEngine::reload*` would be called for a YAML-sourced sandbox.
    ///
    /// A no-op (generation unchanged) when `policy_src` is byte-identical
    /// to what's already loaded — see the `source` field doc.
    ///
    /// # Errors
    ///
    /// Returns an error if `policy_src` fails to load (see
    /// [`Self::from_policy_str`]). On error, the
    /// previous policy and generation stay active (last-known-good,
    /// matching `OpaEngine`'s reload failure behavior).
    pub fn reload_from_policy_str(&self, policy_src: &str) -> Result<()> {
        let staged = self.stage(&policy_from_source(policy_src), 0)?;
        self.commit(staged)
    }

    /// Validates and parses `policy` without activating it.
    ///
    /// Lets a caller validate the Cedar policy before committing any other
    /// engine's reload, so a rejected Cedar policy leaves every engine on
    /// the previous revision. Pass the result to [`Self::commit`].
    ///
    /// The policy gets the same validation as in [`Self::from_proto`], and
    /// the staged policy is built from the canonical form the validator
    /// returns. Its binary paths are resolved in the root filesystem of
    /// `entrypoint_pid`, as `OpaEngine::reload_from_proto_with_pid` resolves
    /// a YAML policy's. A pid of 0 keeps the one the active policy was
    /// resolved with, if any (see [`Self::resolve_binary_symlinks`]).
    ///
    /// # Errors
    ///
    /// Returns an error if `policy` fails validation or fails to load (see
    /// [`Self::from_proto`]), or the engine lock is poisoned.
    pub fn stage(
        &self,
        policy: &ProtoSandboxPolicy,
        entrypoint_pid: u32,
    ) -> Result<StagedCedarPolicy> {
        let policy = crate::policy_validation::validate_sandbox_policy(policy)?;
        let entrypoint_pid = match entrypoint_pid {
            0 => self.read_engine()?.entrypoint_pid,
            pid => pid,
        };
        let middleware = MiddlewareConfigs::from_proto(&policy);
        let inputs = PolicyInputs::from_proto(&policy);
        let unchanged = *self.read_inputs()? == inputs;
        if unchanged {
            return Ok(StagedCedarPolicy {
                policy: None,
                entrypoint_pid,
                middleware,
            });
        }
        let loaded = LoadedPolicy::from_proto(&policy, entrypoint_pid)?;
        Ok(StagedCedarPolicy {
            policy: Some((loaded, inputs)),
            entrypoint_pid,
            middleware,
        })
    }

    /// Activates a policy returned by [`Self::stage`], with its middleware.
    ///
    /// Equivalent to [`Self::commit_configuration`] with no new middleware
    /// services and no credentials to publish.
    ///
    /// # Errors
    ///
    /// See [`Self::commit_configuration`].
    pub fn commit(&self, staged: StagedCedarPolicy) -> Result<()> {
        self.commit_configuration(staged, None, || {}).map(drop)
    }

    /// Activates a staged policy, its middleware, and the caller's
    /// credentials as one runtime configuration, or changes nothing.
    ///
    /// Everything that can fail runs first, before any lock is taken: the
    /// staged policy (or, when the inputs were unchanged, a copy of the
    /// active one) is resolved for the entrypoint process (see
    /// [`Self::prepare_policy`]). Then, under the middleware write lock, the
    /// engine's own locks are acquired; the middleware generation advances,
    /// so pinned middleware readers are stale; the Cedar policy is swapped
    /// in and its generation advances when the policy changed, which closes
    /// inspected tunnels; `commit_credentials` runs; and only then do the
    /// new middleware configs and, when given, `registry` become visible.
    /// Middleware readers stay blocked throughout. An unchanged Cedar policy
    /// keeps its generation, so a middleware-only change does not close
    /// inspected tunnels; they keep the middleware they started with.
    ///
    /// `commit_credentials` must be infallible and must not call back into
    /// this engine.
    ///
    /// Returns a guard on the middleware generation this commit published.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider rules fail to compile for the
    /// entrypoint process, or a lock is poisoned. In either case the policy,
    /// the middleware, and the credentials all stay on the previous revision,
    /// no guard becomes stale, and `commit_credentials` is not called.
    pub fn commit_configuration(
        &self,
        staged: StagedCedarPolicy,
        registry: Option<MiddlewareRegistry>,
        commit_credentials: impl FnOnce(),
    ) -> Result<PolicyGenerationGuard> {
        let StagedCedarPolicy {
            policy,
            entrypoint_pid,
            middleware,
        } = staged;
        let prepared = self.prepare_policy(policy, entrypoint_pid)?;
        self.middleware.commit(
            middleware,
            registry,
            || self.write_locks(),
            |locks| {
                self.publish_policy(locks, prepared);
                commit_credentials();
            },
        )
    }

    /// Resolves the policy a commit will activate, for the entrypoint process.
    ///
    /// A policy staged before the entrypoint process was known is resolved
    /// for it here. When the staged inputs matched the active policy's, the
    /// active policy is resolved again once the entrypoint process is known,
    /// as a YAML reload rebuilds its engine and resolves every binary path
    /// again: a symlink retargeted since the last resolution must not keep
    /// its old alias. Takes only read locks, and none across the resolution.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider rules fail to compile for the
    /// entrypoint process, or the engine lock is poisoned.
    fn prepare_policy(
        &self,
        policy: Option<(LoadedPolicy, PolicyInputs)>,
        entrypoint_pid: u32,
    ) -> Result<PreparedPolicy> {
        let entrypoint_pid = match entrypoint_pid {
            0 => self.read_engine()?.entrypoint_pid,
            pid => pid,
        };
        match policy {
            Some((loaded, inputs)) => {
                let loaded = if loaded.entrypoint_pid == entrypoint_pid {
                    loaded
                } else {
                    loaded.resolved_for(&inputs.provider_rule_map(), entrypoint_pid)?
                };
                Ok(PreparedPolicy::Replaced(loaded, inputs))
            }
            None if entrypoint_pid != 0 => {
                // The read lock is held across the resolution, which reads
                // the entrypoint's root filesystem; the swap compares the
                // result against the active policy again under the write lock.
                let active = self.read_engine()?;
                let rules = self.read_inputs()?.provider_rule_map();
                let resolved = active.resolved_for(&rules, entrypoint_pid)?;
                Ok(PreparedPolicy::Resolved(resolved))
            }
            None => Ok(PreparedPolicy::Unchanged),
        }
    }

    /// Acquires every lock a publish writes, in the engine's lock order.
    ///
    /// # Errors
    ///
    /// Returns an error if any of them is poisoned.
    fn write_locks(&self) -> Result<WriteLocks<'_>> {
        Ok(WriteLocks {
            engine: self.write_engine()?,
            inputs: self
                .inputs
                .write()
                .map_err(|_| miette::miette!("Cedar engine lock poisoned"))?,
            fail_closed_reason: self.write_fail_closed_reason()?,
        })
    }

    /// Swaps `prepared` into the active policy and ends any quarantine.
    ///
    /// The generation advances when the policy changed, when a resolved
    /// alias or the entrypoint process changed, or when a quarantine ended.
    /// Infallible: every lock is already held.
    fn publish_policy(&self, locks: WriteLocks<'_>, prepared: PreparedPolicy) {
        let WriteLocks {
            mut engine,
            mut inputs,
            mut fail_closed_reason,
        } = locks;
        let was_fail_closed = fail_closed_reason.take().is_some();
        let changed = match prepared {
            PreparedPolicy::Unchanged => false,
            PreparedPolicy::Resolved(resolved) => {
                let changed = engine.resolution_differs(&resolved);
                *engine = resolved;
                changed
            }
            PreparedPolicy::Replaced(loaded, new_inputs) => {
                *engine = loaded;
                *inputs = new_inputs;
                true
            }
        };
        if changed || was_fail_closed {
            self.advance_generation();
        }
    }

    /// Resolves the active policy's binary paths in the root filesystem of
    /// the entrypoint process, once it is known.
    ///
    /// The Cedar counterpart of rebuilding the OPA engine with
    /// `OpaEngine::reload_from_proto_with_pid` when the entrypoint starts:
    /// each path policies test in `context.binary_aliases`, and each
    /// provider rule binary used to select token-grant owners, is resolved
    /// as YAML resolves its binary paths. A no-op for 0 or for the pid the
    /// policy was already resolved with; otherwise advances the generation.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned, or the provider rules
    /// fail to load for the entrypoint process; the active policy is
    /// unchanged then.
    pub fn resolve_binary_symlinks(&self, entrypoint_pid: u32) -> Result<()> {
        let mut guard = self.write_engine()?;
        if entrypoint_pid == 0 || guard.entrypoint_pid == entrypoint_pid {
            return Ok(());
        }
        let rules = self.read_inputs()?.provider_rule_map();
        let resolved = guard.resolved_for(&rules, entrypoint_pid)?;
        if guard.resolution_differs(&resolved) {
            *guard = resolved;
            self.advance_generation();
        }
        Ok(())
    }

    fn read_inputs(&self) -> Result<std::sync::RwLockReadGuard<'_, PolicyInputs>> {
        self.inputs
            .read()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))
    }

    /// Publishes a deny-all quarantine generation without activating any
    /// part of a rejected candidate policy.
    ///
    /// The active Cedar policy stays loaded for a later
    /// [`Self::exit_fail_closed`] or valid reload, but every new connection
    /// is denied with `reason`. A quarantine is a configuration change: the
    /// Cedar generation advances, which closes every pinned tunnel, and so
    /// does the middleware generation, which stales the configuration guard
    /// the policy poll loop watches (see
    /// [`crate::policy_engine::PolicyEngine::configuration_generation_guard`]),
    /// as `OpaEngine::enter_fail_closed` stales both with its one counter.
    ///
    /// Returns the new Cedar generation.
    ///
    /// # Errors
    ///
    /// Returns an error if a lock is poisoned.
    pub fn enter_fail_closed(&self, reason: impl Into<String>) -> Result<u64> {
        let reason = reason.into();
        // Lock order: middleware, then engine, as a commit takes them.
        self.middleware.change_configuration(|| {
            let _guard = self.write_engine()?;
            *self.write_fail_closed_reason()? = Some(reason);
            Ok((self.advance_generation(), true))
        })
    }

    /// Reactivates the active policy after a quarantine.
    ///
    /// Returns the current Cedar generation, advanced only if a quarantine
    /// ended; the middleware generation advances with it, so the
    /// configuration guard pinned during the quarantine becomes stale.
    ///
    /// # Errors
    ///
    /// Returns an error if a lock is poisoned.
    pub fn exit_fail_closed(&self) -> Result<u64> {
        self.middleware.change_configuration(|| {
            let _guard = self.write_engine()?;
            if self.write_fail_closed_reason()?.take().is_some() {
                Ok((self.advance_generation(), true))
            } else {
                Ok((self.current_generation(), false))
            }
        })
    }

    /// Returns the quarantine reason while a fail-closed quarantine is active.
    #[must_use]
    pub fn fail_closed_reason(&self) -> Option<String> {
        self.fail_closed_reason
            .read()
            .ok()
            .and_then(|reason| reason.clone())
    }

    fn write_engine(&self) -> Result<std::sync::RwLockWriteGuard<'_, LoadedPolicy>> {
        self.engine
            .write()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))
    }

    fn write_fail_closed_reason(&self) -> Result<std::sync::RwLockWriteGuard<'_, Option<String>>> {
        self.fail_closed_reason
            .write()
            .map_err(|_| miette::miette!("Cedar fail-closed state lock poisoned"))
    }

    fn read_fail_closed_reason(&self) -> Result<Option<String>> {
        Ok(self
            .fail_closed_reason
            .read()
            .map_err(|_| miette::miette!("Cedar fail-closed state lock poisoned"))?
            .clone())
    }

    /// Advances the generation. Callers hold the engine write lock, so a
    /// reader that observes the new generation under the read lock also sees
    /// the state that produced it.
    fn advance_generation(&self) -> u64 {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.generation_tx.send_replace(generation);
        generation
    }

    /// Returns the Landlock path grants the loaded policy authorizes.
    ///
    /// See [`openshell_policy_cedar::CedarEngine::filesystem_grants`].
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn filesystem_grants(&self) -> Result<openshell_policy_cedar::FilesystemGrants> {
        Ok(self.read_engine()?.cedar.filesystem_grants().clone())
    }

    /// See [`openshell_policy_cedar::CedarEngine::has_network_permits`].
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn has_network_permits(&self) -> Result<bool> {
        Ok(self.read_engine()?.cedar.has_network_permits())
    }
}

/// A validated Cedar policy waiting for [`CedarOnlyEngine::commit`].
#[derive(Debug)]
pub struct StagedCedarPolicy {
    /// `None` when the staged inputs matched the active policy's.
    policy: Option<(LoadedPolicy, PolicyInputs)>,
    /// The entrypoint process the policy is to be resolved for; 0 if unknown.
    entrypoint_pid: u32,
    /// The candidate's `network_middlewares`, activated with the policy.
    middleware: MiddlewareConfigs,
}

impl StagedCedarPolicy {
    /// Test-only: makes resolving this policy for the entrypoint process
    /// fail at commit, as provider rules that do not compile for it would.
    ///
    /// # Panics
    ///
    /// Panics if the staged inputs matched the active policy's.
    #[cfg(test)]
    fn fail_binary_resolution_for_tests(&mut self) {
        let (loaded, _) = self.policy.as_mut().expect("a changed policy is staged");
        loaded.fail_resolution = true;
    }
}

/// The policy a commit swaps in, resolved before any lock is taken.
#[derive(Debug)]
enum PreparedPolicy {
    /// The staged inputs matched the active policy's, and the entrypoint
    /// process is not known yet.
    Unchanged,
    /// The active policy, resolved again for the entrypoint process.
    Resolved(LoadedPolicy),
    /// A changed policy and the inputs it was built from.
    Replaced(LoadedPolicy, PolicyInputs),
}

/// Every lock a publish writes, acquired under the middleware write lock.
struct WriteLocks<'a> {
    engine: std::sync::RwLockWriteGuard<'a, LoadedPolicy>,
    inputs: std::sync::RwLockWriteGuard<'a, PolicyInputs>,
    fail_closed_reason: std::sync::RwLockWriteGuard<'a, Option<String>>,
}

impl CedarOnlyEngine {
    /// Authorizes one egress request against the active Cedar policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned, or Cedar fails to
    /// evaluate the request. Callers deny the connection on error.
    pub fn authorize_egress(&self, input: &NetworkInput) -> Result<EgressAuthorization> {
        let mut request = network_request_from_input(input);
        let guard = self.read_engine()?;
        let generation = self.current_generation();
        if let Some(reason) = self.read_fail_closed_reason()? {
            return Ok(EgressAuthorization {
                action: NetworkAction::Deny { reason },
                endpoint_configs: Vec::new(),
                matched_endpoints: Vec::new(),
                exact_declared_endpoint_host: false,
                generation,
                cedar_destination: None,
            });
        }
        request.binary_aliases = guard
            .binary_aliases
            .matching(&request.binary_path, &request.ancestors)?;
        request.binary_globs = guard
            .binary_globs
            .matching(&request.binary_path, &request.ancestors)?;
        // Decided before the host resolves: an allow means Cedar allows some
        // address, and `cedar_destination` checks each resolved one.
        let evaluation = guard
            .cedar
            .authorize_network(&request)
            .map_err(|e| miette::miette!("{e}"))?;

        let action = match evaluation.decision.clone() {
            Decision::Allow { matched_policies } => NetworkAction::Allow {
                matched_policy: matched_policies.into_iter().next(),
            },
            Decision::Deny { matched_policies } => NetworkAction::Deny {
                reason: if matched_policies.is_empty() {
                    "no Cedar policy permits this endpoint/binary".to_string()
                } else {
                    format!("denied by Cedar policy (forbid matched: {matched_policies:?})")
                },
            },
        };

        let allowed = matches!(action, NetworkAction::Allow { .. });
        // Without these, an allowed CONNECT is relayed without inspection
        // and without provider credential settings.
        let endpoint_configs = if allowed {
            guard.endpoint_configs(&request.host, request.port)
        } else {
            Vec::new()
        };
        // Matches the YAML path: an allowed connection to a host a matching
        // policy names exactly (not through a glob) may resolve to private
        // addresses. For Cedar, that is an allowing permit that names this
        // `host:port`.
        let exact_declared_endpoint_host = allowed && evaluation.names_endpoint;
        // Correlates the decision with the policy DNS mapping a transparent
        // connection dialed; see the module docs.
        let matched_endpoints = if allowed {
            guard.matched_endpoints(&request.host, request.port)
        } else {
            Vec::new()
        };

        let cedar_destination = allowed.then(|| CedarDestination {
            engine: Arc::clone(&guard.cedar),
            provider_ranges: guard.provider_ranges(&request.host, request.port),
            request,
            evaluation,
        });

        Ok(EgressAuthorization {
            action,
            endpoint_configs,
            matched_endpoints,
            exact_declared_endpoint_host,
            generation,
            cedar_destination,
        })
    }

    /// Returns the endpoint settings the credential guard checks for `host:port`.
    ///
    /// The same configs [`Self::authorize_egress`] returns for an allowed
    /// connection, including every path-scoped provider endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn credential_guards(&self, host: &str, port: u16) -> Result<Vec<EndpointConfig>> {
        Ok(self.read_engine()?.endpoint_configs(host, port))
    }

    /// Returns the endpoints eligible for policy-gated DNS resolution.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine lock is poisoned.
    pub fn policy_dns_eligibility_snapshot(&self) -> Result<PolicyDnsEligibilitySnapshot> {
        let guard = self.read_engine()?;
        let generation = self.current_generation();
        if self.read_fail_closed_reason()?.is_some() {
            return Ok(PolicyDnsEligibilitySnapshot {
                endpoints: Vec::new(),
                generation,
                fail_closed: true,
            });
        }
        Ok(PolicyDnsEligibilitySnapshot {
            endpoints: guard.dns_records(),
            generation,
            fail_closed: false,
        })
    }
}

/// How the resolved addresses of one allowed Cedar connection are checked.
///
/// Carries the connection's decision made before its host resolved, and the
/// policy that made it, so each resolved address is evaluated against the
/// same policy generation. The admission rules that use it live in
/// `proxy::destination`.
#[derive(Clone)]
pub struct CedarDestination {
    engine: Arc<CedarEngine>,
    request: NetworkConnectRequest,
    evaluation: NetworkEvaluation,
    /// The `allowed_ips` of the matching provider endpoints that have them.
    provider_ranges: Vec<ProviderRanges>,
}

impl CedarDestination {
    /// The `allowed_ips` of each matching provider endpoint that has them.
    ///
    /// Each must admit every address, but they never admit an address
    /// Cedar's own rules reject: providers grant no access.
    pub(crate) fn provider_ranges(&self) -> &[ProviderRanges] {
        &self.provider_ranges
    }

    /// The `destination_ip` ranges of each allowing permit that has them.
    pub(crate) fn address_conditions(&self) -> &[Vec<IpNet>] {
        &self.evaluation.address_conditions
    }

    /// Whether an allowing permit has no `destination_ip` condition.
    pub(crate) fn unconstrained_permit(&self) -> bool {
        self.evaluation.unconstrained_permit
    }

    /// Whether an allowing permit names the connection's host and port
    /// exactly.
    pub(crate) fn names_endpoint(&self) -> bool {
        self.evaluation.names_endpoint
    }

    /// Returns whether Cedar allows the connection to resolved address `ip`,
    /// with every policy: permits with their `destination_ip` ranges, and
    /// forbids with their address conditions, which were false in the
    /// CONNECT-time decision made with the address absent.
    ///
    /// # Errors
    ///
    /// Returns the evaluation error; callers reject the address.
    pub(crate) fn allows(&self, ip: IpAddr) -> std::result::Result<bool, String> {
        let request = NetworkConnectRequest {
            destination_ip: Some(ip),
            ..self.request.clone()
        };
        self.engine
            .evaluate_network(&request)
            .map(|decision| decision.is_allow())
            .map_err(|e| e.to_string())
    }
}

impl std::fmt::Debug for CedarDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CedarDestination")
            .field("request", &self.request)
            .field("evaluation", &self.evaluation)
            .field("provider_ranges", &self.provider_ranges)
            .finish_non_exhaustive()
    }
}

impl PartialEq for CedarDestination {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.engine, &other.engine)
            && self.request == other.request
            && self.evaluation == other.evaluation
            && self.provider_ranges == other.provider_ranges
    }
}

impl Eq for CedarDestination {}

/// Per-tunnel L7 decision handle for a Cedar-sourced sandbox.
///
/// Unlike a YAML tunnel's Rego evaluator, this needs no actual
/// per-tunnel engine clone — `Authorizer`/`PolicySet` are immutable, so
/// concurrent evaluation is just concurrent `RwLock::read()` calls, same as
/// [`CedarOnlyEngine::authorize_egress`]. Only `captured_generation` is
/// per-tunnel state.
#[derive(Debug)]
pub(crate) struct CedarL7TunnelEngine {
    engine: Arc<RwLock<LoadedPolicy>>,
    generation: Arc<AtomicU64>,
    captured_generation: u64,
}

impl CedarL7TunnelEngine {
    /// Evaluates one L7 request and returns `(allowed, deny_reason)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the tunnel's generation is stale, the engine lock
    /// is poisoned, or Cedar fails to evaluate the request.
    pub(crate) fn evaluate_request(
        &self,
        ctx: &crate::l7::relay::L7EvalContext,
        request: &crate::l7::L7RequestInfo,
    ) -> Result<(bool, String)> {
        let guard = self.read_pinned()?;
        Self::decide(&guard, ctx, request, StagedAudit::Log)
    }

    /// Returns the token-grant owners admitted for one request.
    ///
    /// Admits owner O when Cedar allows the request and a provider endpoint
    /// stamped with O admits it under that endpoint's own rules, as a YAML
    /// sandbox admits O. The provider rules are compiled to Cedar and
    /// evaluated with the request's own Cedar evaluations; they only narrow
    /// which owners qualify and never allow a request Cedar denies. A denial
    /// on a Cedar audit path admits no owner, matching a YAML audit denial.
    ///
    /// Two requests that Cedar sees differently from the Rego rules admit
    /// no owner: a JSON-RPC request whose method is not uppercase, which the
    /// Rego rules compare case-sensitively, and a hash-only GraphQL persisted
    /// query, which the Rego rules resolve through the provider endpoint's
    /// registry rather than the endpoint settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the tunnel's generation is stale, the engine lock
    /// is poisoned, or an evaluation fails. Callers inject no token on error.
    pub(crate) fn admitted_token_grant_owners(
        &self,
        ctx: &crate::l7::relay::L7EvalContext,
        request: &crate::l7::L7RequestInfo,
    ) -> Result<std::collections::HashSet<String>> {
        let none = std::collections::HashSet::new;
        let guard = self.read_pinned()?;
        let Some(grants) = &guard.token_grants else {
            return Ok(none());
        };
        let Prepared::Evaluate(requests) = Self::prepare(&guard, ctx, request)? else {
            return Ok(none());
        };
        // `evaluate_request` already logged any staged audit decision for
        // this request.
        for l7_request in &requests {
            if !Self::evaluate_one(&guard.cedar, ctx, request, l7_request, StagedAudit::Skip)?.0 {
                return Ok(none());
            }
        }
        let hash_only = request
            .graphql
            .as_ref()
            .is_some_and(|graphql| graphql.operations.iter().any(needs_graphql_registry));
        let lowercase_jsonrpc =
            request.jsonrpc.is_some() && request.action != request.action.to_ascii_uppercase();
        if hash_only || lowercase_jsonrpc {
            return Ok(none());
        }
        match grants.admitted_owners(&requests) {
            Ok(owners) => Ok(owners.into_iter().collect()),
            // Too many query combinations to evaluate admits no owner.
            Err(CedarEngineError::TooManyQueryCombinations { .. }) => Ok(none()),
            Err(error) => Err(miette::miette!("{error}")),
        }
    }

    /// Takes the engine read lock and checks the tunnel's pinned generation.
    ///
    /// Compared under the read lock: a reload advances the generation under
    /// the write lock, so a request is judged by the policy generation the
    /// tunnel was pinned to, never a newer one.
    fn read_pinned(&self) -> Result<std::sync::RwLockReadGuard<'_, LoadedPolicy>> {
        let guard = self
            .engine
            .read()
            .map_err(|_| miette::miette!("Cedar engine lock poisoned"))?;
        let current_generation = self.generation.load(Ordering::Acquire);
        if current_generation != self.captured_generation {
            return Err(miette::miette!(
                "L7 tunnel policy generation is stale [captured_generation:{} current_generation:{current_generation}]",
                self.captured_generation,
            ));
        }
        Ok(guard)
    }

    /// Decides one L7 request and returns `(allowed, deny_reason)`.
    ///
    /// Same as the YAML path: a GraphQL request is allowed only when every
    /// operation is allowed.
    fn decide(
        policy: &LoadedPolicy,
        ctx: &crate::l7::relay::L7EvalContext,
        request: &crate::l7::L7RequestInfo,
        staged_audit: StagedAudit,
    ) -> Result<(bool, String)> {
        let requests = match Self::prepare(policy, ctx, request)? {
            Prepared::Denied(reason) => return Ok((false, reason)),
            Prepared::Evaluate(requests) => requests,
        };
        for l7_request in &requests {
            let decision =
                Self::evaluate_one(&policy.cedar, ctx, request, l7_request, staged_audit)?;
            if !decision.0 {
                return Ok(decision);
            }
        }
        Ok(Self::decision(true))
    }

    /// Builds the Cedar evaluations of one L7 request, or the reason it is
    /// denied before evaluation.
    fn prepare(
        policy: &LoadedPolicy,
        ctx: &crate::l7::relay::L7EvalContext,
        request: &crate::l7::L7RequestInfo,
    ) -> Result<Prepared> {
        let mut base = HttpRequestInput {
            user: PLACEHOLDER_IDENTITY.to_string(),
            group: PLACEHOLDER_IDENTITY.to_string(),
            binary_path: ctx.binary_path.clone(),
            ancestors: ctx.ancestors.clone(),
            binary_aliases: policy
                .binary_aliases
                .matching(&ctx.binary_path, &ctx.ancestors)?,
            binary_globs: policy
                .binary_globs
                .matching(&ctx.binary_path, &ctx.ancestors)?,
            // The relay parsed the request as GraphQL: an operation on a
            // GraphQL path or a GraphQL-over-WebSocket client message. As
            // the Rego `is_object(request.graphql)`, this makes the routed
            // path authoritative for it.
            graphql_request: request.graphql.is_some(),
            host: ctx.host.clone(),
            port: ctx.port,
            // YAML matches methods case-insensitively, and the request parser
            // keeps the client's case, so normalize before Cedar compares.
            method: request.action.to_ascii_uppercase(),
            path: request.target.clone(),
            // Decoded by the request parser, as the Rego input receives them.
            query: request
                .query_params
                .iter()
                .map(|(key, values)| (key.clone(), values.clone()))
                .collect(),
            ..HttpRequestInput::default()
        };
        // The relay selects the endpoint config, and with it the protocol and
        // enforcement, by the most specific matching path, and denies a
        // request no inspected path matches before evaluating it. A
        // WebSocket message carries its upgrade path, so it is routed as its
        // upgrade was.
        match policy.route_request(&ctx.host, ctx.port, &request.target) {
            RequestRoute::Unmatched => return Ok(Prepared::Denied(UNMATCHED_PATH.to_string())),
            RequestRoute::Routed { endpoint_path } => base.endpoint_path = endpoint_path,
            RequestRoute::Uninspected => {}
        }

        if let Some(info) = &request.jsonrpc {
            // Same as the YAML path: a request that failed inspection is
            // never matched against policy.
            if info.error.is_some() {
                return Ok(Prepared::Denied(
                    "JSON-RPC request could not be inspected".to_string(),
                ));
            }
            // The relay splits batches into single calls before policy
            // evaluation; a batch seen here carries no single method.
            let call = if info.is_batch {
                None
            } else {
                info.calls.first()
            };
            // Same as the YAML path: calls and response frames are only ever
            // allowed in a POST, so a body carried by any other method is
            // denied before Cedar sees it. An MCP receive stream (a GET with
            // no body) is unaffected.
            if (!info.calls.is_empty() || info.has_response)
                && !request.action.eq_ignore_ascii_case("POST")
            {
                return Ok(Prepared::Denied(
                    "JSON-RPC calls and responses must be sent with POST".to_string(),
                ));
            }
            if let Some(call) = call {
                // `method` stays empty for a call so policies match on
                // `jsonrpc_method` instead, the schema's not-applicable
                // convention.
                base.method = String::new();
                base.jsonrpc_method.clone_from(&call.method);
                base.mcp_tool = call.tool.clone().unwrap_or_default();
                base.mcp_method_class = match call.mcp_classification {
                    Some(crate::l7::jsonrpc::McpMethodClassification::Available) => "available",
                    Some(crate::l7::jsonrpc::McpMethodClassification::Extension) => "extension",
                    None => "",
                }
                .to_string();
            }
            base.jsonrpc_receive_stream = info.receive_stream;
            base.jsonrpc_response = info.has_response;
        }

        let Some(graphql) = &request.graphql else {
            return Ok(Prepared::Evaluate(vec![base]));
        };
        // Same as the YAML path: a GraphQL request is allowed only when it
        // parsed into at least one operation and every operation is allowed.
        if graphql.error.is_some() || graphql.operations.is_empty() {
            return Ok(Prepared::Denied(
                "GraphQL request could not be inspected".to_string(),
            ));
        }
        // Resolve every hash-only persisted query before evaluating any
        // operation, so an unregistered one is reported as such, as in YAML.
        let registry = graphql
            .operations
            .iter()
            .any(needs_graphql_registry)
            .then(|| PersistedQueryRegistry::for_request(policy, ctx, &request.target));
        let mut operations = Vec::with_capacity(graphql.operations.len());
        for operation in &graphql.operations {
            let effective = match &registry {
                Some(registry) if needs_graphql_registry(operation) => {
                    let Some(registered) = registry.lookup(operation) else {
                        return Ok(Prepared::Denied(UNREGISTERED_PERSISTED_QUERY.to_string()));
                    };
                    registered
                }
                _ => EffectiveGraphqlOperation::parsed(operation),
            };
            operations.push(effective);
        }
        Ok(Prepared::Evaluate(
            operations
                .into_iter()
                .map(|operation| {
                    let mut l7_request = base.clone();
                    l7_request.graphql_operation_type =
                        operation.operation_type.to_ascii_lowercase();
                    l7_request.graphql_operation_name = operation.operation_name;
                    l7_request.graphql_fields = operation.fields;
                    l7_request
                })
                .collect(),
        ))
    }

    /// Evaluates one Cedar request and returns `(allowed, deny_reason)`,
    /// logging any staged audit decision when `staged_audit` asks for it.
    ///
    /// A query with too many value combinations to evaluate is denied with
    /// that reason.
    fn evaluate_one(
        cedar: &CedarEngine,
        ctx: &crate::l7::relay::L7EvalContext,
        request: &crate::l7::L7RequestInfo,
        l7_request: &HttpRequestInput,
        staged_audit: StagedAudit,
    ) -> Result<(bool, String)> {
        let evaluation = match cedar.evaluate_l7(l7_request) {
            Ok(evaluation) => evaluation,
            Err(error @ CedarEngineError::TooManyQueryCombinations { .. }) => {
                return Ok((false, error.to_string()));
            }
            Err(error) => return Err(miette::miette!("{error}")),
        };
        if staged_audit == StagedAudit::Log
            && let Some(staged) = &evaluation.staged
        {
            ocsf_emit!(staged_audit_event(
                ctx,
                request,
                evaluation.is_allow(),
                staged
            ));
        }
        Ok(Self::decision(evaluation.is_allow()))
    }

    /// Returns the relay's `(allowed, deny_reason)` pair.
    fn decision(allowed: bool) -> (bool, String) {
        let reason = if allowed {
            String::new()
        } else {
            "denied by Cedar HttpRequest policy".to_string()
        };
        (allowed, reason)
    }
}

/// The Cedar evaluations of one L7 request.
#[derive(Debug)]
enum Prepared {
    /// Denied before evaluation, with the reason.
    Denied(String),
    /// One evaluation per GraphQL operation, else one.
    Evaluate(Vec<HttpRequestInput>),
}

/// The deny reason for a hash-only persisted query with no registry entry,
/// the same reason YAML reports.
const UNREGISTERED_PERSISTED_QUERY: &str = "GraphQL persisted query is not registered";

/// Returns whether a parsed operation is a hash-only persisted query.
///
/// Mirrors the Rego `graphql_operation_needs_registry`: the request named a
/// persisted query and sent no operation text, so the operation type is
/// unknown until the registry supplies it.
fn needs_graphql_registry(operation: &crate::l7::graphql::GraphqlOperationInfo) -> bool {
    operation.persisted_query && operation.operation_type.is_empty()
}

/// The GraphQL operation Cedar evaluates.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectiveGraphqlOperation {
    operation_type: String,
    operation_name: String,
    fields: Vec<String>,
}

impl EffectiveGraphqlOperation {
    /// The operation as the request spelled it.
    fn parsed(operation: &crate::l7::graphql::GraphqlOperationInfo) -> Self {
        Self {
            operation_type: operation.operation_type.clone(),
            operation_name: operation.operation_name.clone().unwrap_or_default(),
            fields: operation.fields.clone(),
        }
    }
}

/// The persisted-query registry of the endpoint config a request selects.
#[derive(Debug, Default)]
struct PersistedQueryRegistry {
    /// `None` unless the config sets `persisted_queries: allow_registered`.
    operations: Option<std::collections::BTreeMap<String, GraphqlPersistedQuery>>,
}

impl PersistedQueryRegistry {
    /// Reads the registry from the endpoint config the relay selects for
    /// `target`, which carries the matching `endpoint_settings`.
    fn for_request(
        policy: &LoadedPolicy,
        ctx: &crate::l7::relay::L7EvalContext,
        target: &str,
    ) -> Self {
        let Some(config) = policy.request_config(&ctx.host, ctx.port, target) else {
            return Self::default();
        };
        Self {
            operations: (config.persisted_queries == "allow_registered")
                .then_some(config.graphql_persisted_queries),
        }
    }

    /// Returns the registered operation for a hash-only persisted query.
    ///
    /// Mirrors the Rego `graphql_registered_operation`: the key is the
    /// query hash when the request has one, and the saved-query id
    /// otherwise.
    fn lookup(
        &self,
        operation: &crate::l7::graphql::GraphqlOperationInfo,
    ) -> Option<EffectiveGraphqlOperation> {
        let key = operation
            .persisted_query_hash
            .as_deref()
            .filter(|hash| !hash.is_empty())
            .or_else(|| {
                operation
                    .persisted_query_id
                    .as_deref()
                    .filter(|id| !id.is_empty())
            })?;
        let registered = self.operations.as_ref()?.get(key)?;
        Some(EffectiveGraphqlOperation {
            operation_type: registered.operation_type.clone(),
            operation_name: registered.operation_name.clone(),
            fields: registered.fields.clone(),
        })
    }
}

/// Whether an evaluation logs the decision staged policies would make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StagedAudit {
    /// Log it; the evaluation is the request's own policy decision.
    Log,
    /// Skip it; the request's own decision already logged it.
    Skip,
}

/// Builds the event for a request whose decision staged policies would
/// change.
///
/// The request itself is decided, and logged by the relay, without them.
fn staged_audit_event(
    ctx: &crate::l7::relay::L7EvalContext,
    request: &crate::l7::L7RequestInfo,
    allowed: bool,
    staged: &Decision,
) -> openshell_ocsf::OcsfEvent {
    let (action_id, disposition_id) = if allowed {
        (ActionId::Allowed, DispositionId::Allowed)
    } else {
        (ActionId::Denied, DispositionId::Blocked)
    };
    let (outcome, policies) = match staged {
        Decision::Allow { matched_policies } => ("allow", matched_policies),
        Decision::Deny { matched_policies } => ("deny", matched_policies),
    };
    let method = if request.action.is_empty() {
        "-"
    } else {
        request.action.as_str()
    };
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Other)
        .action(action_id)
        .disposition(disposition_id)
        .severity(SeverityId::Informational)
        .http_request(HttpRequest::new(
            method,
            OcsfUrl::new("http", &ctx.host, &request.target, ctx.port),
        ))
        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
        .firewall_rule(&ctx.policy_name, "cedar")
        .unmapped("cedar_audit", format!("staged_{outcome}"))
        .unmapped("cedar_audit_policies", policies.join(","))
        .message(format!(
            "L7_AUDIT staged {outcome} {method} {}:{}{} policies={}",
            ctx.host,
            ctx.port,
            request.target,
            policies.join(","),
        ))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::L7RequestInfo;
    use crate::l7::relay::L7EvalContext;

    const POLICY: &str = r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when {
    context.binary_path == "/usr/bin/curl"
};

permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when {
    context.binary_path == "/usr/bin/curl"
    && context.method == "GET"
    && context.path == "/v1/status"
};
"#;

    fn ctx() -> L7EvalContext {
        L7EvalContext {
            host: "api.example.com".to_string(),
            port: 443,
            binary_path: "/usr/bin/curl".to_string(),
            ..Default::default()
        }
    }

    fn request(action: &str, target: &str) -> L7RequestInfo {
        L7RequestInfo {
            action: action.to_string(),
            target: target.to_string(),
            query_params: HashMap::new(),
            graphql: None,
            jsonrpc: None,
        }
    }

    #[test]
    fn authorize_egress_populates_endpoint_configs_for_an_l7_endpoint() {
        // Without this, query_l7_route_snapshot (proxy.rs) always sees an
        // empty endpoint_configs and routes every allowed CONNECT to
        // unconditional passthrough — the HttpRequest permit above would
        // then never actually be consulted for a real connection.
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        let input = NetworkInput {
            host: "api.example.com".to_string(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: "deadbeef".to_string(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        };
        let authorization = engine.authorize_egress(&input).expect("request evaluates");
        assert!(
            matches!(authorization.action, NetworkAction::Allow { .. }),
            "{:?}",
            authorization.action
        );
        assert_eq!(authorization.endpoint_configs.len(), 1);
        let config = crate::l7::parse_l7_config(&authorization.endpoint_configs[0])
            .expect("config must parse");
        assert_eq!(config.protocol, openshell_policy::L7Protocol::Rest);
    }

    #[test]
    fn loading_an_audit_only_path_beside_enforced_policies_keeps_the_warning() {
        // `LoadedPolicy::from_proto` logs every analysis warning as an OCSF
        // config event. Tracing callsite interest is process-wide, so the
        // emission is not captured here; this checks that the loaded engine
        // carries exactly the warning the loader iterates over.
        const AUDIT_PATH_POLICY: &str = r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.binary_path == "/usr/bin/curl" };

permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.method == "GET" && context.path like("/v1/**", "/") };

@path("/admin/**")
@enforcement("audit")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.path like("/admin/**", "/") };
"#;
        let engine = CedarOnlyEngine::from_policy_str(AUDIT_PATH_POLICY)
            .expect("policy loads with a warning");
        assert_eq!(
            engine.warnings_for_tests(),
            [
                openshell_policy_cedar::AnalysisWarning::AuditPathOnEnforcedEndpoint {
                    endpoint: "api.example.com:443".to_string(),
                    path: "/admin/**".to_string(),
                }
            ]
        );

        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        assert_eq!(engine.warnings_for_tests(), []);
    }

    #[test]
    fn authorize_egress_omits_endpoint_configs_for_a_connect_only_endpoint() {
        const CONNECT_ONLY_POLICY: &str = r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"pypi.org:443"
)
when { context.binary_path == "/usr/bin/curl" };
"#;
        let engine = CedarOnlyEngine::from_policy_str(CONNECT_ONLY_POLICY).expect("policy parses");
        let input = NetworkInput {
            host: "pypi.org".to_string(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: "deadbeef".to_string(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        };
        let authorization = engine.authorize_egress(&input).expect("request evaluates");
        assert!(
            matches!(authorization.action, NetworkAction::Allow { .. }),
            "{:?}",
            authorization.action
        );
        assert!(authorization.endpoint_configs.is_empty());
    }

    #[test]
    fn l7_override_allows_the_permitted_request() {
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        let generation = engine.current_generation();
        let handle = engine.l7_handle(generation);
        let (allowed, _) = handle
            .evaluate_request(&ctx(), &request("GET", "/v1/status"))
            .expect("request evaluates");
        assert!(allowed);
    }

    #[test]
    fn l7_override_denies_a_different_path() {
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        let generation = engine.current_generation();
        let handle = engine.l7_handle(generation);
        let (allowed, reason) = handle
            .evaluate_request(&ctx(), &request("GET", "/v1/admin"))
            .expect("request evaluates");
        assert!(!allowed);
        assert!(!reason.is_empty());
    }

    #[test]
    fn l7_override_fails_closed_when_tunnel_generation_is_stale() {
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        let captured_generation = engine.current_generation();
        let handle = engine.l7_handle(captured_generation);
        // A reload with genuinely different policy text must still advance
        // the generation — only a byte-identical reload is a no-op.
        let changed_policy = format!("{POLICY}\n// a trailing comment to change the source\n");
        engine
            .reload_from_policy_str(&changed_policy)
            .expect("reload with changed policy advances the generation");

        let result = handle.evaluate_request(&ctx(), &request("GET", "/v1/status"));
        assert!(
            result.is_err(),
            "stale tunnel must fail closed, not silently re-evaluate"
        );
    }

    #[test]
    fn reload_with_identical_policy_source_is_a_no_op() {
        // An unconditional generation bump here would invalidate every
        // in-flight L7 tunnel whenever a policy poll reconciliation pass
        // fires for a reason unrelated to this sandbox's Cedar policy (e.g.
        // middleware registry reconciliation) — not just a real change.
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        let generation_before = engine.current_generation();
        engine
            .reload_from_policy_str(POLICY)
            .expect("reload succeeds");
        assert_eq!(
            engine.current_generation(),
            generation_before,
            "reloading byte-identical policy text must not advance the generation"
        );
    }

    #[test]
    fn tunnel_engine_delegates_l7_decisions_to_cedar() {
        let cedar = Arc::new(CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses"));
        let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));

        let tunnel = engine
            .tunnel_engine(cedar.current_generation())
            .expect("tunnel builds");

        let (allowed, _) = tunnel
            .evaluate_request(&ctx(), &request("GET", "/v1/status"))
            .expect("request evaluates");
        assert!(allowed, "Cedar must decide the request");
    }

    #[tokio::test]
    async fn cedar_mcp_routes_observe_the_configured_inventory_identity() {
        use openshell_core::endpoint_status::{
            EndpointConfigVersion, EndpointInventoryEntry, EndpointResult, endpoint_id,
            endpoint_status_channel,
        };
        use openshell_core::proto::NetworkEndpoint;
        let source = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
@protocol("mcp") @path("/mcp/**")
permit (principal, action == Sandbox::Action::"HttpRequest", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
@protocol("rest") @path("/rest/**")
permit (principal, action == Sandbox::Action::"HttpRequest", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
"#;
        let provider = NetworkEndpoint {
            host: "*.example.com".to_string(),
            ports: vec![8443, 443],
            path: "/mcp/provider/**".to_string(),
            provider_credentialed: true,
            ..Default::default()
        };
        let setting = NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            path: "/mcp/scoped".to_string(),
            allow_encoded_slash: true,
            ..Default::default()
        };
        let mut policy = provider_policy(source, vec![provider.clone()]);
        policy.endpoint_settings.push(setting.clone());
        let policy = openshell_policy::validate_and_canonicalize_sandbox_policy(policy)
            .expect("canonical policy");
        let engine = CedarOnlyEngine::from_proto(&policy).expect("policy loads");
        let descriptors = openshell_policy::endpoint_status::configured_mcp_endpoints(&policy)
            .expect("inventory");
        let (sender, mut receiver) = endpoint_status_channel();
        let mut tracker = receiver.tracker();
        sender
            .reset(
                EndpointConfigVersion {
                    policy_hash: deterministic_policy_hash(&policy),
                    provider_env_revision: 1,
                },
                descriptors
                    .iter()
                    .map(|endpoint| EndpointInventoryEntry {
                        endpoint_id: endpoint_id(endpoint),
                        uses_provider_credentials: endpoint.provider_credentialed,
                    })
                    .collect(),
            )
            .await
            .expect("reset");
        assert!(tracker.apply(receiver.recv().await.expect("reset received")));
        let base = NetworkEndpoint {
            host: "*.example.com".to_string(),
            port: 443,
            path: "/mcp/**".to_string(),
            ..Default::default()
        };
        for (host, path, expected) in [
            ("api.example.com", "/mcp/item", &base),
            ("other.example.com", "/mcp/item", &base),
            ("api.example.com", "/mcp/provider/item", &provider),
            ("other.example.com", "/mcp/provider/item", &provider),
            ("api.example.com", "/mcp/scoped", &setting),
        ] {
            let loaded = engine.read_engine().expect("lock");
            let config = loaded.request_config(host, 443, path).expect("route");
            let selected = crate::l7::parse_l7_config(&config).expect("MCP config");
            assert_eq!(selected.endpoint_id, endpoint_id(expected), "{host}{path}");
            let observer = crate::l7::EndpointObserver::begin(Some(&sender), &selected)
                .expect("observation starts");
            observer.observe(EndpointResult::HttpResponseReceived);
        }
        let rest = engine
            .read_engine()
            .expect("lock")
            .request_config("api.example.com", 443, "/rest/item")
            .expect("REST route");
        let rest = crate::l7::parse_l7_config(&rest).expect("REST config");
        assert!(crate::l7::EndpointObserver::begin(Some(&sender), &rest).is_none());
        while let Ok(command) = receiver.try_recv() {
            tracker.apply(command);
        }
        let snapshot = tracker.snapshot().expect("snapshot");
        for expected in [&base, &provider, &setting] {
            assert!(
                snapshot
                    .endpoints
                    .iter()
                    .any(|endpoint| endpoint.endpoint_id == endpoint_id(expected)
                        && endpoint.result == EndpointResult::HttpResponseReceived)
            );
        }
    }

    #[tokio::test]
    async fn websocket_admission_is_shared_across_forward_tunnels_and_reload() {
        use crate::l7::websocket::{WebSocketAssemblyAdmissionOutcome, WebSocketAssemblyBudget};
        let mut cedar = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        cedar.websocket_assembly_budget = WebSocketAssemblyBudget::new(1, 1);
        let cedar = Arc::new(cedar);
        let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
        let first = engine
            .tunnel_engine(cedar.current_generation())
            .expect("first tunnel");
        let second = engine
            .tunnel_engine(cedar.current_generation())
            .expect("second tunnel");
        let active = first
            .websocket_assembly_budget()
            .reserve()
            .await
            .expect("reserve");
        assert!(matches!(
            active,
            WebSocketAssemblyAdmissionOutcome::Admitted(_)
        ));
        let waiting_budget = second.websocket_assembly_budget();
        let waiting = waiting_budget.reserve();
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut waiting)
                .await
                .is_err()
        );
        assert!(matches!(
            engine
                .websocket_assembly_budget()
                .reserve()
                .await
                .expect("forward admission"),
            WebSocketAssemblyAdmissionOutcome::QueueExhausted
        ));
        cedar
            .reload_from_policy_str(&POLICY.replace("/v1/status", "/v2/status"))
            .expect("reload");
        assert!(
            first.generation_guard().is_stale(),
            "the reload changed policy"
        );
        let reloaded = engine
            .tunnel_engine(cedar.current_generation())
            .expect("new tunnel");
        assert!(matches!(
            reloaded
                .websocket_assembly_budget()
                .reserve()
                .await
                .expect("reloaded admission"),
            WebSocketAssemblyAdmissionOutcome::QueueExhausted
        ));
        drop(active);
        assert!(matches!(
            waiting.await.expect("waiter admitted"),
            WebSocketAssemblyAdmissionOutcome::Admitted(_)
        ));
    }

    #[test]
    fn tunnel_engine_tracks_the_cedar_generation() {
        let cedar = Arc::new(CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses"));
        let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
        let tunnel = engine
            .tunnel_engine(cedar.current_generation())
            .expect("tunnel builds");

        // A middleware registry swap advances the middleware generation, not
        // Cedar's, so it must not close a Cedar tunnel.
        engine
            .replace_middleware_registry(MiddlewareRegistry::default())
            .expect("registry swap");
        assert!(!tunnel.is_stale());

        // A Cedar reload must.
        cedar
            .reload_from_policy_str(&format!("{POLICY}\n// changed\n"))
            .expect("reload");
        assert!(tunnel.is_stale());
    }

    #[test]
    fn tunnel_engine_rejects_a_stale_cedar_generation() {
        let cedar = Arc::new(CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses"));
        let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
        let decided_at = cedar.current_generation();
        cedar
            .reload_from_policy_str(&format!("{POLICY}\n// changed\n"))
            .expect("reload");

        assert!(engine.tunnel_engine(decided_at).is_err());
    }

    fn middleware_policy(include: &str) -> ProtoSandboxPolicy {
        let mut policy = policy_from_source(POLICY);
        policy.network_middlewares.insert(
            "redactor".to_string(),
            openshell_core::proto::NetworkMiddlewareConfig {
                middleware: "openshell/regex".to_string(),
                order: 10,
                endpoints: Some(openshell_core::proto::MiddlewareEndpointSelector {
                    include: vec![include.to_string()],
                    exclude: Vec::new(),
                }),
                ..Default::default()
            },
        );
        policy
    }

    fn middleware_input(host: &str) -> NetworkInput {
        NetworkInput {
            host: host.to_string(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: String::new(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        }
    }

    /// A middleware-only reload publishes the new chain under a new
    /// middleware generation, keeps the Cedar generation so inspected
    /// tunnels stay open, and leaves existing tunnels on the chain they
    /// started with.
    #[test]
    fn middleware_only_reload_keeps_the_cedar_generation_and_tunnel_chains() {
        let cedar = Arc::new(
            CedarOnlyEngine::from_proto(&middleware_policy("api.example.com"))
                .expect("policy loads"),
        );
        let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
        let policy_generation = cedar.current_generation();
        let middleware_generation = engine.middleware_generation();
        let tunnel = engine
            .tunnel_engine(policy_generation)
            .expect("tunnel builds");
        let selected = |chain: Vec<openshell_supervisor_middleware::ChainEntry>| {
            chain
                .into_iter()
                .map(|entry| entry.name)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            selected(
                tunnel
                    .query_middleware_chain(&middleware_input("api.example.com"))
                    .expect("tunnel chain")
            ),
            vec!["redactor"]
        );

        let staged = cedar
            .stage(&middleware_policy("other.example.com"), 0)
            .expect("stage");
        let mut credentials_committed = false;
        let guard = cedar
            .commit_configuration(staged, None, || credentials_committed = true)
            .expect("commit");

        assert!(credentials_committed);
        assert_eq!(cedar.current_generation(), policy_generation);
        assert!(!tunnel.is_stale());
        assert_eq!(guard.captured_generation(), middleware_generation + 1);
        let (chain, generation) = engine
            .query_middleware_chain_with_generation(&middleware_input("api.example.com"))
            .expect("chain");
        assert!(chain.is_empty());
        assert_eq!(generation, middleware_generation + 1);
        assert_eq!(
            selected(
                tunnel
                    .query_middleware_chain(&middleware_input("api.example.com"))
                    .expect("tunnel chain")
            ),
            vec!["redactor"],
            "an open tunnel keeps the middleware it started with"
        );
    }

    /// Existing Cedar guards become stale before credentials change, as the
    /// YAML reload guarantees.
    #[test]
    fn commit_configuration_invalidates_policy_guards_before_credentials_change() {
        let cedar = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        let policy_guard = cedar
            .generation_guard(cedar.current_generation())
            .expect("policy guard");
        let middleware_guard = cedar
            .middleware()
            .generation_guard(cedar.middleware().current_generation())
            .expect("middleware guard");
        let staged = cedar
            .stage(&policy_from_source(&format!("{POLICY}\n// changed\n")), 0)
            .expect("stage");
        let mut stale_at_credential_commit = None;
        cedar
            .commit_configuration(staged, None, || {
                stale_at_credential_commit =
                    Some((policy_guard.is_stale(), middleware_guard.is_stale()));
            })
            .expect("commit");
        assert_eq!(stale_at_credential_commit, Some((true, true)));
    }

    fn chain_names(chain: Vec<openshell_supervisor_middleware::ChainEntry>) -> Vec<String> {
        chain.into_iter().map(|entry| entry.name).collect()
    }

    /// A quarantine is a configuration change: the guard the policy poll
    /// loop pins (the middleware generation) goes stale when the quarantine
    /// starts and when it ends, as the single-counter YAML guard does.
    #[test]
    fn quarantine_entry_and_exit_stale_the_configuration_guard() {
        let cedar = Arc::new(CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses"));
        let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
        let policy_generation = cedar.current_generation();
        let before = engine
            .configuration_generation_guard()
            .expect("configuration guard");

        let quarantined = cedar
            .enter_fail_closed("invalid candidate")
            .expect("quarantine");
        assert_eq!(quarantined, policy_generation + 1);
        assert!(before.is_stale(), "entering a quarantine stales the guard");
        assert!(cedar.fail_closed_reason().is_some());

        let during = engine
            .configuration_generation_guard()
            .expect("configuration guard");
        assert_eq!(
            cedar.exit_fail_closed().expect("exit"),
            policy_generation + 2
        );
        assert!(during.is_stale(), "ending a quarantine stales the guard");
        assert!(cedar.fail_closed_reason().is_none());

        // Without a quarantine to end, nothing changes.
        let after = engine
            .configuration_generation_guard()
            .expect("configuration guard");
        assert_eq!(
            cedar.exit_fail_closed().expect("exit"),
            policy_generation + 2
        );
        assert!(!after.is_stale());
    }

    /// A commit whose binary resolution fails changes nothing: the policy,
    /// the middleware, and the credentials all stay on the previous
    /// revision, and no guard becomes stale.
    #[test]
    fn a_commit_that_fails_to_resolve_changes_nothing() {
        const PID: u32 = 4242;
        let cedar = Arc::new(
            CedarOnlyEngine::from_proto(&middleware_policy("api.example.com"))
                .expect("policy loads"),
        );
        let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
        let input = middleware_input("api.example.com");

        // A changed policy with changed middleware, staged before the
        // entrypoint process is known, so the commit has to resolve it.
        let mut candidate = middleware_policy("other.example.com");
        candidate.cedar_policy_source.push_str("\n// changed\n");
        let mut staged = cedar.stage(&candidate, 0).expect("stage");
        staged.fail_binary_resolution_for_tests();
        cedar.resolve_binary_symlinks(PID).expect("resolves");

        let policy_generation = cedar.current_generation();
        let policy_guard = cedar
            .generation_guard(policy_generation)
            .expect("policy guard");
        let configuration = engine
            .configuration_generation_guard()
            .expect("configuration guard");
        let mut credentials_committed = false;

        let error = cedar
            .commit_configuration(staged, None, || credentials_committed = true)
            .expect_err("resolution fails");

        assert!(
            error.to_string().contains("injected test failure"),
            "{error}"
        );
        assert!(
            !credentials_committed,
            "credentials stay on the previous revision"
        );
        assert!(!policy_guard.is_stale());
        assert!(!configuration.is_stale());
        assert_eq!(cedar.current_generation(), policy_generation);
        assert_eq!(
            cedar.read_inputs().expect("lock").source,
            POLICY,
            "the active policy is unchanged"
        );
        let (chain, generation) = engine
            .query_middleware_chain_with_generation(&input)
            .expect("chain");
        assert_eq!(chain_names(chain), vec!["redactor"]);
        assert_eq!(generation, configuration.captured_generation());

        // The engine is still usable: the same candidate commits once it resolves.
        let staged = cedar.stage(&candidate, 0).expect("stage");
        cedar
            .commit_configuration(staged, None, || credentials_committed = true)
            .expect("commit");
        assert!(credentials_committed);
        assert!(policy_guard.is_stale());
        assert!(configuration.is_stale());
    }

    /// A passthrough tunnel keeps the middleware it started with across a
    /// middleware-only reload, as an inspected tunnel does, and closes when
    /// the Cedar policy changes.
    #[test]
    fn passthrough_middleware_keeps_its_snapshot_across_a_middleware_only_reload() {
        let cedar = Arc::new(
            CedarOnlyEngine::from_proto(&middleware_policy("api.example.com"))
                .expect("policy loads"),
        );
        let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
        let guard = engine
            .generation_guard(cedar.current_generation())
            .expect("tunnel guard");
        let passthrough = engine.passthrough_middleware().expect("snapshot");
        let input = middleware_input("api.example.com");
        let (chain, _) = passthrough
            .select(&input, &guard)
            .expect("select")
            .expect("tunnel open");
        assert_eq!(chain_names(chain), vec!["redactor"]);

        let staged = cedar
            .stage(&middleware_policy("other.example.com"), 0)
            .expect("stage");
        cedar.commit(staged).expect("commit");

        let (live, _) = engine
            .query_middleware_chain_with_generation(&input)
            .expect("chain");
        assert!(live.is_empty(), "new tunnels select the new middleware");
        assert!(
            !guard.is_stale(),
            "a middleware-only reload keeps the Cedar generation"
        );
        let (chain, _) = passthrough
            .select(&input, &guard)
            .expect("select")
            .expect("tunnel open");
        assert_eq!(
            chain_names(chain),
            vec!["redactor"],
            "an open passthrough tunnel keeps the middleware it started with"
        );

        cedar
            .reload_from_policy_str(&format!("{POLICY}\n// changed\n"))
            .expect("reload");
        assert!(guard.is_stale());
        assert!(
            passthrough
                .select(&input, &guard)
                .expect("select")
                .is_none(),
            "a policy change closes the tunnel"
        );
    }

    /// `from_proto` and `stage` validate the policy as `OpaEngine::from_proto`
    /// validates a YAML policy, so no caller can build an unvalidated engine.
    #[test]
    fn engines_validate_the_policy_as_yaml_engines_do() {
        let mut invalid = middleware_policy("api.example.com");
        invalid
            .network_middlewares
            .get_mut("redactor")
            .expect("middleware")
            .on_error = "maybe".to_string();

        let error = CedarOnlyEngine::from_proto(&invalid).expect_err("invalid middleware");
        assert!(
            error
                .to_string()
                .contains("invalid middleware configuration"),
            "{error}"
        );
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy loads");
        let error = engine.stage(&invalid, 0).expect_err("invalid middleware");
        assert!(
            error
                .to_string()
                .contains("invalid middleware configuration"),
            "{error}"
        );

        let error = CedarOnlyEngine::from_proto(&policy_from_source("not cedar {{{"))
            .expect_err("invalid Cedar text");
        assert!(
            error.to_string().contains("invalid Cedar policy"),
            "{error}"
        );
    }

    const CONNECT_ONLY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#;

    fn provider_policy(
        cedar: &str,
        endpoints: Vec<openshell_core::proto::NetworkEndpoint>,
    ) -> ProtoSandboxPolicy {
        let mut policy = policy_from_source(cedar);
        policy.provider_credential_rules.insert(
            "_provider_work".to_string(),
            NetworkPolicyRule {
                name: "_provider_work".to_string(),
                endpoints,
                ..Default::default()
            },
        );
        policy
    }

    fn credentialed_endpoint() -> openshell_core::proto::NetworkEndpoint {
        openshell_core::proto::NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            protocol: "rest".to_string(),
            access: openshell_core::proto::NetworkAccessPreset::ReadOnly as i32,
            provider_credentialed: true,
            request_body_credential_rewrite: true,
            ..Default::default()
        }
    }

    fn curl_input(host: &str) -> NetworkInput {
        NetworkInput {
            host: host.to_string(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: String::new(),
            ancestors: Vec::new(),
            cmdline_paths: Vec::new(),
        }
    }

    #[test]
    fn provider_settings_apply_with_cedar_inspection() {
        let engine =
            CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![credentialed_endpoint()]))
                .expect("policy loads");
        let authorization = engine
            .authorize_egress(&curl_input("api.example.com"))
            .expect("request evaluates");
        assert_eq!(authorization.endpoint_configs.len(), 1);
        let config = crate::l7::parse_l7_config(&authorization.endpoint_configs[0])
            .expect("config must parse");
        assert_eq!(config.protocol, openshell_policy::L7Protocol::Rest);
        assert!(config.provider_credentialed);
        assert!(config.request_body_credential_rewrite);
        assert_eq!(
            authorization.endpoint_configs[0].access,
            crate::policy_types::AccessSetting::None,
            "provider L7 rules must not apply on a Cedar sandbox"
        );
    }

    #[test]
    fn uninspected_credentialed_endpoint_is_refused_at_connect() {
        // Cedar allows the connection but has no HttpRequest policy for it,
        // so it would be relayed without inspection.
        let engine = CedarOnlyEngine::from_proto(&provider_policy(
            CONNECT_ONLY,
            vec![credentialed_endpoint()],
        ))
        .expect("policy loads");
        let guards = engine
            .credential_guards("api.example.com", 443)
            .expect("guards evaluate");
        assert_eq!(guards.len(), 1);
        let guard = crate::l7::parse_endpoint_credential_guard(&guards[0]);
        assert!(guard.provider_credentialed);
        assert!(guard.blocks_connect());
    }

    #[test]
    fn provider_rules_grant_no_access() {
        let mut other = credentialed_endpoint();
        other.host = "other.example.com".to_string();
        let engine = CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![other]))
            .expect("policy loads");
        let authorization = engine
            .authorize_egress(&curl_input("other.example.com"))
            .expect("request evaluates");
        assert!(
            matches!(authorization.action, NetworkAction::Deny { .. }),
            "{:?}",
            authorization.action
        );
        assert!(authorization.endpoint_configs.is_empty());
    }

    #[test]
    fn provider_allowed_ips_narrow_addresses_and_hostless_endpoints_match_nothing() {
        let mut ranged = credentialed_endpoint();
        ranged.allowed_ips = vec!["10.0.0.0/8".to_string()];
        let hostless = openshell_core::proto::NetworkEndpoint {
            host: String::new(),
            port: 8443,
            allowed_ips: vec!["10.0.0.0/8".to_string()],
            provider_credentialed: true,
            ..Default::default()
        };
        let cedar = format!(
            r#"{POLICY}
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {{ resource.port == 8443 }};
"#
        );
        let engine = CedarOnlyEngine::from_proto(&provider_policy(&cedar, vec![ranged, hostless]))
            .expect("policy loads");

        let authorization = engine
            .authorize_egress(&curl_input("api.example.com"))
            .expect("request evaluates");
        assert_eq!(authorization.endpoint_configs.len(), 1);
        assert!(
            authorization.endpoint_configs[0].allowed_ips.is_empty(),
            "{:?}",
            authorization.endpoint_configs[0]
        );
        let destination = authorization
            .cedar_destination
            .expect("the connection is allowed");
        assert_eq!(
            destination.provider_ranges(),
            [Ok(vec!["10.0.0.0/8".parse::<IpNet>().unwrap()])],
            "the ranges travel with the destination rules, not the config"
        );

        let guards = engine
            .credential_guards("anything.example.com", 8443)
            .expect("guards evaluate");
        assert!(
            guards.is_empty(),
            "a host-less provider endpoint lends no credentials"
        );
    }

    const ADDRESS_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"db.corp.net:5432")
when {
    context.binary_path == "/usr/bin/curl"
    && context has destination_ip
    && context.destination_ip.isInRange(ip("10.2.0.0/16"))
};
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.corp.net:443")
when { context.binary_path == "/usr/bin/wget" };
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.corp.net", ".") && resource.port == 443 };
"#;

    #[test]
    fn allowed_connections_carry_their_destination_rules() {
        let engine = CedarOnlyEngine::from_policy_str(ADDRESS_POLICY).expect("policy loads");
        let mut input = curl_input("db.corp.net");
        input.port = 5432;
        let authorization = engine.authorize_egress(&input).expect("request evaluates");
        assert!(matches!(authorization.action, NetworkAction::Allow { .. }));
        assert!(authorization.exact_declared_endpoint_host);
        let destination = authorization
            .cedar_destination
            .expect("an allowed connection carries its destination rules");
        assert_eq!(
            destination.address_conditions(),
            [vec!["10.2.0.0/16".parse::<IpNet>().unwrap()]]
        );
        assert!(!destination.unconstrained_permit());
        assert_eq!(destination.allows("10.2.3.4".parse().unwrap()), Ok(true));
        assert_eq!(destination.allows("10.3.3.4".parse().unwrap()), Ok(false));

        input.port = 5433;
        let denied = engine.authorize_egress(&input).expect("request evaluates");
        assert!(matches!(denied.action, NetworkAction::Deny { .. }));
        assert!(denied.cedar_destination.is_none());
    }

    #[test]
    fn exact_host_counts_only_permits_that_allow_the_connection() {
        let engine = CedarOnlyEngine::from_policy_str(ADDRESS_POLICY).expect("policy loads");
        let curl = engine
            .authorize_egress(&curl_input("api.corp.net"))
            .expect("request evaluates");
        assert!(matches!(curl.action, NetworkAction::Allow { .. }));
        assert!(
            !curl.exact_declared_endpoint_host,
            "the exact permit is for another binary"
        );
        let mut wget = curl_input("api.corp.net");
        wget.binary_path = "/usr/bin/wget".into();
        let wget = engine.authorize_egress(&wget).expect("request evaluates");
        assert!(wget.exact_declared_endpoint_host);
    }

    #[test]
    fn dns_records_carry_destination_ranges_as_allowed_ips() {
        let engine = CedarOnlyEngine::from_policy_str(ADDRESS_POLICY).expect("policy loads");
        let snapshot = engine
            .policy_dns_eligibility_snapshot()
            .expect("snapshot builds");
        let db = snapshot
            .endpoints
            .iter()
            .map(|record| &record.endpoint)
            .find(|record| record.host == "db.corp.net")
            .expect("db.corp.net is eligible");
        assert_eq!(db.allowed_ips, ["10.2.0.0/16"]);
    }

    #[test]
    fn path_scoped_provider_endpoint_keeps_other_paths_inspected() {
        let mut scoped = credentialed_endpoint();
        scoped.path = "/v1/**".to_string();
        let engine = CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![scoped]))
            .expect("policy loads");
        let configs = engine
            .credential_guards("api.example.com", 443)
            .expect("configs build");
        assert_eq!(configs.len(), 2, "path-scoped config plus a path-less one");
        assert!(configs.iter().all(|config| {
            crate::l7::parse_l7_config(config)
                .is_some_and(|config| config.protocol == openshell_policy::L7Protocol::Rest)
        }));
    }

    #[test]
    fn reload_tracks_provider_rule_changes() {
        let engine =
            CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![credentialed_endpoint()]))
                .expect("policy loads");
        let generation = engine.current_generation();

        let unchanged = engine
            .stage(&provider_policy(POLICY, vec![credentialed_endpoint()]), 0)
            .expect("stage");
        engine.commit(unchanged).expect("commit");
        assert_eq!(engine.current_generation(), generation);

        let changed = engine.stage(&policy_from_source(POLICY), 0).expect("stage");
        engine.commit(changed).expect("commit");
        assert_eq!(engine.current_generation(), generation + 1);
        assert_eq!(
            engine
                .credential_guards("api.example.com", 443)
                .expect("configs")
                .len(),
            1,
            "only Cedar's own inspection config remains"
        );
    }

    #[test]
    fn exact_declared_host_follows_the_permit_scope() {
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy parses");
        assert!(
            engine
                .authorize_egress(&curl_input("api.example.com"))
                .expect("request evaluates")
                .exact_declared_endpoint_host
        );

        let glob = CedarOnlyEngine::from_policy_str(
            r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
               when { resource.host like "*.example.com" };"#,
        )
        .expect("policy parses");
        let authorization = glob
            .authorize_egress(&curl_input("api.example.com"))
            .expect("request evaluates");
        assert!(matches!(authorization.action, NetworkAction::Allow { .. }));
        assert!(!authorization.exact_declared_endpoint_host);
    }

    const HOST_GLOB_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
"#;

    #[test]
    fn delimited_host_glob_is_eligible_for_policy_dns() {
        let engine = CedarOnlyEngine::from_policy_str(HOST_GLOB_POLICY).expect("policy parses");
        let snapshot = engine.policy_dns_eligibility_snapshot().expect("snapshot");
        let hosts: Vec<_> = snapshot
            .endpoints
            .iter()
            .map(|endpoint| endpoint.endpoint.host.clone())
            .collect();
        assert_eq!(hosts, ["*.example.com"]);

        let selector =
            openshell_core::host_pattern::HostSelector::new(&["*.example.com".to_string()], &[])
                .expect("policy DNS accepts the glob");
        assert!(selector.matches("api.example.com"));
        assert!(!selector.matches("a.b.example.com"));
    }

    #[test]
    fn host_glob_never_counts_as_an_exact_declared_host() {
        let engine = CedarOnlyEngine::from_policy_str(HOST_GLOB_POLICY).expect("policy parses");
        for host in ["api.example.com", "*.example.com"] {
            let authorization = engine
                .authorize_egress(&curl_input(host))
                .expect("request evaluates");
            assert!(
                matches!(authorization.action, NetworkAction::Allow { .. }),
                "{host}"
            );
            assert!(!authorization.exact_declared_endpoint_host, "{host}");
        }
    }

    const NATIVE_TCP_POLICY: &str = r#"
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"db.example.com:5432")
when { context.binary_path == "/usr/bin/curl" };
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#;

    #[test]
    fn dns_snapshot_marks_native_tcp_records() {
        let engine = CedarOnlyEngine::from_policy_str(NATIVE_TCP_POLICY).expect("policy parses");
        let snapshot = engine.policy_dns_eligibility_snapshot().expect("snapshot");
        let records: Vec<_> = snapshot
            .endpoints
            .iter()
            .map(|record| {
                (
                    record.policy_name.as_str(),
                    record.endpoint_index,
                    record.endpoint.clone(),
                )
            })
            .collect();
        let record = |host: &str, port: u16, protocol: EndpointProtocol| DnsRecord {
            host: host.to_string(),
            ports: vec![port],
            protocol,
            allowed_ips: Vec::new(),
        };
        assert_eq!(
            records,
            [
                (
                    "cedar",
                    0,
                    record("*.example.com", 443, EndpointProtocol::None)
                ),
                (
                    "cedar",
                    1,
                    record("api.example.com", 443, EndpointProtocol::None)
                ),
                (
                    "cedar",
                    2,
                    record("db.example.com", 5432, EndpointProtocol::Tcp)
                ),
            ]
        );
    }

    /// Regression: `matched_endpoints` was always empty, so the transparent
    /// TCP listener, which requires a decision endpoint that the dialed
    /// policy DNS mapping also names, refused every Cedar-allowed connection.
    #[test]
    fn matched_endpoints_are_the_dns_records_covering_the_connection() {
        let engine = CedarOnlyEngine::from_policy_str(NATIVE_TCP_POLICY).expect("policy parses");
        let snapshot = engine.policy_dns_eligibility_snapshot().expect("snapshot");
        let matched = |host: &str, port: u16| {
            let authorization = engine
                .authorize_egress(&NetworkInput {
                    port,
                    ..curl_input(host)
                })
                .expect("request evaluates");
            authorization
                .matched_endpoints
                .iter()
                .map(|record| {
                    let published = &snapshot.endpoints[record.endpoint_index];
                    assert_eq!(published.policy_name, record.policy_name);
                    assert_eq!(published.endpoint, record.endpoint);
                    record.endpoint_index
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(matched("db.example.com", 5432), [2]);
        // The exact host and the glob both cover it.
        assert_eq!(matched("API.example.com.", 443), [0, 1]);
        assert_eq!(matched("www.example.com", 443), [0]);
        // A denied connection matches nothing.
        assert!(matched("db.example.com", 80).is_empty());
        assert!(matched("other.example.org", 443).is_empty());
    }

    const AUDIT_POLICY: &str = r#"
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
);

@enforcement("audit")
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == Sandbox::NetworkEndpoint::"api.example.com:443"
)
when { context.method == "GET" };
"#;

    #[test]
    fn audit_endpoint_configs_use_audit_enforcement() {
        let engine = CedarOnlyEngine::from_proto(&provider_policy(
            AUDIT_POLICY,
            vec![credentialed_endpoint()],
        ))
        .expect("policy loads");
        let authorization = engine
            .authorize_egress(&curl_input("api.example.com"))
            .expect("request evaluates");
        assert!(!authorization.endpoint_configs.is_empty());
        for value in &authorization.endpoint_configs {
            let config = crate::l7::parse_l7_config(value).expect("config must parse");
            assert_eq!(config.enforcement, crate::l7::EnforcementMode::Audit);
        }
    }

    #[test]
    fn audit_endpoint_reports_the_policy_decision_for_the_relay_to_log() {
        let engine = CedarOnlyEngine::from_policy_str(AUDIT_POLICY).expect("policy parses");
        let tunnel = engine.l7_handle(engine.current_generation());
        let (allowed, reason) = tunnel
            .evaluate_request(&ctx(), &request("DELETE", "/v1/items/1"))
            .expect("request evaluates");
        assert!(!allowed, "the relay logs and forwards an audit deny");
        assert!(!reason.is_empty());
        let (allowed, _) = tunnel
            .evaluate_request(&ctx(), &request("GET", "/v1/items/1"))
            .expect("request evaluates");
        assert!(allowed);
    }

    #[test]
    fn staged_audit_event_reports_the_staged_outcome() {
        let staged = Decision::Deny {
            matched_policies: vec!["no-hooks".to_string()],
        };
        let event = staged_audit_event(&ctx(), &request("GET", "/v1/hooks"), true, &staged)
            .to_json()
            .expect("serialize");
        let message = event["message"].as_str().expect("message");
        assert_eq!(
            message,
            "L7_AUDIT staged deny GET api.example.com:443/v1/hooks policies=no-hooks"
        );
        assert_eq!(
            event["action_id"],
            serde_json::json!(ActionId::Allowed as u8)
        );
        assert_eq!(event["unmapped"]["cedar_audit"], "staged_deny");
        assert_eq!(event["unmapped"]["cedar_audit_policies"], "no-hooks");
    }

    #[test]
    fn mcp_and_graphql_endpoint_configs_parse_for_the_relay() {
        for (protocol, expected) in [
            ("mcp", openshell_policy::L7Protocol::Mcp),
            ("graphql", openshell_policy::L7Protocol::Graphql),
        ] {
            let engine = CedarOnlyEngine::from_policy_str(&format!(
                r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@protocol("{protocol}")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#
            ))
            .expect("policy parses");
            let authorization = engine
                .authorize_egress(&curl_input("api.example.com"))
                .expect("request evaluates");
            assert_eq!(authorization.endpoint_configs.len(), 1, "{protocol}");
            let config = crate::l7::parse_l7_config(&authorization.endpoint_configs[0])
                .unwrap_or_else(|| panic!("{protocol} config must parse"));
            assert_eq!(config.protocol, expected);
            assert_eq!(config.enforcement, crate::l7::EnforcementMode::Enforce);
        }
    }

    /// Token-grant reporting binds a request to the policy its endpoint was
    /// selected under through `policy_hash`, for every protocol, as the YAML
    /// engine's endpoint data does; a Cedar config without it would never
    /// match the installed observation inventory.
    #[test]
    fn endpoint_configs_carry_the_policy_hash_for_every_protocol() {
        for protocol in ["rest", "mcp", "graphql", "json-rpc"] {
            let policy = policy_from_source(&protocol_policy(protocol));
            let canonical = crate::policy_validation::validate_sandbox_policy(&policy)
                .expect("policy validates");
            let engine = CedarOnlyEngine::from_proto(&policy).expect("policy loads");
            let configs = parsed_configs(&engine, "api.example.com");
            assert_eq!(configs.len(), 1, "{protocol}");
            assert_eq!(
                configs[0].policy_hash,
                deterministic_policy_hash(&canonical),
                "{protocol}"
            );
        }

        // A provider endpoint's config is bound to the same policy.
        let engine = owner_engine(OWNER_POLICY);
        let configs = parsed_configs(&engine, "api.example.com");
        assert!(!configs.is_empty());
        let expected = engine
            .engine
            .read()
            .expect("engine lock")
            .policy_hash
            .clone();
        assert!(!expected.is_empty());
        assert!(
            configs.iter().all(|config| config.policy_hash == expected),
            "{configs:?}"
        );
    }

    const OWNER_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {
    (context.method == "GET" && context.path like("/a/**", "/"))
    || (context.method == "POST" && context.path like("/a/private/**", "/"))
};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.path == "/a/private/blocked" };
"#;

    /// A provider endpoint stamped with `owner` whose own rule allows
    /// `method` on `path`.
    fn owned_endpoint(
        owner: &str,
        path: &str,
        method: &str,
    ) -> openshell_core::proto::NetworkEndpoint {
        openshell_core::proto::NetworkEndpoint {
            host: "api.example.com".to_string(),
            port: 443,
            path: path.to_string(),
            protocol: "rest".to_string(),
            token_grant_owner: owner.to_string(),
            rules: vec![openshell_core::proto::L7Rule {
                allow: Some(openshell_core::proto::L7Allow {
                    method: method.to_string(),
                    path: path.to_string(),
                    ..Default::default()
                }),
            }],
            ..Default::default()
        }
    }

    fn owner_engine(cedar: &str) -> CedarOnlyEngine {
        let mut policy = provider_policy(
            cedar,
            vec![
                owned_endpoint("owner-broad", "/a/**", "GET"),
                owned_endpoint("owner-narrow", "/a/private/**", "POST"),
            ],
        );
        policy
            .provider_credential_rules
            .get_mut("_provider_work")
            .expect("provider rule")
            .binaries
            .push(openshell_core::proto::NetworkBinary {
                path: "/usr/bin/curl".to_string(),
            });
        CedarOnlyEngine::from_proto(&policy).expect("policy loads")
    }

    fn owners(engine: &CedarOnlyEngine, method: &str, target: &str) -> Vec<String> {
        let mut owners: Vec<_> = engine
            .l7_handle(engine.current_generation())
            .admitted_token_grant_owners(&ctx(), &request(method, target))
            .expect("owners evaluate")
            .into_iter()
            .collect();
        owners.sort();
        owners
    }

    #[test]
    fn token_grant_owner_requires_its_own_provider_rules_to_allow() {
        let engine = owner_engine(OWNER_POLICY);
        // Both endpoints cover the path, but only the broad endpoint's own
        // rule allows GET: Cedar's allow does not lend the narrow grant.
        assert_eq!(owners(&engine, "GET", "/a/private/item"), ["owner-broad"]);
        assert_eq!(owners(&engine, "POST", "/a/private/item"), ["owner-narrow"]);
        assert!(owners(&engine, "GET", "/b/item").is_empty());
    }

    #[test]
    fn token_grant_owner_requires_cedar_to_allow() {
        let engine = owner_engine(OWNER_POLICY);
        // The broad provider rule allows this request, but Cedar forbids it.
        assert!(owners(&engine, "GET", "/a/private/blocked").is_empty());
        // Provider rules never allow what Cedar does not permit.
        let narrow_cedar = OWNER_POLICY.replace(r#"context.method == "GET""#, "false");
        let engine = owner_engine(&narrow_cedar);
        assert!(owners(&engine, "GET", "/a/item").is_empty());
    }

    #[test]
    fn token_grant_owner_needs_an_allowing_audit_decision() {
        let engine = owner_engine(AUDIT_POLICY);
        // Cedar's audit-only endpoint forwards a denied POST, but a denial
        // admits no grant.
        assert!(owners(&engine, "POST", "/a/private/item").is_empty());
        assert_eq!(owners(&engine, "GET", "/a/item"), ["owner-broad"]);
    }

    #[test]
    fn token_grant_owners_are_empty_without_stamped_provider_endpoints() {
        let engine =
            CedarOnlyEngine::from_proto(&provider_policy(POLICY, vec![credentialed_endpoint()]))
                .expect("policy loads");
        assert!(owners(&engine, "GET", "/v1/status").is_empty());
    }

    #[test]
    fn token_grant_owners_fail_closed_when_tunnel_generation_is_stale() {
        let engine = owner_engine(OWNER_POLICY);
        let handle = engine.l7_handle(engine.current_generation());
        engine
            .reload_from_policy_str(OWNER_POLICY)
            .expect("reload without provider rules advances the generation");
        assert!(
            handle
                .admitted_token_grant_owners(&ctx(), &request("GET", "/a/item"))
                .is_err()
        );
    }

    #[test]
    fn tunnel_engine_delegates_token_grant_owners_to_cedar() {
        let cedar = Arc::new(owner_engine(OWNER_POLICY));
        let engine = crate::policy_engine::PolicyEngine::from(Arc::clone(&cedar));
        let tunnel = engine
            .tunnel_engine(cedar.current_generation())
            .expect("tunnel builds");
        let owners = tunnel
            .admitted_token_grant_owners(&ctx(), &request("POST", "/a/private/item"))
            .expect("owners evaluate");
        assert_eq!(
            owners,
            std::collections::HashSet::from(["owner-narrow".to_string()])
        );
    }

    /// A Cedar policy with `settings` as its endpoint settings.
    fn settings_policy(
        cedar: &str,
        settings: Vec<openshell_core::proto::NetworkEndpoint>,
    ) -> ProtoSandboxPolicy {
        let mut policy = policy_from_source(cedar);
        policy.endpoint_settings = settings;
        policy
    }

    fn setting(host: &str, path: &str) -> openshell_core::proto::NetworkEndpoint {
        openshell_core::proto::NetworkEndpoint {
            host: host.to_string(),
            port: 443,
            path: path.to_string(),
            ..Default::default()
        }
    }

    fn parsed_configs(engine: &CedarOnlyEngine, host: &str) -> Vec<crate::l7::L7EndpointConfig> {
        engine
            .authorize_egress(&curl_input(host))
            .expect("request evaluates")
            .endpoint_configs
            .iter()
            .map(|config| crate::l7::parse_l7_config(config).expect("config must parse"))
            .collect()
    }

    fn protocol_policy(protocol: &str) -> String {
        format!(
            r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@protocol("{protocol}")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#
        )
    }

    /// A connect permit and REST inspection for every host matching
    /// `*.example.com` on port 443, allowing `GET`.
    const GLOB_INSPECTED: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
permit (principal, action == Sandbox::Action::"HttpRequest", resource is Sandbox::NetworkEndpoint)
when {
    resource.host like("*.example.com", ".") && resource.port == 443
    && context.method == "GET"
};
"#;

    #[test]
    fn host_glob_selects_inspection_for_every_matching_host() {
        let engine = CedarOnlyEngine::from_policy_str(GLOB_INSPECTED).expect("policy loads");
        for host in ["api.example.com", "other.example.com"] {
            let configs = parsed_configs(&engine, host);
            assert_eq!(configs.len(), 1, "{host}: {configs:?}");
            assert_eq!(configs[0].protocol, openshell_policy::L7Protocol::Rest);
            assert_eq!(configs[0].path, "");
            let guards = engine.credential_guards(host, 443).expect("guards");
            assert_eq!(
                guards.len(),
                1,
                "{host}: the credential guard sees the inspection"
            );

            // Cedar evaluates the actual host, so the glob condition decides
            // each request on the inspected tunnel.
            let handle = engine.l7_handle(engine.current_generation());
            let ctx = L7EvalContext {
                host: host.to_string(),
                ..ctx()
            };
            let (allowed, _) = handle
                .evaluate_request(&ctx, &request("GET", "/x"))
                .expect("evaluates");
            assert!(allowed, "{host}: GET is allowed");
            let (allowed, _) = handle
                .evaluate_request(&ctx, &request("DELETE", "/x"))
                .expect("evaluates");
            assert!(!allowed, "{host}: DELETE is denied");
        }

        // A host outside the glob is not allowed to connect at all.
        let denied = engine
            .authorize_egress(&curl_input("deep.api.example.com"))
            .expect("evaluates");
        assert!(matches!(denied.action, NetworkAction::Deny { .. }));
        assert!(denied.endpoint_configs.is_empty());
    }

    #[test]
    fn exact_endpoint_paths_join_the_matching_glob_paths() {
        let policy = format!(
            r#"{GLOB_INSPECTED}
@path("/api/**") @enforcement("audit")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {{ context.path like("/api/**", "/") }};
"#
        );
        let engine = CedarOnlyEngine::from_policy_str(&policy).expect("policy loads");

        // The exact host gets a config per path of both entries, and the
        // relay routes a request to the most specific one.
        let configs = parsed_configs(&engine, "api.example.com");
        let paths: Vec<(&str, crate::l7::EnforcementMode)> = configs
            .iter()
            .map(|config| (config.path.as_str(), config.enforcement))
            .collect();
        assert_eq!(
            paths,
            vec![
                ("", crate::l7::EnforcementMode::Enforce),
                ("/api/**", crate::l7::EnforcementMode::Audit),
            ]
        );
        let guard = engine.read_engine().expect("engine");
        assert_eq!(
            guard.route_request("api.example.com", 443, "/api/items"),
            RequestRoute::Routed {
                endpoint_path: "/api/**".to_string()
            }
        );
        assert_eq!(
            guard.route_request("api.example.com", 443, "/other"),
            RequestRoute::Routed {
                endpoint_path: String::new()
            }
        );
        // Another matching host has only the glob's path.
        assert_eq!(
            guard.route_request("other.example.com", 443, "/api/items"),
            RequestRoute::Routed {
                endpoint_path: String::new()
            }
        );
        drop(guard);
        assert_eq!(parsed_configs(&engine, "other.example.com").len(), 1);
    }

    #[test]
    fn settings_merge_into_glob_inspected_configs() {
        let mut glob_setting = setting("*.example.com", "");
        glob_setting.allow_encoded_slash = true;
        let mut exact_setting = setting("api.example.com", "");
        exact_setting.tls = openshell_core::proto::NetworkTlsMode::Skip as i32;
        let engine = CedarOnlyEngine::from_proto(&settings_policy(
            GLOB_INSPECTED,
            vec![glob_setting, exact_setting],
        ))
        .expect("policy loads");

        let api = engine
            .authorize_egress(&curl_input("api.example.com"))
            .expect("evaluates")
            .endpoint_configs;
        assert_eq!(api.len(), 1);
        let config = crate::l7::parse_l7_config(&api[0]).expect("inspected");
        assert!(
            config.allow_encoded_slash,
            "the glob setting applies: {config:?}"
        );
        assert_eq!(crate::l7::parse_tls_mode(&api[0]), crate::l7::TlsMode::Skip);

        let other = engine
            .authorize_egress(&curl_input("other.example.com"))
            .expect("evaluates")
            .endpoint_configs;
        assert_eq!(other.len(), 1);
        let config = crate::l7::parse_l7_config(&other[0]).expect("inspected");
        assert!(
            config.allow_encoded_slash,
            "the glob setting applies: {config:?}"
        );
        assert_eq!(
            crate::l7::parse_tls_mode(&other[0]),
            crate::l7::TlsMode::Auto,
            "the exact-host setting does not reach another host"
        );
    }

    #[test]
    fn mcp_settings_replace_the_default_revision() {
        let mut mcp = setting("*.example.com", "");
        mcp.mcp = Some(openshell_core::proto::McpOptions {
            versions: vec!["2026-07-28".to_string(), "2025-06-18".to_string()],
            strict_tool_names: Some(false),
            ..Default::default()
        });
        mcp.json_rpc_max_body_bytes = 4096;
        let engine =
            CedarOnlyEngine::from_proto(&settings_policy(&protocol_policy("mcp"), vec![mcp]))
                .expect("policy loads");
        let configs = parsed_configs(&engine, "api.example.com");
        assert_eq!(configs.len(), 1);
        assert_eq!(
            configs[0].mcp_versions,
            vec![
                openshell_core::mcp::McpProtocolVersion::V2025_06_18,
                openshell_core::mcp::McpProtocolVersion::V2026_07_28,
            ]
        );
        assert!(!configs[0].mcp_strict_tool_names);
        assert_eq!(configs[0].json_rpc_max_body_bytes, 4096);

        // Without settings, the pinned default applies.
        let default = CedarOnlyEngine::from_policy_str(&protocol_policy("mcp")).expect("loads");
        let configs = parsed_configs(&default, "api.example.com");
        assert_eq!(
            configs[0].mcp_versions,
            vec![openshell_policy_schema::DEFAULT_MCP_PROTOCOL_VERSION]
        );
        assert!(configs[0].mcp_strict_tool_names);
    }

    #[test]
    fn protocol_settings_apply_only_to_their_protocol() {
        let mut graphql = setting("api.example.com", "");
        graphql.graphql_max_body_bytes = 1024;
        graphql.persisted_queries = "allow_registered".to_string();
        graphql.mcp = Some(openshell_core::proto::McpOptions {
            versions: vec!["2025-06-18".to_string()],
            ..Default::default()
        });
        let engine =
            CedarOnlyEngine::from_proto(&settings_policy(&protocol_policy("rest"), vec![graphql]))
                .expect("policy loads");
        let config = engine
            .authorize_egress(&curl_input("api.example.com"))
            .expect("evaluates")
            .endpoint_configs
            .remove(0);
        assert_eq!(
            config.graphql_max_body_bytes, 0,
            "graphql_max_body_bytes must not apply to REST: {config:?}"
        );
        assert!(
            config.persisted_queries.is_empty(),
            "persisted_queries must not apply to REST: {config:?}"
        );
        assert!(
            config.mcp_versions.is_empty(),
            "mcp_versions must not apply to REST: {config:?}"
        );
    }

    #[test]
    fn tls_skip_setting_applies_to_a_connect_only_endpoint() {
        let mut skip = setting("api.example.com", "");
        skip.tls = openshell_core::proto::NetworkTlsMode::Skip as i32;
        let engine =
            CedarOnlyEngine::from_proto(&settings_policy(CONNECT_ONLY, vec![skip.clone()]))
                .expect("policy loads");
        let authorization = engine
            .authorize_egress(&curl_input("api.example.com"))
            .expect("evaluates");
        assert_eq!(authorization.endpoint_configs.len(), 1);
        assert!(crate::l7::parse_l7_config(&authorization.endpoint_configs[0]).is_none());
        assert_eq!(
            crate::l7::parse_tls_mode(&authorization.endpoint_configs[0]),
            crate::l7::TlsMode::Skip
        );

        // The setting reaches a provider config too, which the proxy reads
        // first, so the credential guard sees the skipped TLS.
        let mut policy = provider_policy(CONNECT_ONLY, vec![credentialed_endpoint()]);
        policy.endpoint_settings = vec![skip];
        let engine = CedarOnlyEngine::from_proto(&policy).expect("policy loads");
        let guards = engine
            .credential_guards("api.example.com", 443)
            .expect("guards");
        assert_eq!(guards.len(), 1);
        assert_eq!(
            crate::l7::parse_tls_mode(&guards[0]),
            crate::l7::TlsMode::Skip
        );

        // A denied connection gets no configs.
        let denied = engine
            .authorize_egress(&curl_input("other.example.com"))
            .expect("evaluates");
        assert!(denied.endpoint_configs.is_empty());
    }

    #[test]
    fn path_setting_adds_a_scoped_config_with_cedar_inspection() {
        let mut slash = setting("api.example.com", "/repos/**");
        slash.allow_encoded_slash = true;
        let engine = CedarOnlyEngine::from_proto(&settings_policy(POLICY, vec![slash]))
            .expect("policy loads");
        let configs = parsed_configs(&engine, "api.example.com");
        assert_eq!(configs.len(), 2);
        let scoped = configs
            .iter()
            .find(|config| config.path == "/repos/**")
            .expect("scoped config");
        assert!(scoped.allow_encoded_slash);
        assert_eq!(scoped.protocol, openshell_policy::L7Protocol::Rest);
        assert_eq!(scoped.enforcement, crate::l7::EnforcementMode::Enforce);
        let base = configs
            .iter()
            .find(|config| config.path.is_empty())
            .expect("path-less config");
        assert!(!base.allow_encoded_slash);
    }

    #[test]
    fn later_settings_override_earlier_ones() {
        let mut glob = setting("*.example.com", "");
        glob.graphql_max_body_bytes = 1024;
        let mut exact = setting("api.example.com", "");
        exact.graphql_max_body_bytes = 2048;
        let engine = CedarOnlyEngine::from_proto(&settings_policy(
            &protocol_policy("graphql"),
            vec![glob, exact],
        ))
        .expect("policy loads");
        assert_eq!(
            parsed_configs(&engine, "api.example.com")[0].graphql_max_body_bytes,
            2048
        );
    }

    #[test]
    fn reload_tracks_endpoint_setting_changes() {
        let mut slash = setting("api.example.com", "");
        slash.allow_encoded_slash = true;
        let engine = CedarOnlyEngine::from_proto(&settings_policy(POLICY, vec![slash.clone()]))
            .expect("policy loads");
        let generation = engine.current_generation();
        let unchanged = engine
            .stage(&settings_policy(POLICY, vec![slash]), 0)
            .expect("stage");
        engine.commit(unchanged).expect("commit");
        assert_eq!(engine.current_generation(), generation);

        let changed = engine.stage(&policy_from_source(POLICY), 0).expect("stage");
        engine.commit(changed).expect("commit");
        assert_eq!(engine.current_generation(), generation + 1);
        assert!(!parsed_configs(&engine, "api.example.com")[0].allow_encoded_slash);
    }

    const GRAPHQL_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {
    context.graphql_operation_type == "query"
    && ["viewer"].containsAll(context.graphql_fields)
};
"#;

    fn registry_setting(mode: &str) -> openshell_core::proto::NetworkEndpoint {
        let mut registry = setting("api.example.com", "");
        registry.persisted_queries = mode.to_string();
        registry.graphql_persisted_queries.insert(
            "abc123".to_string(),
            openshell_core::proto::GraphqlOperation {
                operation_type: "query".to_string(),
                operation_name: "Viewer".to_string(),
                fields: vec!["viewer".to_string()],
            },
        );
        registry.graphql_persisted_queries.insert(
            "saved-admin".to_string(),
            openshell_core::proto::GraphqlOperation {
                operation_type: "query".to_string(),
                operation_name: "Admin".to_string(),
                fields: vec!["admin".to_string()],
            },
        );
        registry
    }

    fn persisted(hash: Option<&str>, id: Option<&str>) -> L7RequestInfo {
        L7RequestInfo {
            graphql: Some(crate::l7::graphql::GraphqlRequestInfo {
                operations: vec![crate::l7::graphql::GraphqlOperationInfo {
                    operation_type: String::new(),
                    operation_name: None,
                    fields: Vec::new(),
                    persisted_query: true,
                    persisted_query_hash: hash.map(str::to_string),
                    persisted_query_id: id.map(str::to_string),
                }],
                error: None,
            }),
            ..request("POST", "/graphql")
        }
    }

    fn evaluate(engine: &CedarOnlyEngine, request: &L7RequestInfo) -> (bool, String) {
        engine
            .l7_handle(engine.current_generation())
            .evaluate_request(&ctx(), request)
            .expect("request evaluates")
    }

    #[test]
    fn hash_only_persisted_queries_resolve_through_the_registry() {
        let engine = CedarOnlyEngine::from_proto(&settings_policy(
            GRAPHQL_POLICY,
            vec![registry_setting("allow_registered")],
        ))
        .expect("policy loads");
        assert!(evaluate(&engine, &persisted(Some("abc123"), None)).0);
        // The registered operation, not an empty one, is what Cedar judges.
        assert!(!evaluate(&engine, &persisted(None, Some("saved-admin"))).0);
        // The hash is the key whenever it is present.
        let (allowed, reason) = evaluate(&engine, &persisted(Some("missing"), Some("abc123")));
        assert!(!allowed);
        assert_eq!(reason, UNREGISTERED_PERSISTED_QUERY);
    }

    #[test]
    fn hash_only_persisted_queries_are_denied_without_allow_registered() {
        for settings in [vec![registry_setting("deny")], Vec::new()] {
            let engine = CedarOnlyEngine::from_proto(&settings_policy(GRAPHQL_POLICY, settings))
                .expect("policy loads");
            let (allowed, reason) = evaluate(&engine, &persisted(Some("abc123"), None));
            assert!(!allowed);
            assert_eq!(reason, UNREGISTERED_PERSISTED_QUERY);
        }
    }

    #[test]
    fn invalid_provider_rules_with_owners_fail_to_load() {
        let mut endpoint = owned_endpoint("owner", "/a/**", "GET");
        endpoint.protocol = "not-a-protocol".to_string();
        assert!(
            CedarOnlyEngine::from_proto(&provider_policy(OWNER_POLICY, vec![endpoint])).is_err()
        );
    }

    /// REST under `/api/**`, GraphQL-over-WebSocket at `/ws`, and audited
    /// GraphQL at `/graphql`, all on `api.example.com:443`.
    const PATHS_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@path("/api/**")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.method == "GET" && context.path like("/api/**", "/") };
@path("/ws") @protocol("websocket-graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {
    context.path == "/ws"
    && (context.method == "GET"
        || (context.method == "WEBSOCKET_TEXT"
            && context.graphql_operation_type == "subscription"))
};
@path("/graphql") @protocol("graphql") @enforcement("audit")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.path == "/graphql" && context.graphql_operation_type == "query" };
"#;

    #[test]
    fn each_cedar_path_gets_its_own_endpoint_config() {
        use crate::l7::EnforcementMode::{Audit, Enforce};
        use openshell_policy::L7Protocol::{Graphql, Rest, Websocket};

        let engine = CedarOnlyEngine::from_policy_str(PATHS_POLICY).expect("policy loads");
        let mut configs: Vec<_> = parsed_configs(&engine, "api.example.com")
            .into_iter()
            .map(|config| {
                (
                    config.path,
                    config.protocol,
                    config.enforcement,
                    config.websocket_graphql_policy,
                )
            })
            .collect();
        configs.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(
            configs,
            vec![
                ("/api/**".to_string(), Rest, Enforce, false),
                ("/graphql".to_string(), Graphql, Audit, false),
                ("/ws".to_string(), Websocket, Enforce, true),
            ],
            "no path-less config: no policy lacks @path"
        );
    }

    #[test]
    fn requests_take_the_inspection_of_their_routed_path() {
        let engine = CedarOnlyEngine::from_policy_str(PATHS_POLICY).expect("policy loads");
        let evaluate = |request: &L7RequestInfo| {
            engine
                .l7_handle(engine.current_generation())
                .evaluate_request(&ctx_for("api.example.com"), request)
                .expect("request evaluates")
        };
        assert!(evaluate(&request("GET", "/api/items")).0);
        assert_eq!(
            evaluate(&request("GET", "/other")),
            (false, UNMATCHED_PATH.to_string()),
            "no inspected path matches, as the relay denies it"
        );
        assert!(evaluate(&request("GET", "/ws")).0, "the upgrade");
        let message = |operation_type: &str| L7RequestInfo {
            graphql: Some(crate::l7::graphql::GraphqlRequestInfo {
                operations: vec![crate::l7::graphql::GraphqlOperationInfo {
                    operation_type: operation_type.to_string(),
                    operation_name: None,
                    fields: vec!["messageAdded".to_string()],
                    persisted_query: false,
                    persisted_query_hash: None,
                    persisted_query_id: None,
                }],
                error: None,
            }),
            ..request("WEBSOCKET_TEXT", "/ws")
        };
        assert!(evaluate(&message("subscription")).0);
        assert!(!evaluate(&message("mutation")).0);
        // Routed to the audit path, the denial is reported for the relay to
        // log and forward.
        let mutation = L7RequestInfo {
            graphql: message("mutation").graphql,
            ..request("POST", "/graphql")
        };
        assert!(!evaluate(&mutation).0);
    }

    fn ctx_for(host: &str) -> L7EvalContext {
        L7EvalContext {
            host: host.to_string(),
            ..ctx()
        }
    }

    #[test]
    fn provider_endpoints_take_the_inspection_of_their_path() {
        let mut ws = credentialed_endpoint();
        ws.path = "/ws".to_string();
        let mut unrelated = credentialed_endpoint();
        unrelated.path = "/elsewhere/**".to_string();
        let engine =
            CedarOnlyEngine::from_proto(&provider_policy(PATHS_POLICY, vec![ws, unrelated]))
                .expect("policy loads");
        let configs = engine
            .credential_guards("api.example.com", 443)
            .expect("configs build");
        let provider = |path: &str| {
            configs
                .iter()
                .find(|config| {
                    config.path == path
                        && crate::l7::parse_endpoint_credential_guard(config).provider_credentialed
                })
                .expect("provider config")
        };
        let ws = crate::l7::parse_l7_config(provider("/ws")).expect("inspected");
        assert_eq!(ws.protocol, openshell_policy::L7Protocol::Websocket);
        assert!(ws.websocket_graphql_policy);
        // No Cedar path covers the provider path, so its config is not an L7
        // config and the relay never routes requests to it.
        assert!(crate::l7::parse_l7_config(provider("/elsewhere/**")).is_none());
        assert_eq!(
            configs.len(),
            4,
            "two provider configs plus /api/** and /graphql"
        );
    }

    #[test]
    fn path_settings_follow_cedar_inspection() {
        let mut registry = setting("api.example.com", "/ws");
        registry.persisted_queries = "allow_registered".to_string();
        let mut uninspected = setting("api.example.com", "/elsewhere/**");
        uninspected.allow_encoded_slash = true;
        let mut nested = setting("api.example.com", "/api/v2/**");
        nested.allow_encoded_slash = true;
        let engine = CedarOnlyEngine::from_proto(&settings_policy(
            PATHS_POLICY,
            vec![registry, uninspected, nested],
        ))
        .expect("policy loads");
        let configs = parsed_configs(&engine, "api.example.com");
        let paths: Vec<&str> = configs.iter().map(|config| config.path.as_str()).collect();
        assert_eq!(paths, ["/api/**", "/graphql", "/ws", "/api/v2/**"]);
        let nested = &configs[3];
        assert_eq!(nested.protocol, openshell_policy::L7Protocol::Rest);
        assert!(nested.allow_encoded_slash);
    }

    #[test]
    fn plain_websocket_endpoints_take_no_graphql_settings() {
        let mut registry = setting("api.example.com", "");
        registry.persisted_queries = "allow_registered".to_string();
        let engine = CedarOnlyEngine::from_proto(&settings_policy(
            &protocol_policy("websocket"),
            vec![registry],
        ))
        .expect("policy loads");
        let configs = parsed_configs(&engine, "api.example.com");
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].protocol, openshell_policy::L7Protocol::Websocket);
        assert!(
            !configs[0].websocket_graphql_policy,
            "a persisted-query setting must not turn on GraphQL message policy"
        );
    }

    const QUERY_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.query.hasTag("tag") && context.query.getTag("tag") like "foo-*" };
"#;

    fn with_query(query: &[(&str, &[&str])]) -> L7RequestInfo {
        L7RequestInfo {
            query_params: query
                .iter()
                .map(|(key, values)| {
                    (
                        (*key).to_string(),
                        values.iter().map(ToString::to_string).collect(),
                    )
                })
                .collect(),
            ..request("GET", "/download")
        }
    }

    #[test]
    fn query_params_reach_cedar_decoded() {
        let engine = CedarOnlyEngine::from_policy_str(QUERY_POLICY).expect("policy parses");
        let tunnel = engine.l7_handle(engine.current_generation());
        let decide = |query: &[(&str, &[&str])]| {
            tunnel
                .evaluate_request(&ctx(), &with_query(query))
                .expect("request evaluates")
        };
        assert!(decide(&[("tag", &["foo-a", "foo-b"])]).0);
        assert!(!decide(&[("tag", &["foo-a", "evil"])]).0);
        assert!(!decide(&[]).0);

        // Through the relay's parser, which decodes keys and values.
        let (_, parsed) =
            crate::l7::rest::parse_target_query("/download?t%61g=foo%2Da&tag=foo-x+y")
                .expect("target parses");
        let mut request = request("GET", "/download");
        request.query_params = parsed;
        assert!(tunnel.evaluate_request(&ctx(), &request).unwrap().0);
    }

    #[test]
    fn query_over_the_combination_cap_is_denied_with_a_reason() {
        let engine = CedarOnlyEngine::from_policy_str(QUERY_POLICY).expect("policy parses");
        let tunnel = engine.l7_handle(engine.current_generation());
        let values: Vec<String> = (0..=openshell_policy_cedar::MAX_QUERY_COMBINATIONS)
            .map(|value| format!("foo-{value}"))
            .collect();
        let values: Vec<&str> = values.iter().map(String::as_str).collect();
        let (allowed, reason) = tunnel
            .evaluate_request(&ctx(), &with_query(&[("tag", &values)]))
            .expect("an over-cap query is a decision, not an error");
        assert!(!allowed);
        assert!(reason.contains("value combinations"), "{reason}");
        let (allowed, _) = tunnel
            .evaluate_request(&ctx(), &with_query(&[("tag", &values[1..])]))
            .unwrap();
        assert!(allowed, "the cap itself is evaluated");
    }

    /// A connect permit and an HTTP forbid that name `/usr/bin/python3`
    /// through its symlink aliases only.
    const ALIAS_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.binary_aliases.contains("/usr/bin/python3") };

permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");

forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.binary_aliases.contains("/usr/bin/python3") && context.method == "DELETE" };
"#;

    fn alias_set(entries: &[(&str, &str)]) -> BinaryAliases {
        BinaryAliases(
            entries
                .iter()
                .map(|(path, target)| {
                    ((*path).to_string(), AliasTarget::new((*target).to_string()))
                })
                .collect(),
        )
    }

    #[test]
    fn aliases_match_the_binary_or_an_ancestor_exactly() {
        let aliases = alias_set(&[
            ("/usr/bin/python3", "/usr/bin/python3.11"),
            ("/usr/bin/node", "/opt/node/bin/node"),
        ]);
        let matching = |binary: &str, ancestors: &[&str]| {
            let ancestors: Vec<String> = ancestors.iter().map(ToString::to_string).collect();
            aliases.matching(binary, &ancestors).expect("matches")
        };
        assert_eq!(matching("/usr/bin/python3.11", &[]), ["/usr/bin/python3"]);
        assert_eq!(
            matching("/usr/bin/curl", &["/bin/bash", "/opt/node/bin/node"]),
            ["/usr/bin/node"]
        );
        // The symlink itself and near misses are not aliases.
        assert!(matching("/usr/bin/python3", &[]).is_empty());
        assert!(matching("/usr/bin/python3.1", &["/usr/bin/python3.11x"]).is_empty());
    }

    #[test]
    fn a_glob_target_matches_as_the_rego_rules_match_it() {
        let aliases = alias_set(&[("/usr/bin/tool", "/opt/*/tool")]);
        let matching = |binary: &str| aliases.matching(binary, &[]).expect("matches");
        assert_eq!(matching("/opt/v2/tool"), ["/usr/bin/tool"]);
        // `*` does not cross `/`, as in `glob.match(path, ["/"], p)`.
        assert!(matching("/opt/v2/bin/tool").is_empty());

        let invalid = alias_set(&[("/usr/bin/tool", "/opt/[*/tool")]);
        assert!(invalid.matching("/opt/v2/tool", &[]).is_err());
    }

    #[test]
    fn requests_carry_the_aliases_of_their_binary() {
        let engine = CedarOnlyEngine::from_policy_str(ALIAS_POLICY).expect("policy loads");
        let python = NetworkInput {
            binary_path: "/usr/bin/python3.11".into(),
            ..curl_input("api.example.com")
        };
        let allowed = |engine: &CedarOnlyEngine| {
            matches!(
                engine.authorize_egress(&python).expect("evaluates").action,
                NetworkAction::Allow { .. }
            )
        };
        assert!(!allowed(&engine), "no alias before resolution");

        engine.write_engine().expect("lock").binary_aliases =
            alias_set(&[("/usr/bin/python3", "/usr/bin/python3.11")]);
        assert!(allowed(&engine));
        let python_ctx = L7EvalContext {
            binary_path: "/usr/bin/python3.11".to_string(),
            ..ctx()
        };
        let evaluate = |method: &str| {
            engine
                .l7_handle(engine.current_generation())
                .evaluate_request(&python_ctx, &request(method, "/v1/status"))
                .expect("evaluates")
                .0
        };
        assert!(evaluate("GET"));
        assert!(!evaluate("DELETE"), "the forbid reaches the alias");
        let curl = engine
            .l7_handle(engine.current_generation())
            .evaluate_request(&ctx(), &request("DELETE", "/v1/status"))
            .expect("evaluates")
            .0;
        assert!(curl, "another binary has no alias");
    }

    /// A connect permit and an HTTP forbid for the YAML binary glob
    /// `/usr/lib/node_modules/@openai/**`.
    const GLOB_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.binary_globs.contains("/usr/lib/node_modules/@openai/**") };

permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");

forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.binary_globs.contains("/opt/*/tool") && context.method == "DELETE" };
"#;

    #[test]
    fn binary_globs_match_the_binary_or_an_ancestor_as_the_rego_rules_do() {
        let engine = CedarOnlyEngine::from_policy_str(GLOB_POLICY).expect("policy loads");
        let globs = &engine.read_engine().expect("lock").binary_globs;
        let matching = |binary: &str, ancestors: &[&str]| {
            let ancestors: Vec<String> = ancestors.iter().map(ToString::to_string).collect();
            globs.matching(binary, &ancestors).expect("matches")
        };
        assert_eq!(
            matching("/usr/lib/node_modules/@openai/codex/bin/codex.js", &[]),
            ["/usr/lib/node_modules/@openai/**"]
        );
        assert_eq!(
            matching(
                "/usr/bin/node",
                &["/bin/sh", "/usr/lib/node_modules/@openai/codex"]
            ),
            ["/usr/lib/node_modules/@openai/**"]
        );
        // `*` does not cross `/`, as in `glob.match(path, ["/"], p)`.
        assert_eq!(matching("/opt/v2/tool", &[]), ["/opt/*/tool"]);
        assert!(matching("/opt/v2/bin/tool", &[]).is_empty());
        assert!(matching("/usr/lib/node_modules/@other/x", &["/usr/bin/node"]).is_empty());
    }

    #[test]
    fn requests_carry_the_globs_matching_their_binary() {
        let engine = CedarOnlyEngine::from_policy_str(GLOB_POLICY).expect("policy loads");
        let connect = |binary: &str, ancestors: &[&str]| {
            let input = NetworkInput {
                binary_path: binary.into(),
                ancestors: ancestors.iter().map(std::path::PathBuf::from).collect(),
                ..curl_input("api.example.com")
            };
            matches!(
                engine.authorize_egress(&input).expect("evaluates").action,
                NetworkAction::Allow { .. }
            )
        };
        assert!(connect(
            "/usr/bin/node",
            &["/usr/lib/node_modules/@openai/codex/bin/codex.js"]
        ));
        assert!(!connect("/usr/bin/node", &["/usr/bin/bash"]));

        let tool_ctx = L7EvalContext {
            binary_path: "/usr/bin/curl".to_string(),
            ancestors: vec!["/opt/v1/tool".to_string()],
            ..ctx()
        };
        let evaluate = |ctx: &L7EvalContext, method: &str| {
            engine
                .l7_handle(engine.current_generation())
                .evaluate_request(ctx, &request(method, "/v1/status"))
                .expect("evaluates")
                .0
        };
        assert!(evaluate(&tool_ctx, "GET"));
        assert!(
            !evaluate(&tool_ctx, "DELETE"),
            "the forbid reaches the ancestor"
        );
        assert!(
            evaluate(&ctx(), "DELETE"),
            "another process matches no glob"
        );
    }

    #[test]
    fn token_grant_binary_globs_match_ancestors() {
        // The provider rule names a binary glob; a YAML sandbox admits the
        // owner for a process whose ancestor the glob matches.
        let mut policy = provider_policy(
            OWNER_POLICY,
            vec![owned_endpoint("owner-broad", "/a/**", "GET")],
        );
        policy
            .provider_credential_rules
            .get_mut("_provider_work")
            .expect("provider rule")
            .binaries
            .push(openshell_core::proto::NetworkBinary {
                path: "/opt/tools/*".to_string(),
            });
        let engine = CedarOnlyEngine::from_proto(&policy).expect("policy loads");
        assert_eq!(
            engine
                .read_engine()
                .expect("lock")
                .binary_globs
                .matching("/usr/bin/curl", &["/opt/tools/run".to_string()])
                .expect("matches"),
            ["/opt/tools/*"]
        );
        let owners = |ancestors: &[&str]| {
            let ctx = L7EvalContext {
                ancestors: ancestors.iter().map(ToString::to_string).collect(),
                ..ctx()
            };
            engine
                .l7_handle(engine.current_generation())
                .admitted_token_grant_owners(&ctx, &request("GET", "/a/item"))
                .expect("owners evaluate")
                .into_iter()
                .collect::<Vec<_>>()
        };
        assert_eq!(owners(&["/opt/tools/run"]), ["owner-broad"]);
        assert!(owners(&["/usr/bin/bash"]).is_empty());
    }

    #[test]
    fn requests_parsed_as_graphql_are_flagged_for_cedar() {
        // A broad REST permit never allows a GraphQL operation on the
        // GraphQL path, as a YAML GraphQL endpoint is authoritative for the
        // requests it parses; the same request without GraphQL inspection
        // sees the REST permit.
        let engine = CedarOnlyEngine::from_policy_str(
            r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@path("/**")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.method == "GET" };
@path("/graphql") @protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.path == "/graphql" && context.graphql_operation_type == "query" };
"#,
        )
        .expect("policy loads");
        let evaluate = |request: &L7RequestInfo| {
            engine
                .l7_handle(engine.current_generation())
                .evaluate_request(&ctx(), request)
                .expect("evaluates")
                .0
        };
        let operation = |operation_type: &str| L7RequestInfo {
            graphql: Some(crate::l7::graphql::GraphqlRequestInfo {
                operations: vec![crate::l7::graphql::GraphqlOperationInfo {
                    operation_type: operation_type.to_string(),
                    operation_name: None,
                    fields: vec!["viewer".to_string()],
                    persisted_query: false,
                    persisted_query_hash: None,
                    persisted_query_id: None,
                }],
                error: None,
            }),
            ..request("GET", "/graphql")
        };
        assert!(evaluate(&operation("query")));
        assert!(
            !evaluate(&operation("mutation")),
            "the REST permit is left out"
        );
        assert!(
            evaluate(&request("GET", "/graphql")),
            "not parsed as GraphQL"
        );
        assert!(evaluate(&request("GET", "/other")));
    }

    #[test]
    fn audit_policies_decide_requests_routed_to_an_enforced_path() {
        // YAML applies the rules of every matching endpoint and the selected
        // endpoint's enforcement decides whether a denial blocks: the audit
        // path's forbid blocks on the enforced path and is forwarded on its
        // own path.
        let engine = CedarOnlyEngine::from_policy_str(
            r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
@path("/**") @enforcement("audit")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.method == "GET" };
@path("/**") @enforcement("audit")
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.method == "DELETE" };
@path("/api/**")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { ["DELETE", "POST"].contains(context.method) && context.path like("/api/**", "/") };
@path("/api/**") @enforcement("staged")
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.method == "POST" };
"#,
        )
        .expect("policy loads");
        let configs: HashMap<String, crate::l7::EnforcementMode> =
            parsed_configs(&engine, "api.example.com")
                .into_iter()
                .map(|config| (config.path, config.enforcement))
                .collect();
        assert_eq!(configs["/**"], crate::l7::EnforcementMode::Audit);
        assert_eq!(configs["/api/**"], crate::l7::EnforcementMode::Enforce);
        let evaluate = |method: &str, target: &str| {
            engine
                .l7_handle(engine.current_generation())
                .evaluate_request(&ctx(), &request(method, target))
                .expect("evaluates")
                .0
        };
        assert!(!evaluate("DELETE", "/api/item"), "the audit forbid decides");
        assert!(evaluate("GET", "/api/item"), "the audit permit decides");
        assert!(
            evaluate("POST", "/api/item"),
            "the staged forbid never decides"
        );
        assert!(
            !evaluate("DELETE", "/other"),
            "forwarded by the relay on the audit path"
        );
    }

    #[test]
    fn the_entrypoint_pid_is_kept_across_reloads() {
        const PID: u32 = 4242;
        let engine = CedarOnlyEngine::from_policy_str(ALIAS_POLICY).expect("policy loads");
        let generation = engine.current_generation();
        engine.resolve_binary_symlinks(0).expect("resolves");
        assert_eq!(engine.current_generation(), generation, "0 is a no-op");

        engine.resolve_binary_symlinks(PID).expect("resolves");
        assert_eq!(engine.current_generation(), generation + 1);
        engine.resolve_binary_symlinks(PID).expect("resolves");
        assert_eq!(engine.current_generation(), generation + 1, "same pid");

        // A reload that does not know the pid resolves for the known one.
        engine
            .reload_from_policy_str(POLICY)
            .expect("reload succeeds");
        assert_eq!(engine.read_engine().expect("lock").entrypoint_pid, PID);
    }

    #[test]
    fn a_policy_staged_before_the_pid_is_resolved_on_commit() {
        const PID: u32 = 4242;
        let engine = CedarOnlyEngine::from_policy_str(POLICY).expect("policy loads");
        let changed = engine
            .stage(&policy_from_source(ALIAS_POLICY), 0)
            .expect("stage");
        engine.resolve_binary_symlinks(PID).expect("resolves");
        engine.commit(changed).expect("commit");
        assert_eq!(engine.read_engine().expect("lock").entrypoint_pid, PID);

        // An unchanged policy staged with a new pid resolves the active one.
        let other = CedarOnlyEngine::from_policy_str(ALIAS_POLICY).expect("policy loads");
        let generation = other.current_generation();
        let unchanged = other
            .stage(&policy_from_source(ALIAS_POLICY), PID)
            .expect("stage");
        other.commit(unchanged).expect("commit");
        assert_eq!(other.read_engine().expect("lock").entrypoint_pid, PID);
        assert_eq!(other.current_generation(), generation + 1);
    }

    /// Resolves a real symlink through `/proc/<pid>/root`, as for YAML.
    #[cfg(target_os = "linux")]
    #[test]
    fn resolution_finds_symlinked_policy_binaries() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("python3.11");
        let link = dir.path().join("python3");
        std::fs::write(&target, b"python").expect("target");
        symlink(&target, &link).expect("symlink");
        let pid = std::process::id();
        if crate::binary_resolution::resolve_policy_binary(&link.to_string_lossy(), pid).is_none() {
            eprintln!("Skipping: /proc/<pid>/root/ not accessible in this environment");
            return;
        }

        let policy = ALIAS_POLICY.replace("/usr/bin/python3", &link.to_string_lossy());
        let engine = CedarOnlyEngine::from_policy_str(&policy).expect("policy loads");
        let allowed = |binary: &std::path::Path| {
            let input = NetworkInput {
                binary_path: binary.to_path_buf(),
                ..curl_input("api.example.com")
            };
            matches!(
                engine.authorize_egress(&input).expect("evaluates").action,
                NetworkAction::Allow { .. }
            )
        };
        assert!(!allowed(&target), "denied before the pid is known");
        engine.resolve_binary_symlinks(pid).expect("resolves");
        assert!(allowed(&target), "allowed once the symlink resolves");

        // A reload of the same policy resolves the link again, as a YAML
        // reload does, so a retargeted link loses its old alias.
        let retarget = dir.path().join("python3.12");
        std::fs::write(&retarget, b"python").expect("new target");
        std::fs::remove_file(&link).expect("remove link");
        symlink(&retarget, &link).expect("symlink");
        let generation = engine.current_generation();
        let unchanged = engine
            .stage(&policy_from_source(&policy), pid)
            .expect("stage");
        engine.commit(unchanged).expect("commit");
        assert_eq!(engine.current_generation(), generation + 1);
        assert!(!allowed(&target), "the old target is no longer an alias");
        assert!(allowed(&retarget), "the new target is");
    }
}
