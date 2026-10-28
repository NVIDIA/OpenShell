// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The loaded Cedar policy and the endpoint configs it routes connections
//! and requests with.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use miette::Result;
use openshell_core::endpoint_path::path_specificity;
use openshell_core::policy_identity::deterministic_policy_hash;
use openshell_core::proto::{NetworkPolicyRule, SandboxPolicy as ProtoSandboxPolicy};
use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ocsf_emit};
use openshell_policy_cedar::{
    AuthorizedNetworkEndpoint, CedarEngine, IpNet, L7Endpoint, L7Protocol, TokenGrantRules,
    normalize_host,
};

use super::CEDAR_POLICY_NAME;
use crate::policy_types::{
    DnsRecord, EndpointConfig, EndpointProtocol, EnforcementSetting, GraphqlPersistedQuery,
    MatchedEndpoint, TlsSetting,
};

/// The active Cedar policy and the provider settings delivered with it.
///
/// Swapped as one unit on reload so a decision never pairs one revision's
/// Cedar policy with another revision's provider settings.
pub(super) struct LoadedPolicy {
    pub(super) mcp_endpoints: Vec<openshell_core::proto::NetworkEndpoint>,
    /// Shared with the [`super::CedarDestination`] of each decision it makes.
    pub(super) cedar: Arc<CedarEngine>,
    /// Hash of the canonical policy, stamped on every endpoint config so
    /// token-grant reporting binds each request to the policy it was
    /// selected under, as the YAML engine's endpoint data does.
    pub(super) policy_hash: String,
    providers: Vec<ProviderEndpoint>,
    settings: Vec<EndpointSetting>,
    /// The provider rules compiled to Cedar, used only to select token-grant
    /// owners. `None` when no provider endpoint carries an owner.
    pub(super) token_grants: Option<TokenGrantRules>,
    /// The policy binary paths that are symlinks in the sandbox.
    pub(super) binary_aliases: BinaryAliases,
    /// The binary glob patterns the Cedar policy and the provider rules
    /// test, compiled with the YAML matcher.
    pub(super) binary_globs: BinaryGlobs,
    /// The entrypoint process whose root filesystem `binary_aliases` and
    /// `token_grants` were resolved in; 0 before it is known.
    pub(super) entrypoint_pid: u32,
    /// Test-only: makes the next binary resolution fail, standing in for a
    /// provider rule set that compiles for one entrypoint process but not
    /// another.
    #[cfg(test)]
    pub(super) fail_resolution: bool,
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
    ///
    /// `cedar` is the engine validation loaded from the policy's Cedar text;
    /// the text is loaded here only when validation loaded none.
    pub(super) fn from_proto(
        policy: &ProtoSandboxPolicy,
        cedar: Option<Arc<CedarEngine>>,
        entrypoint_pid: u32,
    ) -> Result<Self> {
        let cedar = match cedar {
            Some(cedar) => cedar,
            None => Arc::new(
                CedarEngine::from_policy_str(&policy.cedar_policy_source)
                    .map_err(|e| miette::miette!("{e}"))?,
            ),
        };
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
        // A host the matcher rejects, such as a host-less provider
        // endpoint's, selects no inspected connection.
        let tls_skip_overrides = policy
            .provider_credential_rules
            .values()
            .flat_map(|rule| &rule.endpoints)
            .chain(&policy.endpoint_settings)
            .filter(|endpoint| {
                openshell_policy::cedar::tls_skip_inspected_endpoint(&cedar, endpoint, false)
                    .is_some()
            })
            .count();
        if tls_skip_overrides > 0 {
            ocsf_emit!(
                ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(SeverityId::Low)
                    .status(StatusId::Success)
                    .state(StateId::Enabled, "cedar inspection overrides tls skip")
                    .unmapped("tls_skip_overrides", serde_json::json!(tls_skip_overrides))
                    .message("CONFIG:CEDAR tls: skip ignored on Cedar-inspected endpoints")
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
    pub(super) fn resolved_for(
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
    pub(super) fn resolution_differs(&self, other: &Self) -> bool {
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
    pub(super) fn endpoint_configs(&self, host: &str, port: u16) -> Vec<EndpointConfig> {
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
                inspects_http: false,
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
            inspects_http: true,
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
    pub(super) fn route_request(&self, host: &str, port: u16, path: &str) -> RequestRoute {
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
    pub(super) fn request_config(
        &self,
        host: &str,
        port: u16,
        path: &str,
    ) -> Option<EndpointConfig> {
        let plan = self.route_plan(host, port);
        plan.select(path).map(|route| plan.build(route))
    }

    /// Returns the `allowed_ips` of each provider endpoint matching
    /// `host:port` that has them.
    ///
    /// Each such endpoint supplies credential settings to the connection, so
    /// each one's ranges must admit every address it reaches, as a YAML
    /// provider endpoint's `allowed_ips` restrict its connections.
    pub(super) fn provider_ranges(&self, host: &str, port: u16) -> Vec<ProviderRanges> {
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
pub(super) enum RequestRoute {
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
pub(super) const UNMATCHED_PATH: &str = "no L7 endpoint path matched request";

/// The endpoint configs of one allowed connection, before they are built.
struct RoutePlan<'a> {
    inspects_http: bool,
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
            .max_by_key(|route| path_specificity(&route.path))
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
                            openshell_policy::selector_ports(endpoint)
                                .contains(&u32::from(self.port))
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
        // TLS termination is connection-wide. Even an uninspected provider
        // path must not bypass another path's Cedar HTTP enforcement.
        if self.inspects_http && config.tls == TlsSetting::Skip {
            config.tls = TlsSetting::Auto;
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
                .max_by_key(|(declared, _)| path_specificity(declared))
        })
        .cloned()
}

impl LoadedPolicy {
    /// Returns the policy DNS records, in the order
    /// [`super::CedarOnlyEngine::policy_dns_eligibility_snapshot`] publishes them;
    /// a record's position is its endpoint index.
    pub(super) fn dns_records(&self) -> Vec<MatchedEndpoint> {
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
    pub(super) fn matched_endpoints(&self, host: &str, port: u16) -> Vec<MatchedEndpoint> {
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
pub(super) struct BinaryAliases(pub(super) Vec<(String, AliasTarget)>);

/// The resolved target of one policy binary path.
#[derive(Debug)]
pub(super) enum AliasTarget {
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
    pub(super) fn new(target: String) -> Self {
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
    pub(super) fn resolve<'a>(paths: impl Iterator<Item = &'a str>, entrypoint_pid: u32) -> Self {
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
    pub(super) fn matching(&self, binary_path: &str, ancestors: &[String]) -> Result<Vec<String>> {
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
pub(super) struct BinaryGlobs(Vec<(String, Result<globset::GlobMatcher, String>)>);

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
    pub(super) fn compile(cedar: &CedarEngine, token_grants: Option<&TokenGrantRules>) -> Self {
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
    pub(super) fn matching(&self, binary_path: &str, ancestors: &[String]) -> Result<Vec<String>> {
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
pub type ProviderRanges = std::result::Result<Vec<IpNet>, String>;

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
        Self {
            host: endpoint.host.to_ascii_lowercase(),
            ports: connection_ports(endpoint),
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
        selector_matches(&self.host, &self.ports, host, port)
    }
}

/// Returns the ports of an endpoint selector a connection can have.
fn connection_ports(endpoint: &openshell_core::proto::NetworkEndpoint) -> Vec<u16> {
    openshell_policy::selector_ports(endpoint)
        .iter()
        .filter_map(|port| u16::try_from(*port).ok())
        .filter(|port| *port != 0)
        .collect()
}

/// Matches `host:port` like the Rego `endpoint_matches_request` rule, except
/// that an empty `host_pattern` matches nothing. `host_pattern` is lowercase
/// and `host` normalized.
fn selector_matches(host_pattern: &str, ports: &[u16], host: &str, port: u16) -> bool {
    if !ports.contains(&port) || host_pattern.is_empty() {
        return false;
    }
    if host_pattern.contains('*') {
        openshell_core::host_pattern::host_matches(host_pattern, host).unwrap_or(false)
    } else {
        host_pattern == host
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
            ports: connection_ports(setting),
            path: setting.path.clone(),
            fields,
        }
    }

    /// Matches like the Rego `endpoint_matches_request` rule.
    fn matches(&self, host: &str, port: u16) -> bool {
        selector_matches(&self.host, &self.ports, host, port)
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
/// [`super::CedarDestination`], which carries provider `allowed_ips` separately so
/// they can only narrow what Cedar admits.
fn provider_config(endpoint: &openshell_core::proto::NetworkEndpoint) -> EndpointConfig {
    EndpointConfig {
        endpoint_id: openshell_core::endpoint_status::endpoint_id(endpoint),
        host: endpoint.host.clone(),
        ports: openshell_policy::effective_endpoint_ports(endpoint)
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
    config.protocol = EndpointProtocol::L7(inspection.protocol.into());
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
