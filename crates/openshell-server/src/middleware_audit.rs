// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Re-validation of stored policies against the middleware registry.
//!
//! The gateway checks middleware entries when a policy is written, against
//! the manifests it described at startup. Nothing re-checks a stored policy
//! when a service later changes protocol, or when a release removes behavior
//! the policy relies on. This module checks a policy against the rules of the
//! next release line using the gateway's cached manifests, so it makes no
//! network calls.
//!
//! In [`RevalidationMode::Audit`] findings are only reported, through the
//! upgrade check RPC and the startup log. In [`RevalidationMode::Admission`]
//! a sandbox whose effective policy has blocking findings is served as not
//! admitted with a migration message, which affects only that sandbox and
//! leaves `openshell policy set` as the repair path.

use std::collections::HashSet;

use openshell_core::proto::{NetworkMiddlewareConfig, SandboxPolicy};
use openshell_policy::PolicyViolation;
use openshell_policy_schema::OnUninspectable;
use openshell_supervisor_middleware::{
    HttpProtocol, MiddlewareBindingSummary, MiddlewareRegistry, MiddlewareSource,
};
use tonic::Status;

/// Release line whose rules a check applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeTarget {
    V0_2,
}

impl UpgradeTarget {
    /// The next release line this gateway can check.
    pub const NEXT: Self = Self::V0_2;

    /// Parse a requested release line. Empty selects [`Self::NEXT`].
    pub fn parse(value: &str) -> Result<Self, String> {
        let version = value.strip_prefix('v').unwrap_or(value);
        match version {
            "" => Ok(Self::NEXT),
            "0.2" | "0.2.0" => Ok(Self::V0_2),
            _ => Err(format!(
                "unsupported upgrade target '{value}'; this gateway can check 0.2"
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V0_2 => "0.2",
        }
    }
}

/// How the gateway applies re-validation when it serves sandbox configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RevalidationMode {
    /// Report findings without changing what sandboxes receive.
    #[default]
    Audit,
    /// Serve a sandbox whose effective policy has blocking findings as not
    /// admitted.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "0.2.0 makes admission the default")
    )]
    Admission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingKind {
    LegacyHttpService,
    UnregisteredMiddleware,
    LegacyHttpMiddleware,
    FailOpenNotApplied,
    FailOpenOnHttpV2Only,
    HttpFailOpen,
    OnUninspectableFallback,
    OnUninspectableNeedsCurrentSupervisor,
    SandboxKeepsSupervisor,
    PolicyUnchecked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Warning,
    Blocking,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    /// Key of the policy's `network_middlewares` entry, or empty.
    pub config_name: String,
    /// Built-in middleware name or registration name, or empty.
    pub middleware_name: String,
    pub message: String,
}

impl Finding {
    fn entry(
        kind: FindingKind,
        severity: Severity,
        config_name: &str,
        config: &NetworkMiddlewareConfig,
        message: String,
    ) -> Self {
        Self {
            kind,
            severity,
            config_name: config_name.to_string(),
            middleware_name: config.middleware.clone(),
            message,
        }
    }

    /// The effective policy of a sandbox could not be resolved. A stored
    /// policy that is invalid today is already refused, so the upgrade does
    /// not change it. Any other error leaves the policy unchecked, which
    /// blocks the upgrade until a check succeeds.
    pub fn policy_unchecked(error: &Status) -> Self {
        let already_refused = matches!(
            error.code(),
            tonic::Code::FailedPrecondition | tonic::Code::InvalidArgument
        );
        Self {
            kind: FindingKind::PolicyUnchecked,
            severity: if already_refused {
                Severity::Warning
            } else {
                Severity::Blocking
            },
            config_name: String::new(),
            middleware_name: String::new(),
            message: if already_refused {
                format!(
                    "the effective policy could not be checked: {}; the gateway already refuses \
                     this configuration, so repair it and run the check again",
                    error.message()
                )
            } else {
                format!(
                    "the effective policy could not be checked: {}; run the check again",
                    error.message()
                )
            },
        }
    }

    /// A sandbox that uses middleware keeps its supervisor across a gateway
    /// upgrade, so it keeps the current release's middleware behavior.
    pub fn sandbox_keeps_supervisor(driver: &str) -> Self {
        Self {
            kind: FindingKind::SandboxKeepsSupervisor,
            severity: Severity::Warning,
            config_name: String::new(),
            middleware_name: String::new(),
            message: format!(
                "the '{driver}' compute driver keeps a running sandbox's supervisor when the \
                 gateway is upgraded; recreate this sandbox after the upgrade so its supervisor \
                 applies 0.2 middleware behavior"
            ),
        }
    }
}

/// Whether sandboxes on `driver` keep their supervisor when the gateway is
/// upgraded. Docker and VM sandboxes receive the new supervisor when the
/// gateway restarts, and MXC sandboxes have none. Any other driver is assumed
/// to keep it.
pub fn driver_keeps_supervisors(driver: &str) -> bool {
    !matches!(driver, "docker" | "vm" | "mxc")
}

/// Binding protocols of every registered middleware, read from the cached
/// manifests.
pub struct MiddlewareCatalog {
    middleware: Vec<MiddlewareBindingSummary>,
}

impl MiddlewareCatalog {
    pub async fn from_registry(registry: &MiddlewareRegistry) -> Result<Self, Status> {
        registry
            .binding_summaries()
            .await
            .map(|middleware| Self { middleware })
            .map_err(|error| {
                Status::internal(format!("middleware registry summary failed: {error}"))
            })
    }

    fn get(&self, name: &str) -> Option<&MiddlewareBindingSummary> {
        self.middleware.iter().find(|summary| summary.name == name)
    }

    /// Registered services that 0.2 refuses. Built-in middleware ships with
    /// the gateway and moves to version 2 with it.
    pub fn service_findings(&self) -> Vec<Finding> {
        let mut findings: Vec<_> = self
            .middleware
            .iter()
            .filter(|summary| is_registered_legacy_http(summary))
            .map(|summary| Finding {
                kind: FindingKind::LegacyHttpService,
                severity: Severity::Blocking,
                config_name: String::new(),
                middleware_name: summary.name.clone(),
                message: format!(
                    "registered middleware '{}' serves HTTP over the legacy middleware protocol, \
                     and 0.2 refuses its registration; upgrade the service to HTTP middleware \
                     protocol version 2, or to a build that serves both protocols, then restart \
                     the gateway",
                    summary.name
                ),
            })
            .collect();
        findings.sort_by(|left, right| left.middleware_name.cmp(&right.middleware_name));
        findings
    }
}

// legacy-http-protocol-1
fn is_registered_legacy_http(summary: &MiddlewareBindingSummary) -> bool {
    summary.source == MiddlewareSource::Registered
        && summary.uses_http_protocol(HttpProtocol::Legacy)
}

/// Check one effective policy against the 0.2 rules, entry by entry in name
/// order.
pub fn check_policy(policy: &SandboxPolicy, catalog: &MiddlewareCatalog) -> Vec<Finding> {
    // 0.2 resolves an unset `on_uninspectable` to deny regardless of
    // `on_error`, which turns these entries' `tls: skip` overlaps into
    // validation errors.
    let fallback_conflicts = tls_skip_conflicts(policy, uses_fallback, |config| {
        config.on_uninspectable = "deny".to_string();
    });
    // Supervisors that predate `on_uninspectable` drop the field and gate
    // uninspectable traffic on `on_error` alone, and they re-run static
    // validation on the policies they receive.
    let old_supervisor_conflicts = tls_skip_conflicts(policy, allows_without_fail_open, |config| {
        config.on_uninspectable.clear();
    });

    let mut entries: Vec<_> = policy.network_middlewares.iter().collect();
    entries.sort_unstable_by_key(|(name, _)| name.as_str());
    let mut findings = Vec::new();
    for (name, config) in entries {
        let fail_open = config.on_error == "fail_open";
        let middleware = &config.middleware;
        match catalog.get(middleware) {
            None => findings.push(Finding::entry(
                FindingKind::UnregisteredMiddleware,
                Severity::Blocking,
                name,
                config,
                format!(
                    "middleware config '{name}' uses '{middleware}', which is not registered with \
                     this gateway; register the service or remove the entry"
                ),
            )),
            Some(summary) => {
                if is_registered_legacy_http(summary) {
                    findings.push(Finding::entry(
                        FindingKind::LegacyHttpMiddleware,
                        Severity::Blocking,
                        name,
                        config,
                        format!(
                            "middleware config '{name}' uses '{middleware}', which serves HTTP \
                             over the legacy middleware protocol that 0.2 removes; upgrade the \
                             service before upgrading the gateway"
                        ),
                    ));
                }
                if fail_open {
                    findings.extend(fail_open_finding(name, config, summary));
                }
            }
        }

        if uses_fallback(config) {
            findings.push(if fallback_conflicts.contains(name) {
                Finding::entry(
                    FindingKind::OnUninspectableFallback,
                    Severity::Blocking,
                    name,
                    config,
                    format!(
                        "middleware config '{name}' selects a tls: skip endpoint and relies on \
                         on_error: fail_open to allow traffic middleware cannot inspect; 0.2 \
                         removes that fallback and rejects the policy; set on_uninspectable: allow"
                    ),
                )
            } else {
                Finding::entry(
                    FindingKind::OnUninspectableFallback,
                    Severity::Warning,
                    name,
                    config,
                    format!(
                        "middleware config '{name}' relies on on_error: fail_open to allow traffic \
                         middleware cannot inspect; 0.2 removes that fallback and denies such \
                         traffic; set on_uninspectable: allow or deny explicitly"
                    ),
                )
            });
        } else if old_supervisor_conflicts.contains(name) {
            findings.push(Finding::entry(
                FindingKind::OnUninspectableNeedsCurrentSupervisor,
                Severity::Warning,
                name,
                config,
                format!(
                    "middleware config '{name}' sets on_uninspectable: allow for a tls: skip \
                     endpoint without on_error: fail_open; supervisors that predate \
                     on_uninspectable, such as v0.1.2, reject this policy, so recreate sandboxes \
                     that still run them"
                ),
            ));
        }
    }
    findings
}

fn fail_open_finding(
    name: &str,
    config: &NetworkMiddlewareConfig,
    summary: &MiddlewareBindingSummary,
) -> Option<Finding> {
    let middleware = &config.middleware;
    // Without a WebSocket binding, fail_open has no effect and the finding
    // below covers it.
    if summary.requires_http_v2 && summary.websocket {
        return Some(Finding::entry(
            FindingKind::FailOpenOnHttpV2Only,
            Severity::Blocking,
            name,
            config,
            format!(
                "middleware config '{name}' sets on_error: fail_open on '{middleware}', which \
                 requires HTTP protocol version 2; supervisors that predate version 2 cannot run \
                 it and skip it under fail_open, and the gateway rejects the setting until 0.2.0; \
                 set on_error to fail_closed, or deploy a build of the service that serves both \
                 HTTP protocols to keep WebSocket fail_open"
            ),
        ));
    }
    if !summary.honors_fail_open {
        return Some(Finding::entry(
            FindingKind::FailOpenNotApplied,
            Severity::Blocking,
            name,
            config,
            format!(
                "middleware config '{name}' sets on_error: fail_open, but '{middleware}' has no \
                 binding that honors it, so its HTTP stages already fail closed and 0.2 rejects \
                 the setting; remove on_error or set it to fail_closed"
            ),
        ));
    }
    // legacy-http-protocol-1
    if !summary.uses_http_protocol(HttpProtocol::Legacy) {
        return None;
    }
    Some(if summary.websocket {
        Finding::entry(
            FindingKind::HttpFailOpen,
            Severity::Warning,
            name,
            config,
            format!(
                "middleware config '{name}' sets on_error: fail_open; in 0.2 it applies only to \
                 the WebSocket binding of '{middleware}', and its HTTP stages fail closed"
            ),
        )
    } else {
        Finding::entry(
            FindingKind::HttpFailOpen,
            Severity::Blocking,
            name,
            config,
            format!(
                "middleware config '{name}' sets on_error: fail_open on HTTP middleware \
                 '{middleware}'; HTTP middleware is fail-closed in 0.2, which rejects the \
                 setting; remove on_error or set it to fail_closed, and have the service return \
                 Continue at preflight for traffic it should pass"
            ),
        )
    })
}

fn uses_fallback(config: &NetworkMiddlewareConfig) -> bool {
    OnUninspectable::uses_fail_open_fallback(&config.on_uninspectable, &config.on_error)
}

fn allows_without_fail_open(config: &NetworkMiddlewareConfig) -> bool {
    config.on_uninspectable == "allow" && config.on_error != "fail_open"
}

/// Names of the selected entries whose `tls: skip` overlap static validation
/// reports once `rewrite` has changed them.
fn tls_skip_conflicts(
    policy: &SandboxPolicy,
    selected: impl Fn(&NetworkMiddlewareConfig) -> bool,
    rewrite: impl Fn(&mut NetworkMiddlewareConfig),
) -> HashSet<String> {
    if !policy.network_middlewares.values().any(&selected) {
        return HashSet::new();
    }
    let mut candidate = policy.clone();
    candidate
        .network_middlewares
        .values_mut()
        .filter(|config| selected(config))
        .for_each(rewrite);
    openshell_policy::validate_sandbox_policy(&candidate)
        .err()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|violation| match violation {
            PolicyViolation::MiddlewareTlsSkipConflict {
                middleware_name, ..
            } => Some(middleware_name),
            _ => None,
        })
        .collect()
}

/// The migration message for a policy with blocking findings, or `None` when
/// 0.2 admits it.
///
/// 0.2 accepts `fail_open` for the WebSocket binding of middleware that
/// requires HTTP protocol version 2. That finding blocks the upgrade, because
/// sandboxes that keep older supervisors would skip the middleware, but not
/// admission.
pub fn admission_error(findings: &[Finding]) -> Option<String> {
    let mut blocking = findings.iter().filter(|finding| {
        finding.severity == Severity::Blocking && finding.kind != FindingKind::FailOpenOnHttpV2Only
    });
    let first = blocking.next()?;
    let total = 1 + blocking.count();
    Some(if total == 1 {
        format!("OpenShell 0.2 rejects this policy: {}", first.message)
    } else {
        format!(
            "OpenShell 0.2 rejects this policy ({total} problems; a gateway admin can list them \
             with openshell gateway upgrade-check): {}",
            first.message
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        MiddlewareEndpointSelector, NetworkEndpoint, NetworkPolicyRule, NetworkTlsMode,
    };

    fn summary(
        name: &str,
        source: MiddlewareSource,
        http_protocols: &[HttpProtocol],
        websocket: bool,
    ) -> MiddlewareBindingSummary {
        MiddlewareBindingSummary {
            name: name.into(),
            source,
            http_protocols: http_protocols.to_vec(),
            websocket,
            honors_fail_open: websocket || http_protocols.contains(&HttpProtocol::Legacy),
            requires_http_v2: false,
        }
    }

    /// A service that requires `http-v2`, which supervisors that predate
    /// version 2 refuse.
    fn version_2_only(name: &str, websocket: bool) -> MiddlewareBindingSummary {
        MiddlewareBindingSummary {
            requires_http_v2: true,
            ..summary(
                name,
                MiddlewareSource::Registered,
                &[HttpProtocol::V2],
                websocket,
            )
        }
    }

    fn catalog() -> MiddlewareCatalog {
        use HttpProtocol::{Legacy, V2};
        use MiddlewareSource::{InProcess, Registered};
        MiddlewareCatalog {
            middleware: vec![
                summary("openshell/regex", InProcess, &[Legacy], true),
                summary("example/legacy", Registered, &[Legacy], false),
                summary("example/legacy-ws", Registered, &[Legacy], true),
                summary("example/v2", Registered, &[V2], false),
                summary("example/v2-ws", Registered, &[V2], true),
                version_2_only("example/v2-only", false),
                version_2_only("example/v2-only-ws", true),
            ],
        }
    }

    fn policy(entries: &[(&str, &str, &str, &str)], tls_skip_host: Option<&str>) -> SandboxPolicy {
        let mut policy = openshell_policy::restrictive_default_policy();
        for (name, middleware, on_error, on_uninspectable) in entries {
            policy.network_middlewares.insert(
                (*name).to_string(),
                NetworkMiddlewareConfig {
                    middleware: (*middleware).to_string(),
                    on_error: (*on_error).to_string(),
                    on_uninspectable: (*on_uninspectable).to_string(),
                    endpoints: Some(MiddlewareEndpointSelector {
                        include: vec!["*.example.com".to_string()],
                        exclude: Vec::new(),
                    }),
                    ..Default::default()
                },
            );
        }
        if let Some(host) = tls_skip_host {
            policy.network_policies.insert(
                "skip".to_string(),
                NetworkPolicyRule {
                    name: "skip".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: host.to_string(),
                        port: 443,
                        tls: NetworkTlsMode::Skip as i32,
                        ..Default::default()
                    }],
                    binaries: Vec::new(),
                },
            );
        }
        policy
    }

    fn kinds(findings: &[Finding]) -> Vec<(&str, FindingKind, Severity)> {
        findings
            .iter()
            .map(|finding| (finding.config_name.as_str(), finding.kind, finding.severity))
            .collect()
    }

    #[test]
    fn upgrade_target_accepts_the_next_release_line_only() {
        for value in ["", "0.2", "0.2.0", "v0.2", "v0.2.0"] {
            assert_eq!(UpgradeTarget::parse(value), Ok(UpgradeTarget::V0_2));
        }
        for value in ["0.3", "0.1", "1.0", "latest", "0.2.1"] {
            assert!(UpgradeTarget::parse(value).is_err(), "{value}");
        }
        assert_eq!(UpgradeTarget::V0_2.as_str(), "0.2");
    }

    #[test]
    fn current_policies_have_no_findings() {
        let policy = policy(
            &[
                ("closed", "example/v2", "", "deny"),
                ("websocket", "example/v2-ws", "fail_open", "allow"),
                ("redactor", "openshell/regex", "fail_closed", ""),
            ],
            None,
        );
        assert_eq!(check_policy(&policy, &catalog()), []);
    }

    #[test]
    fn unregistered_and_legacy_middleware_block_the_upgrade() {
        let findings = check_policy(
            &policy(
                &[
                    ("gone", "example/gone", "", ""),
                    ("legacy", "example/legacy", "fail_closed", ""),
                ],
                None,
            ),
            &catalog(),
        );
        assert_eq!(
            kinds(&findings),
            [
                (
                    "gone",
                    FindingKind::UnregisteredMiddleware,
                    Severity::Blocking
                ),
                (
                    "legacy",
                    FindingKind::LegacyHttpMiddleware,
                    Severity::Blocking
                ),
            ]
        );
        assert_eq!(findings[1].middleware_name, "example/legacy");
    }

    #[test]
    fn fail_open_findings_follow_the_bindings_that_honor_it() {
        let findings = check_policy(
            &policy(
                &[
                    ("stale", "example/v2", "fail_open", "deny"),
                    ("http", "example/legacy", "fail_open", "deny"),
                    ("mixed", "example/legacy-ws", "fail_open", "deny"),
                    ("builtin", "openshell/regex", "fail_open", "deny"),
                    ("websocket", "example/v2-ws", "fail_open", "deny"),
                    ("v2-only", "example/v2-only", "fail_open", "deny"),
                    ("v2-only-ws", "example/v2-only-ws", "fail_open", "allow"),
                ],
                None,
            ),
            &catalog(),
        );
        assert_eq!(
            kinds(&findings),
            [
                ("builtin", FindingKind::HttpFailOpen, Severity::Warning),
                (
                    "http",
                    FindingKind::LegacyHttpMiddleware,
                    Severity::Blocking
                ),
                ("http", FindingKind::HttpFailOpen, Severity::Blocking),
                (
                    "mixed",
                    FindingKind::LegacyHttpMiddleware,
                    Severity::Blocking
                ),
                ("mixed", FindingKind::HttpFailOpen, Severity::Warning),
                ("stale", FindingKind::FailOpenNotApplied, Severity::Blocking),
                (
                    "v2-only",
                    FindingKind::FailOpenNotApplied,
                    Severity::Blocking
                ),
                (
                    "v2-only-ws",
                    FindingKind::FailOpenOnHttpV2Only,
                    Severity::Blocking
                ),
            ]
        );
        assert!(
            findings[findings.len() - 1]
                .message
                .contains("supervisors that predate version 2 cannot run it")
        );
    }

    #[test]
    fn on_uninspectable_fallback_blocks_only_with_a_tls_skip_overlap() {
        let entries = [("guard", "example/v2-ws", "fail_open", "")];
        assert_eq!(
            kinds(&check_policy(&policy(&entries, None), &catalog())),
            [(
                "guard",
                FindingKind::OnUninspectableFallback,
                Severity::Warning
            )]
        );
        let findings = check_policy(&policy(&entries, Some("api.example.com")), &catalog());
        assert_eq!(
            kinds(&findings),
            [(
                "guard",
                FindingKind::OnUninspectableFallback,
                Severity::Blocking
            )]
        );
        assert!(findings[0].message.contains("set on_uninspectable: allow"));

        let explicit = [("guard", "example/v2-ws", "fail_open", "allow")];
        assert_eq!(
            check_policy(&policy(&explicit, Some("api.example.com")), &catalog()),
            []
        );
    }

    #[test]
    fn allow_without_fail_open_on_tls_skip_warns_about_older_supervisors() {
        let entries = [("guard", "example/v2", "", "allow")];
        assert_eq!(
            kinds(&check_policy(
                &policy(&entries, Some("api.example.com")),
                &catalog()
            )),
            [(
                "guard",
                FindingKind::OnUninspectableNeedsCurrentSupervisor,
                Severity::Warning
            )]
        );
        assert_eq!(
            check_policy(&policy(&entries, Some("other.test")), &catalog()),
            [],
            "an entry that selects no tls: skip endpoint is valid everywhere"
        );
    }

    #[test]
    fn only_registered_legacy_services_are_service_findings() {
        let findings = catalog().service_findings();
        assert_eq!(
            findings
                .iter()
                .map(|finding| (finding.middleware_name.as_str(), finding.severity))
                .collect::<Vec<_>>(),
            [
                ("example/legacy", Severity::Blocking),
                ("example/legacy-ws", Severity::Blocking),
            ]
        );
    }

    #[test]
    fn admission_error_reports_blocking_findings_only() {
        let catalog = catalog();
        assert_eq!(
            admission_error(&check_policy(
                &policy(&[("builtin", "openshell/regex", "fail_open", "deny")], None),
                &catalog,
            )),
            None,
            "warnings do not affect admission"
        );
        assert_eq!(
            admission_error(&check_policy(
                &policy(
                    &[("guard", "example/v2-only-ws", "fail_open", "allow")],
                    None
                ),
                &catalog,
            )),
            None,
            "0.2 accepts WebSocket fail_open on middleware that requires version 2"
        );
        assert!(
            admission_error(&check_policy(
                &policy(&[("guard", "example/v2-only", "fail_open", "allow")], None),
                &catalog,
            ))
            .is_some(),
            "fail_open has no effect without a WebSocket binding"
        );
        let message = admission_error(&check_policy(
            &policy(
                &[
                    ("gone", "example/gone", "", ""),
                    ("stale", "example/v2", "fail_open", "deny"),
                ],
                None,
            ),
            &catalog,
        ))
        .expect("blocking findings");
        assert!(message.starts_with(
            "OpenShell 0.2 rejects this policy (2 problems; a gateway admin can list them with \
             openshell gateway upgrade-check): middleware config 'gone' uses 'example/gone'"
        ));
    }

    #[test]
    fn unreadable_policies_block_unless_the_gateway_already_refuses_them() {
        for status in [
            Status::failed_precondition("stored policy source 'spec' is invalid"),
            Status::invalid_argument("invalid policy"),
        ] {
            let finding = Finding::policy_unchecked(&status);
            assert_eq!(finding.severity, Severity::Warning, "{status:?}");
            assert!(finding.message.contains("already refuses"));
        }
        for status in [
            Status::internal("fetch latest policy failed"),
            Status::unavailable("provider profile source unavailable"),
        ] {
            let finding = Finding::policy_unchecked(&status);
            assert_eq!(finding.severity, Severity::Blocking, "{status:?}");
            assert!(finding.message.ends_with("run the check again"));
        }
    }

    #[test]
    fn only_drivers_that_refresh_supervisors_skip_the_recreate_advice() {
        for driver in ["docker", "vm", "mxc"] {
            assert!(!driver_keeps_supervisors(driver), "{driver}");
        }
        for driver in ["kubernetes", "podman", "custom"] {
            assert!(driver_keeps_supervisors(driver), "{driver}");
        }
    }
}
