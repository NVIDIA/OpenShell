// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gate for selected traffic that no supervisor middleware can inspect:
//! `tls: skip` tunnels, h2c prior knowledge, unsupported tunnel protocols,
//! and protocols without an L7 relay such as SQL passthrough.

use crate::l7::relay::L7EvalContext;
use crate::opa::OpaEngine;
use miette::Result;
use openshell_ocsf::{
    ActionId, ConfigStateChangeBuilder, DetectionFindingBuilder, DispositionId, FindingInfo,
    OcsfEvent, SeverityId, StateId, StatusId, ocsf_emit,
};
use openshell_policy_schema::OnUninspectable;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninspectableTrafficGate {
    /// No middleware entry selects this destination; raw relay is unaffected.
    Unrestricted,
    /// Every selecting entry's effective `on_uninspectable` is `allow`: relay
    /// raw bytes and emit a bypass detection finding.
    BypassWithFinding,
    /// At least one selecting entry's effective `on_uninspectable` is `deny`.
    Deny,
}

/// Combine the effective `on_uninspectable` values of the middleware entries
/// selecting one destination. One `deny` outweighs any number of `allow`s.
pub fn uninspectable_traffic_gate(selected: &[OnUninspectable]) -> UninspectableTrafficGate {
    if selected.is_empty() {
        UninspectableTrafficGate::Unrestricted
    } else if selected
        .iter()
        .all(|value| *value == OnUninspectable::Allow)
    {
        UninspectableTrafficGate::BypassWithFinding
    } else {
        UninspectableTrafficGate::Deny
    }
}

/// Decide whether raw relay is allowed for the middleware entries selecting
/// this destination.
pub fn destination_gate(
    opa_engine: &OpaEngine,
    ctx: &L7EvalContext,
) -> Result<UninspectableTrafficGate> {
    opa_engine.query_uninspectable_gate(&super::middleware::middleware_network_input(ctx))
}

/// Emit the detection finding for uninspectable traffic: denied, or bypassed
/// under `on_uninspectable: allow`.
pub fn emit_middleware_uninspectable(ctx: &L7EvalContext, detail: &str, denied: bool) {
    ocsf_emit!(middleware_uninspectable_event(ctx, detail, denied));
}

fn middleware_uninspectable_event(ctx: &L7EvalContext, detail: &str, denied: bool) -> OcsfEvent {
    let (action, disposition, severity) = if denied {
        (ActionId::Denied, DispositionId::Blocked, SeverityId::High)
    } else {
        (
            ActionId::Allowed,
            DispositionId::Allowed,
            SeverityId::Medium,
        )
    };
    DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .action(action)
        .disposition(disposition)
        .severity(severity)
        .finding_info(FindingInfo::new(
            "openshell.middleware.traffic_uninspectable",
            "Supervisor middleware cannot inspect this traffic",
        ))
        .evidence_pairs(&[
            ("policy", ctx.policy_name.as_str()),
            ("host", ctx.host.as_str()),
            ("protocol", detail),
            ("disposition", if denied { "denied" } else { "allowed" }),
        ])
        .message(if denied {
            "Uninspectable traffic to host with required middleware; denied"
        } else {
            "Uninspectable traffic bypassed middleware (on_uninspectable: allow)"
        })
        .build()
}

/// Emit one deprecation event for each middleware entry whose effective
/// `on_uninspectable` comes from the `on_error: fail_open` fallback. Call once
/// per accepted policy load, with the policy's OPA data.
pub(crate) fn emit_fail_open_fallback_deprecations(data: &serde_json::Value) {
    for event in fail_open_fallback_deprecation_events(data) {
        ocsf_emit!(event);
    }
}

fn fail_open_fallback_deprecation_events(data: &serde_json::Value) -> Vec<OcsfEvent> {
    let Some(middlewares) = data
        .get("network_middlewares")
        .and_then(serde_json::Value::as_object)
    else {
        return Vec::new();
    };
    let field = |entry: &serde_json::Value, key: &str| {
        entry
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let mut names: Vec<_> = middlewares
        .iter()
        .filter(|(_, entry)| {
            OnUninspectable::uses_fail_open_fallback(
                &field(entry, "on_uninspectable"),
                &field(entry, "on_error"),
            )
        })
        .map(|(name, _)| name.as_str())
        .collect();
    names.sort_unstable();
    names
        .into_iter()
        .map(|name| {
            ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(SeverityId::Medium)
                .status(StatusId::Success)
                .state(StateId::Enabled, "deprecated")
                .unmapped("middleware_config", name)
                .unmapped("on_error", "fail_open")
                .unmapped("on_uninspectable", "allow")
                .message(format!(
                    "middleware config '{name}' uses deprecated on_uninspectable fallback \
                     from on_error: fail_open; set on_uninspectable explicitly"
                ))
                .build()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        MiddlewareEndpointSelector, NetworkBinary, NetworkEndpoint, NetworkMiddlewareConfig,
        NetworkPolicyRule, NetworkTlsMode, SandboxPolicy as ProtoSandboxPolicy,
    };

    const TEST_POLICY: &str = include_str!("../../data/sandbox-policy.rego");

    fn db_ctx() -> L7EvalContext {
        L7EvalContext {
            host: "db.example.test".into(),
            port: 5432,
            policy_name: "db".into(),
            binary_path: "/usr/bin/psql".into(),
            ..Default::default()
        }
    }

    fn tls_skip_policy(on_error: &str, on_uninspectable: &str) -> ProtoSandboxPolicy {
        let mut policy = openshell_policy::restrictive_default_policy();
        policy.network_policies.insert(
            "db".into(),
            NetworkPolicyRule {
                name: "db".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "db.example.test".into(),
                    port: 5432,
                    tls: NetworkTlsMode::Skip as i32,
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/psql".into(),
                }],
            },
        );
        policy.network_middlewares.insert(
            "guard".into(),
            NetworkMiddlewareConfig {
                middleware: "example/guard".into(),
                on_error: on_error.into(),
                on_uninspectable: on_uninspectable.into(),
                endpoints: Some(MiddlewareEndpointSelector {
                    include: vec!["db.example.test".into()],
                    exclude: Vec::new(),
                }),
                ..Default::default()
            },
        );
        policy
    }

    fn deprecations_for(policy: &ProtoSandboxPolicy) -> Vec<OcsfEvent> {
        let data = serde_json::from_str(&crate::opa::proto_to_opa_data_json(policy, 0)).unwrap();
        fail_open_fallback_deprecation_events(&data)
    }

    /// `on_uninspectable` decides whether `tls: skip` traffic selected by a
    /// middleware entry relays raw. `allow` passes it with a finding, `deny`
    /// rejects the policy even alongside `on_error: fail_open`, and a legacy
    /// `fail_open` entry keeps passing it with a deprecation event.
    #[test]
    fn on_uninspectable_governs_tls_skip_traffic_selected_by_middleware() {
        let allow = tls_skip_policy("fail_closed", "allow");
        let engine = OpaEngine::from_proto(&allow).expect("allow may select tls: skip");
        assert_eq!(
            destination_gate(&engine, &db_ctx()).unwrap(),
            UninspectableTrafficGate::BypassWithFinding
        );
        assert!(deprecations_for(&allow).is_empty());

        for (on_error, on_uninspectable) in [("", ""), ("", "deny"), ("fail_open", "deny")] {
            let error = OpaEngine::from_proto(&tls_skip_policy(on_error, on_uninspectable))
                .err()
                .expect("deny must not select tls: skip")
                .to_string();
            assert!(
                error.contains("middleware conflicts with TLS inspection"),
                "on_error={on_error:?} on_uninspectable={on_uninspectable:?}: {error}"
            );
        }

        let legacy = tls_skip_policy("fail_open", "");
        let engine = OpaEngine::from_proto(&legacy).expect("legacy fail_open still validates");
        assert_eq!(
            destination_gate(&engine, &db_ctx()).unwrap(),
            UninspectableTrafficGate::BypassWithFinding
        );
        let deprecations = deprecations_for(&legacy);
        assert_eq!(deprecations.len(), 1);
        assert!(
            serde_json::to_string(&deprecations[0])
                .unwrap()
                .contains("\"middleware_config\":\"guard\"")
        );
    }

    fn gate_for(network_middlewares: &str) -> UninspectableTrafficGate {
        let data = format!(
            "network_middlewares:\n{network_middlewares}network_policies:\n  db:\n    name: db\n    endpoints:\n      - host: db.example.test\n        port: 5432\n    binaries:\n      - path: /usr/bin/psql\n"
        );
        let engine = OpaEngine::from_strings(TEST_POLICY, &data).expect("load policy");
        destination_gate(&engine, &db_ctx()).expect("query gate")
    }

    fn entry(name: &str, host: &str, settings: &str) -> String {
        format!(
            "  {name}:\n    middleware: example/guard\n{settings}    endpoints:\n      include: [\"{host}\"]\n"
        )
    }

    #[test]
    fn on_uninspectable_decides_raw_relay_for_selecting_entries() {
        let cases = [
            ("", UninspectableTrafficGate::Deny),
            (
                "    on_error: fail_closed\n",
                UninspectableTrafficGate::Deny,
            ),
            (
                "    on_uninspectable: allow\n",
                UninspectableTrafficGate::BypassWithFinding,
            ),
            (
                "    on_error: fail_closed\n    on_uninspectable: allow\n",
                UninspectableTrafficGate::BypassWithFinding,
            ),
            (
                "    on_error: fail_open\n",
                UninspectableTrafficGate::BypassWithFinding,
            ),
            (
                "    on_error: fail_open\n    on_uninspectable: deny\n",
                UninspectableTrafficGate::Deny,
            ),
        ];
        for (settings, expected) in cases {
            assert_eq!(
                gate_for(&entry("guard", "db.example.test", settings)),
                expected,
                "{settings:?}"
            );
        }
    }

    #[test]
    fn one_denying_entry_outweighs_allowing_entries() {
        let allow = entry("allow", "*.example.test", "    on_uninspectable: allow\n");
        let deny = entry("deny", "db.example.test", "    order: 1\n");
        assert_eq!(
            gate_for(&format!("{allow}{deny}")),
            UninspectableTrafficGate::Deny
        );
    }

    #[test]
    fn unselected_entries_do_not_restrict_raw_relay() {
        assert_eq!(
            gate_for(&entry("guard", "api.example.test", "")),
            UninspectableTrafficGate::Unrestricted
        );
    }

    #[test]
    fn gate_combines_effective_values() {
        use OnUninspectable::{Allow, Deny};

        assert_eq!(
            uninspectable_traffic_gate(&[]),
            UninspectableTrafficGate::Unrestricted
        );
        assert_eq!(
            uninspectable_traffic_gate(&[Allow, Allow]),
            UninspectableTrafficGate::BypassWithFinding
        );
        assert_eq!(
            uninspectable_traffic_gate(&[Allow, Deny]),
            UninspectableTrafficGate::Deny
        );
    }

    #[test]
    fn uninspectable_findings_report_disposition_and_severity() {
        let ctx = db_ctx();

        let denied = middleware_uninspectable_event(&ctx, "sql passthrough", true);
        assert_eq!(denied.base().severity, SeverityId::High);
        assert!(
            denied
                .format_shorthand()
                .starts_with("FINDING:BLOCKED [HIGH]")
        );
        let denied = serde_json::to_string(&denied).unwrap();
        assert!(denied.contains("openshell.middleware.traffic_uninspectable"));
        assert!(denied.contains("\"denied\""));

        let allowed = middleware_uninspectable_event(&ctx, "sql passthrough", false);
        assert_eq!(allowed.base().severity, SeverityId::Medium);
        assert!(
            allowed
                .format_shorthand()
                .starts_with("FINDING:ALLOWED [MED]")
        );
        let allowed = serde_json::to_string(&allowed).unwrap();
        assert!(allowed.contains("openshell.middleware.traffic_uninspectable"));
        assert!(allowed.contains("\"allowed\""));
        assert!(!allowed.contains("fail_open"));
    }

    #[test]
    fn deprecation_events_cover_only_fail_open_fallback_entries() {
        let data = serde_json::json!({
            "network_middlewares": {
                "legacy-b": {"middleware": "m", "on_error": "fail_open"},
                "legacy-a": {"middleware": "m", "on_error": "fail_open"},
                "explicit-allow": {
                    "middleware": "m", "on_error": "fail_open", "on_uninspectable": "allow"
                },
                "explicit-deny": {
                    "middleware": "m", "on_error": "fail_open", "on_uninspectable": "deny"
                },
                "default": {"middleware": "m"},
            }
        });

        let events = fail_open_fallback_deprecation_events(&data);
        assert_eq!(events.len(), 2);
        for (event, name) in events.iter().zip(["legacy-a", "legacy-b"]) {
            assert_eq!(event.class_uid(), 5019);
            assert_eq!(event.base().severity, SeverityId::Medium);
            let serialized = serde_json::to_string(event).unwrap();
            assert!(serialized.contains(&format!("\"middleware_config\":\"{name}\"")));
            assert!(event.format_shorthand().starts_with(&format!(
                "CONFIG:DEPRECATED [MED] middleware config '{name}' uses deprecated \
                 on_uninspectable fallback"
            )));
        }
        assert!(fail_open_fallback_deprecation_events(&serde_json::json!({})).is_empty());
    }
}
