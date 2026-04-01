// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shorthand formatter — single-line human-readable format derived from OCSF events.
//!
//! Pattern: `<HH:MM:SS.mmm> <severity> <CLASS:ACTIVITY> <action> <key fields> [context]`

use crate::events::OcsfEvent;
use crate::objects::Url;

/// Format a timestamp (ms since epoch) as `HH:MM:SS.mmm`.
///
/// Returns a placeholder `"??:??:??.???"` for out-of-range timestamps
/// instead of panicking.
#[must_use]
pub fn format_ts(time_ms: i64) -> String {
    use chrono::{MappedLocalTime, TimeZone, Utc};
    match Utc.timestamp_millis_opt(time_ms) {
        MappedLocalTime::Single(dt) => dt.format("%H:%M:%S%.3f").to_string(),
        _ => "??:??:??.???".to_string(),
    }
}

/// Map a severity ID byte to its single-character shorthand.
#[must_use]
pub fn severity_char(severity_id: u8) -> char {
    // Safe: we match on the raw u8 value
    match severity_id {
        1 => 'I',
        2 => 'L',
        3 => 'M',
        4 => 'H',
        5 => 'C',
        6 => 'F',
        _ => ' ',
    }
}

/// Format the severity as a bracketed tag placed after the `CLASS:ACTIVITY`.
///
/// Placed as a suffix so the class name always starts at column 0, keeping
/// logs vertically scannable:
///
/// ```text
/// NET:OPEN [INFO] ALLOWED python3(42) -> api.example.com:443
/// NET:OPEN [MED] DENIED python3(42) -> blocked.com:443
/// FINDING:BLOCKED [HIGH] "NSSH1 Nonce Replay Attack"
/// ```
#[must_use]
pub fn severity_tag(severity_id: u8) -> &'static str {
    match severity_id {
        1 => "[INFO]",
        2 => "[LOW]",
        3 => "[MED]",
        4 => "[HIGH]",
        5 => "[CRIT]",
        6 => "[FATAL]",
        _ => "[INFO]",
    }
}

impl OcsfEvent {
    /// Produce the single-line shorthand for `openshell.log` and gRPC log push.
    ///
    /// This is a display-only projection — the full OCSF JSON is the source of truth.
    #[must_use]
    pub fn format_shorthand(&self) -> String {
        let base = self.base();
        let sev = severity_tag(base.severity.as_u8());

        match self {
            Self::NetworkActivity(e) => {
                let activity = e.base.activity_name.to_uppercase();
                let action = e.action.map_or(String::new(), |a| a.label().to_uppercase());
                let actor_str = e
                    .actor
                    .as_ref()
                    .map(|a| format!("{}({})", a.process.name, a.process.pid))
                    .unwrap_or_default();
                let dst = e
                    .dst_endpoint
                    .as_ref()
                    .map(|ep| {
                        let host = ep.domain_or_ip();
                        let port = ep.port.map_or(String::new(), |p| format!(":{p}"));
                        // Include protocol for bypass detection events
                        let proto = e
                            .connection_info
                            .as_ref()
                            .map(|c| format!("/{}", c.protocol_name))
                            .unwrap_or_default();
                        format!("{host}{port}{proto}")
                    })
                    .unwrap_or_default();
                let rule_ctx = e
                    .firewall_rule
                    .as_ref()
                    .map(|r| format!(" [policy:{} engine:{}]", r.name, r.rule_type))
                    .unwrap_or_default();
                let arrow = if actor_str.is_empty() && dst.is_empty() {
                    String::new()
                } else if actor_str.is_empty() {
                    format!(" {dst}")
                } else if dst.is_empty() {
                    format!(" {actor_str}")
                } else {
                    format!(" {actor_str} -> {dst}")
                };

                let detail = match (action.is_empty(), arrow.is_empty()) {
                    (true, true) => String::new(),
                    (true, false) => arrow,
                    (false, true) => format!(" {action}"),
                    (false, false) => format!(" {action}{arrow}"),
                };
                format!("NET:{activity} {sev}{detail}{rule_ctx}")
            }

            Self::HttpActivity(e) => {
                let method = e
                    .http_request
                    .as_ref()
                    .map_or("UNKNOWN", |r| r.http_method.as_str());
                let action = e.action.map_or(String::new(), |a| a.label().to_uppercase());
                let actor_str = e
                    .actor
                    .as_ref()
                    .map(|a| format!("{}({})", a.process.name, a.process.pid))
                    .unwrap_or_default();
                let url_str = e
                    .http_request
                    .as_ref()
                    .and_then(|r| r.url.as_ref())
                    .map(Url::to_display_string)
                    .unwrap_or_default();
                let rule_ctx = e
                    .firewall_rule
                    .as_ref()
                    .map(|r| format!(" [policy:{}]", r.name))
                    .unwrap_or_default();
                let arrow = if actor_str.is_empty() {
                    format!(" {method} {url_str}")
                } else {
                    format!(" {actor_str} -> {method} {url_str}")
                };

                let detail = match (action.is_empty(), arrow.is_empty()) {
                    (true, true) => String::new(),
                    (true, false) => arrow,
                    (false, true) => format!(" {action}"),
                    (false, false) => format!(" {action}{arrow}"),
                };
                format!("HTTP:{method} {sev}{detail}{rule_ctx}")
            }

            Self::SshActivity(e) => {
                let activity = e.base.activity_name.to_uppercase();
                let action = e.action.map_or(String::new(), |a| a.label().to_uppercase());
                let peer = e
                    .src_endpoint
                    .as_ref()
                    .map(|ep| {
                        let host = ep.domain_or_ip();
                        let port = ep.port.map_or(String::new(), |p| format!(":{p}"));
                        format!("{host}{port}")
                    })
                    .unwrap_or_default();
                let auth_ctx = e
                    .auth_type
                    .as_ref()
                    .map(|id| {
                        let label = e
                            .auth_type_custom_label
                            .as_deref()
                            .unwrap_or_else(|| id.label());
                        format!(" [auth:{label}]")
                    })
                    .unwrap_or_default();

                let detail = [
                    if action.is_empty() { "" } else { &action },
                    if peer.is_empty() { "" } else { &peer },
                ]
                .iter()
                .filter(|s| !s.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join(" ");
                let detail = if detail.is_empty() {
                    String::new()
                } else {
                    format!(" {detail}")
                };
                format!("SSH:{activity} {sev}{detail}{auth_ctx}")
            }

            Self::ProcessActivity(e) => {
                let activity = e.base.activity_name.to_uppercase();
                let proc_str = format!("{}({})", e.process.name, e.process.pid);
                let exit_ctx = e
                    .exit_code
                    .map(|c| format!(" [exit:{c}]"))
                    .unwrap_or_default();
                let cmd_ctx = e
                    .process
                    .cmd_line
                    .as_ref()
                    .map(|c| format!(" [cmd:{c}]"))
                    .unwrap_or_default();

                format!("PROC:{activity} {sev} {proc_str}{exit_ctx}{cmd_ctx}")
            }

            Self::DetectionFinding(e) => {
                let disposition = e
                    .disposition
                    .map_or_else(|| "UNKNOWN".to_string(), |d| d.label().to_uppercase());
                let title = &e.finding_info.title;
                let confidence_ctx = e
                    .confidence
                    .map(|c| format!(" [confidence:{}]", c.label().to_lowercase()))
                    .unwrap_or_default();

                format!("FINDING:{disposition} {sev} \"{title}\"{confidence_ctx}")
            }

            Self::ApplicationLifecycle(e) => {
                let activity = e.base.activity_name.to_uppercase();
                let app = &e.app.name;
                let status = e
                    .base
                    .status
                    .map(|s| s.label().to_lowercase())
                    .unwrap_or_default();

                format!("LIFECYCLE:{activity} {sev} {app} {status}")
            }

            Self::DeviceConfigStateChange(e) => {
                let state = e.state.map_or_else(
                    || "UNKNOWN".to_string(),
                    |s| {
                        e.state_custom_label
                            .as_deref()
                            .unwrap_or_else(|| s.label())
                            .to_uppercase()
                    },
                );
                let what = e.base.message.as_deref().unwrap_or("config");
                let version_ctx = e
                    .base
                    .unmapped
                    .as_ref()
                    .and_then(|u| {
                        let ver = u.get("policy_version").and_then(|v| v.as_str());
                        let hash = u.get("policy_hash").and_then(|v| v.as_str());
                        match (ver, hash) {
                            (Some(v), Some(h)) => Some(format!(" [version:{v} hash:{h}]")),
                            (Some(v), None) => Some(format!(" [version:{v}]")),
                            _ => None,
                        }
                    })
                    .unwrap_or_default();

                format!("CONFIG:{state} {sev} {what}{version_ctx}")
            }

            Self::Base(e) => {
                let message = e.base.message.as_deref().unwrap_or("");
                let unmapped_ctx = e
                    .base
                    .unmapped
                    .as_ref()
                    .and_then(|u| {
                        let obj = u.as_object()?;
                        if obj.is_empty() {
                            return None;
                        }
                        let fields: Vec<String> = obj
                            .iter()
                            .take(3) // Limit to 3 most important fields
                            .map(|(k, v)| {
                                let val = v.as_str().map_or_else(|| v.to_string(), String::from);
                                format!("{k}:{val}")
                            })
                            .collect();
                        Some(format!(" [{}]", fields.join(" ")))
                    })
                    .unwrap_or_default();

                format!("EVENT {sev} {message}{unmapped_ctx}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{ActionId, AuthTypeId, ConfidenceId, DispositionId, LaunchTypeId, StateId};
    use crate::events::base_event::BaseEventData;
    use crate::events::{
        ApplicationLifecycleEvent, BaseEvent, DetectionFindingEvent, DeviceConfigStateChangeEvent,
        HttpActivityEvent, NetworkActivityEvent, ProcessActivityEvent, SshActivityEvent,
    };
    use crate::objects::*;

    fn test_metadata() -> Metadata {
        Metadata {
            version: "1.7.0".to_string(),
            product: Product::openshell_sandbox("0.1.0"),
            profiles: vec!["security_control".to_string()],
            uid: Some("sandbox-abc123".to_string()),
            log_source: None,
        }
    }

    fn base(
        class_uid: u32,
        class_name: &str,
        cat_uid: u8,
        cat_name: &str,
        act_id: u8,
        act_name: &str,
    ) -> BaseEventData {
        let mut b = BaseEventData::new(
            class_uid,
            class_name,
            cat_uid,
            cat_name,
            act_id,
            act_name,
            crate::enums::SeverityId::Informational,
            test_metadata(),
        );
        b.set_time(1_742_047_200_000); // Fixed timestamp for deterministic tests
        b
    }

    #[test]
    fn test_format_ts() {
        let ts = format_ts(1_742_047_200_000);
        assert_eq!(ts, "14:00:00.000");
    }

    #[test]
    fn test_format_ts_invalid_timestamp_does_not_panic() {
        // Out-of-range timestamp should return placeholder, not panic
        let ts = format_ts(i64::MAX);
        assert_eq!(ts, "??:??:??.???");

        let ts = format_ts(i64::MIN);
        assert_eq!(ts, "??:??:??.???");
    }

    #[test]
    fn test_severity_char_mapping() {
        assert_eq!(severity_char(0), ' ');
        assert_eq!(severity_char(1), 'I');
        assert_eq!(severity_char(2), 'L');
        assert_eq!(severity_char(3), 'M');
        assert_eq!(severity_char(4), 'H');
        assert_eq!(severity_char(5), 'C');
        assert_eq!(severity_char(6), 'F');
    }

    #[test]
    fn test_network_activity_shorthand_allow() {
        let event = OcsfEvent::NetworkActivity(NetworkActivityEvent {
            base: base(4001, "Network Activity", 4, "Network Activity", 1, "Open"),
            src_endpoint: None,
            dst_endpoint: Some(Endpoint::from_domain("api.example.com", 443)),
            proxy_endpoint: None,
            actor: Some(Actor {
                process: Process::new("python3", 42),
            }),
            firewall_rule: Some(FirewallRule::new("default-egress", "mechanistic")),
            connection_info: None,
            action: Some(ActionId::Allowed),
            disposition: Some(DispositionId::Allowed),
            observation_point_id: None,
            is_src_dst_assignment_known: None,
        });

        let shorthand = event.format_shorthand();
        assert_eq!(
            shorthand,
            "NET:OPEN [INFO] ALLOWED python3(42) -> api.example.com:443 [policy:default-egress engine:mechanistic]"
        );
    }

    #[test]
    fn test_network_activity_shorthand_bypass() {
        let event = OcsfEvent::NetworkActivity(NetworkActivityEvent {
            base: {
                let mut b = base(4001, "Network Activity", 4, "Network Activity", 5, "Refuse");
                b.severity = crate::enums::SeverityId::Medium;
                b
            },
            src_endpoint: None,
            dst_endpoint: Some(Endpoint::from_ip_str("93.184.216.34", 443)),
            proxy_endpoint: None,
            actor: Some(Actor {
                process: Process::new("node", 1234),
            }),
            firewall_rule: Some(FirewallRule::new("bypass-detect", "iptables")),
            connection_info: Some(ConnectionInfo::new("tcp")),
            action: Some(ActionId::Denied),
            disposition: Some(DispositionId::Blocked),
            observation_point_id: Some(3),
            is_src_dst_assignment_known: Some(true),
        });

        let shorthand = event.format_shorthand();
        assert_eq!(
            shorthand,
            "NET:REFUSE [MED] DENIED node(1234) -> 93.184.216.34:443/tcp [policy:bypass-detect engine:iptables]"
        );
    }

    #[test]
    fn test_http_activity_shorthand() {
        let event = OcsfEvent::HttpActivity(HttpActivityEvent {
            base: base(4002, "HTTP Activity", 4, "Network Activity", 3, "Get"),
            http_request: Some(HttpRequest::new(
                "GET",
                Url::new("https", "api.example.com", "/v1/data", 443),
            )),
            http_response: None,
            src_endpoint: None,
            dst_endpoint: None,
            proxy_endpoint: None,
            actor: Some(Actor {
                process: Process::new("curl", 88),
            }),
            firewall_rule: Some(FirewallRule::new("default-egress", "mechanistic")),
            action: Some(ActionId::Allowed),
            disposition: None,
            observation_point_id: None,
            is_src_dst_assignment_known: None,
        });

        let shorthand = event.format_shorthand();
        assert_eq!(
            shorthand,
            "HTTP:GET [INFO] ALLOWED curl(88) -> GET https://api.example.com/v1/data [policy:default-egress]"
        );
    }

    #[test]
    fn test_ssh_activity_shorthand() {
        let event = OcsfEvent::SshActivity(SshActivityEvent {
            base: base(4007, "SSH Activity", 4, "Network Activity", 1, "Open"),
            src_endpoint: Some(Endpoint::from_ip_str("10.42.0.1", 48201)),
            dst_endpoint: None,
            actor: None,
            auth_type: Some(AuthTypeId::Other),
            auth_type_custom_label: Some("NSSH1".to_string()),
            protocol_ver: None,
            action: Some(ActionId::Allowed),
            disposition: None,
        });

        let shorthand = event.format_shorthand();
        assert_eq!(
            shorthand,
            "SSH:OPEN [INFO] ALLOWED 10.42.0.1:48201 [auth:NSSH1]"
        );
    }

    #[test]
    fn test_process_activity_shorthand_launch() {
        let event = OcsfEvent::ProcessActivity(ProcessActivityEvent {
            base: base(1007, "Process Activity", 1, "System Activity", 1, "Launch"),
            process: Process::new("python3", 42).with_cmd_line("python3 /app/main.py"),
            actor: None,
            launch_type: Some(LaunchTypeId::Spawn),
            exit_code: None,
            action: None,
            disposition: None,
        });

        let shorthand = event.format_shorthand();
        assert_eq!(
            shorthand,
            "PROC:LAUNCH [INFO] python3(42) [cmd:python3 /app/main.py]"
        );
    }

    #[test]
    fn test_process_activity_shorthand_terminate() {
        let event = OcsfEvent::ProcessActivity(ProcessActivityEvent {
            base: base(
                1007,
                "Process Activity",
                1,
                "System Activity",
                2,
                "Terminate",
            ),
            process: Process::new("python3", 42),
            actor: None,
            launch_type: None,
            exit_code: Some(0),
            action: None,
            disposition: None,
        });

        let shorthand = event.format_shorthand();
        assert_eq!(shorthand, "PROC:TERMINATE [INFO] python3(42) [exit:0]");
    }

    #[test]
    fn test_detection_finding_shorthand() {
        let event = OcsfEvent::DetectionFinding(DetectionFindingEvent {
            base: {
                let mut b = base(2004, "Detection Finding", 2, "Findings", 1, "Create");
                b.severity = crate::enums::SeverityId::High;
                b
            },
            finding_info: FindingInfo::new("nssh1-replay-abc", "NSSH1 Nonce Replay Attack"),
            evidences: None,
            attacks: None,
            remediation: None,
            is_alert: Some(true),
            confidence: Some(ConfidenceId::High),
            risk_level: None,
            action: None,
            disposition: Some(DispositionId::Blocked),
        });

        let shorthand = event.format_shorthand();
        assert_eq!(
            shorthand,
            "FINDING:BLOCKED [HIGH] \"NSSH1 Nonce Replay Attack\" [confidence:high]"
        );
    }

    #[test]
    fn test_lifecycle_shorthand() {
        let mut b = base(
            6002,
            "Application Lifecycle",
            6,
            "Application Activity",
            3,
            "Start",
        );
        b.set_status(crate::enums::StatusId::Success);
        let event = OcsfEvent::ApplicationLifecycle(ApplicationLifecycleEvent {
            base: b,
            app: Product {
                name: "openshell-sandbox".to_string(),
                vendor_name: "OpenShell".to_string(),
                version: Some("0.1.0".to_string()),
            },
        });

        let shorthand = event.format_shorthand();
        assert_eq!(
            shorthand,
            "LIFECYCLE:START [INFO] openshell-sandbox success"
        );
    }

    #[test]
    fn test_config_state_change_shorthand() {
        let mut b = base(5019, "Device Config State Change", 5, "Discovery", 1, "Log");
        b.set_message("policy reloaded");
        b.add_unmapped("policy_version", serde_json::json!("v3"));
        b.add_unmapped("policy_hash", serde_json::json!("sha256:abc123def456"));

        let event = OcsfEvent::DeviceConfigStateChange(DeviceConfigStateChangeEvent {
            base: b,
            state: Some(StateId::Enabled),
            state_custom_label: Some("LOADED".to_string()),
            security_level: None,
            prev_security_level: None,
        });

        let shorthand = event.format_shorthand();
        assert_eq!(
            shorthand,
            "CONFIG:LOADED [INFO] policy reloaded [version:v3 hash:sha256:abc123def456]"
        );
    }

    #[test]
    fn test_base_event_shorthand() {
        let mut b = base(0, "Base Event", 0, "Uncategorized", 99, "Other");
        b.set_message("Network namespace created");
        b.add_unmapped("ns", serde_json::json!("openshell-sandbox-abc123"));

        let event = OcsfEvent::Base(BaseEvent { base: b });

        let shorthand = event.format_shorthand();
        assert_eq!(
            shorthand,
            "EVENT [INFO] Network namespace created [ns:openshell-sandbox-abc123]"
        );
    }
}
