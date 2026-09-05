// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OcsfEvent` JSON round-trip fidelity.
//!
//! `Serialize` is written by hand and `Deserialize` dispatches on `class_uid`
//! into independent per-variant paths, so a field can serialize correctly and
//! still be dropped or rejected on the way back in.

use std::net::{IpAddr, Ipv4Addr};

use openshell_ocsf::{
    ActionId, ActivityId, AiModel, ApiActivityBuilder, AppLifecycleBuilder, Attack, AuthTypeId,
    BaseEventBuilder, ConfidenceId, ConfigStateChangeBuilder, ConnectionInfo,
    DetectionFindingBuilder, DispositionId, Endpoint, FindingInfo, HttpActivityBuilder, HttpMethod,
    HttpRequest, HttpResponse, LaunchTypeId, NetworkActivityBuilder, OcsfEvent, Process,
    ProcessActivityBuilder, RiskLevelId, SandboxContext, SecurityLevelId, SeverityId,
    SshActivityBuilder, StateId, StatusId, Url,
};

fn ctx() -> SandboxContext {
    SandboxContext {
        sandbox_id: "sb-7f3a9c2e14b8".to_string(),
        sandbox_name: "agent-workspace-01".to_string(),
        container_image: "ghcr.io/nvidia/openshell-community/sandboxes/base:latest".to_string(),
        hostname: "openshell-sb-7f3a9c2e14b8".to_string(),
        product_version: "0.42.1".to_string(),
        proxy_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_port: 8888,
    }
}

/// Assert an event survives `to_json -> from_value -> to_json` unchanged.
fn assert_round_trips(label: &str, event: &OcsfEvent) {
    let json = event.to_json().expect("serialize");

    let decoded: OcsfEvent = serde_json::from_value(json.clone())
        .unwrap_or_else(|e| panic!("{label}: deserialize failed: {e}\njson: {json}"));

    let reserialized = decoded.to_json().expect("re-serialize");
    assert_eq!(
        json, reserialized,
        "{label}: JSON changed across round trip"
    );
}

#[test]
fn network_activity_round_trips() {
    let event = NetworkActivityBuilder::new(&ctx())
        .activity(ActivityId::Open)
        .activity_name("Open")
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .dst_endpoint(Endpoint::from_domain("api.example.com", 443))
        .src_endpoint_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 51234)
        .actor_process(
            Process::new("/usr/bin/curl", 4711)
                .with_cmd_line("curl -sS https://api.example.com")
                .with_parent(Process::new("/bin/bash", 4700)),
        )
        .firewall_rule("default-deny-egress", "opa")
        .connection_info(ConnectionInfo::new("tcp"))
        .observation_point(3)
        .status_detail("blocked by egress policy")
        .log_source("/dev/kmsg")
        .message("CONNECT denied api.example.com:443")
        .unmapped("policy_version", 42)
        .unmapped("engine", "opa")
        .build();

    assert_round_trips("network_activity", &event);
}

#[test]
fn http_activity_round_trips() {
    let event = HttpActivityBuilder::new(&ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Allowed)
        .disposition(DispositionId::Allowed)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .http_request(HttpRequest {
            http_method: HttpMethod::Post,
            url: Some(Url::new("https", "api.example.com", "/v1/items", 443)),
        })
        .http_response(HttpResponse { code: 201 })
        .src_endpoint(Endpoint::from_ip(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            51235,
        ))
        .dst_endpoint(Endpoint::from_domain("api.example.com", 443))
        .actor_process(Process::new("/usr/bin/node", 4712))
        .firewall_rule("allow-api", "l7")
        .status_detail("allowed by L7 rule")
        .message("POST /v1/items 201")
        .unmapped("l7_decision", "allow")
        .build();

    assert_round_trips("http_activity", &event);
}

#[test]
fn ssh_activity_round_trips() {
    let event = SshActivityBuilder::new(&ctx())
        .activity(ActivityId::Open)
        .auth_type(AuthTypeId::Other, "publickey-nonce")
        .protocol_ver("SSH-2.0-OpenSSH_9.6")
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .src_endpoint_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 44321)
        .dst_endpoint(Endpoint::from_domain("sandbox.local", 22))
        .message("ssh session accepted")
        .build();

    assert_round_trips("ssh_activity", &event);
}

#[test]
fn process_activity_round_trips() {
    let event = ProcessActivityBuilder::new(&ctx())
        .activity(ActivityId::Open)
        .process(
            Process::new("/usr/bin/python3", 4713)
                .with_cmd_line("python3 -m pytest")
                .with_parent(Process::new("/bin/sh", 4701)),
        )
        .launch_type(LaunchTypeId::Other)
        .exit_code(0)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message("process started")
        .build();

    assert_round_trips("process_activity", &event);
}

#[test]
fn detection_finding_round_trips() {
    let event = DetectionFindingBuilder::new(&ctx())
        .finding_info(
            FindingInfo::new("finding-001", "Sandbox bypass attempt")
                .with_desc("Process attempted to reach the host network directly"),
        )
        .severity(SeverityId::High)
        .is_alert(true)
        .confidence(ConfidenceId::High)
        .risk_level(RiskLevelId::High)
        .attack(Attack::mitre(
            "T1046",
            "Network Service Discovery",
            "TA0007",
            "Discovery",
        ))
        .evidence_pairs(&[("dst_host", "169.254.169.254"), ("dst_port", "80")])
        .evidence("binary", "/usr/bin/curl")
        .remediation("Tighten the egress policy for this sandbox")
        .log_source("/dev/kmsg")
        .message("bypass attempt detected")
        .unmapped("detector", "bypass_monitor")
        .build();

    assert_round_trips("detection_finding", &event);
}

#[test]
fn application_lifecycle_round_trips() {
    let event = AppLifecycleBuilder::new(&ctx())
        .activity(ActivityId::Open)
        .severity(SeverityId::Informational)
        .message("supervisor started")
        .build();

    assert_round_trips("application_lifecycle", &event);
}

#[test]
fn device_config_state_change_round_trips() {
    let event = ConfigStateChangeBuilder::new(&ctx())
        .state(StateId::Other, "policy-loaded")
        .security_level(SecurityLevelId::Secure)
        .prev_security_level(SecurityLevelId::AtRisk)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message("policy reloaded")
        .unmapped("policy_version", 7)
        .build();

    assert_round_trips("device_config_state_change", &event);
}

#[test]
fn api_activity_round_trips() {
    let event = ApiActivityBuilder::new(&ctx(), "chat.completions")
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .http_request(HttpRequest {
            http_method: HttpMethod::Post,
            url: Some(Url::new("https", "inference.local", "/v1/chat", 443)),
        })
        .dst_endpoint(Endpoint::from_domain("inference.local", 443))
        .ai_model(AiModel::new("llama-3.1-8b", "nvidia"))
        .message("inference request routed")
        .unmapped("route", "system")
        .build();

    assert_round_trips("api_activity", &event);
}

#[test]
fn base_event_round_trips() {
    let event = BaseEventBuilder::new(&ctx())
        .activity_name("custom activity")
        .severity(SeverityId::Low)
        .message("base event")
        .unmapped("detail", "value")
        .build();

    assert_round_trips("base_event", &event);
}
