// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-rendered log text must match what the sandbox would have rendered.
//!
//! A decode gap corrupts `openshell logs` output rather than erroring.

use std::net::{IpAddr, Ipv4Addr};

use openshell_ocsf::{
    ActionId, ActivityId, AppLifecycleBuilder, ConfigStateChangeBuilder, DetectionFindingBuilder,
    DispositionId, Endpoint, EventOrigin, FindingInfo, HttpActivityBuilder, HttpMethod,
    HttpRequest, HttpResponse, NetworkActivityBuilder, OcsfEvent, Process, ProcessActivityBuilder,
    SandboxContext, SeverityId, SshActivityBuilder, StateId, StatusId, Url,
};

fn ctx() -> SandboxContext {
    SandboxContext {
        sandbox_id: "sb-1".to_string(),
        sandbox_name: "agent-01".to_string(),
        container_image: "ghcr.io/nvidia/openshell/sandbox:0.42.1".to_string(),
        hostname: "openshell-sb-1".to_string(),
        product_version: "0.42.1".to_string(),
        proxy_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_port: 8888,
        origin: EventOrigin::Sandbox,
    }
}

/// Serialize as the supervisor does, then decode as the gateway does.
fn across_the_wire(event: &OcsfEvent) -> OcsfEvent {
    let bytes = event.to_json_line().expect("serialize").into_bytes();
    serde_json::from_slice(&bytes).expect("gateway should decode the payload")
}

fn assert_renders_identically(label: &str, event: &OcsfEvent) {
    assert_eq!(
        across_the_wire(event).format_shorthand(),
        event.format_shorthand(),
        "{label}: gateway-rendered text differs from sandbox-rendered text"
    );
}

#[test]
fn network_activity_renders_identically_across_the_wire() {
    let event = NetworkActivityBuilder::new(&ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .dst_endpoint(Endpoint::from_domain("api.example.com", 443))
        .src_endpoint_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 51234)
        .actor_process(Process::new("/usr/bin/curl", 4711).with_cmd_line("curl -sS https://x"))
        .firewall_rule("default-deny-egress", "opa")
        .message("CONNECT denied api.example.com:443")
        .build();
    assert_renders_identically("network_activity", &event);
}

#[test]
fn http_activity_renders_identically_across_the_wire() {
    let event = HttpActivityBuilder::new(&ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Allowed)
        .disposition(DispositionId::Allowed)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .http_request(HttpRequest {
            http_method: HttpMethod::Get,
            url: Some(Url::new("https", "api.example.com", "/v1/items", 443)),
        })
        .http_response(HttpResponse { code: 200 })
        .message("GET /v1/items 200")
        .build();
    assert_renders_identically("http_activity", &event);
}

#[test]
fn ssh_activity_renders_identically_across_the_wire() {
    let event = SshActivityBuilder::new(&ctx())
        .activity(ActivityId::Open)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .dst_endpoint(Endpoint::from_domain("sandbox.local", 22))
        .message("ssh session accepted")
        .build();
    assert_renders_identically("ssh_activity", &event);
}

#[test]
fn process_activity_renders_identically_across_the_wire() {
    let event = ProcessActivityBuilder::new(&ctx())
        .activity(ActivityId::Open)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .process(Process::new("/usr/bin/python3", 4713).with_cmd_line("python3 -m pytest"))
        .message("process started")
        .build();
    assert_renders_identically("process_activity", &event);
}

#[test]
fn detection_finding_renders_identically_across_the_wire() {
    let event = DetectionFindingBuilder::new(&ctx())
        .finding_info(FindingInfo::new("finding-1", "Sandbox bypass attempt"))
        .severity(SeverityId::High)
        .is_alert(true)
        .evidence("dst_host", "169.254.169.254")
        .message("bypass attempt detected")
        .build();
    assert_renders_identically("detection_finding", &event);
}

#[test]
fn config_state_change_renders_identically_across_the_wire() {
    let event = ConfigStateChangeBuilder::new(&ctx())
        .state(StateId::Other, "policy-loaded")
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message("policy reloaded")
        .unmapped("policy_version", 7)
        .build();
    assert_renders_identically("config_state_change", &event);
}

#[test]
fn application_lifecycle_renders_identically_across_the_wire() {
    let event = AppLifecycleBuilder::new(&ctx())
        .activity(ActivityId::Open)
        .severity(SeverityId::Informational)
        .message("supervisor started")
        .build();
    assert_renders_identically("application_lifecycle", &event);
}
