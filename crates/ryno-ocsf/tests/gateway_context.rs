// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-origin events carry gateway identity, not sandbox identity.

use std::net::{IpAddr, Ipv4Addr};

use ryno_ocsf::{
    ActivityId, AppLifecycleBuilder, ConfigStateChangeBuilder, EventContext, EventOrigin, OsInfo,
    SeverityId, StateId, StatusId,
};

fn gateway_ctx() -> EventContext {
    EventContext {
        sandbox_id: String::new(),
        sandbox_name: String::new(),
        container_image: String::new(),
        hostname: "ryno-gateway-0".to_string(),
        product_version: "0.42.1".to_string(),
        proxy_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_port: 0,
        origin: EventOrigin::Gateway {
            name: "production-us-west".to_string(),
        },
    }
}

fn supervisor_ctx() -> EventContext {
    EventContext {
        sandbox_id: "sb-1".to_string(),
        sandbox_name: "agent-01".to_string(),
        container_image: "ghcr.io/nvidia/ryno/sandbox:0.42.1".to_string(),
        hostname: "ryno-sb-1".to_string(),
        product_version: "0.42.1".to_string(),
        proxy_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_port: 8888,
        origin: EventOrigin::Supervisor,
    }
}

#[test]
fn gateway_events_report_the_gateway_os() {
    let expected_os = OsInfo::pretty_name(std::env::consts::OS);

    for sandbox_id in ["", "sb-1"] {
        let mut context = gateway_ctx();
        context.sandbox_id = sandbox_id.to_string();
        let json = AppLifecycleBuilder::new(&context)
            .activity(ActivityId::Open)
            .build()
            .to_json()
            .unwrap();

        assert_eq!(json["device"]["os"]["name"], expected_os);
    }
}

#[test]
fn supervisor_events_preserve_platform_os() {
    let json = AppLifecycleBuilder::new(&supervisor_ctx())
        .activity(ActivityId::Open)
        .build()
        .to_json()
        .unwrap();

    let expected_os = if cfg!(target_os = "windows") {
        "Windows"
    } else {
        "Linux"
    };
    assert_eq!(json["device"]["os"]["name"], expected_os);
}

#[test]
fn gateway_events_report_the_gateway_product() {
    let event = AppLifecycleBuilder::new(&gateway_ctx())
        .activity(ActivityId::Open)
        .severity(SeverityId::Informational)
        .message("gateway started")
        .build();
    let json = event.to_json().unwrap();

    assert_eq!(json["metadata"]["product"]["name"], "Ryno Gateway");
    assert_eq!(json["metadata"]["product"]["vendor_name"], "Ryno");
    assert_eq!(json["metadata"]["version"], "1.8.0");
    assert_eq!(json["metadata"]["product"]["version"], "0.42.1");
}

#[test]
fn supervisor_events_still_report_the_supervisor_product() {
    let event = AppLifecycleBuilder::new(&supervisor_ctx())
        .activity(ActivityId::Open)
        .severity(SeverityId::Informational)
        .message("supervisor started")
        .build();
    let json = event.to_json().unwrap();

    assert_eq!(
        json["metadata"]["product"]["name"],
        "Ryno Sandbox Supervisor"
    );
}

#[test]
fn gateway_events_identify_the_device_by_operator_assigned_name() {
    let event = ConfigStateChangeBuilder::new(&gateway_ctx())
        .state(StateId::Enabled, "reloaded")
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message("TLS certificate config reloaded")
        .build();
    let json = event.to_json().unwrap();

    assert_eq!(json["device"]["name"], "production-us-west");
    assert_eq!(json["device"]["uid"], "production-us-west");
    assert_eq!(json["device"]["hostname"], "ryno-gateway-0");
}

#[test]
fn gateway_events_omit_the_container_object() {
    let event = ConfigStateChangeBuilder::new(&gateway_ctx())
        .state(StateId::Enabled, "reloaded")
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message("TLS certificate config reloaded")
        .build();
    let json = event.to_json().unwrap();

    assert!(
        json.get("container").is_none(),
        "a gateway event without a sandbox association should omit container: {json}"
    );
}

#[test]
fn supervisor_events_still_carry_their_sandbox_container() {
    let event = ConfigStateChangeBuilder::new(&supervisor_ctx())
        .state(StateId::Enabled, "loaded")
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message("policy loaded")
        .build();
    let json = event.to_json().unwrap();

    assert_eq!(json["container"]["name"], "agent-01");
    assert_eq!(json["container"]["uid"], "sb-1");
    assert!(json["device"].get("name").is_none());
}
