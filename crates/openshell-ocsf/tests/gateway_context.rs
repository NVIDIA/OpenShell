// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-origin events carry gateway identity, not sandbox identity.

use std::net::{IpAddr, Ipv4Addr};

use openshell_ocsf::{
    ActivityId, AppLifecycleBuilder, ConfigStateChangeBuilder, EventContext, EventOrigin, OsInfo,
    SeverityId, StateId, StatusId,
};

fn gateway_ctx() -> EventContext {
    EventContext {
        sandbox_id: String::new(),
        sandbox_name: String::new(),
        container_image: String::new(),
        container_image_uid: None,
        hostname: "openshell-gateway-0".to_string(),
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
        container_image: "ghcr.io/nvidia/openshell/sandbox:0.42.1".to_string(),
        container_image_uid: None,
        hostname: "openshell-sb-1".to_string(),
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

    assert_eq!(json["metadata"]["product"]["name"], "OpenShell Gateway");
    assert_eq!(json["metadata"]["product"]["vendor_name"], "OpenShell");
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
        "OpenShell Sandbox Supervisor"
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
    assert_eq!(json["device"]["hostname"], "openshell-gateway-0");
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
        json.get("container").is_none() && json["device"].get("container").is_none(),
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

    assert_eq!(json["device"]["container"]["name"], "agent-01");
    assert_eq!(json["device"]["container"]["uid"], "sb-1");
    assert!(json["device"].get("name").is_none());
}

#[test]
fn gateway_sandbox_attribution_uses_resources_or_unmapped() {
    use openshell_ocsf::{ApiActivityBuilder, DetectionFindingBuilder, OcsfEvent, ResourceDetails};

    let mut ctx = gateway_ctx();
    ctx.sandbox_id = "sb-1".into();
    ctx.sandbox_name = "agent-01".into();
    let events = [
        ApiActivityBuilder::new(&ctx, "GetSandbox")
            .resource(ResourceDetails::new("workspace", "ws-1"))
            .resource(ResourceDetails::new("sandbox", "sb-other"))
            .resource(ResourceDetails::new("sandbox", "sb-1"))
            .build(),
        DetectionFindingBuilder::new(&ctx)
            .resource(ResourceDetails::new("workspace", "ws-1"))
            .build(),
        ConfigStateChangeBuilder::new(&ctx).build(),
    ];
    for event in events {
        let json = event.to_json().unwrap();
        openshell_ocsf_validate::validate_event(&json).unwrap();
        assert_eq!(json["device"]["uid"], "production-us-west");
        assert!(json["device"].get("container").is_none());
        assert!(json.get("container").is_none());
        assert!(
            !json["metadata"]["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|profile| profile == "container")
        );
        assert_eq!(event.sandbox_id(), Some("sb-1"));
        if event.class_uid() == 5019 {
            assert!(json.get("resources").is_none());
            assert_eq!(json["unmapped"]["sandbox_id"], "sb-1");
            assert_eq!(json["unmapped"]["sandbox_name"], "agent-01");
        } else {
            let resources = json["resources"].as_array().unwrap();
            assert_eq!(
                resources[0],
                serde_json::json!({
                    "type": "sandbox", "uid": "sb-1", "name": "agent-01"
                })
            );
            assert_eq!(resources.iter().filter(|r| r["uid"] == "sb-1").count(), 1);
            assert!(resources.iter().any(|r| r["type"] == "workspace"));
            assert!(json.get("unmapped").is_none());
        }
        let decoded: OcsfEvent = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(decoded.sandbox_id(), Some("sb-1"));
        assert_eq!(decoded.to_json().unwrap(), json);
    }
}

#[test]
fn gateway_authentication_does_not_attach_a_container_or_resources() {
    use openshell_ocsf::{AuthenticationBuilder, Service, User};
    let mut ctx = gateway_ctx();
    ctx.sandbox_id = "sb-1".into();
    let event =
        AuthenticationBuilder::new(&ctx, User::unidentified(), Service::new("gateway")).build();
    let json = event.to_json().unwrap();
    openshell_ocsf_validate::validate_event(&json).unwrap();
    assert!(json["device"].get("container").is_none());
    assert!(json.get("resources").is_none());
    assert!(event.sandbox_id().is_none());
}

#[test]
fn gateway_lifecycle_without_a_container_profile_is_schema_conformant() {
    let ctx = gateway_ctx();
    let event = AppLifecycleBuilder::new(&ctx).build();
    let json = event.to_json().unwrap();
    openshell_ocsf_validate::validate_event(&json).unwrap();
    assert!(json["device"].get("container").is_none());
    assert!(event.sandbox_id().is_none());
}
