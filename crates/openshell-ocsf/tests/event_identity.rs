// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `metadata.uid` identifies the event; `device.container.uid` identifies the sandbox.

use std::net::{IpAddr, Ipv4Addr};

use openshell_ocsf::{
    ActivityId, Endpoint, EventContext, EventOrigin, NetworkActivityBuilder, OcsfEvent, SeverityId,
};

fn sandbox_ctx(container_image: &str) -> EventContext {
    EventContext {
        sandbox_id: "sb-1".to_string(),
        sandbox_name: "agent-01".to_string(),
        container_image: container_image.to_string(),
        container_image_uid: None,
        hostname: "openshell-sb-1".to_string(),
        product_version: "0.42.1".to_string(),
        proxy_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_port: 8888,
        origin: EventOrigin::Supervisor,
    }
}

fn event(ctx: &EventContext) -> OcsfEvent {
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Open)
        .severity(SeverityId::Medium)
        .dst_endpoint(Endpoint::from_domain("api.example.com", 443))
        .message("CONNECT api.example.com:443")
        .build()
}

#[test]
fn each_event_gets_its_own_metadata_uid() {
    let ctx = sandbox_ctx("ghcr.io/nvidia/openshell/sandbox:0.42.1");
    let first = event(&ctx);
    let second = event(&ctx);

    let first_uid = first.base().metadata.uid.clone().expect("uid is set");
    let second_uid = second.base().metadata.uid.clone().expect("uid is set");

    assert!(!first_uid.is_empty());
    assert_ne!(first_uid, second_uid);
}

#[test]
fn metadata_uid_is_no_longer_the_sandbox_id() {
    let event = event(&sandbox_ctx("ghcr.io/nvidia/openshell/sandbox:0.42.1"));
    assert_ne!(event.base().metadata.uid.as_deref(), Some("sb-1"));
}

#[test]
fn the_sandbox_id_is_carried_by_the_container() {
    let json = event(&sandbox_ctx("ghcr.io/nvidia/openshell/sandbox:0.42.1"))
        .to_json()
        .expect("serializes");

    assert_eq!(json["device"]["container"]["uid"], "sb-1");
    assert_eq!(json["device"]["container"]["name"], "agent-01");
}

#[test]
fn image_references_without_a_resolved_uid_are_omitted() {
    for reference in ["", "image:1", "ghcr.io/nvidia/openshell/sandbox:0.42.1"] {
        let json = event(&sandbox_ctx(reference))
            .to_json()
            .expect("serializes");
        assert!(json["device"]["container"].is_object());
        assert!(json["device"]["container"].get("image").is_none());
    }
}

#[test]
fn resolved_workload_image_survives_serialization() {
    let mut ctx = sandbox_ctx("registry.example/agent:latest");
    for uid in [
        None,
        Some(""),
        Some("   "),
        Some("sha256:resolved-workload"),
    ] {
        ctx.container_image_uid = uid.map(str::to_string);
        let original = event(&ctx);
        let json = original.to_json().unwrap();
        let image = &json["device"]["container"]["image"];
        if uid == Some("sha256:resolved-workload") {
            assert_eq!(image["uid"], "sha256:resolved-workload");
            assert_eq!(image["name"], "registry.example/agent:latest");
        } else {
            assert!(image.is_null());
        }
        let decoded: OcsfEvent = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(decoded.to_json().unwrap(), json);
    }
    ctx.origin = EventOrigin::Gateway {
        name: "gateway".into(),
    };
    assert!(
        event(&ctx).to_json().unwrap()["device"]
            .get("container")
            .is_none()
    );
}

#[test]
fn device_identifies_the_sandbox_environment() {
    let json = event(&sandbox_ctx("image:1")).to_json().unwrap();

    assert_eq!(json["device"]["type_id"], 99);
    assert_eq!(json["device"]["type"], "Sandbox");
    let expected_os = if cfg!(target_os = "windows") {
        "Windows"
    } else {
        "Linux"
    };
    assert_eq!(json["device"]["os"]["name"], expected_os);
}

#[test]
fn event_identity_survives_serialization() {
    let original = event(&sandbox_ctx("image:1"));
    let decoded: OcsfEvent = serde_json::from_value(original.to_json().unwrap()).unwrap();
    assert_eq!(decoded.base().metadata.uid, original.base().metadata.uid);
}
