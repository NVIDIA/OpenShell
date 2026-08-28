// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `metadata.uid` identifies the event; `container.uid` identifies the sandbox.

use std::net::{IpAddr, Ipv4Addr};

use openshell_ocsf::{
    ActivityId, EventOrigin, NetworkActivityBuilder, OcsfEvent, SandboxContext, SeverityId,
};

fn sandbox_ctx() -> SandboxContext {
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

fn gateway_ctx(sandbox_id: &str, sandbox_name: &str) -> SandboxContext {
    SandboxContext {
        sandbox_id: sandbox_id.to_string(),
        sandbox_name: sandbox_name.to_string(),
        container_image: String::new(),
        hostname: "openshell-gateway-0".to_string(),
        product_version: "0.42.1".to_string(),
        proxy_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_port: 0,
        origin: EventOrigin::Gateway {
            name: "production-us-west".to_string(),
        },
    }
}

fn event(ctx: &SandboxContext) -> OcsfEvent {
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Open)
        .severity(SeverityId::Medium)
        .message("CONNECT api.example.com:443")
        .build()
}

#[test]
fn each_event_gets_its_own_metadata_uid() {
    let ctx = sandbox_ctx();

    let first = event(&ctx);
    let second = event(&ctx);

    let first_uid = first.base().metadata.uid.clone().expect("uid is set");
    let second_uid = second.base().metadata.uid.clone().expect("uid is set");

    assert!(!first_uid.is_empty());
    assert_ne!(
        first_uid, second_uid,
        "a shared uid invites a SIEM to dedup distinct events"
    );
}

#[test]
fn metadata_uid_is_no_longer_the_sandbox_id() {
    let event = event(&sandbox_ctx());

    assert_ne!(
        event.base().metadata.uid.as_deref(),
        Some("sb-1"),
        "metadata.uid is a per-event identifier, not a producer identifier"
    );
}

#[test]
fn the_sandbox_id_is_carried_by_the_container() {
    let json = event(&sandbox_ctx()).to_json().expect("serializes");

    assert_eq!(json["container"]["uid"], "sb-1");
    assert_eq!(json["container"]["name"], "agent-01");
}

#[test]
fn a_gateway_event_about_a_sandbox_still_names_that_container() {
    let json = event(&gateway_ctx("sb-7", "agent-07"))
        .to_json()
        .expect("serializes");

    assert_eq!(json["container"]["uid"], "sb-7");
    assert_eq!(json["container"]["name"], "agent-07");
    assert_eq!(json["metadata"]["product"]["name"], "OpenShell Gateway");
}

#[test]
fn a_gateway_event_about_no_sandbox_omits_the_container() {
    let json = event(&gateway_ctx("", "")).to_json().expect("serializes");

    assert!(
        json.get("container").is_none(),
        "an event with no sandbox association has no container: {json}"
    );
}

#[test]
fn a_container_without_an_image_omits_the_image() {
    let json = event(&gateway_ctx("sb-7", "agent-07"))
        .to_json()
        .expect("serializes");

    assert!(
        json["container"].get("image").is_none(),
        "an empty image reference is worse than none: {json}"
    );
}
