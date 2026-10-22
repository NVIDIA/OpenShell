// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fixtures for tests that assert on gateway audit events.

use super::{ConnectionSource, RequestOrigin};
use openshell_ocsf::test_support::OcsfCapture;
use openshell_ocsf::validation::schema::{
    load_class_schema, validate_known_fields, validate_required_fields,
};
use serde_json::Value;
use std::future::Future;

/// The `x-request-id` a test request carries.
pub const REQUEST_ID: &str = "6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f";

/// The address a test request comes from.
pub const PEER: &str = "203.0.113.7:51234";

/// The IP address of [`PEER`] as events record it.
pub const PEER_IP: &str = "203.0.113.7";

/// A direct connection from [`PEER`].
pub fn peer() -> ConnectionSource {
    ConnectionSource::Peer(PEER.parse().expect("peer address"))
}

/// A request from [`PEER`] carrying [`REQUEST_ID`].
pub fn origin() -> RequestOrigin {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-request-id", REQUEST_ID.parse().expect("request ID"));
    RequestOrigin::new(Some(peer()), &headers)
}

/// Run `handler` as a routed request to `path` from [`origin`], returning
/// its output and the OCSF events it emitted.
pub async fn audited<F: Future>(path: &str, handler: F) -> (F::Output, Vec<Value>) {
    let capture = OcsfCapture::default();
    let output = {
        let _guard = capture.install();
        super::with_request(path.to_string(), origin(), handler).await
    };
    (output, capture.json_events())
}

/// Assert that `event` records the request from [`origin`].
pub fn assert_origin(event: &Value) {
    assert_eq!(event["src_endpoint"]["ip"], PEER_IP, "{event}");
    assert_eq!(event["metadata"]["correlation_uid"], REQUEST_ID, "{event}");
}

/// Assert that `event` never mentions `secret`.
pub fn assert_redacted(event: &Value, secret: &str) {
    assert!(
        !event.to_string().contains(secret),
        "event mentions {secret}: {event}"
    );
}

fn assert_conforms(event: &Value, class: &str) {
    let schema = load_class_schema(class);
    validate_required_fields(event, &schema);
    validate_known_fields(event, &schema);
}

/// Assert that `event` is an Authentication failure for `reason` on a
/// request to `path`.
pub fn assert_authentication_failure(event: &Value, path: &str, reason: &str) {
    assert_conforms(event, "authentication");
    assert_eq!(event["class_uid"], 3002, "{event}");
    assert_eq!(event["activity_id"], 1, "{event}");
    assert_eq!(event["status_id"], 2, "{event}");
    assert_eq!(event["action_id"], 2, "{event}");
    assert_eq!(event["disposition_id"], 2, "{event}");
    assert_eq!(event["status_detail"], reason, "{event}");
    assert_eq!(event["service"]["name"], "openshell-gateway", "{event}");
    assert_eq!(event["http_request"]["url"]["path"], path, "{event}");
}

/// Assert that `event` is an Authentication logon for a request to `path`.
pub fn assert_logon(event: &Value, path: &str) {
    assert_conforms(event, "authentication");
    assert_eq!(event["class_uid"], 3002, "{event}");
    assert_eq!(event["activity_id"], 1, "{event}");
    assert_eq!(event["status_id"], 1, "{event}");
    assert_eq!(event["action_id"], 1, "{event}");
    assert_eq!(event["disposition_id"], 1, "{event}");
    assert_eq!(event["severity_id"], 1, "{event}");
    assert_eq!(event["service"]["name"], "openshell-gateway", "{event}");
    assert_eq!(event["http_request"]["url"]["path"], path, "{event}");
}

/// Assert that `event` is an API Activity denial for `reason` on a request
/// to `path`.
pub fn assert_denial(event: &Value, path: &str, reason: &str) {
    assert_conforms(event, "api_activity");
    assert_eq!(event["class_uid"], 6003, "{event}");
    assert_eq!(event["action_id"], 2, "{event}");
    assert_eq!(event["disposition_id"], 2, "{event}");
    assert_eq!(event["status_id"], 2, "{event}");
    assert_eq!(event["status_detail"], reason, "{event}");
    assert_eq!(event["http_request"]["url"]["path"], path, "{event}");
}

/// Assert that `finding` is the sandbox boundary finding paired with
/// `denial`.
pub fn assert_boundary_finding(denial: &Value, finding: &Value) {
    assert_conforms(finding, "detection_finding");
    assert_eq!(finding["class_uid"], 2004, "{finding}");
    assert_eq!(
        finding["finding_info"]["uid"], "sandbox-authorization-boundary",
        "{finding}"
    );
    assert_eq!(finding["severity_id"], 4, "{finding}");
    assert_eq!(finding["is_alert"], true, "{finding}");
    let correlation_uid = &denial["metadata"]["correlation_uid"];
    assert!(correlation_uid.is_string(), "{denial}");
    assert_eq!(
        &finding["metadata"]["correlation_uid"], correlation_uid,
        "{finding}"
    );
}
