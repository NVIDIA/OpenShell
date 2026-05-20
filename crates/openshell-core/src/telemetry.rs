// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Best-effort anonymous telemetry emission helpers.

use chrono::{SecondsFormat, Utc};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{OnceLock, mpsc};
use std::thread;
use std::time::Duration;

const TELEMETRY_EVENT_QUEUE_CAPACITY: usize = 1024;
const MAX_TELEMETRY_INTEGER: u64 = 9_223_372_036_854_775_807;
const CLIENT_ID: &str = "415437562476676";
const DEFAULT_ENDPOINT: &str = "https://events.telemetry.data-uat.nvidia.com/v1.1/events/json";
const EVENT_SCHEMA_VERSION: &str = "3.0";
const EVENT_PROTOCOL_VERSION: &str = "1.6";
const EVENT_SYSTEM_VERSION: &str = "openshell-telemetry/1.0";
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const SOURCE: &str = "openshell";
static TELEMETRY_SENDER: OnceLock<Option<mpsc::SyncSender<TelemetryEvent>>> = OnceLock::new();

#[derive(Debug)]
struct TelemetryEvent {
    endpoint: String,
    name: &'static str,
    event_ts: String,
    event: Value,
}

pub fn enabled() -> bool {
    telemetry_enabled_from(std::env::var("OPENSHELL_TELEMETRY_ENABLED").ok().as_deref())
}

pub fn enabled_env_value() -> &'static str {
    enabled_env_value_from(std::env::var("OPENSHELL_TELEMETRY_ENABLED").ok().as_deref())
}

fn enabled_env_value_from(value: Option<&str>) -> &'static str {
    if telemetry_enabled_from(value) {
        "true"
    } else {
        "false"
    }
}

fn telemetry_enabled_from(value: Option<&str>) -> bool {
    let value = value.unwrap_or("true");
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn telemetry_endpoint() -> Option<String> {
    telemetry_endpoint_from(
        std::env::var("OPENSHELL_TELEMETRY_ENDPOINT")
            .ok()
            .as_deref(),
    )
}

fn telemetry_endpoint_from(endpoint: Option<&str>) -> Option<String> {
    let endpoint = endpoint.unwrap_or(DEFAULT_ENDPOINT);
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        None
    } else {
        Some(endpoint.to_string())
    }
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn client_version() -> &'static str {
    crate::VERSION
}

fn build_payload(name: &str, event: Value, event_ts: &str, sent_ts: &str) -> Value {
    json!({
        "browserType": "undefined",
        "clientId": CLIENT_ID,
        "clientType": "Native",
        "clientVariant": "Release",
        "clientVer": client_version(),
        "cpuArchitecture": std::env::consts::ARCH,
        "deviceGdprBehOptIn": "None",
        "deviceGdprFuncOptIn": "None",
        "deviceGdprTechOptIn": "None",
        "deviceId": "undefined",
        "deviceMake": "undefined",
        "deviceModel": "undefined",
        "deviceOS": "undefined",
        "deviceOSVersion": "undefined",
        "deviceType": "undefined",
        "eventProtocol": EVENT_PROTOCOL_VERSION,
        "eventSchemaVer": EVENT_SCHEMA_VERSION,
        "eventSysVer": EVENT_SYSTEM_VERSION,
        "externalUserId": "undefined",
        "gdprBehOptIn": "None",
        "gdprFuncOptIn": "None",
        "gdprTechOptIn": "None",
        "idpId": "undefined",
        "integrationId": "undefined",
        "productName": "undefined",
        "productVersion": "undefined",
        "sentTs": sent_ts,
        "sessionId": "undefined",
        "userId": "undefined",
        "events": [
            {
                "ts": event_ts,
                "parameters": event,
                "name": name,
            }
        ],
    })
}

fn telemetry_sender() -> Option<&'static mpsc::SyncSender<TelemetryEvent>> {
    TELEMETRY_SENDER
        .get_or_init(|| {
            let (tx, rx) = mpsc::sync_channel(TELEMETRY_EVENT_QUEUE_CAPACITY);
            thread::Builder::new()
                .name("openshell-telemetry".to_string())
                .spawn(move || telemetry_worker(rx))
                .ok()
                .map(|_| tx)
        })
        .as_ref()
}

fn telemetry_worker(rx: mpsc::Receiver<TelemetryEvent>) {
    for event in rx {
        let payload = build_payload(event.name, event.event, &event.event_ts, &timestamp());
        let _ = publish_payload(&event.endpoint, payload);
    }
}

fn publish_payload(endpoint: &str, payload: Value) -> Result<(), reqwest::Error> {
    Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(true)
        .timeout(HTTP_TIMEOUT)
        .build()?
        .post(endpoint)
        .json(&payload)
        .send()?
        .error_for_status()?;
    Ok(())
}

fn try_enqueue_event(sender: &mpsc::SyncSender<TelemetryEvent>, event: TelemetryEvent) -> bool {
    sender.try_send(event).is_ok()
}

fn emit_event(name: &'static str, event: Value) {
    if !enabled() {
        return;
    }
    let Some(endpoint) = telemetry_endpoint() else {
        return;
    };
    let Some(sender) = telemetry_sender() else {
        return;
    };

    let _ = try_enqueue_event(
        sender,
        TelemetryEvent {
            endpoint,
            name,
            event_ts: timestamp(),
            event,
        },
    );
}

pub fn emit_lifecycle(resource: &str, operation: &str, outcome: &str) {
    let Some(resource) = lifecycle_resource(resource) else {
        return;
    };
    let Some(operation) = lifecycle_operation(operation) else {
        return;
    };
    let Some(outcome) = telemetry_outcome(outcome) else {
        return;
    };
    emit_event(
        "openshell_lifecycle_event",
        json!({
            "nvidiaSource": SOURCE,
            "resource": resource,
            "operation": operation,
            "outcome": outcome,
        }),
    );
}

pub fn emit_provider_lifecycle(operation: &str, outcome: &str, provider_profile: &str) {
    let Some(operation) = lifecycle_operation(operation) else {
        return;
    };
    let Some(outcome) = telemetry_outcome(outcome) else {
        return;
    };
    let provider_profile = provider_profile_bucket(provider_profile);
    emit_event(
        "openshell_provider_lifecycle_event",
        json!({
            "nvidiaSource": SOURCE,
            "operation": operation,
            "outcome": outcome,
            "providerProfile": provider_profile,
        }),
    );
}

pub fn emit_sandbox_create(
    outcome: &str,
    requested_gpu: bool,
    provider_count: u64,
    has_custom_policy: bool,
    template_source: &str,
    compute_driver: &str,
) {
    let Some(outcome) = telemetry_outcome(outcome) else {
        return;
    };
    if !valid_count(provider_count) {
        return;
    }
    let template_source = sandbox_template_source_bucket(template_source);
    let compute_driver = compute_driver_bucket(compute_driver);
    emit_event(
        "openshell_sandbox_create_event",
        json!({
            "nvidiaSource": SOURCE,
            "outcome": outcome,
            "requestedGpu": requested_gpu,
            "providerCount": provider_count,
            "hasCustomPolicy": has_custom_policy,
            "templateSource": template_source,
            "computeDriver": compute_driver,
        }),
    );
}

pub fn emit_policy_decision(operation: &str, outcome: &str, rule_count: u64) {
    let Some(operation) = policy_decision_operation(operation) else {
        return;
    };
    let Some(outcome) = telemetry_outcome(outcome) else {
        return;
    };
    if !valid_count(rule_count) {
        return;
    }
    emit_event(
        "openshell_policy_decision_event",
        json!({
            "nvidiaSource": SOURCE,
            "operation": operation,
            "outcome": outcome,
            "ruleCount": rule_count,
        }),
    );
}

pub fn emit_sandbox_activity_summary<I, S>(
    network_activity_count: u64,
    denied_action_count: u64,
    denial_rate_pct: f64,
    denials_by_group: I,
) where
    I: IntoIterator<Item = (S, u64)>,
    S: Into<String>,
{
    if !valid_count(network_activity_count)
        || !valid_count(denied_action_count)
        || !denial_rate_pct.is_finite()
        || !(0.0..=100.0).contains(&denial_rate_pct)
    {
        return;
    }
    let Some(denials_by_group) = sanitize_denials_by_group(denials_by_group) else {
        return;
    };
    let rows: Vec<Value> = denials_by_group
        .into_iter()
        .map(|(group, count)| json!({ "denyGroup": group, "deniedCount": count }))
        .collect();
    emit_event(
        "openshell_sandbox_activity_summary_event",
        json!({
            "nvidiaSource": SOURCE,
            "networkActivityCount": network_activity_count,
            "deniedActionCount": denied_action_count,
            "denialRatePct": denial_rate_pct,
            "denialsByGroup": rows,
        }),
    );
}

fn valid_count(value: u64) -> bool {
    value <= MAX_TELEMETRY_INTEGER
}

fn telemetry_outcome(raw: &str) -> Option<&'static str> {
    match raw {
        "success" => Some("success"),
        "failure" => Some("failure"),
        _ => None,
    }
}

fn lifecycle_resource(raw: &str) -> Option<&'static str> {
    match raw {
        "sandbox" => Some("sandbox"),
        "sandbox_policy" => Some("sandbox_policy"),
        _ => None,
    }
}

fn lifecycle_operation(raw: &str) -> Option<&'static str> {
    match raw {
        "create" => Some("create"),
        "delete" => Some("delete"),
        "update" => Some("update"),
        _ => None,
    }
}

fn policy_decision_operation(raw: &str) -> Option<&'static str> {
    match raw {
        "approve" => Some("approve"),
        "reject" => Some("reject"),
        "undo" => Some("undo"),
        "approve_all" => Some("approve_all"),
        _ => None,
    }
}

fn sandbox_template_source_bucket(raw: &str) -> &'static str {
    match raw {
        "default" => "default",
        "image" => "image",
        _ => "undefined",
    }
}

fn compute_driver_bucket(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "docker" => "docker",
        "k8s" | "kubernetes" => "kubernetes",
        "podman" => "podman",
        "vm" => "vm",
        _ => "unknown",
    }
}

fn provider_profile_bucket(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "anthropic" => "anthropic",
        "claude" => "claude",
        "codex" => "codex",
        "copilot" => "copilot",
        "github" => "github",
        "gitlab" => "gitlab",
        "nvidia" => "nvidia",
        "openai" => "openai",
        "opencode" => "opencode",
        "outlook" => "outlook",
        _ => "custom",
    }
}

fn deny_group_bucket(raw: &str) -> &'static str {
    match raw {
        "connect_policy" | "connect" | "l4_deny" => "connect_policy",
        "forward_policy" | "forward" => "forward_policy",
        "l7_policy" | "l7" | "l7_deny" | "forward-l7-deny" => "l7_policy",
        "l7_parse_rejection" | "parse_rejection" => "l7_parse_rejection",
        "ssrf" => "ssrf",
        "bypass" => "bypass",
        "policy_stale" => "policy_stale",
        _ => "unknown",
    }
}

fn sanitize_denials_by_group<I, S>(denials_by_group: I) -> Option<BTreeMap<&'static str, u64>>
where
    I: IntoIterator<Item = (S, u64)>,
    S: Into<String>,
{
    let mut sanitized = BTreeMap::<&'static str, u64>::new();
    for (group, count) in denials_by_group {
        if !valid_count(count) {
            return None;
        }
        let group = group.into();
        let bucket = deny_group_bucket(&group);
        let next_count = sanitized
            .get(bucket)
            .copied()
            .unwrap_or(0)
            .checked_add(count)?;
        if !valid_count(next_count) {
            return None;
        }
        sanitized.insert(bucket, next_count);
    }
    Some(sanitized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_enabled_defaults_true() {
        assert!(telemetry_enabled_from(None));
    }

    #[test]
    fn telemetry_enabled_honors_false_values() {
        assert!(!telemetry_enabled_from(Some("off")));
        assert!(!telemetry_enabled_from(Some("false")));
        assert!(telemetry_enabled_from(Some("yes")));
    }

    #[test]
    fn telemetry_enabled_env_value_is_normalized() {
        assert_eq!(enabled_env_value_from(Some("false")), "false");
        assert_eq!(enabled_env_value_from(Some("0")), "false");
        assert_eq!(enabled_env_value_from(None), "true");
        assert_eq!(enabled_env_value_from(Some("yes")), "true");
    }

    #[test]
    fn telemetry_endpoint_empty_disables_publish() {
        assert_eq!(telemetry_endpoint_from(Some("  ")), None);
        assert_eq!(
            telemetry_endpoint_from(None),
            Some(DEFAULT_ENDPOINT.to_string())
        );
    }

    #[test]
    fn build_payload_matches_schema_metadata() {
        let payload = build_payload(
            "openshell_sandbox_create_event",
            json!({
                "nvidiaSource": SOURCE,
                "outcome": "success",
                "requestedGpu": false,
                "providerCount": 1,
                "hasCustomPolicy": true,
                "templateSource": "default",
                "computeDriver": "docker",
            }),
            "2026-05-18T00:00:00.000Z",
            "2026-05-18T00:00:01.000Z",
        );

        assert_eq!(payload["clientId"], CLIENT_ID);
        assert_eq!(payload["clientVer"], crate::VERSION);
        assert_eq!(payload["eventSchemaVer"], EVENT_SCHEMA_VERSION);
        assert_eq!(payload["deviceId"], "undefined");
        assert_eq!(payload["userId"], "undefined");
        assert_eq!(
            payload["events"][0]["name"],
            "openshell_sandbox_create_event"
        );
        assert_eq!(payload["events"][0]["parameters"]["nvidiaSource"], SOURCE);
        assert_eq!(payload["events"][0]["ts"], "2026-05-18T00:00:00.000Z");
        assert_eq!(payload["sentTs"], "2026-05-18T00:00:01.000Z");
    }

    #[test]
    fn compute_driver_values_are_sanitized() {
        assert_eq!(compute_driver_bucket("docker"), "docker");
        assert_eq!(compute_driver_bucket("k8s"), "kubernetes");
        assert_eq!(compute_driver_bucket("KUBERNETES"), "kubernetes");
        assert_eq!(compute_driver_bucket("vm"), "vm");
        assert_eq!(compute_driver_bucket("podman"), "podman");
        assert_eq!(compute_driver_bucket("private-driver"), "unknown");
    }

    #[test]
    fn telemetry_enqueue_drops_when_queue_is_full() {
        let (tx, _rx) = mpsc::sync_channel(1);
        let event = || TelemetryEvent {
            endpoint: "https://example.test/events".to_string(),
            name: "openshell_lifecycle_event",
            event_ts: "2026-05-18T00:00:00.000Z".to_string(),
            event: json!({
                "nvidiaSource": SOURCE,
                "resource": "sandbox",
                "operation": "create",
                "outcome": "success",
            }),
        };

        assert!(try_enqueue_event(&tx, event()));
        assert!(!try_enqueue_event(&tx, event()));
    }

    #[test]
    fn telemetry_validation_maps_privacy_sensitive_strings_to_safe_buckets() {
        assert_eq!(provider_profile_bucket("corp-llm-prod"), "custom");
        assert_eq!(
            sandbox_template_source_bucket("ghcr.io/acme/private:latest"),
            "undefined"
        );
        assert_eq!(deny_group_bucket("host=private.example"), "unknown");
    }

    #[test]
    fn telemetry_validation_rejects_schema_invalid_values() {
        assert_eq!(lifecycle_resource("gateway"), None);
        assert_eq!(lifecycle_operation("restart"), None);
        assert_eq!(policy_decision_operation("merge_internal_rule"), None);
        assert_eq!(telemetry_outcome("partial"), None);
        assert!(!valid_count(MAX_TELEMETRY_INTEGER + 1));
    }

    #[test]
    fn activity_groups_are_sanitized_and_aggregated() {
        let rows = sanitize_denials_by_group([
            ("connect".to_string(), 1),
            ("connect_policy".to_string(), 2),
            ("host=private.example".to_string(), 3),
        ])
        .expect("rows should sanitize");

        assert_eq!(rows.get("connect_policy"), Some(&3));
        assert_eq!(rows.get("unknown"), Some(&3));
    }
}
