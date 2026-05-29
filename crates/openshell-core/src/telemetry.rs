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
const DEFAULT_ENDPOINT: &str = "https://events.telemetry.data.nvidia.com/v1.1/events/json";
const EVENT_SCHEMA_VERSION: &str = "4.0";
const EVENT_PROTOCOL_VERSION: &str = "1.6";
const EVENT_SYSTEM_VERSION: &str = "openshell-telemetry/1.0";
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const SOURCE: TelemetrySource = TelemetrySource::OpenShell;
static TELEMETRY_SENDER: OnceLock<Option<mpsc::SyncSender<TelemetryEvent>>> = OnceLock::new();

#[derive(Debug)]
struct TelemetryEvent {
    endpoint: String,
    name: &'static str,
    event_ts: String,
    event: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TelemetrySource {
    OpenShell,
}

impl TelemetrySource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::OpenShell => "openshell",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryOutcome {
    Success,
    Failure,
}

impl TelemetryOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }

    #[must_use]
    pub const fn from_success(success: bool) -> Self {
        if success {
            Self::Success
        } else {
            Self::Failure
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleResource {
    Sandbox,
    SandboxPolicy,
}

impl LifecycleResource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox",
            Self::SandboxPolicy => "sandbox_policy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleOperation {
    Create,
    Delete,
    Update,
}

impl LifecycleOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Delete => "delete",
            Self::Update => "update",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecisionOperation {
    Approve,
    Reject,
    Undo,
    ApproveAll,
}

impl PolicyDecisionOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Undo => "undo",
            Self::ApproveAll => "approve_all",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxTemplateSource {
    Default,
    Image,
    Undefined,
}

impl SandboxTemplateSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Image => "image",
            Self::Undefined => "undefined",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryComputeDriver {
    Docker,
    Kubernetes,
    Podman,
    Vm,
    Unknown,
}

impl TelemetryComputeDriver {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Kubernetes => "kubernetes",
            Self::Podman => "podman",
            Self::Vm => "vm",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub fn from_raw(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "docker" => Self::Docker,
            "k8s" | "kubernetes" => Self::Kubernetes,
            "podman" => Self::Podman,
            "vm" => Self::Vm,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn from_driver_kind(driver_kind: Option<crate::ComputeDriverKind>) -> Self {
        match driver_kind {
            Some(crate::ComputeDriverKind::Docker) => Self::Docker,
            Some(crate::ComputeDriverKind::Kubernetes) => Self::Kubernetes,
            Some(crate::ComputeDriverKind::Podman) => Self::Podman,
            Some(crate::ComputeDriverKind::Vm) => Self::Vm,
            None => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderProfile {
    Anthropic,
    Claude,
    Codex,
    Copilot,
    Github,
    Gitlab,
    Nvidia,
    Openai,
    Opencode,
    Outlook,
    Custom,
}

impl ProviderProfile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Copilot => "copilot",
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Nvidia => "nvidia",
            Self::Openai => "openai",
            Self::Opencode => "opencode",
            Self::Outlook => "outlook",
            Self::Custom => "custom",
        }
    }

    #[must_use]
    pub fn from_raw(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "anthropic" => Self::Anthropic,
            "claude" | "claude-code" => Self::Claude,
            "codex" => Self::Codex,
            "copilot" => Self::Copilot,
            "github" | "gh" => Self::Github,
            "gitlab" | "glab" => Self::Gitlab,
            "nvidia" => Self::Nvidia,
            "openai" => Self::Openai,
            "opencode" => Self::Opencode,
            "outlook" => Self::Outlook,
            _ => Self::Custom,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DenyGroup {
    Bypass,
    ConnectPolicy,
    ForwardPolicy,
    L7ParseRejection,
    L7Policy,
    PolicyStale,
    Ssrf,
    Unknown,
}

impl DenyGroup {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bypass => "bypass",
            Self::ConnectPolicy => "connect_policy",
            Self::ForwardPolicy => "forward_policy",
            Self::L7ParseRejection => "l7_parse_rejection",
            Self::L7Policy => "l7_policy",
            Self::PolicyStale => "policy_stale",
            Self::Ssrf => "ssrf",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub fn from_raw(raw: &str) -> Self {
        match raw {
            "connect_policy" | "connect" | "l4_deny" => Self::ConnectPolicy,
            "forward_policy" | "forward" => Self::ForwardPolicy,
            "l7_policy" | "l7" | "l7_deny" | "forward-l7-deny" => Self::L7Policy,
            "l7_parse_rejection" | "parse_rejection" => Self::L7ParseRejection,
            "ssrf" => Self::Ssrf,
            "bypass" => Self::Bypass,
            "policy_stale" => Self::PolicyStale,
            _ => Self::Unknown,
        }
    }
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

pub fn emit_lifecycle(
    resource: LifecycleResource,
    operation: LifecycleOperation,
    outcome: TelemetryOutcome,
) {
    emit_event(
        "openshell_lifecycle_event",
        json!({
            "nvidiaSource": SOURCE.as_str(),
            "resource": resource.as_str(),
            "operation": operation.as_str(),
            "outcome": outcome.as_str(),
        }),
    );
}

pub fn emit_provider_lifecycle(
    operation: LifecycleOperation,
    outcome: TelemetryOutcome,
    provider_profile: ProviderProfile,
) {
    emit_event(
        "openshell_provider_lifecycle_event",
        json!({
            "nvidiaSource": SOURCE.as_str(),
            "operation": operation.as_str(),
            "outcome": outcome.as_str(),
            "providerProfile": provider_profile.as_str(),
        }),
    );
}

pub fn emit_sandbox_create(
    outcome: TelemetryOutcome,
    requested_gpu: bool,
    provider_count: u64,
    has_custom_policy: bool,
    template_source: SandboxTemplateSource,
    compute_driver: TelemetryComputeDriver,
) {
    if !valid_count(provider_count) {
        return;
    }
    emit_event(
        "openshell_sandbox_create_event",
        json!({
            "nvidiaSource": SOURCE.as_str(),
            "outcome": outcome.as_str(),
            "requestedGpu": requested_gpu,
            "providerCount": provider_count,
            "hasCustomPolicy": has_custom_policy,
            "templateSource": template_source.as_str(),
            "computeDriver": compute_driver.as_str(),
        }),
    );
}

pub fn emit_policy_decision(
    operation: PolicyDecisionOperation,
    outcome: TelemetryOutcome,
    rule_count: u64,
) {
    if !valid_count(rule_count) {
        return;
    }
    emit_event(
        "openshell_policy_decision_event",
        json!({
            "nvidiaSource": SOURCE.as_str(),
            "operation": operation.as_str(),
            "outcome": outcome.as_str(),
            "ruleCount": rule_count,
        }),
    );
}

pub fn emit_sandbox_activity_summary<I>(
    network_activity_count: u64,
    denied_action_count: u64,
    denial_rate_pct: f64,
    denials_by_group: I,
) where
    I: IntoIterator<Item = (DenyGroup, u64)>,
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
        .map(|(group, count)| json!({ "denyGroup": group.as_str(), "deniedCount": count }))
        .collect();
    emit_event(
        "openshell_sandbox_activity_summary_event",
        json!({
            "nvidiaSource": SOURCE.as_str(),
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

fn sanitize_denials_by_group<I>(denials_by_group: I) -> Option<BTreeMap<DenyGroup, u64>>
where
    I: IntoIterator<Item = (DenyGroup, u64)>,
{
    let mut sanitized = BTreeMap::<DenyGroup, u64>::new();
    for (group, count) in denials_by_group {
        if !valid_count(count) {
            return None;
        }
        let next_count = sanitized
            .get(&group)
            .copied()
            .unwrap_or(0)
            .checked_add(count)?;
        if !valid_count(next_count) {
            return None;
        }
        sanitized.insert(group, next_count);
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
                "nvidiaSource": SOURCE.as_str(),
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
        assert_eq!(
            payload["events"][0]["parameters"]["nvidiaSource"],
            SOURCE.as_str()
        );
        assert_eq!(payload["events"][0]["ts"], "2026-05-18T00:00:00.000Z");
        assert_eq!(payload["sentTs"], "2026-05-18T00:00:01.000Z");
    }

    #[test]
    fn compute_driver_values_are_sanitized() {
        assert_eq!(
            TelemetryComputeDriver::from_raw("docker").as_str(),
            "docker"
        );
        assert_eq!(
            TelemetryComputeDriver::from_raw("k8s").as_str(),
            "kubernetes"
        );
        assert_eq!(
            TelemetryComputeDriver::from_raw("KUBERNETES").as_str(),
            "kubernetes"
        );
        assert_eq!(TelemetryComputeDriver::from_raw("vm").as_str(), "vm");
        assert_eq!(
            TelemetryComputeDriver::from_raw("podman").as_str(),
            "podman"
        );
        assert_eq!(
            TelemetryComputeDriver::from_raw("private-driver").as_str(),
            "unknown"
        );
    }

    #[test]
    fn telemetry_enqueue_drops_when_queue_is_full() {
        let (tx, _rx) = mpsc::sync_channel(1);
        let event = || TelemetryEvent {
            endpoint: "https://example.test/events".to_string(),
            name: "openshell_lifecycle_event",
            event_ts: "2026-05-18T00:00:00.000Z".to_string(),
            event: json!({
                "nvidiaSource": SOURCE.as_str(),
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
        assert_eq!(
            ProviderProfile::from_raw("corp-llm-prod"),
            ProviderProfile::Custom
        );
        assert_eq!(
            DenyGroup::from_raw("host=private.example"),
            DenyGroup::Unknown
        );
    }

    #[test]
    fn telemetry_enums_serialize_to_expected_strings() {
        assert_eq!(LifecycleResource::SandboxPolicy.as_str(), "sandbox_policy");
        assert_eq!(LifecycleOperation::Delete.as_str(), "delete");
        assert_eq!(PolicyDecisionOperation::ApproveAll.as_str(), "approve_all");
        assert_eq!(TelemetryOutcome::Failure.as_str(), "failure");
        assert_eq!(SandboxTemplateSource::Undefined.as_str(), "undefined");
        assert!(!valid_count(MAX_TELEMETRY_INTEGER + 1));
    }

    #[test]
    fn activity_groups_are_sanitized_and_aggregated() {
        let rows = sanitize_denials_by_group([
            (DenyGroup::from_raw("connect"), 1),
            (DenyGroup::from_raw("connect_policy"), 2),
            (DenyGroup::from_raw("host=private.example"), 3),
        ])
        .expect("rows should sanitize");

        assert_eq!(rows.get(&DenyGroup::ConnectPolicy), Some(&3));
        assert_eq!(rows.get(&DenyGroup::Unknown), Some(&3));
    }
}
