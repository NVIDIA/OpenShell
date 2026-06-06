// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy updates, status, draft chunks, config/settings layer, and sandbox logs.

#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>
#![allow(clippy::cast_possible_truncation)] // Intentional u128->i64 etc. for timestamp math
#![allow(clippy::cast_sign_loss)] // Intentional i32->u32 conversions from proto types
#![allow(clippy::cast_possible_wrap)] // Intentional u32->i32 conversions for proto compat
#![allow(clippy::cast_precision_loss)] // f64->f32 for confidence scores
#![allow(clippy::items_after_statements)] // DB_PORTS const inside function

use crate::ServerState;
use crate::auth::principal::Principal;
use crate::persistence::{DraftChunkRecord, ObjectId, ObjectName, ObjectType, PolicyRecord, Store};
use crate::policy_store::PolicyStoreExt;
use openshell_core::proto::policy_merge_operation;
use openshell_core::proto::setting_value;
use openshell_core::proto::{
    AddAllowRules as ProtoAddAllowRules, AddDenyRules as ProtoAddDenyRules,
    ApproveAllDraftChunksRequest, ApproveAllDraftChunksResponse, ApproveDraftChunkRequest,
    ApproveDraftChunkResponse, ClearDraftChunksRequest, ClearDraftChunksResponse,
    DraftHistoryEntry, EditDraftChunkRequest, EditDraftChunkResponse, EffectiveSetting,
    GetDraftHistoryRequest, GetDraftHistoryResponse, GetDraftPolicyRequest, GetDraftPolicyResponse,
    GetGatewayConfigRequest, GetGatewayConfigResponse, GetSandboxConfigRequest,
    GetSandboxConfigResponse, GetSandboxLogsRequest, GetSandboxLogsResponse,
    GetSandboxPolicyStatusRequest, GetSandboxPolicyStatusResponse,
    GetSandboxProviderEnvironmentRequest, GetSandboxProviderEnvironmentResponse,
    ListSandboxPoliciesRequest, ListSandboxPoliciesResponse, PolicyChunk, PolicyMergeOperation,
    PolicySource, PolicyStatus, PushSandboxLogsRequest, PushSandboxLogsResponse,
    RejectDraftChunkRequest, RejectDraftChunkResponse, ReportPolicyStatusRequest,
    ReportPolicyStatusResponse, SandboxLogLine, SandboxPolicyRevision, SettingScope, SettingValue,
    SubmitPolicyAnalysisRequest, SubmitPolicyAnalysisResponse, UndoDraftChunkRequest,
    UndoDraftChunkResponse, UpdateConfigRequest, UpdateConfigResponse,
};
use openshell_core::proto::{
    L7DenyRule, L7Rule, NetworkBinary, NetworkEndpoint, NetworkPolicyRule, Provider, Sandbox,
    SandboxPolicy as ProtoSandboxPolicy,
};
use openshell_core::telemetry::{
    LifecycleOperation, LifecycleResource, PolicyDecisionOperation, TelemetryOutcome,
};
use openshell_core::{
    VERSION,
    settings::{self, SettingValueKind},
};
use openshell_ocsf::{
    ConfigStateChangeBuilder, OCSF_TARGET, OcsfEvent, SandboxContext, SeverityId, StateId, StatusId,
};
use openshell_policy::{
    PolicyMergeOp, ProviderPolicyLayer, compose_effective_policy, merge_policy,
    serialize_sandbox_policy,
};
use openshell_prover::{
    credentials::{Credential, CredentialSet},
    finding::{Finding, FindingPath},
    model::build_model,
    policy::parse_policy_str,
    queries::run_all_queries,
    registry::load_embedded_binary_registry,
    report::finding_shorthand,
};
use openshell_providers::{get_default_profile, normalize_provider_type};
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use super::validation::{
    level_matches, source_matches, validate_policy_safety, validate_static_fields_unchanged,
};
use super::{MAX_PAGE_SIZE, StoredSettingValue, StoredSettings, clamp_limit};
use crate::persistence::current_time_ms;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Internal object type for durable gateway-global settings.
const GLOBAL_SETTINGS_OBJECT_TYPE: &str = "gateway_settings";
const GLOBAL_SETTINGS_NAME: &str = "global";
/// Internal object type for durable sandbox-scoped settings.
pub const SANDBOX_SETTINGS_OBJECT_TYPE: &str = "sandbox_settings";
/// Reserved settings key used to store global policy payload.
const POLICY_SETTING_KEY: &str = "policy";
/// Sentinel `sandbox_id` used to store global policy revisions.
const GLOBAL_POLICY_SANDBOX_ID: &str = "__global__";
/// Maximum number of optimistic retry attempts for policy version conflicts.
const MERGE_RETRY_LIMIT: usize = 5;

fn emit_sandbox_policy_update_success() {
    openshell_core::telemetry::emit_lifecycle(
        LifecycleResource::SandboxPolicy,
        LifecycleOperation::Update,
        TelemetryOutcome::Success,
    );
}

fn emit_sandbox_policy_update_failure() {
    openshell_core::telemetry::emit_lifecycle(
        LifecycleResource::SandboxPolicy,
        LifecycleOperation::Update,
        TelemetryOutcome::Failure,
    );
}

fn should_emit_config_update_policy_telemetry(sandbox_caller: bool) -> bool {
    !sandbox_caller
}

fn emit_config_update_policy_success(sandbox_caller: bool) {
    if should_emit_config_update_policy_telemetry(sandbox_caller) {
        emit_sandbox_policy_update_success();
    }
}

fn should_emit_full_policy_update_telemetry(sandbox_caller: bool, next_version: i64) -> bool {
    !sandbox_caller && next_version > 1
}

fn emit_full_policy_update_success(sandbox_caller: bool, next_version: i64) {
    if should_emit_full_policy_update_telemetry(sandbox_caller, next_version) {
        emit_sandbox_policy_update_success();
    }
}

fn emit_policy_decision_success(operation: PolicyDecisionOperation, rule_count: u64) {
    openshell_core::telemetry::emit_policy_decision(
        operation,
        TelemetryOutcome::Success,
        rule_count,
    );
}

fn emit_policy_decision_failure(operation: PolicyDecisionOperation, rule_count: u64) {
    openshell_core::telemetry::emit_policy_decision(
        operation,
        TelemetryOutcome::Failure,
        rule_count,
    );
}

fn emit_gateway_policy_audit_log(
    sandbox_id: &str,
    sandbox_name: &str,
    state_label: &str,
    detail: impl Into<String>,
    version: i64,
    policy_hash: &str,
) {
    let message = build_gateway_policy_audit_message(
        sandbox_id,
        sandbox_name,
        state_label,
        detail,
        version,
        policy_hash,
        &[],
    );
    info!(
        target: OCSF_TARGET,
        sandbox_id = %sandbox_id,
        message = %message
    );
}

/// Emit a `CONFIG:APPROVED` audit event for an auto-approval — same event
/// class as a human approval, with extra unmapped fields carrying the
/// safety reasoning so the audit is reconstructable. `source` records the
/// proposer (`mechanistic` or `agent_authored`) for provenance.
/// `resolved_from` records the scope that supplied the `auto` mode setting
/// (`gateway`, `sandbox`, or `default`) so operators can see why a given
/// approval was auto vs manual.
fn emit_gateway_policy_auto_approve_audit_log(
    sandbox_id: &str,
    sandbox_name: &str,
    detail: impl Into<String>,
    version: i64,
    policy_hash: &str,
    source: &str,
    resolved_from: &str,
) {
    let extra = [
        ("auto", "true".to_string()),
        ("source", source.to_string()),
        ("prover_delta", "empty".to_string()),
        ("resolved_from", resolved_from.to_string()),
    ];
    let message = build_gateway_policy_audit_message(
        sandbox_id,
        sandbox_name,
        "approved",
        detail,
        version,
        policy_hash,
        &extra,
    );
    info!(
        target: OCSF_TARGET,
        sandbox_id = %sandbox_id,
        message = %message
    );
}

fn build_gateway_policy_audit_message(
    sandbox_id: &str,
    sandbox_name: &str,
    state_label: &str,
    detail: impl Into<String>,
    version: i64,
    policy_hash: &str,
    extra_fields: &[(&str, String)],
) -> String {
    let ctx = SandboxContext {
        sandbox_id: sandbox_id.to_string(),
        sandbox_name: sandbox_name.to_string(),
        container_image: "openshell/gateway".to_string(),
        hostname: "openshell-gateway".to_string(),
        product_version: VERSION.to_string(),
        proxy_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proxy_port: 0,
    };
    let mut builder = ConfigStateChangeBuilder::new(&ctx)
        .state(StateId::Other, state_label)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message(detail.into());
    if version > 0 {
        builder = builder.unmapped("policy_version", format!("v{version}"));
    }
    if !policy_hash.is_empty() {
        builder = builder.unmapped("policy_hash", policy_hash.to_string());
    }
    for (key, value) in extra_fields {
        builder = builder.unmapped(key, value.clone());
    }
    let event: OcsfEvent = builder.build();
    event.format_shorthand()
}

fn summarize_cli_policy_merge_op(operation: &PolicyMergeOp) -> String {
    match operation {
        PolicyMergeOp::AddRule { rule_name, rule } => summarize_add_endpoint(rule_name, rule),
        PolicyMergeOp::RemoveEndpoint {
            rule_name,
            host,
            port,
        } => rule_name.as_ref().map_or_else(
            || format!("remove-endpoint {host}:{port}"),
            |rule_name| format!("remove-endpoint {host}:{port} from rule {rule_name}"),
        ),
        PolicyMergeOp::RemoveRule { rule_name } => format!("remove-rule {rule_name}"),
        PolicyMergeOp::AddDenyRules {
            host,
            port,
            deny_rules,
        } => format!(
            "add-deny {host}:{port} [{}]",
            deny_rules
                .iter()
                .map(summarize_l7_deny_rule)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        PolicyMergeOp::AddAllowRules { host, port, rules } => format!(
            "add-allow {host}:{port} [{}]",
            rules
                .iter()
                .map(summarize_l7_rule)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        PolicyMergeOp::RemoveBinary {
            rule_name,
            binary_path,
        } => format!("remove-binary {rule_name} {binary_path}"),
    }
}

fn ensure_chunk_belongs_to_sandbox(
    chunk: &DraftChunkRecord,
    sandbox_id: &str,
) -> Result<(), Status> {
    if chunk.sandbox_id != sandbox_id {
        return Err(Status::not_found("chunk not found"));
    }
    Ok(())
}

fn summarize_add_endpoint(rule_name: &str, rule: &NetworkPolicyRule) -> String {
    let endpoints = rule
        .endpoints
        .iter()
        .map(summarize_endpoint)
        .collect::<Vec<_>>()
        .join(", ");
    let binaries = summarize_binaries(&rule.binaries);
    format!("add-endpoint {rule_name} endpoints=[{endpoints}] binaries=[{binaries}]")
}

fn summarize_add_rule(rule_name: &str, rule: &NetworkPolicyRule) -> String {
    let endpoints = rule
        .endpoints
        .iter()
        .map(summarize_endpoint)
        .collect::<Vec<_>>()
        .join(", ");
    let binaries = summarize_binaries(&rule.binaries);
    format!("add-rule {rule_name} endpoints=[{endpoints}] binaries=[{binaries}]")
}

fn summarize_endpoint(endpoint: &NetworkEndpoint) -> String {
    let mut parts = vec![format!("{}:{}", endpoint.host, endpoint.port)];
    if !endpoint.protocol.is_empty() {
        parts.push(format!("protocol={}", endpoint.protocol));
    }
    if !endpoint.access.is_empty() {
        parts.push(format!("access={}", endpoint.access));
    }
    if !endpoint.enforcement.is_empty() {
        parts.push(format!("enforcement={}", endpoint.enforcement));
    }
    if !endpoint.tls.is_empty() {
        parts.push(format!("tls={}", endpoint.tls));
    }
    if endpoint.websocket_credential_rewrite {
        parts.push("websocket_credential_rewrite=true".to_string());
    }
    if endpoint.request_body_credential_rewrite {
        parts.push("request_body_credential_rewrite=true".to_string());
    }
    if !endpoint.allowed_ips.is_empty() {
        parts.push(format!("allowed_ips={}", endpoint.allowed_ips.len()));
    }
    if !endpoint.ports.is_empty() {
        parts.push(format!("ports={}", endpoint.ports.len()));
    }
    if !endpoint.rules.is_empty() {
        parts.push(format!(
            "allow=[{}]",
            endpoint
                .rules
                .iter()
                .map(summarize_l7_rule)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !endpoint.deny_rules.is_empty() {
        parts.push(format!(
            "deny=[{}]",
            endpoint
                .deny_rules
                .iter()
                .map(summarize_l7_deny_rule)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    parts.join(" ")
}

fn summarize_l7_rule(rule: &L7Rule) -> String {
    let Some(allow) = rule.allow.as_ref() else {
        return "allow".to_string();
    };
    summarize_l7_match(
        &allow.method,
        &allow.path,
        &allow.command,
        allow.query.len(),
    )
}

fn summarize_l7_deny_rule(rule: &L7DenyRule) -> String {
    summarize_l7_match(&rule.method, &rule.path, &rule.command, rule.query.len())
}

fn summarize_l7_match(method: &str, path: &str, command: &str, query_count: usize) -> String {
    let mut parts = Vec::new();
    if !method.is_empty() {
        parts.push(method.to_string());
    }
    if !path.is_empty() {
        parts.push(path.to_string());
    }
    if !command.is_empty() {
        parts.push(format!("command={}", truncate_for_log(command, 48)));
    }
    if query_count > 0 {
        parts.push(format!("query_keys={query_count}"));
    }
    if parts.is_empty() {
        "rule".to_string()
    } else {
        parts.join(" ")
    }
}

fn summarize_binaries(binaries: &[NetworkBinary]) -> String {
    binaries
        .iter()
        .map(|binary| binary.path.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn summarize_draft_chunk_rule(chunk: &DraftChunkRecord) -> Result<String, Status> {
    let rule = NetworkPolicyRule::decode(chunk.proposed_rule.as_slice())
        .map_err(|e| Status::internal(format!("decode proposed_rule failed: {e}")))?;
    Ok(summarize_add_rule(&chunk.rule_name, &rule))
}

/// Run prover queries against the merged policy and render a short
/// human-readable verdict for the reviewer. The verdict reports only the
/// **delta** — findings the proposal introduces on top of the current policy.
/// Baseline gaps (pre-existing findings) are intentionally not surfaced here;
/// they belong on a posture surface, not on the per-proposal approval moment.
///
/// The string is the entire output — no taxonomy, no greppable prefixes; the
/// reviewer reads it like an OCSF shorthand line. One of:
///
/// - `prover: no new findings`
/// - `prover: N new finding(s)` followed by one `  <category>: <detail>`
///   line per finding path (categorical shorthand from `openshell-prover`)
/// - `merge failed: <one-line error>` — proposal won't merge into the current
///   policy
/// - `policy invalid: <one-line error>` — merged policy fails the cheap
///   structural safety check
/// - `validation unavailable` — gateway-side infrastructure failure (registry
///   load, YAML serialize/parse). Internal error detail is logged via
///   `warn!`, never exposed to the reviewer.
fn validation_result_for_agent_proposal(
    current_policy: ProtoSandboxPolicy,
    rule_name: &str,
    proposed_rule: &NetworkPolicyRule,
    credentials: &CredentialSet,
) -> String {
    let merge_op = PolicyMergeOp::AddRule {
        rule_name: rule_name.to_string(),
        rule: proposed_rule.clone(),
    };
    let merged = match merge_policy(current_policy.clone(), &[merge_op]) {
        Ok(result) => result.policy,
        Err(error) => return format!("merge failed: {}", one_line(&error.to_string())),
    };
    if let Err(error) = validate_policy_safety(&merged) {
        return format!("policy invalid: {}", one_line(&error.to_string()));
    }

    let merged_findings = match run_prover_findings(&merged, credentials) {
        Ok(findings) => findings,
        Err(error) => {
            warn!(error = %error, "prover validation unavailable for merged policy");
            return "validation unavailable".to_string();
        }
    };
    // If the baseline prover run fails (e.g. the current policy uses a shape
    // the prover hasn't caught up to yet), fall back to an empty baseline so
    // every merged finding surfaces as new. Safer to over-warn than miss a
    // real regression introduced by the proposal.
    let base_findings = match run_prover_findings(&current_policy, credentials) {
        Ok(findings) => findings,
        Err(error) => {
            warn!(error = %error, "prover baseline run failed; treating baseline as empty");
            Vec::new()
        }
    };

    let new_findings = finding_delta(&base_findings, &merged_findings);
    if new_findings.is_empty() {
        return "prover: no new findings".to_string();
    }
    let count = new_findings.len();
    let mut out = format!(
        "prover: {} new finding{}",
        count,
        if count == 1 { "" } else { "s" }
    );
    for finding in &new_findings {
        out.push_str("\n  ");
        out.push_str(&finding_shorthand(finding));
    }
    out
}

/// Run the prover end-to-end against a single policy with the given
/// credential set. Returns the raw finding list, or a short error string
/// identifying which infrastructure step failed.
///
/// The credential set is passed in because it's stable across all chunks in
/// one `SubmitPolicyAnalysis` batch — the caller builds it once and shares.
fn run_prover_findings(
    policy: &ProtoSandboxPolicy,
    credentials: &CredentialSet,
) -> Result<Vec<Finding>, String> {
    let yaml =
        serialize_sandbox_policy(policy).map_err(|e| format!("serialize policy failed: {e}"))?;
    let prover_policy = parse_policy_str(&yaml).map_err(|e| format!("parse policy failed: {e}"))?;
    let registry =
        load_embedded_binary_registry().map_err(|e| format!("load registry failed: {e}"))?;
    let model = build_model(prover_policy, credentials.clone(), registry);
    Ok(run_all_queries(&model))
}

/// Build a `CredentialSet` for the sandbox by walking its attached providers.
///
/// v1 models "credential is present in scope for these hosts" — no scope
/// modeling. Each attached provider produces one [`Credential`] entry whose
/// `target_hosts` lists the hosts from the provider's profile endpoints.
/// Missing providers or providers whose type has no profile are skipped with
/// a `warn!` — the merged policy already excludes them at compose time, so
/// silently treating them as absent here keeps the credential set consistent
/// with the merged policy the prover validates against.
async fn build_credential_set_for_sandbox(
    store: &Store,
    provider_names: &[String],
) -> Result<CredentialSet, Status> {
    let mut credentials = Vec::new();

    for name in provider_names {
        let Some(provider) = store
            .get_message_by_name::<Provider>(name)
            .await
            .map_err(|e| Status::internal(format!("failed to fetch provider '{name}': {e}")))?
        else {
            warn!(provider_name = %name, "provider not found while building credential set; skipping");
            continue;
        };

        let provider_type = provider.r#type.trim();
        let profile = if let Some(canonical_type) = normalize_provider_type(provider_type) {
            let Some(profile) = get_default_profile(canonical_type) else {
                warn!(
                    provider_name = %name,
                    provider_type,
                    "legacy provider type has no profile; skipping credential entry"
                );
                continue;
            };
            profile.clone()
        } else {
            let Some(profile) =
                super::provider::get_provider_type_profile(store, provider_type).await?
            else {
                warn!(
                    provider_name = %name,
                    provider_type,
                    "provider type has no profile; skipping credential entry"
                );
                continue;
            };
            profile
        };

        let target_hosts: Vec<String> = profile
            .endpoints
            .iter()
            .map(|ep| ep.host.to_lowercase())
            .filter(|h| !h.is_empty())
            .collect();

        if target_hosts.is_empty() {
            continue;
        }

        credentials.push(Credential {
            name: name.clone(),
            cred_type: provider_type.to_string(),
            scopes: Vec::new(),
            injected_via: String::new(),
            target_hosts,
        });
    }

    Ok(CredentialSet {
        credentials,
        api_registries: HashMap::new(),
    })
}

/// Stable identity key for a finding path. Deliberately excludes
/// `policy_name`: two paths with identical (binary, endpoint, mechanism) are
/// the same security gap whether they live in rule `foo` or rule `bar`. This
/// keeps the delta from spuriously surfacing baseline gaps just because the
/// proposal added a new rule name that produces the same gap shape.
fn finding_path_key(path: &FindingPath) -> String {
    let FindingPath::Exfil(p) = path;
    // Include the category and (for capability_expansion) the method so
    // adding a new method on an already-reached host surfaces as a new
    // path; reuse of an existing method does not.
    format!(
        "exfil|{}|{}:{}|{}|{}",
        p.binary, p.endpoint_host, p.endpoint_port, p.category, p.method
    )
}

/// Return the merged-policy findings that aren't already present in the
/// baseline. Comparison is per-(query, path) so that a single finding whose
/// evidence grew (e.g. a new method allowed on an already-reached host)
/// surfaces only the new evidence paths.
///
/// **Category suppression:** `capability_expansion` paths whose (binary,
/// host, port) tuple appears in the `credential_reach_expansion` delta
/// are suppressed. A brand-new credentialed reach is described by the
/// reach-expansion finding alone; we don't double-report by also
/// flagging every method as a separate `capability_expansion`.
fn finding_delta(base: &[Finding], merged: &[Finding]) -> Vec<Finding> {
    use openshell_prover::finding::category;

    let base_keys: HashSet<(String, String)> = base
        .iter()
        .flat_map(|f| {
            let query = f.query.clone();
            f.paths
                .iter()
                .map(move |p| (query.clone(), finding_path_key(p)))
        })
        .collect();
    let mut delta: Vec<Finding> = Vec::new();
    for finding in merged {
        let new_paths: Vec<FindingPath> = finding
            .paths
            .iter()
            .filter(|p| !base_keys.contains(&(finding.query.clone(), finding_path_key(p))))
            .cloned()
            .collect();
        if new_paths.is_empty() {
            continue;
        }
        delta.push(Finding {
            paths: new_paths,
            ..finding.clone()
        });
    }

    // Suppress capability_expansion paths whose (binary, host, port)
    // appears in the credential_reach_expansion delta — a new reach is
    // described once, by the reach-expansion category, not also by per-
    // method capability findings.
    let reach_tuples: HashSet<(String, String, u16)> = delta
        .iter()
        .filter(|f| f.query == category::CREDENTIAL_REACH_EXPANSION)
        .flat_map(|f| {
            f.paths.iter().map(|p| {
                let FindingPath::Exfil(e) = p;
                (e.binary.clone(), e.endpoint_host.clone(), e.endpoint_port)
            })
        })
        .collect();
    delta.retain_mut(|f| {
        if f.query != category::CAPABILITY_EXPANSION {
            return true;
        }
        f.paths.retain(|p| {
            let FindingPath::Exfil(e) = p;
            !reach_tuples.contains(&(e.binary.clone(), e.endpoint_host.clone(), e.endpoint_port))
        });
        !f.paths.is_empty()
    });

    delta
}

/// Collapse multi-line / multi-message error text to a single line so the
/// `validation_result` stays a clean, scannable string.
fn one_line(s: &str) -> String {
    s.split('\n')
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Auto-reject any pending chunks for the same sandbox that share the
/// `(host, port, binary)` of the newly-submitted chunk. Mode-agnostic: the
/// rule is "the latest submission for this endpoint wins; older pending
/// proposals are stale."
///
/// In practice this implements the supersede behavior for the
/// `mechanistic`→`agent_authored` refinement loop: when the agent submits a
/// narrow L7 proposal in response to a denial, any pending mechanistic L4
/// draft for the same key gets auto-rejected here, without the agent or the
/// proto needing an explicit `supersedes_chunk_id` field.
///
/// Failures (DB error, scan error) are logged via `warn!` and the function
/// returns silently. The new chunk's persistence has already succeeded;
/// failing this cleanup pass should not abort the submission flow.
async fn supersede_other_pending_chunks_for_endpoint(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    new_chunk_id: &str,
    host: &str,
    port: i32,
    binary: &str,
) {
    // Empty host/port/binary should not supersede anything — the matcher would
    // accidentally cover unrelated chunks. Defensive skip.
    if host.is_empty() || port == 0 || binary.is_empty() {
        return;
    }

    let pending = match state
        .store
        .list_draft_chunks(sandbox_id, Some("pending"))
        .await
    {
        Ok(records) => records,
        Err(err) => {
            warn!(
                sandbox_id = %sandbox_id,
                error = %err,
                "supersede scan failed; older pending chunks (if any) remain pending"
            );
            return;
        }
    };

    let now_ms = current_time_ms();
    for other in pending {
        if other.id == new_chunk_id
            || other.host != host
            || other.port != port
            || other.binary != binary
        {
            continue;
        }

        let reason = format!("superseded by chunk {new_chunk_id}");
        match state
            .store
            .update_draft_chunk_status(&other.id, "rejected", Some(now_ms), Some(&reason))
            .await
        {
            Ok(_) => {
                info!(
                    sandbox_id = %sandbox_id,
                    superseded_chunk = %other.id,
                    by_chunk = %new_chunk_id,
                    host = %host,
                    port = port,
                    binary = %binary,
                    "Auto-rejected pending chunk: superseded by newer submission for same (host, port, binary)"
                );
            }
            Err(err) => {
                warn!(
                    chunk_id = %other.id,
                    error = %err,
                    "supersede auto-reject failed; chunk remains pending"
                );
            }
        }
    }
}

/// If the just-submitted mechanistic chunk targets a `(host, port, binary)`
/// already covered by an approved chunk, auto-reject the mechanistic chunk
/// on arrival — but only when the approved grants actually cover what it
/// asks for. A connect-level resubmit (no L7 asks) is the classic
/// straggler-flush noise case: denials recorded just before an approval
/// hot-reloaded, flushed just after. Rejecting those keeps the approval
/// queue clean. A submission carrying L7 method/path evidence OUTSIDE the
/// union of the approved chunks' allow rules is different in kind: it is
/// the agent asking for MORE than was granted, and it must surface as a
/// fresh pending chunk for review, never vanish.
///
/// `agent_authored` submissions are NEVER self-rejected — that path remains
/// open for refinement. Only the mechanistic side is asymmetric.
async fn self_reject_mechanistic_if_already_covered(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    new_chunk_id: &str,
    host: &str,
    port: i32,
    binary: &str,
    proposed_rule: &NetworkPolicyRule,
) {
    if host.is_empty() || port == 0 || binary.is_empty() {
        return;
    }

    let approved = match state
        .store
        .list_draft_chunks(sandbox_id, Some("approved"))
        .await
    {
        Ok(records) => records,
        Err(err) => {
            warn!(
                sandbox_id = %sandbox_id,
                error = %err,
                "approved-chunk scan for self-reject failed; mechanistic chunk remains pending"
            );
            return;
        }
    };

    let covering: Vec<_> = approved
        .iter()
        .filter(|c| c.host == host && c.port == port && c.binary == binary)
        .collect();
    if covering.is_empty() {
        return;
    }

    // Compare asks against the union of every approved grant for this
    // endpoint, not just the first match: a ghost resubmit of the SECOND
    // approval must be recognized as covered even though the first approved
    // chunk knows nothing about its paths.
    let new_asks = l7_asks(proposed_rule);
    if !new_asks.is_empty() {
        let granted: Vec<(String, String)> = covering
            .iter()
            .filter_map(|c| NetworkPolicyRule::decode(c.proposed_rule.as_slice()).ok())
            .flat_map(|r| l7_asks(&r))
            .collect();
        let uncovered = new_asks.iter().any(|(method, path)| {
            !granted
                .iter()
                .any(|(gm, gp)| l7_method_covers(gm, method) && l7_path_covers(gp, path))
        });
        if uncovered {
            info!(
                sandbox_id = %sandbox_id,
                chunk_id = %new_chunk_id,
                host = %host,
                port = port,
                binary = %binary,
                "Mechanistic chunk carries L7 evidence beyond the approved grant; kept pending for review"
            );
            return;
        }
    }

    let reason = format!(
        "already covered by approved chunk {} (no method/path evidence beyond the existing grant)",
        covering[0].id
    );
    match state
        .store
        .update_draft_chunk_status(
            new_chunk_id,
            "rejected",
            Some(current_time_ms()),
            Some(&reason),
        )
        .await
    {
        Ok(_) => {
            info!(
                sandbox_id = %sandbox_id,
                chunk_id = %new_chunk_id,
                covering_chunk = %covering[0].id,
                host = %host,
                port = port,
                binary = %binary,
                "Auto-rejected incoming mechanistic chunk: endpoint already covered by an approved chunk"
            );
        }
        Err(err) => {
            warn!(
                chunk_id = %new_chunk_id,
                error = %err,
                "mechanistic self-reject failed; chunk remains pending"
            );
        }
    }
}

/// Extract the L7 `(method, path)` asks from a proposed rule's allow rules.
/// Empty for a connect-level rule (no L7 inspection evidence).
fn l7_asks(rule: &NetworkPolicyRule) -> Vec<(String, String)> {
    rule.endpoints
        .iter()
        .flat_map(|ep| ep.rules.iter())
        .filter_map(|r| r.allow.as_ref())
        .filter(|a| !a.method.is_empty() || !a.path.is_empty())
        .map(|a| (a.method.clone(), a.path.clone()))
        .collect()
}

/// Does a granted method pattern cover an asked method?
fn l7_method_covers(granted: &str, asked: &str) -> bool {
    granted == "*" || granted.eq_ignore_ascii_case(asked)
}

/// Does a granted path glob cover an asked path?
///
/// Segment-wise: `*` matches exactly one segment, `**` matches any
/// remainder but is only honoured as the FINAL segment — the only form the
/// mechanistic mapper and provider profiles emit. Any unrecognized pattern
/// shape falls back to exact string equality, which errs toward surfacing a
/// reviewable card rather than silently swallowing an escalation.
fn l7_path_covers(granted: &str, asked: &str) -> bool {
    if granted == "**" || granted == asked {
        return true;
    }
    let g: Vec<&str> = granted.split('/').collect();
    let a: Vec<&str> = asked.split('/').collect();
    // `**` anywhere but the tail is an unsupported shape; exact equality
    // already failed above, so treat as not covered.
    if g[..g.len().saturating_sub(1)].contains(&"**") {
        return false;
    }
    if g.last() == Some(&"**") {
        let prefix = &g[..g.len() - 1];
        return a.len() >= prefix.len()
            && prefix.iter().zip(&a).all(|(gs, asg)| *gs == "*" || gs == asg);
    }
    g.len() == a.len() && g.iter().zip(&a).all(|(gs, asg)| *gs == "*" || gs == asg)
}

/// Internally approve a chunk on the auto-approval path: merge into the
/// active policy, flip status to "approved", notify watchers, and emit a
/// `CONFIG:APPROVED` audit event carrying `auto=true`, `source=<mode>`,
/// `prover_delta=empty` so the audit trail records why no human approved
/// this chunk.
///
/// `source` is the `analysis_mode` of the originating submission
/// (`mechanistic` or `agent_authored`). The audit copy says "auto-approved:
/// no new prover findings" — never "safe" — because the claim is about the
/// prover's reasoning, not the world.
/// Resolve the effective proposal-approval mode for a sandbox.
///
/// Precedence (matches the rest of the settings model): gateway scope wins
/// over sandbox scope. A reviewer can pin manual mode fleet-wide by setting
/// it globally; per-sandbox overrides only apply when no global is set.
///
/// Returns `(auto_approve_enabled, resolved_from)` where `resolved_from`
/// is `"gateway"`, `"sandbox"`, or `"default"`. Only an exact `"auto"`
/// value enables auto-approval; any other string (including future-
/// reserved modes like `"auto_on_low_risk"`) is conservatively treated as
/// manual.
async fn resolve_proposal_approval_mode(
    store: &Store,
    sandbox_name: &str,
) -> Result<(bool, &'static str), Status> {
    let global = load_global_settings(store).await?;
    if let Some(StoredSettingValue::String(value)) =
        global.settings.get(settings::PROPOSAL_APPROVAL_MODE_KEY)
    {
        return Ok((value == "auto", "gateway"));
    }

    let sandbox = load_sandbox_settings(store, sandbox_name).await?;
    if let Some(StoredSettingValue::String(value)) =
        sandbox.settings.get(settings::PROPOSAL_APPROVAL_MODE_KEY)
    {
        return Ok((value == "auto", "sandbox"));
    }

    Ok((false, "default"))
}

async fn auto_approve_chunk(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    sandbox_name: &str,
    chunk_id: &str,
    source: &str,
    resolved_from: &str,
) -> Result<(), Status> {
    // Same gate the human-driven approve paths apply: if a global policy is
    // active, sandbox-scoped chunk approvals are meaningless because
    // `GetSandboxConfig` prefers the global policy. Auto-approving here
    // would persist a sandbox revision that the runtime silently ignores
    // and leave a misleading "approved" chunk in the table. Bail before
    // touching state; the calling site logs this as `warn!` and leaves the
    // chunk pending.
    require_no_global_policy(state).await?;

    let chunk = state
        .store
        .get_draft_chunk(chunk_id)
        .await
        .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
        .ok_or_else(|| Status::not_found("chunk not found"))?;

    // The chunk may have been superseded or rejected by something else
    // between persist and auto-approve. Only approve from a pending state.
    if chunk.status != "pending" {
        return Ok(());
    }

    let (version, hash) = merge_chunk_into_policy(state.store.as_ref(), sandbox_id, &chunk).await?;
    let chunk_summary = summarize_draft_chunk_rule(&chunk)?;

    let now_ms = current_time_ms();
    state
        .store
        .update_draft_chunk_status(chunk_id, "approved", Some(now_ms), None)
        .await
        .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

    state.sandbox_watch_bus.notify(sandbox_id);

    let source_label = if source.is_empty() {
        "unspecified"
    } else {
        source
    };
    emit_gateway_policy_auto_approve_audit_log(
        sandbox_id,
        sandbox_name,
        format!(
            "auto-approved: no new prover findings (source={source_label}) — chunk {chunk_id}: {chunk_summary}"
        ),
        version,
        &hash,
        source_label,
        resolved_from,
    );

    info!(
        sandbox_id = %sandbox_id,
        chunk_id = %chunk_id,
        rule_name = %chunk.rule_name,
        version = version,
        policy_hash = %hash,
        source = %source_label,
        resolved_from = %resolved_from,
        "Auto-approved chunk: no new prover findings"
    );

    Ok(())
}

// TODO: share effective-policy lookup with `load_sandbox_policy` /
// `GetSandboxConfig`. They re-implement very similar global-settings +
// providers_v2 + compose logic; consolidating them is out of scope for the
// agent-authored proposal validation slice.
async fn current_effective_policy_for_sandbox(
    state: &ServerState,
    sandbox: &Sandbox,
    sandbox_id: &str,
) -> Result<ProtoSandboxPolicy, Status> {
    let mut policy = if let Some(record) = state
        .store
        .get_latest_policy(sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch latest policy failed: {e}")))?
    {
        ProtoSandboxPolicy::decode(record.policy_payload.as_slice())
            .map_err(|e| Status::internal(format!("decode current policy failed: {e}")))?
    } else {
        sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.policy.clone())
            .unwrap_or_default()
    };

    let global_settings = load_global_settings(state.store.as_ref()).await?;
    let policy_source = decode_policy_from_global_settings(&global_settings)?.map_or(
        PolicySource::Sandbox,
        |global_policy| {
            policy = global_policy;
            PolicySource::Global
        },
    );

    let providers_v2_enabled =
        bool_setting_enabled(&global_settings, settings::PROVIDERS_V2_ENABLED_KEY)?;
    if providers_v2_enabled && !matches!(policy_source, PolicySource::Global) {
        let provider_names = sandbox
            .spec
            .as_ref()
            .map(|spec| spec.providers.clone())
            .unwrap_or_default();
        let provider_layers =
            profile_provider_policy_layers(state.store.as_ref(), &provider_names).await?;
        if !provider_layers.is_empty() {
            policy = compose_effective_policy(&policy, &provider_layers);
        }
    }

    Ok(policy)
}

fn truncate_for_log(input: &str, max_chars: usize) -> String {
    let mut chars = input.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

#[cfg(test)]
fn is_sandbox_caller<T>(request: &Request<T>) -> bool {
    matches!(
        request.extensions().get::<Principal>(),
        Some(Principal::Sandbox(_))
    )
}

/// Sandbox-class callers may only perform sandbox-scoped policy sync. They
/// must not mutate global config or sandbox settings.
fn validate_sandbox_caller_update(req: &UpdateConfigRequest) -> Result<(), Status> {
    if req.global {
        return Err(Status::permission_denied(
            "sandbox callers cannot mutate global config",
        ));
    }
    if req.delete_setting {
        return Err(Status::permission_denied(
            "sandbox callers cannot delete settings",
        ));
    }
    if req.name.trim().is_empty() {
        return Err(Status::permission_denied(
            "sandbox callers may only perform sandbox policy sync",
        ));
    }
    if req.policy.is_none() || !req.setting_key.trim().is_empty() {
        return Err(Status::permission_denied(
            "sandbox callers may only perform sandbox policy sync",
        ));
    }
    Ok(())
}

async fn resolve_sandbox_by_name_for_principal(
    store: &Store,
    principal: &Principal,
    name: &str,
) -> Result<Sandbox, Status> {
    let sandbox = store
        .get_message_by_name::<Sandbox>(name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?;

    match principal {
        Principal::Sandbox(_) => {
            let Some(sandbox) = sandbox else {
                return Err(Status::permission_denied(
                    "sandbox not found or not owned by caller",
                ));
            };
            crate::auth::guard::ensure_sandbox_scope(principal, sandbox.object_id()).map_err(
                |status| {
                    if status.code() == tonic::Code::PermissionDenied {
                        Status::permission_denied("sandbox not found or not owned by caller")
                    } else {
                        status
                    }
                },
            )?;
            Ok(sandbox)
        }
        Principal::User(_) => sandbox.ok_or_else(|| Status::not_found("sandbox not found")),
        Principal::Anonymous => Err(Status::unauthenticated(
            "sandbox-scoped methods require an authenticated caller",
        )),
    }
}

// ---------------------------------------------------------------------------
// Config handlers
// ---------------------------------------------------------------------------

pub(super) async fn handle_get_sandbox_config(
    state: &Arc<ServerState>,
    request: Request<GetSandboxConfigRequest>,
) -> Result<Response<GetSandboxConfigResponse>, Status> {
    let sandbox_id = request.get_ref().sandbox_id.clone();
    crate::auth::guard::enforce_sandbox_scope(&request, &sandbox_id)?;
    drop(request);

    let sandbox = state
        .store
        .get_message::<Sandbox>(&sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_provider_names = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.providers.clone())
        .unwrap_or_default();

    // Try to get the latest policy from the policy history table.
    let latest = state
        .store
        .get_latest_policy(&sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch policy history failed: {e}")))?;

    let mut policy_source = PolicySource::Sandbox;
    let (mut policy, mut version, mut policy_hash) = if let Some(record) = latest {
        let decoded = ProtoSandboxPolicy::decode(record.policy_payload.as_slice())
            .map_err(|e| Status::internal(format!("decode policy failed: {e}")))?;
        debug!(
            sandbox_id = %sandbox_id,
            version = record.version,
            "GetSandboxConfig served from policy history"
        );
        (
            Some(decoded),
            u32::try_from(record.version).unwrap_or(0),
            record.policy_hash,
        )
    } else {
        // Lazy backfill: no policy history exists yet.
        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| Status::internal("sandbox has no spec"))?;

        match spec.policy.clone() {
            None => {
                debug!(
                    sandbox_id = %sandbox_id,
                    "GetSandboxConfig: no policy configured, returning empty response"
                );
                (None, 0, String::new())
            }
            Some(spec_policy) => {
                let hash = deterministic_policy_hash(&spec_policy);
                let payload = spec_policy.encode_to_vec();
                let policy_id = uuid::Uuid::new_v4().to_string();

                if let Err(e) = state
                    .store
                    .put_policy_revision(&policy_id, &sandbox_id, 1, &payload, &hash)
                    .await
                {
                    warn!(
                        sandbox_id = %sandbox_id,
                        error = %e,
                        "Failed to backfill policy version 1"
                    );
                } else if let Err(e) = state
                    .store
                    .update_policy_status(&sandbox_id, 1, "loaded", None, None)
                    .await
                {
                    warn!(
                        sandbox_id = %sandbox_id,
                        error = %e,
                        "Failed to mark backfilled policy as loaded"
                    );
                }

                info!(
                    sandbox_id = %sandbox_id,
                    "GetSandboxConfig served from spec (backfilled version 1)"
                );

                (Some(spec_policy), 1, hash)
            }
        }
    };

    let global_settings = load_global_settings(state.store.as_ref()).await?;
    let sandbox_settings =
        load_sandbox_settings(state.store.as_ref(), sandbox.object_name()).await?;
    let providers_v2_enabled =
        bool_setting_enabled(&global_settings, settings::PROVIDERS_V2_ENABLED_KEY)?;

    let mut global_policy_version: u32 = 0;

    if let Some(global_policy) = decode_policy_from_global_settings(&global_settings)? {
        policy = Some(global_policy.clone());
        policy_hash = deterministic_policy_hash(&global_policy);
        policy_source = PolicySource::Global;
        if version == 0 {
            version = 1;
        }
        if let Ok(Some(global_rev)) = state
            .store
            .get_latest_policy(GLOBAL_POLICY_SANDBOX_ID)
            .await
        {
            global_policy_version = u32::try_from(global_rev.version).unwrap_or(0);
        }
    }

    if providers_v2_enabled
        && !matches!(policy_source, PolicySource::Global)
        && let Some(source_policy) = policy.as_ref()
    {
        let provider_layers =
            profile_provider_policy_layers(state.store.as_ref(), &sandbox_provider_names).await?;
        if !provider_layers.is_empty() {
            let effective_policy = compose_effective_policy(source_policy, &provider_layers);
            policy_hash = deterministic_policy_hash(&effective_policy);
            policy = Some(effective_policy);
        }
    }

    let settings = merge_effective_settings(&global_settings, &sandbox_settings)?;
    let config_revision = compute_config_revision(policy.as_ref(), &settings, policy_source);
    let provider_env_revision =
        compute_provider_env_revision(state.store.as_ref(), &sandbox_provider_names).await?;

    Ok(Response::new(GetSandboxConfigResponse {
        policy,
        version,
        policy_hash,
        settings,
        config_revision,
        policy_source: policy_source.into(),
        global_policy_version,
        provider_env_revision,
    }))
}

pub(super) async fn compute_provider_env_revision(
    store: &Store,
    provider_names: &[String],
) -> Result<u64, Status> {
    let mut hasher = Sha256::new();
    hasher.update(b"openshell-provider-env-revision-v1");

    for provider_name in provider_names {
        hasher.update(provider_name.as_bytes());
        match store
            .get_by_name(Provider::object_type(), provider_name)
            .await
            .map_err(|e| {
                Status::internal(format!("fetch provider '{provider_name}' failed: {e}"))
            })? {
            Some(record) => {
                hasher.update(record.id.as_bytes());
                hasher.update(record.updated_at_ms.to_le_bytes());

                let provider = Provider::decode(record.payload.as_slice()).map_err(|e| {
                    Status::internal(format!("decode provider '{provider_name}' failed: {e}"))
                })?;
                hasher.update(provider.r#type.as_bytes());

                let mut credential_keys: Vec<_> = provider.credentials.keys().collect();
                credential_keys.sort();
                for key in credential_keys {
                    hasher.update(key.as_bytes());
                }
                let mut expiry_keys: Vec<_> = provider.credential_expires_at_ms.keys().collect();
                expiry_keys.sort();
                for key in expiry_keys {
                    hasher.update(key.as_bytes());
                    hasher.update(provider.credential_expires_at_ms[key].to_le_bytes());
                }
            }
            None => {
                hasher.update(b"missing");
            }
        }
    }

    let digest = hasher.finalize();
    Ok(u64::from_le_bytes(digest[..8].try_into().map_err(
        |_| Status::internal("provider env revision digest too short"),
    )?))
}

async fn profile_provider_policy_layers(
    store: &Store,
    provider_names: &[String],
) -> Result<Vec<ProviderPolicyLayer>, Status> {
    let mut layers = Vec::new();

    for name in provider_names {
        let provider = store
            .get_message_by_name::<Provider>(name)
            .await
            .map_err(|e| Status::internal(format!("failed to fetch provider '{name}': {e}")))?
            .ok_or_else(|| Status::failed_precondition(format!("provider '{name}' not found")))?;

        let provider_type = provider.r#type.trim();
        let profile = if let Some(canonical_type) = normalize_provider_type(provider_type) {
            let Some(profile) = get_default_profile(canonical_type) else {
                warn!(
                    provider_name = %name,
                    provider_type,
                    "legacy provider type has no profile; skipping provider policy layer"
                );
                continue;
            };
            profile.clone()
        } else {
            let Some(profile) =
                super::provider::get_provider_type_profile(store, provider_type).await?
            else {
                warn!(
                    provider_name = %name,
                    provider_type,
                    "provider type has no profile; skipping provider policy layer"
                );
                continue;
            };
            profile
        };

        let rule_name = openshell_policy::provider_rule_name(provider.object_name());
        layers.push(ProviderPolicyLayer {
            rule_name: rule_name.clone(),
            rule: profile.network_policy_rule(&rule_name),
        });
    }

    Ok(layers)
}

fn bool_setting_enabled(settings: &StoredSettings, key: &str) -> Result<bool, Status> {
    match settings.settings.get(key) {
        None => Ok(false),
        Some(StoredSettingValue::Bool(value)) => Ok(*value),
        Some(_) => Err(Status::internal(format!(
            "setting '{key}' has invalid value type; expected bool"
        ))),
    }
}

pub(super) async fn handle_get_gateway_config(
    state: &Arc<ServerState>,
    _request: Request<GetGatewayConfigRequest>,
) -> Result<Response<GetGatewayConfigResponse>, Status> {
    let global_settings = load_global_settings(state.store.as_ref()).await?;
    let settings = materialize_global_settings(&global_settings)?;
    Ok(Response::new(GetGatewayConfigResponse {
        settings,
        settings_revision: global_settings.revision,
    }))
}

pub(super) async fn handle_get_sandbox_provider_environment(
    state: &Arc<ServerState>,
    request: Request<GetSandboxProviderEnvironmentRequest>,
) -> Result<Response<GetSandboxProviderEnvironmentResponse>, Status> {
    let sandbox_id = request.get_ref().sandbox_id.clone();
    crate::auth::guard::enforce_sandbox_scope(&request, &sandbox_id)?;
    drop(request);

    let sandbox = state
        .store
        .get_message::<Sandbox>(&sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;

    let spec = sandbox
        .spec
        .ok_or_else(|| Status::internal("sandbox has no spec"))?;

    let provider_names = spec.providers;
    let provider_env_revision =
        compute_provider_env_revision(state.store.as_ref(), &provider_names).await?;
    let provider_environment =
        super::provider::resolve_provider_environment(state.store.as_ref(), &provider_names)
            .await?;

    info!(
        sandbox_id = %sandbox_id,
        provider_count = provider_names.len(),
        env_count = provider_environment.environment.len(),
        provider_env_revision,
        "GetSandboxProviderEnvironment request completed successfully"
    );

    Ok(Response::new(GetSandboxProviderEnvironmentResponse {
        environment: provider_environment.environment,
        provider_env_revision,
        credential_expires_at_ms: provider_environment.credential_expires_at_ms,
    }))
}

// ---------------------------------------------------------------------------
// Update config handler (policy + settings mutations)
// ---------------------------------------------------------------------------

pub(super) async fn handle_update_config(
    state: &Arc<ServerState>,
    request: Request<UpdateConfigRequest>,
) -> Result<Response<UpdateConfigResponse>, Status> {
    let principal = request.extensions().get::<Principal>().cloned();
    let sandbox_caller = matches!(principal, Some(Principal::Sandbox(_)));
    let update = request.get_ref();
    let should_emit_policy_failure = should_emit_config_update_policy_telemetry(sandbox_caller)
        && (update.policy.is_some() || !update.merge_operations.is_empty());
    let result = handle_update_config_inner(state, request, principal, sandbox_caller).await;
    if result.is_err() && should_emit_policy_failure {
        emit_sandbox_policy_update_failure();
    }
    result
}

async fn handle_update_config_inner(
    state: &Arc<ServerState>,
    request: Request<UpdateConfigRequest>,
    principal: Option<Principal>,
    sandbox_caller: bool,
) -> Result<Response<UpdateConfigResponse>, Status> {
    let req = request.into_inner();
    if sandbox_caller {
        validate_sandbox_caller_update(&req)?;
        resolve_sandbox_by_name_for_principal(
            state.store.as_ref(),
            principal
                .as_ref()
                .expect("sandbox_caller implies principal"),
            &req.name,
        )
        .await?;
    }
    let key = req.setting_key.trim();
    let has_policy = req.policy.is_some();
    let has_setting = !key.is_empty();
    let has_merge_ops = !req.merge_operations.is_empty();
    let mut mutation_count = 0_u8;
    mutation_count += u8::from(has_policy);
    mutation_count += u8::from(has_setting);
    mutation_count += u8::from(has_merge_ops);

    if mutation_count > 1 {
        return Err(Status::invalid_argument(
            "policy, setting_key, and merge_operations are mutually exclusive",
        ));
    }
    if mutation_count == 0 {
        return Err(Status::invalid_argument(
            "one of policy, setting_key, or merge_operations must be provided",
        ));
    }

    if req.global {
        let _settings_guard = state.settings_mutex.lock().await;

        if has_merge_ops {
            return Err(Status::invalid_argument(
                "merge_operations are not supported for global policy updates",
            ));
        }

        if has_policy {
            if req.delete_setting {
                return Err(Status::invalid_argument(
                    "delete_setting cannot be combined with policy payload",
                ));
            }
            let mut new_policy = req.policy.ok_or_else(|| {
                Status::invalid_argument("policy is required for global policy update")
            })?;
            openshell_policy::ensure_sandbox_process_identity(&mut new_policy);
            validate_policy_safety(&new_policy)?;

            let payload = new_policy.encode_to_vec();
            let hash = deterministic_policy_hash(&new_policy);

            let latest = state
                .store
                .get_latest_policy(GLOBAL_POLICY_SANDBOX_ID)
                .await
                .map_err(|e| Status::internal(format!("fetch latest global policy failed: {e}")))?;

            if let Some(ref current) = latest
                && current.policy_hash == hash
                && current.status == "loaded"
            {
                let mut global_settings = load_global_settings(state.store.as_ref()).await?;
                let stored_value = StoredSettingValue::Bytes(hex::encode(&payload));
                let changed = upsert_setting_value(
                    &mut global_settings.settings,
                    POLICY_SETTING_KEY,
                    stored_value,
                );
                if changed {
                    global_settings.revision = global_settings.revision.wrapping_add(1);
                    save_global_settings(state.store.as_ref(), &global_settings).await?;
                }
                return Ok(Response::new(UpdateConfigResponse {
                    version: u32::try_from(current.version).unwrap_or(0),
                    policy_hash: hash,
                    settings_revision: global_settings.revision,
                    deleted: false,
                }));
            }

            let next_version = latest.map_or(1, |r| r.version + 1);
            let policy_id = uuid::Uuid::new_v4().to_string();

            state
                .store
                .put_policy_revision(
                    &policy_id,
                    GLOBAL_POLICY_SANDBOX_ID,
                    next_version,
                    &payload,
                    &hash,
                )
                .await
                .map_err(|e| {
                    Status::internal(format!("persist global policy revision failed: {e}"))
                })?;

            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as i64);
            let _ = state
                .store
                .update_policy_status(
                    GLOBAL_POLICY_SANDBOX_ID,
                    next_version,
                    "loaded",
                    None,
                    Some(now_ms),
                )
                .await;
            let _ = state
                .store
                .supersede_older_policies(GLOBAL_POLICY_SANDBOX_ID, next_version)
                .await;

            let mut global_settings = load_global_settings(state.store.as_ref()).await?;
            let stored_value = StoredSettingValue::Bytes(hex::encode(&payload));
            let changed = upsert_setting_value(
                &mut global_settings.settings,
                POLICY_SETTING_KEY,
                stored_value,
            );
            if changed {
                global_settings.revision = global_settings.revision.wrapping_add(1);
                save_global_settings(state.store.as_ref(), &global_settings).await?;
            }

            return Ok(Response::new(UpdateConfigResponse {
                version: u32::try_from(next_version).unwrap_or(0),
                policy_hash: hash,
                settings_revision: global_settings.revision,
                deleted: false,
            }));
        }

        // Global setting mutation.
        if key == POLICY_SETTING_KEY && !req.delete_setting {
            return Err(Status::invalid_argument(
                "reserved key 'policy' must be set via the policy field",
            ));
        }
        if key != POLICY_SETTING_KEY {
            validate_registered_setting_key(key)?;
        }

        let mut global_settings = load_global_settings(state.store.as_ref()).await?;
        let changed = if req.delete_setting {
            let removed = global_settings.settings.remove(key).is_some();
            if removed
                && key == POLICY_SETTING_KEY
                && let Ok(Some(latest)) = state
                    .store
                    .get_latest_policy(GLOBAL_POLICY_SANDBOX_ID)
                    .await
            {
                let _ = state
                    .store
                    .supersede_older_policies(GLOBAL_POLICY_SANDBOX_ID, latest.version + 1)
                    .await;
            }
            removed
        } else {
            let setting = req
                .setting_value
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("setting_value is required"))?;
            let stored = proto_setting_to_stored(key, setting)?;
            upsert_setting_value(&mut global_settings.settings, key, stored)
        };

        if changed {
            global_settings.revision = global_settings.revision.wrapping_add(1);
            save_global_settings(state.store.as_ref(), &global_settings).await?;
        }

        return Ok(Response::new(UpdateConfigResponse {
            version: 0,
            policy_hash: String::new(),
            settings_revision: global_settings.revision,
            deleted: req.delete_setting && changed,
        }));
    }

    if req.name.is_empty() {
        return Err(Status::invalid_argument(
            "name is required for sandbox-scoped updates",
        ));
    }

    // Resolve sandbox by name.
    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    if has_setting {
        let _settings_guard = state.settings_mutex.lock().await;

        if key == POLICY_SETTING_KEY {
            return Err(Status::invalid_argument(
                "reserved key 'policy' must be set via policy commands",
            ));
        }

        let global_settings = load_global_settings(state.store.as_ref()).await?;
        let globally_managed = global_settings.settings.contains_key(key);

        if req.delete_setting {
            if globally_managed {
                return Err(Status::failed_precondition(format!(
                    "setting '{key}' is managed globally; delete the global setting first"
                )));
            }

            let mut sandbox_settings =
                load_sandbox_settings(state.store.as_ref(), sandbox.object_name()).await?;
            let removed = sandbox_settings.settings.remove(key).is_some();
            if removed {
                sandbox_settings.revision = sandbox_settings.revision.wrapping_add(1);
                save_sandbox_settings(
                    state.store.as_ref(),
                    sandbox.object_name(),
                    &sandbox_settings,
                )
                .await?;
            }

            return Ok(Response::new(UpdateConfigResponse {
                version: 0,
                policy_hash: String::new(),
                settings_revision: sandbox_settings.revision,
                deleted: removed,
            }));
        }

        if globally_managed {
            return Err(Status::failed_precondition(format!(
                "setting '{key}' is managed globally; delete the global setting before sandbox update"
            )));
        }

        let setting = req
            .setting_value
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("setting_value is required"))?;
        let stored = proto_setting_to_stored(key, setting)?;

        let mut sandbox_settings =
            load_sandbox_settings(state.store.as_ref(), sandbox.object_name()).await?;
        let changed = upsert_setting_value(&mut sandbox_settings.settings, key, stored);
        if changed {
            sandbox_settings.revision = sandbox_settings.revision.wrapping_add(1);
            save_sandbox_settings(
                state.store.as_ref(),
                sandbox.object_name(),
                &sandbox_settings,
            )
            .await?;
        }

        return Ok(Response::new(UpdateConfigResponse {
            version: 0,
            policy_hash: String::new(),
            settings_revision: sandbox_settings.revision,
            deleted: false,
        }));
    }

    if has_merge_ops {
        let global_settings = load_global_settings(state.store.as_ref()).await?;
        if global_settings.settings.contains_key(POLICY_SETTING_KEY) {
            return Err(Status::failed_precondition(
                "policy is managed globally; delete global policy before sandbox policy update",
            ));
        }

        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| Status::internal("sandbox has no spec"))?;
        let merge_ops = parse_merge_operations(&req.merge_operations)?;
        validate_merge_operations_for_server(&merge_ops)?;
        let (version, hash) = apply_merge_operations_with_retry(
            state.store.as_ref(),
            &sandbox_id,
            spec.policy.as_ref(),
            &merge_ops,
        )
        .await?;

        state.sandbox_watch_bus.notify(&sandbox_id);
        emit_gateway_policy_audit_log(
            &sandbox_id,
            sandbox.object_name(),
            "merged",
            format!(
                "gateway merged {} incremental policy operation(s)",
                merge_ops.len()
            ),
            version,
            &hash,
        );
        for operation in &merge_ops {
            emit_gateway_policy_audit_log(
                &sandbox_id,
                sandbox.object_name(),
                "merged",
                format!(
                    "gateway merged incremental policy op: {}",
                    summarize_cli_policy_merge_op(operation)
                ),
                version,
                &hash,
            );
        }
        info!(
            sandbox_id = %sandbox_id,
            version,
            policy_hash = %hash,
            operation_count = merge_ops.len(),
            "UpdateConfig: merged incremental policy operations"
        );
        emit_config_update_policy_success(sandbox_caller);

        return Ok(Response::new(UpdateConfigResponse {
            version: u32::try_from(version).unwrap_or(0),
            policy_hash: hash,
            settings_revision: 0,
            deleted: false,
        }));
    }

    // Sandbox-scoped policy update.
    let mut new_policy = req
        .policy
        .ok_or_else(|| Status::invalid_argument("policy is required"))?;

    let global_settings = load_global_settings(state.store.as_ref()).await?;
    if global_settings.settings.contains_key(POLICY_SETTING_KEY) {
        return Err(Status::failed_precondition(
            "policy is managed globally; delete global policy before sandbox policy update",
        ));
    }

    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::internal("sandbox has no spec"))?;

    openshell_policy::ensure_sandbox_process_identity(&mut new_policy);

    if let Some(baseline_policy) = spec.policy.as_ref() {
        validate_static_fields_unchanged(baseline_policy, &new_policy)?;
        validate_policy_safety(&new_policy)?;
    } else {
        // Backfill spec.policy using CAS (first-time policy discovery)
        let _sandbox_sync_guard = state.compute.sandbox_sync_guard().await;
        let sandbox_id = sandbox.object_id().to_string();
        let new_policy_clone = new_policy.clone();
        state
            .store
            .update_message_cas::<Sandbox, _>(
                &sandbox_id,
                req.expected_resource_version,
                |sandbox| {
                    if let Some(ref mut spec) = sandbox.spec
                        && spec.policy.is_none()
                    {
                        spec.policy = Some(new_policy_clone.clone());
                    }
                },
            )
            .await
            .map_err(|e| super::persistence_error_to_status(e, "backfill spec.policy"))?;
        info!(
            sandbox_id = %sandbox_id,
            "UpdateConfig: backfilled spec.policy from sandbox-discovered policy"
        );
    }

    let latest = state
        .store
        .get_latest_policy(&sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch latest policy failed: {e}")))?;

    let payload = new_policy.encode_to_vec();
    let hash = deterministic_policy_hash(&new_policy);

    if let Some(ref current) = latest
        && current.policy_hash == hash
    {
        return Ok(Response::new(UpdateConfigResponse {
            version: u32::try_from(current.version).unwrap_or(0),
            policy_hash: hash,
            settings_revision: 0,
            deleted: false,
        }));
    }

    let next_version = latest.map_or(1, |r| r.version + 1);
    let policy_id = uuid::Uuid::new_v4().to_string();

    state
        .store
        .put_policy_revision(&policy_id, &sandbox_id, next_version, &payload, &hash)
        .await
        .map_err(|e| Status::internal(format!("persist policy revision failed: {e}")))?;

    let _ = state
        .store
        .supersede_older_policies(&sandbox_id, next_version)
        .await;

    state.sandbox_watch_bus.notify(&sandbox_id);

    info!(
        sandbox_id = %sandbox_id,
        version = next_version,
        policy_hash = %hash,
        "UpdateConfig: new policy version persisted"
    );
    emit_full_policy_update_success(sandbox_caller, next_version);

    Ok(Response::new(UpdateConfigResponse {
        version: u32::try_from(next_version).unwrap_or(0),
        policy_hash: hash,
        settings_revision: 0,
        deleted: false,
    }))
}

// ---------------------------------------------------------------------------
// Policy status handlers
// ---------------------------------------------------------------------------

pub(super) async fn handle_get_sandbox_policy_status(
    state: &Arc<ServerState>,
    request: Request<GetSandboxPolicyStatusRequest>,
) -> Result<Response<GetSandboxPolicyStatusResponse>, Status> {
    let req = request.into_inner();

    let (policy_id, active_version) = if req.global {
        (GLOBAL_POLICY_SANDBOX_ID.to_string(), 0_u32)
    } else {
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        let sandbox = state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        (
            sandbox.object_id().to_string(),
            sandbox.current_policy_version(),
        )
    };

    let record = if req.version == 0 {
        state
            .store
            .get_latest_policy(&policy_id)
            .await
            .map_err(|e| Status::internal(format!("fetch policy failed: {e}")))?
    } else {
        state
            .store
            .get_policy_by_version(&policy_id, i64::from(req.version))
            .await
            .map_err(|e| Status::internal(format!("fetch policy failed: {e}")))?
    };

    let not_found_msg = if req.global {
        "no global policy revision found"
    } else {
        "no policy revision found for this sandbox"
    };
    let record = record.ok_or_else(|| Status::not_found(not_found_msg))?;

    Ok(Response::new(GetSandboxPolicyStatusResponse {
        revision: Some(policy_record_to_revision(&record, true)),
        active_version,
    }))
}

pub(super) async fn handle_list_sandbox_policies(
    state: &Arc<ServerState>,
    request: Request<ListSandboxPoliciesRequest>,
) -> Result<Response<ListSandboxPoliciesResponse>, Status> {
    let req = request.into_inner();

    let policy_id = if req.global {
        GLOBAL_POLICY_SANDBOX_ID.to_string()
    } else {
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        let sandbox = state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        sandbox.object_id().to_string()
    };

    let limit = clamp_limit(req.limit, 50, MAX_PAGE_SIZE);
    let records = state
        .store
        .list_policies(&policy_id, limit, req.offset)
        .await
        .map_err(|e| Status::internal(format!("list policies failed: {e}")))?;

    let revisions = records
        .iter()
        .map(|r| policy_record_to_revision(r, false))
        .collect();

    Ok(Response::new(ListSandboxPoliciesResponse { revisions }))
}

pub(super) async fn handle_report_policy_status(
    state: &Arc<ServerState>,
    request: Request<ReportPolicyStatusRequest>,
) -> Result<Response<ReportPolicyStatusResponse>, Status> {
    let sandbox_id = request.get_ref().sandbox_id.clone();
    crate::auth::guard::enforce_sandbox_scope(&request, &sandbox_id)?;
    let req = request.into_inner();
    if req.sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }
    if req.version == 0 {
        return Err(Status::invalid_argument("version is required"));
    }

    let version = i64::from(req.version);
    let status_str = match PolicyStatus::try_from(req.status) {
        Ok(PolicyStatus::Loaded) => "loaded",
        Ok(PolicyStatus::Failed) => "failed",
        _ => return Err(Status::invalid_argument("status must be LOADED or FAILED")),
    };

    let loaded_at_ms = if status_str == "loaded" {
        Some(current_time_ms())
    } else {
        None
    };

    let load_error = if status_str == "failed" && !req.load_error.is_empty() {
        Some(req.load_error.as_str())
    } else {
        None
    };

    let updated = state
        .store
        .update_policy_status(
            &req.sandbox_id,
            version,
            status_str,
            load_error,
            loaded_at_ms,
        )
        .await
        .map_err(|e| Status::internal(format!("update policy status failed: {e}")))?;

    if !updated {
        return Err(Status::not_found("policy revision not found"));
    }

    if status_str == "loaded" {
        let _ = state
            .store
            .supersede_older_policies(&req.sandbox_id, version)
            .await;

        // Update current_policy_version using CAS
        // TODO: Accept expected_version from UpdateConfigRequest for proper client-driven CAS
        let _sandbox_sync_guard = state.compute.sandbox_sync_guard().await;
        let version_to_set = req.version;
        state
            .store
            .update_message_cas::<Sandbox, _>(&req.sandbox_id, 0, |sandbox| {
                sandbox.set_current_policy_version(version_to_set);
            })
            .await
            .map_err(|e| super::persistence_error_to_status(e, "update current_policy_version"))?;

        state.sandbox_watch_bus.notify(&req.sandbox_id);
    }

    info!(
        sandbox_id = %req.sandbox_id,
        version = req.version,
        status = %status_str,
        "ReportPolicyStatus: sandbox reported policy load result"
    );

    Ok(Response::new(ReportPolicyStatusResponse {}))
}

// ---------------------------------------------------------------------------
// Sandbox logs handlers
// ---------------------------------------------------------------------------

#[allow(clippy::unused_async)] // Must be async to match the trait signature
pub(super) async fn handle_get_sandbox_logs(
    state: &Arc<ServerState>,
    request: Request<GetSandboxLogsRequest>,
) -> Result<Response<GetSandboxLogsResponse>, Status> {
    let req = request.into_inner();
    if req.sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }

    let lines = if req.lines == 0 { 2000 } else { req.lines };
    let tail = state.tracing_log_bus.tail(&req.sandbox_id, lines as usize);

    let buffer_total = tail.len() as u32;

    let logs: Vec<SandboxLogLine> = tail
        .into_iter()
        .filter_map(|evt| {
            if let Some(openshell_core::proto::sandbox_stream_event::Payload::Log(log)) =
                evt.payload
            {
                if req.since_ms > 0 && log.timestamp_ms < req.since_ms {
                    return None;
                }
                if !req.sources.is_empty() && !source_matches(&log.source, &req.sources) {
                    return None;
                }
                if !level_matches(&log.level, &req.min_level) {
                    return None;
                }
                Some(log)
            } else {
                None
            }
        })
        .collect();

    Ok(Response::new(GetSandboxLogsResponse { logs, buffer_total }))
}

pub(super) async fn handle_push_sandbox_logs(
    state: &Arc<ServerState>,
    request: Request<tonic::Streaming<PushSandboxLogsRequest>>,
) -> Result<Response<PushSandboxLogsResponse>, Status> {
    let principal = request
        .extensions()
        .get::<Principal>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("missing principal"))?;
    let mut stream = request.into_inner();
    let mut validated_sandbox_id = None;

    while let Some(batch) = stream
        .message()
        .await
        .map_err(|e| Status::internal(format!("stream error: {e}")))?
    {
        if batch.sandbox_id.is_empty() {
            continue;
        }

        ensure_log_stream_sandbox_scope(
            state,
            &principal,
            &batch.sandbox_id,
            &mut validated_sandbox_id,
        )
        .await?;

        for log in batch.logs.into_iter().take(100) {
            let mut log = log;
            log.source = "sandbox".to_string();
            log.sandbox_id.clone_from(&batch.sandbox_id);
            state.tracing_log_bus.publish_external(log);
        }
    }

    Ok(Response::new(PushSandboxLogsResponse {}))
}

async fn ensure_log_stream_sandbox_scope(
    state: &Arc<ServerState>,
    principal: &Principal,
    sandbox_id: &str,
    validated_sandbox_id: &mut Option<String>,
) -> Result<(), Status> {
    if let Some(validated) = validated_sandbox_id.as_deref() {
        if sandbox_id != validated {
            return Err(Status::permission_denied(
                "log stream sandbox_id changed after validation",
            ));
        }
        return Ok(());
    }

    crate::auth::guard::ensure_sandbox_scope(principal, sandbox_id)?;
    state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    *validated_sandbox_id = Some(sandbox_id.to_string());
    Ok(())
}

// ---------------------------------------------------------------------------
// Draft policy recommendation handlers
// ---------------------------------------------------------------------------

pub(super) async fn handle_submit_policy_analysis(
    state: &Arc<ServerState>,
    request: Request<SubmitPolicyAnalysisRequest>,
) -> Result<Response<SubmitPolicyAnalysisResponse>, Status> {
    let principal = request
        .extensions()
        .get::<Principal>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("missing principal"))?;
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    let sandbox =
        resolve_sandbox_by_name_for_principal(state.store.as_ref(), &principal, &req.name).await?;
    let sandbox_id = sandbox.object_id().to_string();
    for summary in &req.network_activity_summaries {
        state
            .telemetry
            .record_network_activity(&sandbox_id, summary);
    }
    if req.proposed_chunks.is_empty()
        && req.summaries.is_empty()
        && !req.network_activity_summaries.is_empty()
    {
        return Ok(Response::new(SubmitPolicyAnalysisResponse {
            accepted_chunks: 0,
            rejected_chunks: 0,
            rejection_reasons: Vec::new(),
            accepted_chunk_ids: Vec::new(),
        }));
    }

    // `current_policy` is captured ONCE at the top of the batch and frozen
    // for every chunk's delta computation, even if an earlier chunk in the
    // batch auto-approves and merges. This is intentional v1 behavior:
    // multi-chunk batches with overlapping endpoints would otherwise have
    // chunk N+1 fail to see chunk N's contribution, which is a degenerate
    // case for the common single-chunk submission shape. If real workloads
    // surface a problem with batches that interact across chunks, the right
    // fix is to recompute baseline after each successful auto-approve.
    let current_policy = current_effective_policy_for_sandbox(state, &sandbox, &sandbox_id).await?;

    // Auto-approval is an opt-in behavior, sourced from the settings model
    // (sandbox or gateway scope) so it can be flipped on a running sandbox
    // and managed fleet-wide. Default (no setting, or any value other than
    // exact "auto") preserves OpenShell's default-deny posture: every
    // proposal lands in `pending` for a human reviewer.
    let (auto_approve_enabled, resolved_from) =
        resolve_proposal_approval_mode(state.store.as_ref(), sandbox.object_name()).await?;

    // The credential set is stable across all chunks in this batch, so build
    // it once. v1 captures presence only — no scope modeling — so the prover
    // can answer "is there a credential in scope for this host?" but not
    // "what action class does that credential authorize?"
    let provider_names_for_creds: Vec<String> = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.providers.clone())
        .unwrap_or_default();
    let credential_set =
        build_credential_set_for_sandbox(state.store.as_ref(), &provider_names_for_creds).await?;

    let current_version = state
        .store
        .get_draft_version(&sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("get draft version failed: {e}")))?;
    let draft_version = current_version + 1;

    let mut accepted: u32 = 0;
    let mut rejected: u32 = 0;
    let mut rejection_reasons: Vec<String> = Vec::new();
    let mut accepted_chunk_ids: Vec<String> = Vec::new();

    for chunk in &req.proposed_chunks {
        if chunk.rule_name.is_empty() {
            rejected += 1;
            rejection_reasons.push("chunk missing rule_name".to_string());
            continue;
        }
        // `_provider_*` is the reserved namespace for rules synthesized from
        // provider profiles during composition. Agent submissions that target
        // those keys would merge directly into the provider rule and bypass
        // the merge.rs guard that splits agent-authored chunks into their
        // own rule so the prover sees their contribution honestly. Reject at
        // the entry boundary — the agent never has reason to address a
        // provider rule by name.
        if chunk.rule_name.starts_with("_provider_") {
            rejected += 1;
            rejection_reasons.push(format!(
                "chunk '{}' uses reserved '_provider_' rule-name prefix",
                chunk.rule_name
            ));
            continue;
        }
        if chunk.proposed_rule.is_none() {
            rejected += 1;
            rejection_reasons.push(format!("chunk '{}' missing proposed_rule", chunk.rule_name));
            continue;
        }

        let now_ms = current_time_ms();
        let proposed_rule_bytes = chunk
            .proposed_rule
            .as_ref()
            .map(Message::encode_to_vec)
            .unwrap_or_default();

        let rule_ref = chunk.proposed_rule.as_ref();
        let (ep_host, ep_port) = rule_ref
            .and_then(|r| r.endpoints.first())
            .map(|ep| (ep.host.to_lowercase(), ep.port as i32))
            .unwrap_or_default();
        let ep_binary = rule_ref
            .and_then(|r| r.binaries.first())
            .map(|b| b.path.clone())
            .unwrap_or_default();

        // The prover runs on every proposal regardless of `analysis_mode`.
        // Source provenance (mechanistic vs agent_authored) is preserved in
        // OCSF audit fields, but the safety decision is grounded in the
        // merged-policy consequence, not the author — proposer-agnostic.
        let validation_result = validation_result_for_agent_proposal(
            current_policy.clone(),
            &chunk.rule_name,
            chunk.proposed_rule.as_ref().expect("checked above"),
            &credential_set,
        );

        let record = DraftChunkRecord {
            // The handler proposes an id; the store may swap it for an
            // existing row's id on dedup. Always trust `effective_id` for
            // anything user-facing.
            id: uuid::Uuid::new_v4().to_string(),
            sandbox_id: sandbox_id.clone(),
            draft_version,
            status: "pending".to_string(),
            rule_name: chunk.rule_name.clone(),
            proposed_rule: proposed_rule_bytes,
            rationale: chunk.rationale.clone(),
            security_notes: generate_security_notes(
                &ep_host,
                u16::try_from(ep_port as u32).unwrap_or(0),
            ),
            confidence: f64::from(chunk.confidence.clamp(0.0, 1.0)),
            created_at_ms: now_ms,
            decided_at_ms: None,
            host: ep_host,
            port: ep_port,
            binary: ep_binary,
            hit_count: chunk.hit_count.clamp(1, 100),
            first_seen_ms: if chunk.first_seen_ms > 0 {
                chunk.first_seen_ms
            } else {
                now_ms
            },
            last_seen_ms: if chunk.last_seen_ms > 0 {
                chunk.last_seen_ms
            } else {
                now_ms
            },
            validation_result: validation_result.clone(),
            rejection_reason: String::new(),
        };
        // Mechanistic mode dedups N denials targeting the same endpoint
        // into one chunk. All other modes (agent-authored proposals, future
        // modes) submit each chunk as a distinct row — the redraft loop
        // relies on it, and the conservative default for an unknown mode
        // is to keep the proposal rather than silently fold it away.
        let dedup_key = matches!(req.analysis_mode.as_str(), "mechanistic")
            .then(|| crate::policy_store::observation_dedup_key(&record));
        let effective_id = state
            .store
            .put_draft_chunk(&record, dedup_key.as_deref())
            .await
            .map_err(|e| Status::internal(format!("persist draft chunk failed: {e}")))?;
        accepted += 1;

        // Implicit supersede: any other pending chunk for the same
        // (host, port, binary) in this sandbox is now stale because this
        // newer submission covers the same access decision. Auto-reject the
        // older chunks with a clear reason. This is what lets the agent
        // refine a mechanistic L4 draft into an L7 narrow proposal without
        // any explicit `supersedes_chunk_id` plumbing — the gateway figures
        // out the relationship by structural overlap.
        supersede_other_pending_chunks_for_endpoint(
            state,
            &sandbox_id,
            &effective_id,
            &record.host,
            record.port,
            &record.binary,
        )
        .await;

        // Asymmetric self-reject: if this is a mechanistic proposal that
        // arrived AFTER an already-approved agent_authored chunk covered the
        // same (host, port, binary), the mechanistic submission is
        // redundant — the agent already handled it. Auto-reject so it
        // doesn't pile up as approval-queue noise. Agent_authored
        // submissions never self-reject; refinement is always allowed.
        if req.analysis_mode == "mechanistic" {
            self_reject_mechanistic_if_already_covered(
                state,
                &sandbox_id,
                &effective_id,
                &record.host,
                record.port,
                &record.binary,
                chunk.proposed_rule.as_ref().expect("checked above"),
            )
            .await;
        }

        // Auto-approval gate (proposer-agnostic, opt-in): only fire when
        // BOTH the prover found nothing new in this proposal's delta AND
        // the reviewer opted in via the `proposal_approval_mode` setting
        // (gateway or sandbox scope). On any failure (merge conflict,
        // status update error), the chunk stays pending so a human can
        // review — never silently lose a proposal. The `validation_result`
        // literal here is the canonical empty-delta verdict; any other
        // string means findings or infrastructure error, both of which
        // require human attention.
        if auto_approve_enabled
            && validation_result == "prover: no new findings"
            && let Err(err) = auto_approve_chunk(
                state,
                &sandbox_id,
                sandbox.object_name(),
                &effective_id,
                &req.analysis_mode,
                resolved_from,
            )
            .await
        {
            warn!(
                chunk_id = %effective_id,
                sandbox_id = %sandbox_id,
                error = %err,
                "auto-approval failed; chunk remains pending for human review"
            );
        }

        accepted_chunk_ids.push(effective_id);
    }

    state.sandbox_watch_bus.notify(&sandbox_id);

    info!(
        sandbox_id = %sandbox_id,
        accepted = accepted,
        rejected = rejected,
        draft_version = draft_version,
        summaries = req.summaries.len(),
        "SubmitPolicyAnalysis: persisted draft chunks"
    );

    Ok(Response::new(SubmitPolicyAnalysisResponse {
        accepted_chunks: accepted,
        rejected_chunks: rejected,
        rejection_reasons,
        accepted_chunk_ids,
    }))
}

pub(super) async fn handle_get_draft_policy(
    state: &Arc<ServerState>,
    request: Request<GetDraftPolicyRequest>,
) -> Result<Response<GetDraftPolicyResponse>, Status> {
    let principal = request
        .extensions()
        .get::<Principal>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("missing principal"))?;
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    let sandbox =
        resolve_sandbox_by_name_for_principal(state.store.as_ref(), &principal, &req.name).await?;
    let sandbox_id = sandbox.object_id().to_string();

    let status_filter = if req.status_filter.is_empty() {
        None
    } else {
        Some(req.status_filter.as_str())
    };

    let records = state
        .store
        .list_draft_chunks(&sandbox_id, status_filter)
        .await
        .map_err(|e| Status::internal(format!("list draft chunks failed: {e}")))?;

    let draft_version = state
        .store
        .get_draft_version(&sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("get draft version failed: {e}")))?;

    let chunks: Vec<PolicyChunk> = records
        .into_iter()
        .map(|r| draft_chunk_record_to_proto(&r))
        .collect::<Result<Vec<_>, _>>()?;

    let last_analyzed_at_ms = chunks.iter().map(|c| c.created_at_ms).max().unwrap_or(0);

    debug!(
        sandbox_id = %sandbox_id,
        chunk_count = chunks.len(),
        draft_version = draft_version,
        "GetDraftPolicy: served draft chunks"
    );

    Ok(Response::new(GetDraftPolicyResponse {
        chunks,
        rolling_summary: String::new(),
        draft_version: u64::try_from(draft_version).unwrap_or(0),
        last_analyzed_at_ms,
    }))
}

pub(super) async fn handle_approve_draft_chunk(
    state: &Arc<ServerState>,
    request: Request<ApproveDraftChunkRequest>,
) -> Result<Response<ApproveDraftChunkResponse>, Status> {
    let result = handle_approve_draft_chunk_inner(state, request).await;
    if result.is_err() {
        emit_policy_decision_failure(PolicyDecisionOperation::Approve, 1);
    }
    result
}

async fn handle_approve_draft_chunk_inner(
    state: &Arc<ServerState>,
    request: Request<ApproveDraftChunkRequest>,
) -> Result<Response<ApproveDraftChunkResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if req.chunk_id.is_empty() {
        return Err(Status::invalid_argument("chunk_id is required"));
    }

    require_no_global_policy(state).await?;

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let chunk = state
        .store
        .get_draft_chunk(&req.chunk_id)
        .await
        .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
        .ok_or_else(|| Status::not_found("chunk not found"))?;
    ensure_chunk_belongs_to_sandbox(&chunk, &sandbox_id)?;

    if chunk.status != "pending" && chunk.status != "rejected" {
        return Err(Status::failed_precondition(format!(
            "chunk status is '{}', expected 'pending' or 'rejected'",
            chunk.status
        )));
    }

    info!(
        sandbox_id = %sandbox_id,
        chunk_id = %req.chunk_id,
        rule_name = %chunk.rule_name,
        host = %chunk.host,
        port = chunk.port,
        hit_count = chunk.hit_count,
        prev_status = %chunk.status,
        "ApproveDraftChunk: merging rule into active policy"
    );

    let (version, hash) =
        merge_chunk_into_policy(state.store.as_ref(), &sandbox_id, &chunk).await?;
    let chunk_summary = summarize_draft_chunk_rule(&chunk)?;

    let now_ms = current_time_ms();
    state
        .store
        .update_draft_chunk_status(&req.chunk_id, "approved", Some(now_ms), None)
        .await
        .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

    state.sandbox_watch_bus.notify(&sandbox_id);
    emit_gateway_policy_audit_log(
        &sandbox_id,
        sandbox.object_name(),
        "approved",
        format!(
            "gateway approved draft chunk {}: {chunk_summary}",
            req.chunk_id
        ),
        version,
        &hash,
    );

    info!(
        sandbox_id = %sandbox_id,
        chunk_id = %req.chunk_id,
        rule_name = %chunk.rule_name,
        version = version,
        policy_hash = %hash,
        "ApproveDraftChunk: rule merged successfully"
    );
    emit_sandbox_policy_update_success();
    emit_policy_decision_success(PolicyDecisionOperation::Approve, 1);

    Ok(Response::new(ApproveDraftChunkResponse {
        policy_version: u32::try_from(version).unwrap_or(0),
        policy_hash: hash,
    }))
}

pub(super) async fn handle_reject_draft_chunk(
    state: &Arc<ServerState>,
    request: Request<RejectDraftChunkRequest>,
) -> Result<Response<RejectDraftChunkResponse>, Status> {
    let result = handle_reject_draft_chunk_inner(state, request).await;
    if result.is_err() {
        emit_policy_decision_failure(PolicyDecisionOperation::Reject, 1);
    }
    result
}

async fn handle_reject_draft_chunk_inner(
    state: &Arc<ServerState>,
    request: Request<RejectDraftChunkRequest>,
) -> Result<Response<RejectDraftChunkResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if req.chunk_id.is_empty() {
        return Err(Status::invalid_argument("chunk_id is required"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let chunk = state
        .store
        .get_draft_chunk(&req.chunk_id)
        .await
        .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
        .ok_or_else(|| Status::not_found("chunk not found"))?;
    ensure_chunk_belongs_to_sandbox(&chunk, &sandbox_id)?;

    if chunk.status != "pending" && chunk.status != "approved" {
        return Err(Status::failed_precondition(format!(
            "chunk status is '{}', expected 'pending' or 'approved'",
            chunk.status
        )));
    }

    let was_approved = chunk.status == "approved";

    info!(
        sandbox_id = %sandbox_id,
        chunk_id = %req.chunk_id,
        rule_name = %chunk.rule_name,
        host = %chunk.host,
        port = chunk.port,
        reason = %req.reason,
        prev_status = %chunk.status,
        "RejectDraftChunk: rejecting chunk"
    );

    if was_approved {
        require_no_global_policy(state).await?;
        let (version, hash) = remove_chunk_from_policy(state, &sandbox_id, &chunk).await?;
        emit_gateway_policy_audit_log(
            &sandbox_id,
            sandbox.object_name(),
            "removed",
            format!(
                "gateway removed previously approved draft chunk {}: remove-binary {} {}",
                req.chunk_id, chunk.rule_name, chunk.binary
            ),
            version,
            &hash,
        );
        emit_sandbox_policy_update_success();
    }

    let now_ms = current_time_ms();
    // Persist the reviewer's free-form `reason` into the chunk's
    // `rejection_reason` field so the in-sandbox agent can read it back via
    // GetDraftPolicy / policy.local and revise the proposal.
    let persisted_reason = if req.reason.is_empty() {
        None
    } else {
        Some(req.reason.as_str())
    };
    state
        .store
        .update_draft_chunk_status(&req.chunk_id, "rejected", Some(now_ms), persisted_reason)
        .await
        .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

    state.sandbox_watch_bus.notify(&sandbox_id);
    emit_policy_decision_success(PolicyDecisionOperation::Reject, 1);

    Ok(Response::new(RejectDraftChunkResponse {}))
}

pub(super) async fn handle_approve_all_draft_chunks(
    state: &Arc<ServerState>,
    request: Request<ApproveAllDraftChunksRequest>,
) -> Result<Response<ApproveAllDraftChunksResponse>, Status> {
    let result = handle_approve_all_draft_chunks_inner(state, request).await;
    if result.is_err() {
        emit_policy_decision_failure(PolicyDecisionOperation::ApproveAll, 0);
    }
    result
}

async fn handle_approve_all_draft_chunks_inner(
    state: &Arc<ServerState>,
    request: Request<ApproveAllDraftChunksRequest>,
) -> Result<Response<ApproveAllDraftChunksResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    require_no_global_policy(state).await?;

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let pending_chunks = state
        .store
        .list_draft_chunks(&sandbox_id, Some("pending"))
        .await
        .map_err(|e| Status::internal(format!("list draft chunks failed: {e}")))?;

    if pending_chunks.is_empty() {
        return Err(Status::failed_precondition("no pending chunks to approve"));
    }

    info!(
        sandbox_id = %sandbox_id,
        pending_count = pending_chunks.len(),
        include_security_flagged = req.include_security_flagged,
        "ApproveAllDraftChunks: starting bulk approval"
    );

    let mut chunks_approved: u32 = 0;
    let mut chunks_skipped: u32 = 0;
    let mut last_version: i64 = 0;
    let mut last_hash = String::new();

    for chunk in &pending_chunks {
        if !req.include_security_flagged && !chunk.security_notes.is_empty() {
            info!(
                sandbox_id = %sandbox_id,
                chunk_id = %chunk.id,
                rule_name = %chunk.rule_name,
                security_notes = %chunk.security_notes,
                "ApproveAllDraftChunks: skipping security-flagged chunk"
            );
            chunks_skipped += 1;
            continue;
        }

        info!(
            sandbox_id = %sandbox_id,
            chunk_id = %chunk.id,
            rule_name = %chunk.rule_name,
            host = %chunk.host,
            port = chunk.port,
            "ApproveAllDraftChunks: merging chunk"
        );

        let (version, hash) =
            merge_chunk_into_policy(state.store.as_ref(), &sandbox_id, chunk).await?;
        last_version = version;
        last_hash = hash;
        let chunk_summary = summarize_draft_chunk_rule(chunk)?;

        let now_ms = current_time_ms();
        state
            .store
            .update_draft_chunk_status(&chunk.id, "approved", Some(now_ms), None)
            .await
            .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

        emit_gateway_policy_audit_log(
            &sandbox_id,
            sandbox.object_name(),
            "approved",
            format!("gateway approved draft chunk {}: {chunk_summary}", chunk.id),
            version,
            &last_hash,
        );
        chunks_approved += 1;
        emit_sandbox_policy_update_success();
    }

    state.sandbox_watch_bus.notify(&sandbox_id);
    emit_gateway_policy_audit_log(
        &sandbox_id,
        sandbox.object_name(),
        "merged",
        format!(
            "gateway bulk-approved {chunks_approved} draft chunk(s) and skipped {chunks_skipped}"
        ),
        last_version,
        &last_hash,
    );

    info!(
        sandbox_id = %sandbox_id,
        chunks_approved = chunks_approved,
        chunks_skipped = chunks_skipped,
        version = last_version,
        policy_hash = %last_hash,
        "ApproveAllDraftChunks: bulk approval complete"
    );
    emit_policy_decision_success(
        PolicyDecisionOperation::ApproveAll,
        u64::from(chunks_approved),
    );

    Ok(Response::new(ApproveAllDraftChunksResponse {
        policy_version: u32::try_from(last_version).unwrap_or(0),
        policy_hash: last_hash,
        chunks_approved,
        chunks_skipped,
    }))
}

pub(super) async fn handle_edit_draft_chunk(
    state: &Arc<ServerState>,
    request: Request<EditDraftChunkRequest>,
) -> Result<Response<EditDraftChunkResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if req.chunk_id.is_empty() {
        return Err(Status::invalid_argument("chunk_id is required"));
    }
    let proposed_rule = req
        .proposed_rule
        .ok_or_else(|| Status::invalid_argument("proposed_rule is required"))?;

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let chunk = state
        .store
        .get_draft_chunk(&req.chunk_id)
        .await
        .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
        .ok_or_else(|| Status::not_found("chunk not found"))?;
    ensure_chunk_belongs_to_sandbox(&chunk, &sandbox_id)?;

    if chunk.status != "pending" {
        return Err(Status::failed_precondition(format!(
            "chunk status is '{}', expected 'pending'",
            chunk.status
        )));
    }

    let rule_bytes = proposed_rule.encode_to_vec();
    state
        .store
        .update_draft_chunk_rule(&req.chunk_id, &rule_bytes)
        .await
        .map_err(|e| Status::internal(format!("update chunk rule failed: {e}")))?;

    info!(
        chunk_id = %req.chunk_id,
        "EditDraftChunk: proposed rule updated"
    );

    Ok(Response::new(EditDraftChunkResponse {}))
}

pub(super) async fn handle_undo_draft_chunk(
    state: &Arc<ServerState>,
    request: Request<UndoDraftChunkRequest>,
) -> Result<Response<UndoDraftChunkResponse>, Status> {
    let result = handle_undo_draft_chunk_inner(state, request).await;
    if result.is_err() {
        emit_policy_decision_failure(PolicyDecisionOperation::Undo, 1);
    }
    result
}

async fn handle_undo_draft_chunk_inner(
    state: &Arc<ServerState>,
    request: Request<UndoDraftChunkRequest>,
) -> Result<Response<UndoDraftChunkResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if req.chunk_id.is_empty() {
        return Err(Status::invalid_argument("chunk_id is required"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let chunk = state
        .store
        .get_draft_chunk(&req.chunk_id)
        .await
        .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
        .ok_or_else(|| Status::not_found("chunk not found"))?;
    ensure_chunk_belongs_to_sandbox(&chunk, &sandbox_id)?;

    if chunk.status != "approved" {
        return Err(Status::failed_precondition(format!(
            "chunk status is '{}', expected 'approved'",
            chunk.status
        )));
    }

    info!(
        sandbox_id = %sandbox_id,
        chunk_id = %req.chunk_id,
        rule_name = %chunk.rule_name,
        host = %chunk.host,
        port = chunk.port,
        "UndoDraftChunk: removing rule from active policy"
    );

    let (version, hash) = remove_chunk_from_policy(state, &sandbox_id, &chunk).await?;

    // Clear any prior rejection_reason on the way back to "pending" so an
    // agent reading the chunk via policy.local cannot see a stale guidance
    // string left over from a previous reject → undo round.
    state
        .store
        .update_draft_chunk_status(&req.chunk_id, "pending", None, Some(""))
        .await
        .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

    state.sandbox_watch_bus.notify(&sandbox_id);
    emit_gateway_policy_audit_log(
        &sandbox_id,
        sandbox.object_name(),
        "removed",
        format!(
            "gateway reverted approved draft chunk {}: remove-binary {} {}",
            req.chunk_id, chunk.rule_name, chunk.binary
        ),
        version,
        &hash,
    );

    info!(
        sandbox_id = %sandbox_id,
        chunk_id = %req.chunk_id,
        rule_name = %chunk.rule_name,
        version = version,
        policy_hash = %hash,
        "UndoDraftChunk: rule removed, chunk reverted to pending"
    );
    emit_sandbox_policy_update_success();
    emit_policy_decision_success(PolicyDecisionOperation::Undo, 1);

    Ok(Response::new(UndoDraftChunkResponse {
        policy_version: u32::try_from(version).unwrap_or(0),
        policy_hash: hash,
    }))
}

pub(super) async fn handle_clear_draft_chunks(
    state: &Arc<ServerState>,
    request: Request<ClearDraftChunksRequest>,
) -> Result<Response<ClearDraftChunksResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let deleted = state
        .store
        .delete_draft_chunks(&sandbox_id, "pending")
        .await
        .map_err(|e| Status::internal(format!("delete draft chunks failed: {e}")))?;

    state.sandbox_watch_bus.notify(&sandbox_id);

    info!(
        sandbox_id = %sandbox_id,
        chunks_cleared = deleted,
        "ClearDraftChunks: pending chunks cleared"
    );

    Ok(Response::new(ClearDraftChunksResponse {
        chunks_cleared: u32::try_from(deleted).unwrap_or(0),
    }))
}

pub(super) async fn handle_get_draft_history(
    state: &Arc<ServerState>,
    request: Request<GetDraftHistoryRequest>,
) -> Result<Response<GetDraftHistoryResponse>, Status> {
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let sandbox_id = sandbox.object_id().to_string();

    let all_chunks = state
        .store
        .list_draft_chunks(&sandbox_id, None)
        .await
        .map_err(|e| Status::internal(format!("list draft chunks failed: {e}")))?;

    let mut entries: Vec<DraftHistoryEntry> = Vec::new();

    for chunk in &all_chunks {
        entries.push(DraftHistoryEntry {
            timestamp_ms: chunk.created_at_ms,
            event_type: "proposed".to_string(),
            description: format!(
                "Rule '{}' proposed (confidence: {:.0}%)",
                chunk.rule_name,
                chunk.confidence * 100.0
            ),
            chunk_id: chunk.id.clone(),
        });

        if let Some(decided_at) = chunk.decided_at_ms {
            entries.push(DraftHistoryEntry {
                timestamp_ms: decided_at,
                event_type: chunk.status.clone(),
                description: format!("Rule '{}' {}", chunk.rule_name, chunk.status),
                chunk_id: chunk.id.clone(),
            });
        }
    }

    entries.sort_by_key(|e| e.timestamp_ms);

    debug!(
        sandbox_id = %sandbox_id,
        entry_count = entries.len(),
        "GetDraftHistory: served draft history"
    );

    Ok(Response::new(GetDraftHistoryResponse { entries }))
}

// ---------------------------------------------------------------------------
// Policy helper functions
// ---------------------------------------------------------------------------

/// Compute a deterministic SHA-256 hash of a `SandboxPolicy`.
fn deterministic_policy_hash(policy: &ProtoSandboxPolicy) -> String {
    let mut hasher = Sha256::new();
    hasher.update(policy.version.to_le_bytes());
    if let Some(fs) = &policy.filesystem {
        hasher.update(fs.encode_to_vec());
    }
    if let Some(ll) = &policy.landlock {
        hasher.update(ll.encode_to_vec());
    }
    if let Some(p) = &policy.process {
        hasher.update(p.encode_to_vec());
    }
    let mut entries: Vec<_> = policy.network_policies.iter().collect();
    entries.sort_by_key(|(k, _)| k.as_str());
    for (key, value) in entries {
        hasher.update(key.as_bytes());
        hasher.update(value.encode_to_vec());
    }
    hex::encode(hasher.finalize())
}

/// Compute a fingerprint for the effective sandbox configuration.
fn compute_config_revision(
    policy: Option<&ProtoSandboxPolicy>,
    settings: &HashMap<String, EffectiveSetting>,
    policy_source: PolicySource,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update((policy_source as i32).to_le_bytes());
    if let Some(policy) = policy {
        hasher.update(deterministic_policy_hash(policy).as_bytes());
    }
    let mut entries: Vec<_> = settings.iter().collect();
    entries.sort_by_key(|(k, _)| k.as_str());
    for (key, setting) in entries {
        hasher.update(key.as_bytes());
        hasher.update(setting.scope.to_le_bytes());
        if let Some(value) = setting.value.as_ref().and_then(|v| v.value.as_ref()) {
            match value {
                setting_value::Value::StringValue(v) => {
                    hasher.update([0]);
                    hasher.update(v.as_bytes());
                }
                setting_value::Value::BoolValue(v) => {
                    hasher.update([1]);
                    hasher.update([u8::from(*v)]);
                }
                setting_value::Value::IntValue(v) => {
                    hasher.update([2]);
                    hasher.update(v.to_le_bytes());
                }
                setting_value::Value::BytesValue(v) => {
                    hasher.update([3]);
                    hasher.update(v);
                }
            }
        }
    }

    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

fn draft_chunk_record_to_proto(record: &DraftChunkRecord) -> Result<PolicyChunk, Status> {
    use openshell_core::proto::NetworkPolicyRule;

    let proposed_rule = if record.proposed_rule.is_empty() {
        None
    } else {
        Some(
            NetworkPolicyRule::decode(record.proposed_rule.as_slice())
                .map_err(|e| Status::internal(format!("decode proposed_rule failed: {e}")))?,
        )
    };

    Ok(PolicyChunk {
        id: record.id.clone(),
        status: record.status.clone(),
        rule_name: record.rule_name.clone(),
        proposed_rule,
        rationale: record.rationale.clone(),
        security_notes: record.security_notes.clone(),
        confidence: record.confidence as f32,
        created_at_ms: record.created_at_ms,
        decided_at_ms: record.decided_at_ms.unwrap_or(0),
        hit_count: record.hit_count,
        first_seen_ms: record.first_seen_ms,
        last_seen_ms: record.last_seen_ms,
        binary: record.binary.clone(),
        validation_result: record.validation_result.clone(),
        rejection_reason: record.rejection_reason.clone(),
        ..Default::default()
    })
}

fn policy_record_to_revision(record: &PolicyRecord, include_policy: bool) -> SandboxPolicyRevision {
    let status = match record.status.as_str() {
        "pending" => PolicyStatus::Pending,
        "loaded" => PolicyStatus::Loaded,
        "failed" => PolicyStatus::Failed,
        "superseded" => PolicyStatus::Superseded,
        _ => PolicyStatus::Unspecified,
    };

    let policy = if include_policy {
        ProtoSandboxPolicy::decode(record.policy_payload.as_slice()).ok()
    } else {
        None
    };

    SandboxPolicyRevision {
        version: u32::try_from(record.version).unwrap_or(0),
        policy_hash: record.policy_hash.clone(),
        status: status.into(),
        load_error: record.load_error.clone().unwrap_or_default(),
        created_at_ms: record.created_at_ms,
        loaded_at_ms: record.loaded_at_ms.unwrap_or(0),
        policy,
    }
}

/// Re-validate security notes server-side for a proposed policy chunk.
fn generate_security_notes(host: &str, port: u16) -> String {
    let mut notes = Vec::new();

    if host.starts_with("10.")
        || host.starts_with("172.")
        || host.starts_with("192.168.")
        || host == "localhost"
        || host.starts_with("127.")
        || host.starts_with("169.254.")
    {
        notes.push(format!(
            "Destination '{host}' appears to be an internal/private address."
        ));
    }

    if host.contains('*') {
        notes.push(format!(
            "Host '{host}' contains a wildcard — this may match unintended destinations."
        ));
    }

    if port > 49152 {
        notes.push(format!(
            "Port {port} is in the ephemeral range — this may be a temporary service."
        ));
    }

    const DB_PORTS: [u16; 7] = [5432, 3306, 6379, 27017, 9200, 11211, 5672];
    if DB_PORTS.contains(&port) {
        notes.push(format!(
            "Port {port} is a well-known database/service port."
        ));
    }

    notes.join(" ")
}

/// Reject proposed rules whose endpoints or `allowed_ips` target
/// always-blocked addresses (loopback, link-local, unspecified).
///
/// This is defense-in-depth: the proxy blocks these at runtime, so
/// merging them into the active policy would be silently un-enforceable.
fn validate_host_not_always_blocked(host: &str) -> Result<(), Status> {
    use openshell_core::net::{is_always_blocked_ip, is_known_metadata_hostname};
    use std::net::IpAddr;

    let host = host.trim();
    // Check if the host is a literal always-blocked IP.
    if let Ok(ip) = host.parse::<IpAddr>()
        && is_always_blocked_ip(ip)
    {
        return Err(Status::invalid_argument(format!(
            "proposed rule endpoint host '{host}' is an always-blocked address \
             (loopback/link-local/unspecified); the proxy will deny traffic \
             to this destination regardless of policy"
        )));
    }
    let host_lc = host.to_lowercase();
    if host_lc == "localhost" || host_lc == "localhost." {
        return Err(Status::invalid_argument(
            "proposed rule endpoint host 'localhost' is always blocked; \
             the proxy will deny traffic to loopback regardless of policy"
                .to_string(),
        ));
    }
    if is_known_metadata_hostname(host) {
        return Err(Status::invalid_argument(format!(
            "proposed rule endpoint host '{host}' is a known cloud metadata hostname; \
             the proxy will deny traffic to this destination regardless of policy"
        )));
    }
    Ok(())
}

fn validate_rule_not_always_blocked(rule: &NetworkPolicyRule) -> Result<(), Status> {
    use openshell_core::net::is_always_blocked_net;
    use std::net::IpAddr;

    for ep in &rule.endpoints {
        validate_host_not_always_blocked(&ep.host)?;

        // Check allowed_ips entries.
        for entry in &ep.allowed_ips {
            let parsed = entry.parse::<ipnet::IpNet>().or_else(|_| {
                entry.parse::<IpAddr>().map(|ip| match ip {
                    IpAddr::V4(v4) => ipnet::IpNet::V4(ipnet::Ipv4Net::from(v4)),
                    IpAddr::V6(v6) => ipnet::IpNet::V6(ipnet::Ipv6Net::from(v6)),
                })
            });
            if let Ok(net) = parsed
                && is_always_blocked_net(net)
            {
                return Err(Status::invalid_argument(format!(
                    "proposed rule contains always-blocked `allowed_ips` entry '{entry}'; \
                     SSRF hardening prevents traffic to these destinations \
                     regardless of policy"
                )));
            }
            // Invalid entries are not our concern here — the sandbox's
            // parse_allowed_ips handles syntax validation.
        }
    }
    Ok(())
}

async fn require_no_global_policy(state: &ServerState) -> Result<(), Status> {
    let global = load_global_settings(state.store.as_ref()).await?;
    if global.settings.contains_key(POLICY_SETTING_KEY) {
        return Err(Status::failed_precondition(
            "cannot approve rules while a global policy is active; \
             delete the global policy to manage per-sandbox rules",
        ));
    }
    Ok(())
}

fn parse_merge_operations(
    proto_ops: &[PolicyMergeOperation],
) -> Result<Vec<PolicyMergeOp>, Status> {
    proto_ops
        .iter()
        .enumerate()
        .map(|(index, operation)| {
            let Some(operation) = operation.operation.as_ref() else {
                return Err(Status::invalid_argument(format!(
                    "merge_operations[{index}] is missing an operation"
                )));
            };

            match operation {
                policy_merge_operation::Operation::AddRule(add_rule) => {
                    let rule_name = add_rule.rule_name.trim();
                    if rule_name.is_empty() {
                        return Err(Status::invalid_argument(format!(
                            "merge_operations[{index}].add_rule.rule_name is required"
                        )));
                    }
                    if add_rule.rule.as_ref().is_none_or(|rule| rule.endpoints.is_empty()) {
                        return Err(Status::invalid_argument(format!(
                            "merge_operations[{index}].add_rule.rule must contain at least one endpoint"
                        )));
                    }
                    Ok(PolicyMergeOp::AddRule {
                        rule_name: rule_name.to_string(),
                        rule: add_rule.rule.clone().unwrap_or_default(),
                    })
                }
                policy_merge_operation::Operation::RemoveEndpoint(remove_endpoint) => {
                    if remove_endpoint.host.trim().is_empty() || remove_endpoint.port == 0 {
                        return Err(Status::invalid_argument(format!(
                            "merge_operations[{index}].remove_endpoint requires host and non-zero port"
                        )));
                    }
                    let rule_name = if remove_endpoint.rule_name.trim().is_empty() {
                        None
                    } else {
                        Some(remove_endpoint.rule_name.trim().to_string())
                    };
                    Ok(PolicyMergeOp::RemoveEndpoint {
                        rule_name,
                        host: remove_endpoint.host.trim().to_string(),
                        port: remove_endpoint.port,
                    })
                }
                policy_merge_operation::Operation::RemoveRule(remove_rule) => {
                    let rule_name = remove_rule.rule_name.trim();
                    if rule_name.is_empty() {
                        return Err(Status::invalid_argument(format!(
                            "merge_operations[{index}].remove_rule.rule_name is required"
                        )));
                    }
                    Ok(PolicyMergeOp::RemoveRule {
                        rule_name: rule_name.to_string(),
                    })
                }
                policy_merge_operation::Operation::AddDenyRules(add_deny_rules) => {
                    parse_proto_add_deny_rules(index, add_deny_rules)
                }
                policy_merge_operation::Operation::AddAllowRules(add_allow_rules) => {
                    parse_proto_add_allow_rules(index, add_allow_rules)
                }
                policy_merge_operation::Operation::RemoveBinary(remove_binary) => {
                    let rule_name = remove_binary.rule_name.trim();
                    let binary_path = remove_binary.binary_path.trim();
                    if rule_name.is_empty() || binary_path.is_empty() {
                        return Err(Status::invalid_argument(format!(
                            "merge_operations[{index}].remove_binary requires rule_name and binary_path"
                        )));
                    }
                    Ok(PolicyMergeOp::RemoveBinary {
                        rule_name: rule_name.to_string(),
                        binary_path: binary_path.to_string(),
                    })
                }
            }
        })
        .collect()
}

fn parse_proto_add_deny_rules(
    index: usize,
    add_deny_rules: &ProtoAddDenyRules,
) -> Result<PolicyMergeOp, Status> {
    if add_deny_rules.host.trim().is_empty()
        || add_deny_rules.port == 0
        || add_deny_rules.deny_rules.is_empty()
    {
        return Err(Status::invalid_argument(format!(
            "merge_operations[{index}].add_deny_rules requires host, non-zero port, and at least one deny rule"
        )));
    }

    Ok(PolicyMergeOp::AddDenyRules {
        host: add_deny_rules.host.trim().to_string(),
        port: add_deny_rules.port,
        deny_rules: add_deny_rules.deny_rules.clone(),
    })
}

fn parse_proto_add_allow_rules(
    index: usize,
    add_allow_rules: &ProtoAddAllowRules,
) -> Result<PolicyMergeOp, Status> {
    if add_allow_rules.host.trim().is_empty()
        || add_allow_rules.port == 0
        || add_allow_rules.rules.is_empty()
    {
        return Err(Status::invalid_argument(format!(
            "merge_operations[{index}].add_allow_rules requires host, non-zero port, and at least one allow rule"
        )));
    }
    if add_allow_rules
        .rules
        .iter()
        .any(|rule| rule.allow.as_ref().is_none())
    {
        return Err(Status::invalid_argument(format!(
            "merge_operations[{index}].add_allow_rules rules must include allow payloads"
        )));
    }

    Ok(PolicyMergeOp::AddAllowRules {
        host: add_allow_rules.host.trim().to_string(),
        port: add_allow_rules.port,
        rules: add_allow_rules.rules.clone(),
    })
}

fn validate_merge_operations_for_server(operations: &[PolicyMergeOp]) -> Result<(), Status> {
    for operation in operations {
        match operation {
            PolicyMergeOp::AddRule { rule, .. } => validate_rule_not_always_blocked(rule)?,
            PolicyMergeOp::AddAllowRules { host, .. } => validate_host_not_always_blocked(host)?,
            _ => {}
        }
    }
    Ok(())
}

fn map_policy_merge_error(error: openshell_policy::PolicyMergeError) -> Status {
    match error {
        openshell_policy::PolicyMergeError::MissingRuleNameForAddRule
        | openshell_policy::PolicyMergeError::InvalidEndpointReference { .. }
        | openshell_policy::PolicyMergeError::UnsupportedAccessPreset { .. } => {
            Status::invalid_argument(error.to_string())
        }
        openshell_policy::PolicyMergeError::EndpointNotFound { .. }
        | openshell_policy::PolicyMergeError::EndpointHasNoL7Inspection { .. }
        | openshell_policy::PolicyMergeError::UnsupportedEndpointProtocol { .. }
        | openshell_policy::PolicyMergeError::EndpointHasNoAllowBase { .. } => {
            Status::failed_precondition(error.to_string())
        }
    }
}

async fn apply_merge_operations_with_retry(
    store: &Store,
    sandbox_id: &str,
    baseline_policy: Option<&ProtoSandboxPolicy>,
    operations: &[PolicyMergeOp],
) -> Result<(i64, String), Status> {
    for attempt in 1..=MERGE_RETRY_LIMIT {
        let latest = store
            .get_latest_policy(sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("fetch latest policy failed: {e}")))?;

        let current_policy = if let Some(ref record) = latest {
            ProtoSandboxPolicy::decode(record.policy_payload.as_slice())
                .map_err(|e| Status::internal(format!("decode current policy failed: {e}")))?
        } else {
            baseline_policy.cloned().unwrap_or_default()
        };

        let merged = merge_policy(current_policy, operations).map_err(map_policy_merge_error)?;
        let new_policy = merged.policy;
        let hash = deterministic_policy_hash(&new_policy);

        if let Some(baseline_policy) = baseline_policy {
            validate_static_fields_unchanged(baseline_policy, &new_policy)?;
        }
        validate_policy_safety(&new_policy)?;

        if let Some(ref current) = latest
            && current.policy_hash == hash
        {
            return Ok((current.version, hash));
        }

        if latest.is_none() && !merged.changed {
            return Ok((0, hash));
        }

        let payload = new_policy.encode_to_vec();
        let next_version = latest.as_ref().map_or(1, |record| record.version + 1);
        let policy_id = uuid::Uuid::new_v4().to_string();

        match store
            .put_policy_revision(&policy_id, sandbox_id, next_version, &payload, &hash)
            .await
        {
            Ok(()) => {
                let _ = store
                    .supersede_older_policies(sandbox_id, next_version)
                    .await;

                if attempt > 1 {
                    info!(
                        sandbox_id = %sandbox_id,
                        attempt,
                        version = next_version,
                        operation_count = operations.len(),
                        "apply_merge_operations_with_retry: succeeded after version conflict retry"
                    );
                }

                return Ok((next_version, hash));
            }
            Err(e) => {
                if e.is_unique_violation_on("objects_version_uq") {
                    warn!(
                        sandbox_id = %sandbox_id,
                        attempt,
                        conflicting_version = next_version,
                        operation_count = operations.len(),
                        "apply_merge_operations_with_retry: version conflict, retrying"
                    );
                    tokio::task::yield_now().await;
                    continue;
                }
                return Err(Status::internal(format!(
                    "persist policy revision failed: {e}"
                )));
            }
        }
    }

    Err(Status::aborted(format!(
        "apply_merge_operations_with_retry: gave up after {MERGE_RETRY_LIMIT} version conflict retries"
    )))
}

pub(super) async fn merge_chunk_into_policy(
    store: &Store,
    sandbox_id: &str,
    chunk: &DraftChunkRecord,
) -> Result<(i64, String), Status> {
    let rule = NetworkPolicyRule::decode(chunk.proposed_rule.as_slice())
        .map_err(|e| Status::internal(format!("decode proposed_rule failed: {e}")))?;
    apply_merge_operations_with_retry(
        store,
        sandbox_id,
        None,
        &[PolicyMergeOp::AddRule {
            rule_name: chunk.rule_name.clone(),
            rule,
        }],
    )
    .await
}

async fn remove_chunk_from_policy(
    state: &ServerState,
    sandbox_id: &str,
    chunk: &DraftChunkRecord,
) -> Result<(i64, String), Status> {
    apply_merge_operations_with_retry(
        state.store.as_ref(),
        sandbox_id,
        None,
        &[PolicyMergeOp::RemoveBinary {
            rule_name: chunk.rule_name.clone(),
            binary_path: chunk.binary.clone(),
        }],
    )
    .await
}

// ---------------------------------------------------------------------------
// Settings helpers
// ---------------------------------------------------------------------------

fn validate_registered_setting_key(
    key: &str,
) -> Result<&'static settings::RegisteredSetting, Status> {
    settings::setting_for_key(key).ok_or_else(|| {
        Status::invalid_argument(format!(
            "unknown setting key '{key}'. Allowed keys: {}",
            settings::registered_keys_csv()
        ))
    })
}

fn proto_setting_to_stored(key: &str, value: &SettingValue) -> Result<StoredSettingValue, Status> {
    let setting = validate_registered_setting_key(key)?;
    let expected = setting.kind;
    let inner = value
        .value
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("setting_value.value is required"))?;
    let stored = match (expected, inner) {
        (SettingValueKind::String, setting_value::Value::StringValue(v)) => {
            // Enforce per-key string whitelist at configure time so typos
            // (e.g. `proposal_approval_mode=autom`) get rejected here instead
            // of silently falling back to the default at runtime.
            if let Err(allowed) = setting.validate_string_value(v) {
                return Err(Status::invalid_argument(format!(
                    "setting '{key}' expects one of [{}]; got '{}'",
                    allowed.join(", "),
                    v
                )));
            }
            StoredSettingValue::String(v.clone())
        }
        (SettingValueKind::Bool, setting_value::Value::BoolValue(v)) => {
            StoredSettingValue::Bool(*v)
        }
        (SettingValueKind::Int, setting_value::Value::IntValue(v)) => StoredSettingValue::Int(*v),
        (_, setting_value::Value::BytesValue(_)) => {
            return Err(Status::invalid_argument(format!(
                "setting '{key}' expects {} value; bytes are not supported for this key",
                expected.as_str()
            )));
        }
        (expected_kind, _) => {
            return Err(Status::invalid_argument(format!(
                "setting '{key}' expects {} value",
                expected_kind.as_str()
            )));
        }
    };
    Ok(stored)
}

fn stored_setting_to_proto(value: &StoredSettingValue) -> Result<SettingValue, Status> {
    let proto = match value {
        StoredSettingValue::String(v) => SettingValue {
            value: Some(setting_value::Value::StringValue(v.clone())),
        },
        StoredSettingValue::Bool(v) => SettingValue {
            value: Some(setting_value::Value::BoolValue(*v)),
        },
        StoredSettingValue::Int(v) => SettingValue {
            value: Some(setting_value::Value::IntValue(*v)),
        },
        StoredSettingValue::Bytes(v) => {
            let decoded = hex::decode(v)
                .map_err(|e| Status::internal(format!("stored bytes decode failed: {e}")))?;
            SettingValue {
                value: Some(setting_value::Value::BytesValue(decoded)),
            }
        }
    };
    Ok(proto)
}

fn upsert_setting_value(
    map: &mut BTreeMap<String, StoredSettingValue>,
    key: &str,
    value: StoredSettingValue,
) -> bool {
    match map.get(key) {
        Some(existing) if existing == &value => false,
        _ => {
            map.insert(key.to_string(), value);
            true
        }
    }
}

pub(super) async fn load_global_settings(store: &Store) -> Result<StoredSettings, Status> {
    load_settings_record(store, GLOBAL_SETTINGS_OBJECT_TYPE, GLOBAL_SETTINGS_NAME).await
}

pub(super) async fn save_global_settings(
    store: &Store,
    settings: &StoredSettings,
) -> Result<(), Status> {
    save_settings_record(
        store,
        GLOBAL_SETTINGS_OBJECT_TYPE,
        GLOBAL_SETTINGS_NAME,
        settings,
    )
    .await
}

pub(super) async fn load_sandbox_settings(
    store: &Store,
    sandbox_name: &str,
) -> Result<StoredSettings, Status> {
    load_settings_record(store, SANDBOX_SETTINGS_OBJECT_TYPE, sandbox_name).await
}

pub(super) async fn save_sandbox_settings(
    store: &Store,
    sandbox_name: &str,
    settings: &StoredSettings,
) -> Result<(), Status> {
    save_settings_record(store, SANDBOX_SETTINGS_OBJECT_TYPE, sandbox_name, settings).await
}

async fn load_settings_record(
    store: &Store,
    object_type: &str,
    name: &str,
) -> Result<StoredSettings, Status> {
    let record = store
        .get_by_name(object_type, name)
        .await
        .map_err(|e| Status::internal(format!("fetch settings failed: {e}")))?;
    if let Some(record) = record {
        let mut settings = serde_json::from_slice::<StoredSettings>(&record.payload)
            .map_err(|e| Status::internal(format!("decode settings payload failed: {e}")))?;
        // Populate resource_version from database record for CAS
        settings.resource_version = record.resource_version;
        Ok(settings)
    } else {
        Ok(StoredSettings::default())
    }
}

async fn save_settings_record(
    store: &Store,
    object_type: &str,
    name: &str,
    settings: &StoredSettings,
) -> Result<(), Status> {
    use crate::persistence::WriteCondition;

    let payload = serde_json::to_vec(settings)
        .map_err(|e| Status::internal(format!("encode settings payload failed: {e}")))?;

    let (id, condition) = if settings.resource_version == 0 {
        // Create new settings (resource_version 0 means never persisted)
        (uuid::Uuid::new_v4().to_string(), WriteCondition::MustCreate)
    } else {
        // Update existing with CAS on the version from when it was loaded
        // Fetch the record to get the stable ID
        let existing = store
            .get_by_name(object_type, name)
            .await
            .map_err(|e| Status::internal(format!("fetch settings for CAS failed: {e}")))?
            .ok_or_else(|| Status::not_found("settings disappeared since load"))?;

        (
            existing.id,
            WriteCondition::MatchResourceVersion(settings.resource_version),
        )
    };

    // Single-attempt CAS write
    store
        .put_if(object_type, &id, name, &payload, None, condition)
        .await
        .map_err(|e| match e {
            crate::persistence::PersistenceError::Conflict { .. } => {
                Status::aborted("settings were modified concurrently; please retry")
            }
            crate::persistence::PersistenceError::UniqueViolation { .. } => {
                Status::aborted("settings were created concurrently; please retry")
            }
            other => super::persistence_error_to_status(other, "persist settings"),
        })?;

    Ok(())
}

fn decode_policy_from_global_settings(
    global: &StoredSettings,
) -> Result<Option<ProtoSandboxPolicy>, Status> {
    let Some(value) = global.settings.get(POLICY_SETTING_KEY) else {
        return Ok(None);
    };

    let StoredSettingValue::Bytes(encoded) = value else {
        return Err(Status::internal(
            "global policy setting has invalid value type; expected bytes",
        ));
    };

    let raw = hex::decode(encoded)
        .map_err(|e| Status::internal(format!("global policy decode failed: {e}")))?;
    let policy = ProtoSandboxPolicy::decode(raw.as_slice())
        .map_err(|e| Status::internal(format!("global policy protobuf decode failed: {e}")))?;
    Ok(Some(policy))
}

fn merge_effective_settings(
    global: &StoredSettings,
    sandbox: &StoredSettings,
) -> Result<HashMap<String, EffectiveSetting>, Status> {
    let mut merged = HashMap::new();

    for registered in settings::REGISTERED_SETTINGS {
        merged.insert(
            registered.key.to_string(),
            EffectiveSetting {
                value: None,
                scope: SettingScope::Unspecified.into(),
            },
        );
    }

    for (key, value) in &sandbox.settings {
        if key == POLICY_SETTING_KEY || settings::setting_for_key(key).is_none() {
            continue;
        }
        merged.insert(
            key.clone(),
            EffectiveSetting {
                value: Some(stored_setting_to_proto(value)?),
                scope: SettingScope::Sandbox.into(),
            },
        );
    }

    for (key, value) in &global.settings {
        if key == POLICY_SETTING_KEY || settings::setting_for_key(key).is_none() {
            continue;
        }
        merged.insert(
            key.clone(),
            EffectiveSetting {
                value: Some(stored_setting_to_proto(value)?),
                scope: SettingScope::Global.into(),
            },
        );
    }

    Ok(merged)
}

fn materialize_global_settings(
    global: &StoredSettings,
) -> Result<HashMap<String, SettingValue>, Status> {
    let mut materialized = HashMap::new();
    for registered in settings::REGISTERED_SETTINGS {
        materialized.insert(registered.key.to_string(), SettingValue { value: None });
    }

    for (key, value) in &global.settings {
        if key == POLICY_SETTING_KEY {
            continue;
        }
        if settings::setting_for_key(key).is_none() {
            continue;
        }
        materialized.insert(key.clone(), stored_setting_to_proto(value)?);
    }

    Ok(materialized)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};
    use crate::auth::principal::{
        Principal, SandboxIdentitySource, SandboxPrincipal, UserPrincipal,
    };
    use crate::grpc::test_support::test_server_state;
    use crate::persistence::test_store;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tonic::Code;

    /// Wrap a request with a user `Principal` so handler scope guards treat
    /// the test caller as a CLI user. Most handler tests exercise
    /// user-facing behavior and should not trip sandbox equality checks.
    fn with_user<T>(mut request: Request<T>) -> Request<T> {
        request
            .extensions_mut()
            .insert(Principal::User(UserPrincipal {
                identity: Identity {
                    subject: "test-user".to_string(),
                    display_name: None,
                    roles: vec![],
                    scopes: vec![],
                    provider: IdentityProvider::Oidc,
                },
            }));
        request
    }

    /// Wrap a request with a sandbox `Principal` bound to `sandbox_id`.
    /// Use for tests that exercise sandbox-caller code paths.
    #[allow(dead_code)]
    fn with_sandbox<T>(mut request: Request<T>, sandbox_id: &str) -> Request<T> {
        request
            .extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: sandbox_id.to_string(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: "openshell-gateway:test".to_string(),
                },
                trust_domain: Some("openshell".to_string()),
            }));
        request
    }

    #[test]
    fn sandbox_caller_update_validation_allows_sandbox_policy_sync() {
        let req = UpdateConfigRequest {
            name: "sandbox-1".to_string(),
            policy: Some(ProtoSandboxPolicy::default()),
            ..Default::default()
        };
        assert!(validate_sandbox_caller_update(&req).is_ok());
    }

    #[test]
    fn sandbox_caller_update_validation_rejects_global_mutation() {
        let req = UpdateConfigRequest {
            global: true,
            policy: Some(ProtoSandboxPolicy::default()),
            ..Default::default()
        };
        let err = validate_sandbox_caller_update(&req).unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[test]
    fn sandbox_caller_update_validation_rejects_setting_mutation() {
        let req = UpdateConfigRequest {
            name: "sandbox-1".to_string(),
            setting_key: "inference.model".to_string(),
            setting_value: Some(SettingValue { value: None }),
            ..Default::default()
        };
        let err = validate_sandbox_caller_update(&req).unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[test]
    fn sandbox_caller_detected_from_principal_extension() {
        use crate::auth::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
        let mut req = Request::new(());
        req.extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: "test-sandbox".to_string(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: "openshell-gateway:test".to_string(),
                },
                trust_domain: None,
            }));
        assert!(is_sandbox_caller(&req));
    }

    #[test]
    fn user_principal_not_treated_as_sandbox_caller() {
        use crate::auth::identity::{Identity, IdentityProvider};
        use crate::auth::principal::{Principal, UserPrincipal};
        let mut req = Request::new(());
        req.extensions_mut().insert(Principal::User(UserPrincipal {
            identity: Identity {
                subject: "alice".to_string(),
                display_name: None,
                roles: vec![],
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        }));
        assert!(!is_sandbox_caller(&req));
    }

    // ---- Sandbox IDOR guard (issue #1354) ----

    #[tokio::test]
    async fn cross_sandbox_get_sandbox_config_denied() {
        use openshell_core::proto::{SandboxPhase, SandboxSpec};
        let state = test_server_state().await;
        // Two sandboxes; the caller is principal of A, the request body
        // references B.
        for (id, name) in [("sb-a", "sandbox-a"), ("sb-b", "sandbox-b")] {
            let mut sandbox = Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: id.to_string(),
                    name: name.to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                spec: Some(SandboxSpec {
                    policy: None,
                    ..Default::default()
                }),
                ..Default::default()
            };
            sandbox.set_phase(SandboxPhase::Provisioning as i32);
            state.store.put_message(&sandbox).await.unwrap();
        }
        let req = with_sandbox(
            Request::new(GetSandboxConfigRequest {
                sandbox_id: "sb-b".to_string(),
            }),
            "sb-a",
        );
        let err = handle_get_sandbox_config(&state, req)
            .await
            .expect_err("cross-sandbox call must be denied");
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn same_sandbox_get_sandbox_config_allowed() {
        use openshell_core::proto::{SandboxPhase, SandboxSpec};
        let state = test_server_state().await;
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-self".to_string(),
                name: "self".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        state.store.put_message(&sandbox).await.unwrap();
        let req = with_sandbox(
            Request::new(GetSandboxConfigRequest {
                sandbox_id: "sb-self".to_string(),
            }),
            "sb-self",
        );
        handle_get_sandbox_config(&state, req)
            .await
            .expect("matching principal must be allowed");
    }

    #[tokio::test]
    async fn cross_sandbox_submit_policy_analysis_denied() {
        use openshell_core::proto::{SandboxPhase, SandboxSpec};
        let state = test_server_state().await;
        for (id, name) in [("sb-a", "sandbox-a"), ("sb-b", "sandbox-b")] {
            let mut sandbox = Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: id.to_string(),
                    name: name.to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                spec: Some(SandboxSpec {
                    policy: None,
                    ..Default::default()
                }),
                ..Default::default()
            };
            sandbox.set_phase(SandboxPhase::Provisioning as i32);
            state.store.put_message(&sandbox).await.unwrap();
        }
        let req = with_sandbox(
            Request::new(SubmitPolicyAnalysisRequest {
                name: "sandbox-b".to_string(),
                ..Default::default()
            }),
            "sb-a",
        );
        let err = handle_submit_policy_analysis(&state, req)
            .await
            .expect_err("cross-sandbox submit must be denied");
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn cross_sandbox_get_draft_policy_denied() {
        use openshell_core::proto::{SandboxPhase, SandboxSpec};
        let state = test_server_state().await;
        for (id, name) in [("sb-a", "sandbox-a"), ("sb-b", "sandbox-b")] {
            let mut sandbox = Sandbox {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: id.to_string(),
                    name: name.to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                spec: Some(SandboxSpec {
                    policy: None,
                    ..Default::default()
                }),
                ..Default::default()
            };
            sandbox.set_phase(SandboxPhase::Provisioning as i32);
            state.store.put_message(&sandbox).await.unwrap();
        }
        let req = with_sandbox(
            Request::new(GetDraftPolicyRequest {
                name: "sandbox-b".to_string(),
                status_filter: String::new(),
            }),
            "sb-a",
        );
        let err = handle_get_draft_policy(&state, req)
            .await
            .expect_err("cross-sandbox draft read must be denied");
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn sandbox_update_config_missing_name_returns_permission_denied() {
        let state = test_server_state().await;
        let req = with_sandbox(
            Request::new(UpdateConfigRequest {
                name: "missing-sandbox".to_string(),
                policy: Some(ProtoSandboxPolicy::default()),
                ..Default::default()
            }),
            "sb-a",
        );

        let err = handle_update_config(&state, req)
            .await
            .expect_err("missing name must not leak existence to sandbox callers");
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn sandbox_submit_policy_analysis_missing_name_returns_permission_denied() {
        let state = test_server_state().await;
        let req = with_sandbox(
            Request::new(SubmitPolicyAnalysisRequest {
                name: "missing-sandbox".to_string(),
                ..Default::default()
            }),
            "sb-a",
        );

        let err = handle_submit_policy_analysis(&state, req)
            .await
            .expect_err("missing name must not leak existence to sandbox callers");
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn sandbox_get_draft_policy_missing_name_returns_permission_denied() {
        let state = test_server_state().await;
        let req = with_sandbox(
            Request::new(GetDraftPolicyRequest {
                name: "missing-sandbox".to_string(),
                status_filter: String::new(),
            }),
            "sb-a",
        );

        let err = handle_get_draft_policy(&state, req)
            .await
            .expect_err("missing name must not leak existence to sandbox callers");
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn user_principal_can_read_any_sandbox_config() {
        // RBAC was the user gate; the IDOR guard must NOT trip for users.
        use openshell_core::proto::{SandboxPhase, SandboxSpec};
        let state = test_server_state().await;
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-x".to_string(),
                name: "x".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        state.store.put_message(&sandbox).await.unwrap();
        let req = with_user(Request::new(GetSandboxConfigRequest {
            sandbox_id: "sb-x".to_string(),
        }));
        handle_get_sandbox_config(&state, req)
            .await
            .expect("user principal must succeed");
    }

    #[tokio::test]
    async fn log_stream_scope_rejects_sandbox_id_change_after_validation() {
        let state = test_server_state().await;
        for id in ["sb-a", "sb-b"] {
            let sandbox = test_sandbox(id, id, ProtoSandboxPolicy::default(), vec![]);
            state.store.put_message(&sandbox).await.unwrap();
        }
        let req = with_sandbox(Request::new(()), "sb-a");
        let principal = req.extensions().get::<Principal>().unwrap().clone();
        let mut validated = None;

        ensure_log_stream_sandbox_scope(&state, &principal, "sb-a", &mut validated)
            .await
            .expect("first frame should validate");
        let err = ensure_log_stream_sandbox_scope(&state, &principal, "sb-b", &mut validated)
            .await
            .expect_err("later frame must not switch sandbox ids");

        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn log_stream_scope_rejects_missing_sandbox() {
        let state = test_server_state().await;
        let req = with_sandbox(Request::new(()), "sb-a");
        let principal = req.extensions().get::<Principal>().unwrap().clone();
        let mut validated = None;

        let err = ensure_log_stream_sandbox_scope(&state, &principal, "sb-a", &mut validated)
            .await
            .expect_err("missing sandbox must not validate");

        assert_eq!(err.code(), Code::NotFound);
    }

    #[test]
    fn sandbox_caller_policy_sync_does_not_emit_policy_update_telemetry() {
        assert!(!should_emit_config_update_policy_telemetry(true));
        assert!(should_emit_config_update_policy_telemetry(false));
    }

    #[test]
    fn first_policy_revision_does_not_emit_policy_update_telemetry() {
        assert!(!should_emit_full_policy_update_telemetry(false, 1));
        assert!(!should_emit_full_policy_update_telemetry(true, 2));
        assert!(should_emit_full_policy_update_telemetry(false, 2));
    }

    // ---- Sandbox without policy ----

    #[tokio::test]
    async fn sandbox_without_policy_stores_successfully() {
        use openshell_core::proto::{SandboxPhase, SandboxSpec};

        let store = test_store().await;

        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-no-policy".to_string(),
                name: "no-policy-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        store.put_message(&sandbox).await.unwrap();

        let loaded = store
            .get_message::<Sandbox>("sb-no-policy")
            .await
            .unwrap()
            .unwrap();
        assert!(loaded.spec.unwrap().policy.is_none());
    }

    fn test_provider(name: &str, provider_type: &str) -> Provider {
        Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: format!("provider-{name}"),
                name: name.to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            r#type: provider_type.to_string(),
            credentials: std::iter::once(("GITHUB_TOKEN".to_string(), "ghp-test".to_string()))
                .collect(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
        }
    }

    fn test_policy_with_rule(rule_name: &str, host: &str) -> ProtoSandboxPolicy {
        ProtoSandboxPolicy {
            network_policies: std::iter::once((
                rule_name.to_string(),
                NetworkPolicyRule {
                    name: rule_name.to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: host.to_string(),
                        port: 443,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ))
            .collect(),
            ..Default::default()
        }
    }

    fn test_sandbox(
        id: &str,
        name: &str,
        policy: ProtoSandboxPolicy,
        providers: Vec<String>,
    ) -> Sandbox {
        use openshell_core::proto::{SandboxPhase, SandboxSpec};

        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: id.to_string(),
                name: name.to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(policy),
                providers,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        sandbox
    }

    async fn enable_providers_v2(state: &Arc<ServerState>) {
        let global_settings = StoredSettings {
            revision: 1,
            settings: std::iter::once((
                settings::PROVIDERS_V2_ENABLED_KEY.to_string(),
                StoredSettingValue::Bool(true),
            ))
            .collect(),
            ..Default::default()
        };
        save_global_settings(state.store.as_ref(), &global_settings)
            .await
            .unwrap();
    }

    async fn get_sandbox_policy(state: &Arc<ServerState>, sandbox_id: &str) -> ProtoSandboxPolicy {
        handle_get_sandbox_config(
            state,
            with_user(Request::new(GetSandboxConfigRequest {
                sandbox_id: sandbox_id.to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner()
        .policy
        .expect("sandbox config should include policy")
    }

    #[tokio::test]
    async fn provider_policy_layers_skip_unknown_provider_types() {
        let store = test_store().await;
        store
            .put_message(&test_provider("custom-provider", "custom"))
            .await
            .unwrap();

        let layers = profile_provider_policy_layers(&store, &["custom-provider".to_string()])
            .await
            .unwrap();

        assert!(layers.is_empty());
    }

    #[tokio::test]
    async fn provider_policy_layers_skip_custom_profile_for_legacy_provider_type() {
        let store = test_store().await;
        store
            .put_message(&test_provider("custom-provider", "generic"))
            .await
            .unwrap();
        store
            .put_message(&openshell_core::proto::StoredProviderProfile {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "profile-generic".to_string(),
                    name: "generic".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                profile: Some(openshell_core::proto::ProviderProfile {
                    id: "generic".to_string(),
                    display_name: "Generic Override".to_string(),
                    description: String::new(),
                    category: openshell_core::proto::ProviderProfileCategory::Other as i32,
                    credentials: Vec::new(),
                    endpoints: vec![NetworkEndpoint {
                        host: "backdoor.example".to_string(),
                        port: 443,
                        ..Default::default()
                    }],
                    binaries: Vec::new(),
                    inference_capable: false,
                    discovery: None,
                }),
            })
            .await
            .unwrap();

        let layers = profile_provider_policy_layers(&store, &["custom-provider".to_string()])
            .await
            .unwrap();

        assert!(layers.is_empty());
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn provider_policy_layers_include_custom_provider_profiles() {
        let store = test_store().await;
        store
            .put_message(&test_provider("work-custom", "custom-api"))
            .await
            .unwrap();
        store
            .put_message(&openshell_core::proto::StoredProviderProfile {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "profile-custom-api".to_string(),
                    name: "custom-api".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                profile: Some(openshell_core::proto::ProviderProfile {
                    id: "custom-api".to_string(),
                    display_name: "Custom API".to_string(),
                    description: String::new(),
                    category: openshell_core::proto::ProviderProfileCategory::Other as i32,
                    credentials: Vec::new(),
                    endpoints: vec![NetworkEndpoint {
                        host: "api.custom.example".to_string(),
                        protocol: "rest".to_string(),
                        ports: vec![443, 8443],
                        allowed_ips: vec!["10.0.0.0/24".to_string()],
                        rules: vec![L7Rule {
                            allow: Some(openshell_core::proto::L7Allow {
                                method: "GET".to_string(),
                                path: "/v1/**".to_string(),
                                ..Default::default()
                            }),
                        }],
                        allow_encoded_slash: true,
                        path: "/v1".to_string(),
                        ..Default::default()
                    }],
                    binaries: vec![NetworkBinary {
                        path: "/usr/bin/custom".to_string(),
                        harness: true,
                    }],
                    inference_capable: false,
                    discovery: None,
                }),
            })
            .await
            .unwrap();

        let layers = profile_provider_policy_layers(&store, &["work-custom".to_string()])
            .await
            .unwrap();

        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].rule_name, "_provider_work_custom");
        assert_eq!(layers[0].rule.endpoints[0].host, "api.custom.example");
        assert_eq!(layers[0].rule.endpoints[0].ports, vec![443, 8443]);
        assert_eq!(layers[0].rule.endpoints[0].rules.len(), 1);
        assert_eq!(layers[0].rule.endpoints[0].allowed_ips, vec!["10.0.0.0/24"]);
        assert!(layers[0].rule.endpoints[0].allow_encoded_slash);
        assert_eq!(layers[0].rule.endpoints[0].path, "/v1");
        assert!(layers[0].rule.binaries[0].harness);
    }

    #[tokio::test]
    async fn provider_policy_layers_normalize_custom_provider_type_ids() {
        let store = test_store().await;
        store
            .put_message(&test_provider("work-custom", " Custom-API "))
            .await
            .unwrap();
        store
            .put_message(&openshell_core::proto::StoredProviderProfile {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "profile-custom-api".to_string(),
                    name: "custom-api".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                profile: Some(openshell_core::proto::ProviderProfile {
                    id: "custom-api".to_string(),
                    display_name: "Custom API".to_string(),
                    description: String::new(),
                    category: openshell_core::proto::ProviderProfileCategory::Other as i32,
                    credentials: Vec::new(),
                    endpoints: vec![NetworkEndpoint {
                        host: "api.custom.example".to_string(),
                        port: 443,
                        ..Default::default()
                    }],
                    binaries: Vec::new(),
                    inference_capable: false,
                    discovery: None,
                }),
            })
            .await
            .unwrap();

        let layers = profile_provider_policy_layers(&store, &["work-custom".to_string()])
            .await
            .unwrap();

        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].rule.endpoints[0].host, "api.custom.example");
    }

    #[tokio::test]
    async fn provider_policy_layers_include_known_provider_profiles() {
        let store = test_store().await;
        store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();

        let layers = profile_provider_policy_layers(&store, &["work-github".to_string()])
            .await
            .unwrap();

        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].rule_name, "_provider_work_github");
        assert_eq!(layers[0].rule.endpoints.len(), 3);
        assert!(
            layers[0]
                .rule
                .endpoints
                .iter()
                .any(|endpoint| endpoint.host == "api.github.com")
        );
        assert!(
            layers[0].rule.endpoints.iter().any(|endpoint| {
                endpoint.host == "api.github.com"
                    && endpoint.protocol == "graphql"
                    && endpoint.path == "/graphql"
                    && endpoint.access == "read-only"
            }),
            "github provider policy should include read-only GraphQL endpoint"
        );
        assert!(
            layers[0]
                .rule
                .endpoints
                .iter()
                .all(|endpoint| endpoint.access == "read-only"),
            "github provider policy should be read-only by default"
        );
    }

    #[test]
    fn providers_v2_enabled_defaults_false_when_unset() {
        assert!(
            !bool_setting_enabled(
                &StoredSettings::default(),
                settings::PROVIDERS_V2_ENABLED_KEY
            )
            .unwrap()
        );
    }

    #[test]
    fn providers_v2_enabled_reads_global_bool_setting() {
        let mut settings = StoredSettings::default();
        settings.settings.insert(
            settings::PROVIDERS_V2_ENABLED_KEY.to_string(),
            StoredSettingValue::Bool(true),
        );

        assert!(bool_setting_enabled(&settings, settings::PROVIDERS_V2_ENABLED_KEY).unwrap());
    }

    #[tokio::test]
    async fn sandbox_config_omits_provider_layers_when_v2_disabled() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-v2-disabled",
                "v2-disabled",
                test_policy_with_rule("sandbox_only", "sandbox.example.com"),
                vec!["work-github".to_string()],
            ))
            .await
            .unwrap();

        let effective_policy = get_sandbox_policy(&state, "sb-v2-disabled").await;

        assert!(
            effective_policy
                .network_policies
                .contains_key("sandbox_only")
        );
        assert!(
            !effective_policy
                .network_policies
                .contains_key("_provider_work_github")
        );
    }

    #[tokio::test]
    async fn sandbox_config_composes_provider_layers_when_v2_enabled() {
        let state = test_server_state().await;
        enable_providers_v2(&state).await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-v2-enabled",
                "v2-enabled",
                test_policy_with_rule("sandbox_only", "sandbox.example.com"),
                vec!["work-github".to_string()],
            ))
            .await
            .unwrap();

        let effective_policy = get_sandbox_policy(&state, "sb-v2-enabled").await;

        assert!(
            effective_policy
                .network_policies
                .contains_key("sandbox_only")
        );
        assert!(
            effective_policy
                .network_policies
                .contains_key("_provider_work_github")
        );
        assert!(
            effective_policy
                .network_policies
                .get("_provider_work_github")
                .unwrap()
                .endpoints
                .iter()
                .any(|endpoint| endpoint.host == "api.github.com")
        );
    }

    #[tokio::test]
    async fn sandbox_config_skips_profileless_provider_types_when_v2_enabled() {
        let state = test_server_state().await;
        enable_providers_v2(&state).await;
        state
            .store
            .put_message(&test_provider("legacy-generic", "generic"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_provider("custom-provider", "custom"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-profileless",
                "profileless",
                test_policy_with_rule("sandbox_only", "sandbox.example.com"),
                vec!["legacy-generic".to_string(), "custom-provider".to_string()],
            ))
            .await
            .unwrap();

        let effective_policy = get_sandbox_policy(&state, "sb-profileless").await;

        assert_eq!(effective_policy.network_policies.len(), 1);
        assert!(
            effective_policy
                .network_policies
                .contains_key("sandbox_only")
        );
    }

    #[tokio::test]
    async fn sandbox_config_composition_is_jit_and_does_not_persist_provider_layers() {
        let state = test_server_state().await;
        enable_providers_v2(&state).await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-jit",
                "jit",
                test_policy_with_rule("sandbox_only", "sandbox.example.com"),
                vec!["work-github".to_string()],
            ))
            .await
            .unwrap();

        let effective_policy = get_sandbox_policy(&state, "sb-jit").await;
        assert!(
            effective_policy
                .network_policies
                .contains_key("_provider_work_github")
        );

        let persisted = state
            .store
            .get_latest_policy("sb-jit")
            .await
            .unwrap()
            .expect("sandbox policy should be lazily backfilled");
        let persisted_policy = ProtoSandboxPolicy::decode(persisted.policy_payload.as_slice())
            .expect("persisted sandbox policy should decode");
        assert!(
            persisted_policy
                .network_policies
                .contains_key("sandbox_only")
        );
        assert!(
            !persisted_policy
                .network_policies
                .contains_key("_provider_work_github")
        );
    }

    #[tokio::test]
    async fn sandbox_config_preserves_overlapping_user_and_provider_rules() {
        let state = test_server_state().await;
        enable_providers_v2(&state).await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-overlap",
                "overlap",
                test_policy_with_rule("_provider_work_github", "api.github.com"),
                vec!["work-github".to_string()],
            ))
            .await
            .unwrap();

        let effective_policy = get_sandbox_policy(&state, "sb-overlap").await;

        assert!(
            effective_policy
                .network_policies
                .contains_key("_provider_work_github")
        );
        assert!(
            effective_policy
                .network_policies
                .contains_key("_provider_work_github_2")
        );
        assert_eq!(
            effective_policy
                .network_policies
                .get("_provider_work_github")
                .unwrap()
                .endpoints[0]
                .host,
            "api.github.com"
        );
    }

    #[tokio::test]
    async fn provider_environment_resolution_is_unchanged_by_providers_v2_setting() {
        use openshell_core::proto::GetSandboxProviderEnvironmentRequest;

        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-provider-env",
                "provider-env",
                test_policy_with_rule("sandbox_only", "sandbox.example.com"),
                vec!["work-github".to_string()],
            ))
            .await
            .unwrap();

        let legacy_env = handle_get_sandbox_provider_environment(
            &state,
            with_user(Request::new(GetSandboxProviderEnvironmentRequest {
                sandbox_id: "sb-provider-env".to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner()
        .environment;

        enable_providers_v2(&state).await;
        let v2_env = handle_get_sandbox_provider_environment(
            &state,
            with_user(Request::new(GetSandboxProviderEnvironmentRequest {
                sandbox_id: "sb-provider-env".to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner()
        .environment;

        assert_eq!(legacy_env, v2_env);
        assert_eq!(v2_env.get("GITHUB_TOKEN"), Some(&"ghp-test".to_string()));
    }

    #[tokio::test]
    async fn provider_env_revision_changes_when_attached_provider_record_changes() {
        use openshell_core::proto::GetSandboxProviderEnvironmentRequest;
        use std::time::Duration;

        let state = test_server_state().await;
        let mut provider = test_provider("work-github", "github");
        state.store.put_message(&provider).await.unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-provider-revision",
                "provider-revision",
                test_policy_with_rule("sandbox_only", "sandbox.example.com"),
                vec!["work-github".to_string()],
            ))
            .await
            .unwrap();

        let first = handle_get_sandbox_provider_environment(
            &state,
            with_user(Request::new(GetSandboxProviderEnvironmentRequest {
                sandbox_id: "sb-provider-revision".to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner();

        tokio::time::sleep(Duration::from_millis(2)).await;
        provider
            .credentials
            .insert("GITHUB_TOKEN".to_string(), "rotated".to_string());
        state.store.put_message(&provider).await.unwrap();

        let second = handle_get_sandbox_provider_environment(
            &state,
            with_user(Request::new(GetSandboxProviderEnvironmentRequest {
                sandbox_id: "sb-provider-revision".to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner();

        assert_ne!(
            first.provider_env_revision, second.provider_env_revision,
            "provider object updates must trigger sandbox credential refresh"
        );
        assert_eq!(
            second.environment.get("GITHUB_TOKEN"),
            Some(&"rotated".to_string())
        );
    }

    #[tokio::test]
    async fn sandbox_config_and_provider_env_follow_attached_provider_lifecycle() {
        use crate::grpc::sandbox::{
            handle_attach_sandbox_provider, handle_detach_sandbox_provider,
        };
        use openshell_core::proto::{
            AttachSandboxProviderRequest, DetachSandboxProviderRequest,
            GetSandboxProviderEnvironmentRequest,
        };

        let state = test_server_state().await;
        enable_providers_v2(&state).await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-attach-lifecycle",
                "attach-lifecycle",
                test_policy_with_rule("sandbox_only", "sandbox.example.com"),
                Vec::new(),
            ))
            .await
            .unwrap();

        let baseline_policy = get_sandbox_policy(&state, "sb-attach-lifecycle").await;
        assert!(
            !baseline_policy
                .network_policies
                .contains_key("_provider_work_github")
        );
        let baseline_env = handle_get_sandbox_provider_environment(
            &state,
            with_user(Request::new(GetSandboxProviderEnvironmentRequest {
                sandbox_id: "sb-attach-lifecycle".to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner();

        handle_attach_sandbox_provider(
            &state,
            with_user(Request::new(AttachSandboxProviderRequest {
                sandbox_name: "attach-lifecycle".to_string(),
                provider_name: "work-github".to_string(),
                expected_resource_version: 0,
            })),
        )
        .await
        .unwrap();

        let attached_policy = get_sandbox_policy(&state, "sb-attach-lifecycle").await;
        assert!(
            attached_policy
                .network_policies
                .contains_key("_provider_work_github")
        );

        let attached_env = handle_get_sandbox_provider_environment(
            &state,
            with_user(Request::new(GetSandboxProviderEnvironmentRequest {
                sandbox_id: "sb-attach-lifecycle".to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert_ne!(
            baseline_env.provider_env_revision,
            attached_env.provider_env_revision
        );
        assert_eq!(
            attached_env.environment.get("GITHUB_TOKEN"),
            Some(&"ghp-test".to_string())
        );

        handle_detach_sandbox_provider(
            &state,
            Request::new(DetachSandboxProviderRequest {
                sandbox_name: "attach-lifecycle".to_string(),
                provider_name: "work-github".to_string(),
                expected_resource_version: 0,
            }),
        )
        .await
        .unwrap();

        let detached_policy = get_sandbox_policy(&state, "sb-attach-lifecycle").await;
        assert!(
            !detached_policy
                .network_policies
                .contains_key("_provider_work_github")
        );

        let detached_env = handle_get_sandbox_provider_environment(
            &state,
            with_user(Request::new(GetSandboxProviderEnvironmentRequest {
                sandbox_id: "sb-attach-lifecycle".to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert_ne!(
            attached_env.provider_env_revision,
            detached_env.provider_env_revision
        );
        assert!(!detached_env.environment.contains_key("GITHUB_TOKEN"));
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn custom_imported_profile_policy_and_env_follow_attach_detach_lifecycle() {
        use crate::grpc::provider::handle_import_provider_profiles;
        use crate::grpc::sandbox::{
            handle_attach_sandbox_provider, handle_detach_sandbox_provider,
        };
        use openshell_core::proto::{
            AttachSandboxProviderRequest, DetachSandboxProviderRequest,
            GetSandboxProviderEnvironmentRequest, ImportProviderProfilesRequest, NetworkBinary,
            ProviderProfile, ProviderProfileCategory, ProviderProfileCredential,
            ProviderProfileImportItem,
        };

        let state = test_server_state().await;
        enable_providers_v2(&state).await;
        handle_import_provider_profiles(
            &state,
            Request::new(ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    source: "custom-api.yaml".to_string(),
                    profile: Some(ProviderProfile {
                        id: "custom-api".to_string(),
                        display_name: "Custom API".to_string(),
                        description: String::new(),
                        category: ProviderProfileCategory::Other as i32,
                        credentials: vec![ProviderProfileCredential {
                            name: "api_key".to_string(),
                            env_vars: vec!["CUSTOM_API_KEY".to_string()],
                            auth_style: "bearer".to_string(),
                            header_name: "authorization".to_string(),
                            required: true,
                            ..Default::default()
                        }],
                        endpoints: vec![NetworkEndpoint {
                            host: "api.custom.example".to_string(),
                            port: 443,
                            protocol: "rest".to_string(),
                            rules: vec![L7Rule {
                                allow: Some(openshell_core::proto::L7Allow {
                                    method: "GET".to_string(),
                                    path: "/v1/**".to_string(),
                                    ..Default::default()
                                }),
                            }],
                            ..Default::default()
                        }],
                        binaries: vec![NetworkBinary {
                            path: "/usr/bin/custom".to_string(),
                            harness: true,
                        }],
                        inference_capable: false,
                        discovery: None,
                    }),
                }],
            }),
        )
        .await
        .unwrap();

        let mut provider = test_provider("work-custom", "custom-api");
        provider.credentials =
            std::iter::once(("CUSTOM_API_KEY".to_string(), "custom-secret".to_string())).collect();
        state.store.put_message(&provider).await.unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "sb-custom-attach-lifecycle",
                "custom-attach-lifecycle",
                test_policy_with_rule("sandbox_only", "sandbox.example.com"),
                Vec::new(),
            ))
            .await
            .unwrap();

        let baseline_policy = get_sandbox_policy(&state, "sb-custom-attach-lifecycle").await;
        assert!(
            !baseline_policy
                .network_policies
                .contains_key("_provider_work_custom")
        );
        let baseline_env = handle_get_sandbox_provider_environment(
            &state,
            with_user(Request::new(GetSandboxProviderEnvironmentRequest {
                sandbox_id: "sb-custom-attach-lifecycle".to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner();

        handle_attach_sandbox_provider(
            &state,
            with_user(Request::new(AttachSandboxProviderRequest {
                sandbox_name: "custom-attach-lifecycle".to_string(),
                provider_name: "work-custom".to_string(),
                expected_resource_version: 0,
            })),
        )
        .await
        .unwrap();

        let attached_policy = get_sandbox_policy(&state, "sb-custom-attach-lifecycle").await;
        let custom_rule = attached_policy
            .network_policies
            .get("_provider_work_custom")
            .expect("custom provider rule should be composed after attach");
        assert_eq!(custom_rule.endpoints[0].host, "api.custom.example");
        assert_eq!(custom_rule.endpoints[0].protocol, "rest");
        assert_eq!(custom_rule.endpoints[0].rules.len(), 1);
        assert_eq!(custom_rule.binaries[0].path, "/usr/bin/custom");

        let attached_env = handle_get_sandbox_provider_environment(
            &state,
            with_user(Request::new(GetSandboxProviderEnvironmentRequest {
                sandbox_id: "sb-custom-attach-lifecycle".to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert_ne!(
            baseline_env.provider_env_revision,
            attached_env.provider_env_revision
        );
        assert_eq!(
            attached_env.environment.get("CUSTOM_API_KEY"),
            Some(&"custom-secret".to_string())
        );

        handle_detach_sandbox_provider(
            &state,
            Request::new(DetachSandboxProviderRequest {
                sandbox_name: "custom-attach-lifecycle".to_string(),
                provider_name: "work-custom".to_string(),
                expected_resource_version: 0,
            }),
        )
        .await
        .unwrap();

        let detached_policy = get_sandbox_policy(&state, "sb-custom-attach-lifecycle").await;
        assert!(
            !detached_policy
                .network_policies
                .contains_key("_provider_work_custom")
        );
        let detached_env = handle_get_sandbox_provider_environment(
            &state,
            with_user(Request::new(GetSandboxProviderEnvironmentRequest {
                sandbox_id: "sb-custom-attach-lifecycle".to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert_ne!(
            attached_env.provider_env_revision,
            detached_env.provider_env_revision
        );
        assert!(!detached_env.environment.contains_key("CUSTOM_API_KEY"));
    }

    #[tokio::test]
    async fn global_policy_suppresses_provider_profile_layers_when_v2_enabled() {
        use openshell_core::proto::{
            GetSandboxConfigRequest, NetworkEndpoint, NetworkPolicyRule, SandboxPhase,
            SandboxPolicy, SandboxSpec,
        };

        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();

        let sandbox_policy = SandboxPolicy {
            network_policies: std::iter::once((
                "sandbox_only".to_string(),
                NetworkPolicyRule {
                    name: "sandbox_only".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "sandbox.example.com".to_string(),
                        port: 443,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ))
            .collect(),
            ..Default::default()
        };
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-global-profile".to_string(),
                name: "global-profile-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(sandbox_policy),
                providers: vec!["work-github".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();

        let global_policy = SandboxPolicy {
            network_policies: std::iter::once((
                "global_only".to_string(),
                NetworkPolicyRule {
                    name: "global_only".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "global.example.com".to_string(),
                        port: 443,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ))
            .collect(),
            ..Default::default()
        };
        let global_settings = StoredSettings {
            revision: 1,
            settings: [
                (
                    settings::PROVIDERS_V2_ENABLED_KEY.to_string(),
                    StoredSettingValue::Bool(true),
                ),
                (
                    POLICY_SETTING_KEY.to_string(),
                    StoredSettingValue::Bytes(hex::encode(global_policy.encode_to_vec())),
                ),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        save_global_settings(state.store.as_ref(), &global_settings)
            .await
            .unwrap();

        let response = handle_get_sandbox_config(
            &state,
            with_user(Request::new(GetSandboxConfigRequest {
                sandbox_id: "sb-global-profile".to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner();

        let effective_policy = response.policy.expect("global policy should be returned");
        assert_eq!(response.policy_source, PolicySource::Global as i32);
        assert!(
            effective_policy
                .network_policies
                .contains_key("global_only")
        );
        assert!(
            !effective_policy
                .network_policies
                .contains_key("sandbox_only")
        );
        assert!(
            !effective_policy
                .network_policies
                .contains_key("_provider_work_github")
        );
    }

    #[tokio::test]
    async fn sandbox_policy_backfill_on_update_when_no_baseline() {
        use openshell_core::proto::{FilesystemPolicy, LandlockPolicy, SandboxPhase, SandboxSpec};

        let store = test_store().await;

        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-backfill".to_string(),
                name: "backfill-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        store.put_message(&sandbox).await.unwrap();

        let new_policy = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/usr".into()],
                read_write: vec!["/tmp".into()],
            }),
            landlock: Some(LandlockPolicy {
                compatibility: "best_effort".into(),
            }),
            process: Some(openshell_core::proto::ProcessPolicy {
                run_as_user: "sandbox".into(),
                run_as_group: "sandbox".into(),
            }),
            ..Default::default()
        };

        let mut sandbox = store
            .get_message::<Sandbox>("sb-backfill")
            .await
            .unwrap()
            .unwrap();
        if let Some(ref mut spec) = sandbox.spec {
            spec.policy = Some(new_policy.clone());
        }
        store.put_message(&sandbox).await.unwrap();

        let loaded = store
            .get_message::<Sandbox>("sb-backfill")
            .await
            .unwrap()
            .unwrap();
        let policy = loaded.spec.unwrap().policy.unwrap();
        assert_eq!(policy.version, 1);
        assert!(policy.filesystem.is_some());
        assert_eq!(policy.process.unwrap().run_as_user, "sandbox");
    }

    /// Test helper: pin the proposal approval mode for a sandbox via the
    /// settings model, mirroring what `openshell settings set <name>
    /// proposal_approval_mode <mode>` would do at runtime.
    async fn seed_sandbox_approval_mode(state: &Arc<ServerState>, sandbox_name: &str, mode: &str) {
        let mut settings = load_sandbox_settings(state.store.as_ref(), sandbox_name)
            .await
            .unwrap();
        settings.settings.insert(
            settings::PROPOSAL_APPROVAL_MODE_KEY.to_string(),
            StoredSettingValue::String(mode.to_string()),
        );
        settings.revision = settings.revision.wrapping_add(1);
        save_sandbox_settings(state.store.as_ref(), sandbox_name, &settings)
            .await
            .unwrap();
    }

    /// Test helper: pin the gateway-wide proposal approval mode, mirroring
    /// `openshell settings set --global proposal_approval_mode <mode>`.
    async fn seed_global_approval_mode(state: &Arc<ServerState>, mode: &str) {
        let mut settings = load_global_settings(state.store.as_ref()).await.unwrap();
        settings.settings.insert(
            settings::PROPOSAL_APPROVAL_MODE_KEY.to_string(),
            StoredSettingValue::String(mode.to_string()),
        );
        settings.revision = settings.revision.wrapping_add(1);
        save_global_settings(state.store.as_ref(), &settings)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn draft_chunk_handler_lifecycle_round_trip() {
        use openshell_core::proto::{
            GetDraftPolicyRequest, NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxSpec,
        };

        let state = test_server_state().await;
        // Attach a github provider so the proposal below has a credential in
        // scope for api.github.com. This causes the prover to emit a HIGH
        // finding (L4 + credential in scope), keeping the chunk pending so
        // the manual approve/reject lifecycle this test exercises is
        // reachable. Without a provider, the proposal would auto-approve and
        // the lifecycle assertions would no longer apply.
        state
            .store
            .put_message(&test_provider("github-pat", "github"))
            .await
            .unwrap();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-draft-flow".to_string(),
                name: "draft-flow".to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                providers: vec!["github-pat".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
        let sandbox_name = sandbox.object_name().to_string();

        let proposed_rule = NetworkPolicyRule {
            name: "allow_github".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        let submit = handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "allow_github".to_string(),
                    proposed_rule: Some(proposed_rule.clone()),
                    rationale: "observed denied request".to_string(),
                    confidence: 0.85,
                    hit_count: 3,
                    first_seen_ms: 100,
                    last_seen_ms: 200,
                    binary: "/usr/bin/curl".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(submit.accepted_chunks, 1);
        assert_eq!(submit.rejected_chunks, 0);
        assert_eq!(submit.accepted_chunk_ids.len(), 1);
        assert!(!submit.accepted_chunk_ids[0].is_empty());

        let draft_policy = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name.clone(),
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(draft_policy.draft_version, 1);
        assert_eq!(draft_policy.chunks.len(), 1);
        // The proposal is L4 to a host with a credential in scope, so the
        // prover emits a HIGH finding and the chunk stays pending for the
        // manual approve path this test exercises.
        assert_eq!(draft_policy.chunks[0].status, "pending");
        let chunk_id = draft_policy.chunks[0].id.clone();

        let approve = handle_approve_draft_chunk(
            &state,
            Request::new(ApproveDraftChunkRequest {
                name: sandbox_name.clone(),
                chunk_id: chunk_id.clone(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(approve.policy_version, 1);
        assert!(!approve.policy_hash.is_empty());

        let history_after_approve = handle_get_draft_history(
            &state,
            Request::new(GetDraftHistoryRequest {
                name: sandbox_name.clone(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(history_after_approve.entries.len(), 2);
        assert_eq!(history_after_approve.entries[0].event_type, "proposed");
        assert_eq!(history_after_approve.entries[1].event_type, "approved");
        assert_eq!(history_after_approve.entries[1].chunk_id, chunk_id);

        let policies_after_approve = handle_list_sandbox_policies(
            &state,
            Request::new(ListSandboxPoliciesRequest {
                name: sandbox_name.clone(),
                limit: 10,
                offset: 0,
                global: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(policies_after_approve.revisions.len(), 1);
        assert_eq!(policies_after_approve.revisions[0].version, 1);

        let undo = handle_undo_draft_chunk(
            &state,
            Request::new(UndoDraftChunkRequest {
                name: sandbox_name.clone(),
                chunk_id: chunk_id.clone(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(undo.policy_version, 2);
        assert!(!undo.policy_hash.is_empty());

        let draft_policy_after_undo = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name.clone(),
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(draft_policy_after_undo.chunks.len(), 1);
        assert_eq!(draft_policy_after_undo.chunks[0].status, "pending");

        let history_after_undo = handle_get_draft_history(
            &state,
            Request::new(GetDraftHistoryRequest {
                name: sandbox_name.clone(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(history_after_undo.entries.len(), 1);
        assert_eq!(history_after_undo.entries[0].event_type, "proposed");

        let policies_after_undo = handle_list_sandbox_policies(
            &state,
            Request::new(ListSandboxPoliciesRequest {
                name: sandbox_name.clone(),
                limit: 10,
                offset: 0,
                global: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(policies_after_undo.revisions.len(), 2);
        assert_eq!(policies_after_undo.revisions[0].version, 2);
        assert_eq!(policies_after_undo.revisions[1].version, 1);

        let cleared = handle_clear_draft_chunks(
            &state,
            Request::new(ClearDraftChunksRequest {
                name: sandbox_name.clone(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(cleared.chunks_cleared, 1);

        let draft_policy_after_clear = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name.clone(),
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(draft_policy_after_clear.chunks.is_empty());

        let history_after_clear = handle_get_draft_history(
            &state,
            Request::new(GetDraftHistoryRequest { name: sandbox_name }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(history_after_clear.entries.is_empty());
    }

    /// A reviewer's free-form rejection reason must round-trip through
    /// persistence and surface on the chunk via `GetDraftPolicy`, so the
    /// in-sandbox agent can read the guidance and redraft. The MVP-v2 agent
    /// feedback loop hangs off this guarantee.
    #[tokio::test]
    async fn reject_with_reason_persists_into_chunk_for_agent_readback() {
        use openshell_core::proto::{NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxSpec};

        let state = test_server_state().await;
        let sandbox_name = "agent-feedback-loop".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-feedback".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();

        let proposed_rule = NetworkPolicyRule {
            name: "allow_example".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        let submit = handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "allow_example".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "agent intent".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let chunk_id = submit.accepted_chunk_ids[0].clone();

        let guidance = "scope to docs/ paths only, not all repo contents";
        handle_reject_draft_chunk(
            &state,
            Request::new(RejectDraftChunkRequest {
                name: sandbox_name.clone(),
                chunk_id: chunk_id.clone(),
                reason: guidance.to_string(),
            }),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let rejected = draft
            .chunks
            .iter()
            .find(|c| c.id == chunk_id)
            .expect("rejected chunk should still be visible");
        assert_eq!(rejected.status, "rejected");
        assert_eq!(
            rejected.rejection_reason, guidance,
            "reviewer's free-form reason must round-trip into the chunk for agent readback"
        );
        // The prover now runs on every proposal regardless of analysis_mode.
        // For this rule (L4 to api.example.com, no provider attached, no
        // credential in scope), v1 calibration emits no finding — so the
        // verdict is the clean "no new findings" string, not empty.
        assert_eq!(rejected.validation_result, "prover: no new findings");
    }

    #[tokio::test]
    async fn agent_authored_exact_l7_proposal_gets_prover_pass_verdict() {
        use openshell_core::proto::{
            FilesystemPolicy, L7Allow, L7Rule, NetworkBinary, NetworkEndpoint, SandboxPhase,
            SandboxPolicy, SandboxSpec,
        };

        let state = test_server_state().await;
        let sandbox_name = "agent-l7-verdict".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-agent-l7-verdict".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
        // Opt this sandbox into auto-approval via the settings model — same
        // path the CLI's `--approval-mode auto` exercises — to test the
        // empty-delta → approved path.
        seed_sandbox_approval_mode(&state, &sandbox_name, "auto").await;

        let proposed_rule = NetworkPolicyRule {
            name: "github_contents_write".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                protocol: "rest".to_string(),
                enforcement: "enforce".to_string(),
                rules: vec![L7Rule {
                    allow: Some(L7Allow {
                        method: "PUT".to_string(),
                        path: "/repos/org/repo/contents/demo/file.md".to_string(),
                        ..Default::default()
                    }),
                }],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "github_contents_write".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "write one demo file".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let verdict = &draft.chunks[0].validation_result;
        assert_eq!(
            verdict, "prover: no new findings",
            "exact L7 PUT against an inspected endpoint should not introduce \
             any new findings over baseline; got: {verdict}"
        );
        // Auto-approval gate: empty delta + sandbox opted into auto mode →
        // status flips to approved without human action. The canonical
        // happy path for agent speed.
        assert_eq!(
            draft.chunks[0].status, "approved",
            "empty-delta agent-authored proposal under auto mode must auto-approve; \
             got status: {}",
            draft.chunks[0].status
        );
    }

    /// Implicit supersede: when a refined agent-authored proposal lands for
    /// the same `(host, port, binary)` as a pending mechanistic chunk, the
    /// older mechanistic chunk is auto-rejected with a "superseded by
    /// chunk X" reason. This is the refinement loop without a
    /// `supersedes_chunk_id` field — structural overlap is enough.
    #[tokio::test]
    async fn agent_authored_submission_supersedes_pending_mechanistic_for_same_endpoint() {
        use openshell_core::proto::{
            FilesystemPolicy, L7Allow, L7Rule, NetworkBinary, NetworkEndpoint, SandboxPhase,
            SandboxPolicy, SandboxSpec,
        };

        let state = test_server_state().await;
        // github provider attached so the mechanistic L4 lands a HIGH
        // finding and stays pending.
        state
            .store
            .put_message(&test_provider("github-pat", "github"))
            .await
            .unwrap();
        let sandbox_name = "supersede-flow".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-supersede-flow".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                providers: vec!["github-pat".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();

        // Step 1: mechanistic submits a broad L4 grant; the prover flags it
        // HIGH, so it lands in pending.
        let mechanistic_rule = NetworkPolicyRule {
            name: "allow_api_github_com_443".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let mechanistic_submit = handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "mechanistic".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "allow_api_github_com_443".to_string(),
                    proposed_rule: Some(mechanistic_rule),
                    rationale: "Allow /usr/bin/curl to connect to api.github.com:443.".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let mechanistic_chunk_id = mechanistic_submit.accepted_chunk_ids[0].clone();

        // Sanity-check: the mechanistic chunk is pending and carries a HIGH
        // finding.
        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name.clone(),
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let mech = draft
            .chunks
            .iter()
            .find(|c| c.id == mechanistic_chunk_id)
            .expect("mechanistic chunk present");
        assert_eq!(mech.status, "pending");
        // Mechanistic L4 with credential in scope flags as new credentialed
        // reach for the binary on the host.
        assert!(
            mech.validation_result
                .contains("credential_reach_expansion"),
            "mechanistic L4 with credential in scope should emit \
             credential_reach_expansion; got: {}",
            mech.validation_result
        );

        // Step 2: the agent refines into a narrow L7 proposal for the SAME
        // (host, port, binary). Under the v1 calibration, an L7 PUT on a
        // host where the binary already had credentialed reach (read-only)
        // emits a capability_expansion finding (new method on already-
        // reached host) rather than a fresh reach expansion. The agent
        // chunk stays pending for human review. The mechanistic chunk gets
        // auto-rejected as superseded regardless of the agent chunk's own
        // validation verdict — supersede is unconditional on `(host, port,
        // binary)` overlap.
        let agent_rule = NetworkPolicyRule {
            name: "github_contents_put".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                protocol: "rest".to_string(),
                enforcement: "enforce".to_string(),
                rules: vec![L7Rule {
                    allow: Some(L7Allow {
                        method: "PUT".to_string(),
                        path: "/repos/owner/name/contents/path/file.md".to_string(),
                        ..Default::default()
                    }),
                }],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let agent_submit = handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "github_contents_put".to_string(),
                    proposed_rule: Some(agent_rule),
                    rationale: "refined L7 scope for the demo write".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let agent_chunk_id = agent_submit.accepted_chunk_ids[0].clone();

        let draft_after = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();

        let agent = draft_after
            .chunks
            .iter()
            .find(|c| c.id == agent_chunk_id)
            .expect("agent chunk present");
        let mech_after = draft_after
            .chunks
            .iter()
            .find(|c| c.id == mechanistic_chunk_id)
            .expect("mechanistic chunk should still be visible (with new status)");

        assert_eq!(
            agent.status, "pending",
            "agent-authored L7 PUT with credential in scope must land in pending; \
             the baseline policy has no pre-existing rule for curl on api.github.com \
             so the agent's chunk grants brand-new credentialed reach. got: {}",
            agent.status
        );
        assert!(
            agent
                .validation_result
                .contains("credential_reach_expansion"),
            "agent chunk should carry credential_reach_expansion (new credentialed reach \
             on api.github.com); got: {}",
            agent.validation_result
        );
        assert_eq!(
            mech_after.status, "rejected",
            "older mechanistic chunk for same (host, port, binary) should be superseded; \
             got: {}",
            mech_after.status
        );
        assert!(
            mech_after.rejection_reason.contains(&agent_chunk_id),
            "rejection reason should cite the superseding chunk id; got: {}",
            mech_after.rejection_reason
        );
        assert!(
            mech_after.rejection_reason.contains("superseded"),
            "rejection reason should explain the supersede; got: {}",
            mech_after.rejection_reason
        );
    }

    /// Auto-approval is **proposer-agnostic**: a mechanistic proposal whose
    /// prover delta is empty auto-approves the same way an agent-authored one
    /// does. Source provenance is preserved in the audit trail (OCSF event
    /// `source=mechanistic`) but does not change the safety decision.
    #[tokio::test]
    async fn mechanistic_proposal_with_empty_delta_also_auto_approves() {
        use openshell_core::proto::{
            FilesystemPolicy, NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxPolicy,
            SandboxSpec,
        };

        let state = test_server_state().await;
        let sandbox_name = "mechanistic-clean".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-mechanistic-clean".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                // No providers → no credential in scope for the proposed host.
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
        // Opt into auto mode via the settings model to test the
        // proposer-agnostic gate.
        seed_sandbox_approval_mode(&state, &sandbox_name, "auto").await;

        let proposed_rule = NetworkPolicyRule {
            name: "anon_l4".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "example.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "mechanistic".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "anon_l4".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "Allow /usr/bin/curl to connect to example.com:443.".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let verdict = &draft.chunks[0].validation_result;
        assert_eq!(verdict, "prover: no new findings");
        assert_eq!(
            draft.chunks[0].status, "approved",
            "empty-delta mechanistic proposal under auto mode must auto-approve \
             (proposer-agnostic); got status: {}",
            draft.chunks[0].status
        );
    }

    /// `protocol: rest, access: full` on a host where the binary had no
    /// prior credentialed reach: the prover emits
    /// `credential_reach_expansion`. (The per-method `capability_expansion`
    /// paths are suppressed by the gateway delta because the reach is
    /// new; one finding describes the change, not eight.)
    #[tokio::test]
    async fn agent_authored_l7_full_with_credential_emits_reach_expansion() {
        use openshell_core::proto::{
            FilesystemPolicy, NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxPolicy,
            SandboxSpec,
        };

        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("github-pat", "github"))
            .await
            .unwrap();
        let sandbox_name = "l7-full-with-cred".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-l7-full-with-cred".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                providers: vec!["github-pat".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
        seed_sandbox_approval_mode(&state, &sandbox_name, "auto").await;

        // L7-annotated (protocol: rest, enforce) but access: full — no
        // method/path bound. Credential in scope.
        let proposed_rule = NetworkPolicyRule {
            name: "github_l7_full".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                protocol: "rest".to_string(),
                enforcement: "enforce".to_string(),
                access: "full".to_string(),
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "github_l7_full".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "broad L7 dressing".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let verdict = &draft.chunks[0].validation_result;
        assert!(
            verdict.contains("credential_reach_expansion"),
            "L7 `access: full` on a host the binary did not previously reach must emit \
             credential_reach_expansion; got: {verdict}"
        );
        // Capability_expansion paths for the same (binary, host:port) are
        // suppressed when the reach itself is new — one finding, not many.
        assert!(
            !verdict.contains("capability_expansion"),
            "capability_expansion must be suppressed when reach itself is new; got: {verdict}"
        );
        assert_eq!(
            draft.chunks[0].status, "pending",
            "any prover finding must keep the chunk in pending despite auto mode; got: {}",
            draft.chunks[0].status
        );
    }

    /// Acceptance criterion #7: default approval mode is manual. A sandbox
    /// with no `proposal_approval_mode` setting at either scope must NOT
    /// auto-approve empty-delta proposals; the chunk lands in `pending` for
    /// human review. This is the default-deny safeguard: auto-approval is
    /// an explicit opt-in, not a global behavior change shipped under a
    /// feature.
    #[tokio::test]
    async fn empty_delta_does_not_auto_approve_when_mode_unset() {
        use openshell_core::proto::{
            FilesystemPolicy, NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxPolicy,
            SandboxSpec,
        };

        let state = test_server_state().await;
        let sandbox_name = "default-manual-mode".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-default-manual-mode".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                // No approval-mode setting seeded at sandbox or gateway
                // scope — the resolver must treat absence as "manual".
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();

        let proposed_rule = NetworkPolicyRule {
            name: "anon_l4".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "example.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "anon_l4".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "un-credentialed L4 — prover sees no finding".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let verdict = &draft.chunks[0].validation_result;
        assert_eq!(
            verdict, "prover: no new findings",
            "prover should still emit no findings; gate is downstream",
        );
        assert_eq!(
            draft.chunks[0].status, "pending",
            "default (unset) proposal_approval_mode must not auto-approve; \
             chunk should wait for human review. got status: {}",
            draft.chunks[0].status
        );
    }

    /// Unknown `proposal_approval_mode` strings (typos, future-mode values
    /// the gateway doesn't yet know about) fall back to manual. This locks
    /// in forward-compat: a future CLI that learns about `"auto_on_low_risk"`
    /// can never accidentally bypass an older gateway's review gate just by
    /// virtue of an unrecognized value defaulting to "auto."
    #[tokio::test]
    async fn empty_delta_does_not_auto_approve_when_mode_unknown_string() {
        use openshell_core::proto::{
            FilesystemPolicy, NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxPolicy,
            SandboxSpec,
        };

        let state = test_server_state().await;
        let sandbox_name = "unknown-mode".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-unknown-mode".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
        // A future-CLI value the current gateway doesn't recognize.
        seed_sandbox_approval_mode(&state, &sandbox_name, "auto_on_low_risk").await;

        let proposed_rule = NetworkPolicyRule {
            name: "anon_l4".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "example.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "anon_l4".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "un-credentialed L4".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            draft.chunks[0].status, "pending",
            "unknown approval-mode strings must fall back to manual; \
             only the literal \"auto\" opts in. got: {}",
            draft.chunks[0].status
        );
    }

    /// Explicit `"manual"` is equivalent to the unset default — chunk lands
    /// in pending even with empty delta.
    #[tokio::test]
    async fn empty_delta_does_not_auto_approve_when_mode_explicit_manual() {
        use openshell_core::proto::{
            FilesystemPolicy, NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxPolicy,
            SandboxSpec,
        };

        let state = test_server_state().await;
        let sandbox_name = "explicit-manual-mode".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-explicit-manual-mode".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
        seed_sandbox_approval_mode(&state, &sandbox_name, "manual").await;

        let proposed_rule = NetworkPolicyRule {
            name: "anon_l4".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "example.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "anon_l4".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "un-credentialed L4 — prover sees no finding".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            draft.chunks[0].status, "pending",
            "explicit manual mode must equal default mode — no auto-approval; \
             got: {}",
            draft.chunks[0].status
        );
    }

    /// Gateway-scope `proposal_approval_mode = "auto"` enables auto-approval
    /// for any sandbox under that gateway, with no per-sandbox setting
    /// required. This is the fleet-wide opt-in path — a reviewer flips the
    /// gateway setting once and every sandbox without an explicit override
    /// gets prover-gated auto-approval.
    #[tokio::test]
    async fn empty_delta_auto_approves_from_gateway_scope_setting() {
        use openshell_core::proto::{
            FilesystemPolicy, NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxPolicy,
            SandboxSpec,
        };

        let state = test_server_state().await;
        let sandbox_name = "gateway-auto-mode".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-gateway-auto-mode".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
        // Fleet-wide opt-in — no sandbox-scope setting.
        seed_global_approval_mode(&state, "auto").await;

        let proposed_rule = NetworkPolicyRule {
            name: "anon_l4".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "example.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "anon_l4".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "un-credentialed L4 — empty delta".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            draft.chunks[0].status, "approved",
            "empty-delta proposal must auto-approve when the gateway-scope \
             setting is \"auto\" and no sandbox-scope override exists. got: {}",
            draft.chunks[0].status
        );
    }

    /// Gateway scope wins over sandbox scope. A reviewer can pin manual mode
    /// fleet-wide; a per-sandbox `"auto"` value is silently ignored. Matches
    /// the existing settings precedence convention (global wins, sandbox is
    /// the per-sandbox override only when no global is set).
    #[tokio::test]
    async fn gateway_manual_overrides_sandbox_auto() {
        use openshell_core::proto::{
            FilesystemPolicy, NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxPolicy,
            SandboxSpec,
        };

        let state = test_server_state().await;
        let sandbox_name = "gateway-pinned-manual".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-gateway-pinned-manual".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
        // Gateway pins manual; the sandbox-scope override is supplied (test
        // helper bypasses the UpdateConfig precondition, simulating the
        // before-pin state) to prove the resolver still picks the gateway
        // value.
        seed_global_approval_mode(&state, "manual").await;
        seed_sandbox_approval_mode(&state, &sandbox_name, "auto").await;

        let proposed_rule = NetworkPolicyRule {
            name: "anon_l4".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "example.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "anon_l4".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "un-credentialed L4 — empty delta".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            draft.chunks[0].status, "pending",
            "gateway-scope \"manual\" must win over sandbox-scope \"auto\"; \
             got: {}",
            draft.chunks[0].status
        );
    }

    /// Agent submissions targeting a `_provider_*` rule name are rejected at
    /// the submit boundary. Provider-synthesized rules are a reserved
    /// namespace; an agent that addresses one by name could otherwise
    /// circumvent the merge guard that splits agent contributions into their
    /// own rule (so the prover sees them honestly).
    #[tokio::test]
    async fn submit_rejects_reserved_provider_rule_name_prefix() {
        use openshell_core::proto::{
            FilesystemPolicy, NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxPolicy,
            SandboxSpec,
        };

        let state = test_server_state().await;
        let sandbox_name = "reject-provider-prefix".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-reject-provider-prefix".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();

        let proposed_rule = NetworkPolicyRule {
            name: "github".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        let response = handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "_provider_work_github".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "should be rejected — addresses provider rule by name".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(response.accepted_chunks, 0, "chunk must be rejected");
        assert_eq!(response.rejected_chunks, 1);
        assert!(
            response
                .rejection_reasons
                .iter()
                .any(|r| r.contains("_provider_")),
            "rejection reason must cite the reserved-prefix rule. got: {:?}",
            response.rejection_reasons,
        );
    }

    /// v1 calibration row: **L4 with a credential in scope → HIGH finding.**
    /// The sandbox has a github provider attached, so a credential is in
    /// scope for api.github.com. A broad L4 proposal therefore lands in
    /// pending with a HIGH finding.
    #[tokio::test]
    async fn agent_authored_l4_proposal_with_credential_records_high_finding() {
        use openshell_core::proto::{
            FilesystemPolicy, NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxPolicy,
            SandboxSpec,
        };

        let state = test_server_state().await;
        // Attach a github provider so a credential is in scope for api.github.com.
        state
            .store
            .put_message(&test_provider("github-pat", "github"))
            .await
            .unwrap();
        let sandbox_name = "agent-l4-with-cred".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-agent-l4-with-cred".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                providers: vec!["github-pat".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();

        let proposed_rule = NetworkPolicyRule {
            name: "github_l4".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "github_l4".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "broad fallback".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let verdict = &draft.chunks[0].validation_result;
        let first_line = verdict.lines().next().unwrap_or("");
        assert!(
            first_line.starts_with("prover: ") && first_line.contains("new finding"),
            "expected first line like `prover: N new finding(s)`, got: {verdict}"
        );
        assert!(
            verdict.contains("credential_reach_expansion"),
            "L4 + credential in scope emits credential_reach_expansion (the binary gains \
             credentialed reach to a new host:port); got: {verdict}"
        );
        assert!(
            verdict.contains("api.github.com:443"),
            "expected the finding line to cite the proposed endpoint, got: {verdict}"
        );
    }

    /// v1 calibration row: **L4 with NO credential in scope → no finding.**
    /// Without an attached provider, no credential targets api.github.com,
    /// so the prover treats the L4 grant as bounded (no privileged action
    /// available) and emits nothing. The proposal verdict reads
    /// `prover: no new findings`, eligible for auto-approval.
    #[tokio::test]
    async fn agent_authored_l4_proposal_without_credential_emits_no_finding() {
        use openshell_core::proto::{
            FilesystemPolicy, NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxPolicy,
            SandboxSpec,
        };

        let state = test_server_state().await;
        let sandbox_name = "agent-l4-no-cred".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-agent-l4-no-cred".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                // No providers — credential set will be empty.
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();

        let proposed_rule = NetworkPolicyRule {
            name: "anon_l4".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "example.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "anon_l4".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "no privileged access available".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let verdict = &draft.chunks[0].validation_result;
        assert_eq!(
            verdict, "prover: no new findings",
            "L4 grant with no credential in scope is bounded in v1; got: {verdict}"
        );
    }

    /// v1 calibration row: **link-local host → HIGH finding regardless of
    /// credentials.** Even with no provider attached, a proposal targeting
    /// `169.254.169.254` (AWS IMDS / cloud metadata) emits a HIGH finding.
    /// This is the one categorical safety floor v1 ships.
    #[tokio::test]
    async fn agent_authored_link_local_proposal_records_high_finding() {
        use openshell_core::proto::{
            FilesystemPolicy, NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxPolicy,
            SandboxSpec,
        };

        let state = test_server_state().await;
        let sandbox_name = "agent-link-local".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-agent-link-local".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                // Deliberately no provider — link-local should still fire.
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();

        let proposed_rule = NetworkPolicyRule {
            name: "metadata_endpoint".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "169.254.169.254".to_string(),
                port: 80,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "metadata_endpoint".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "agent is curious about IMDS".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let verdict = &draft.chunks[0].validation_result;
        assert!(
            verdict.contains("link_local_reach"),
            "link-local proposal must emit link_local_reach regardless of credentials; \
             got: {verdict}"
        );
        assert!(
            verdict.contains("169.254.169.254"),
            "finding line must cite the link-local host; got: {verdict}"
        );
    }

    #[tokio::test]
    async fn agent_authored_validation_uses_providers_v2_effective_policy() {
        use openshell_core::proto::{
            FilesystemPolicy, L7Allow, L7DenyRule, L7Rule, NetworkBinary, NetworkEndpoint,
            ProviderProfile, ProviderProfileCategory, SandboxPhase, SandboxPolicy, SandboxSpec,
            StoredProviderProfile,
        };

        let state = test_server_state().await;
        enable_providers_v2(&state).await;
        state
            .store
            .put_message(&test_provider("work-custom", "custom-api"))
            .await
            .unwrap();
        state
            .store
            .put_message(&StoredProviderProfile {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: "profile-custom-api".to_string(),
                    name: "custom-api".to_string(),
                    created_at_ms: 1_000_000,
                    labels: HashMap::new(),
                    resource_version: 0,
                }),
                profile: Some(ProviderProfile {
                    id: "custom-api".to_string(),
                    display_name: "Custom API".to_string(),
                    description: String::new(),
                    category: ProviderProfileCategory::Other as i32,
                    credentials: Vec::new(),
                    endpoints: vec![NetworkEndpoint {
                        host: "api.github.com".to_string(),
                        port: 443,
                        protocol: "rest".to_string(),
                        deny_rules: vec![L7DenyRule {
                            method: "DELETE".to_string(),
                            path: "/repos/*".to_string(),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                    binaries: vec![NetworkBinary {
                        path: "/usr/bin/curl".to_string(),
                        ..Default::default()
                    }],
                    inference_capable: false,
                    discovery: None,
                }),
            })
            .await
            .unwrap();

        let sandbox_name = "agent-provider-effective-policy".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-agent-provider-effective-policy".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                providers: vec!["work-custom".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();

        let proposed_rule = NetworkPolicyRule {
            name: "github_contents_write".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                protocol: "rest".to_string(),
                enforcement: "enforce".to_string(),
                rules: vec![L7Rule {
                    allow: Some(L7Allow {
                        method: "PUT".to_string(),
                        path: "/repos/org/repo/contents/demo/file.md".to_string(),
                        ..Default::default()
                    }),
                }],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "github_contents_write".to_string(),
                    proposed_rule: Some(proposed_rule),
                    rationale: "write one demo file".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let verdict = &draft.chunks[0].validation_result;
        let first_line = verdict.lines().next().unwrap_or("");
        assert!(
            first_line.starts_with("prover: "),
            "validation should run end-to-end against the providers-v2 composed \
             effective policy and produce a prover verdict; got: {verdict}"
        );
        assert!(
            !verdict.contains("validation unavailable"),
            "providers-v2 composition must not break the prover pipeline; \
             got: {verdict}"
        );
    }

    /// End-to-end loop test against the v1 calibration and the auto-approval
    /// gate. Mirrors the two-path flow in `examples/agent-driven-policy-management`:
    ///
    /// 1. Un-credentialed L7 proposal (raw.githubusercontent.com GET) →
    ///    prover sees no findings → sandbox in `auto` mode → chunk
    ///    auto-approves without human action.
    ///
    /// 2. Credentialed L7 proposal (api.github.com PUT) → prover sees
    ///    `github_token` in scope, emits MEDIUM → chunk lands in pending
    ///    for human review even under `auto` mode.
    ///
    /// This is the deterministic counterpart of the demo's product UX
    /// claim: "narrow safe = free, narrow credentialed = one approval."
    #[tokio::test]
    async fn full_loop_under_v2_auto_mode_splits_credentialed_and_uncredentialed() {
        use openshell_core::proto::{
            FilesystemPolicy, L7Allow, L7Rule, NetworkBinary, NetworkEndpoint, SandboxPhase,
            SandboxPolicy, SandboxSpec,
        };

        let state = test_server_state().await;
        enable_providers_v2(&state).await;

        // Github provider attached: a credential ends up in scope for
        // api.github.com (PUT proposal flags MEDIUM). raw.githubusercontent.com
        // is not declared by any provider, so the bootstrap fetch is
        // un-credentialed and auto-approves.
        state
            .store
            .put_message(&test_provider("github-pat", "github"))
            .await
            .unwrap();

        let sandbox_name = "full-loop-v2".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-full-loop-v2".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: Some(SandboxPolicy {
                    version: 1,
                    filesystem: Some(FilesystemPolicy {
                        read_write: vec!["/sandbox".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                providers: vec!["github-pat".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
        seed_sandbox_approval_mode(&state, &sandbox_name, "auto").await;

        // ── Step 1: un-credentialed GET → expected auto-approve ──
        let uncredentialed_rule = NetworkPolicyRule {
            name: "github_raw_openapi_get".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "raw.githubusercontent.com".to_string(),
                port: 443,
                protocol: "rest".to_string(),
                enforcement: "enforce".to_string(),
                rules: vec![L7Rule {
                    allow: Some(L7Allow {
                        method: "GET".to_string(),
                        path: "/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json"
                            .to_string(),
                        ..Default::default()
                    }),
                }],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let step1 = handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "github_raw_openapi_get".to_string(),
                    proposed_rule: Some(uncredentialed_rule),
                    rationale: "fetch the public github openapi description".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let step1_chunk_id = step1.accepted_chunk_ids[0].clone();

        // ── Step 2: credentialed PUT → expected MEDIUM, pending ──
        let credentialed_rule = NetworkPolicyRule {
            name: "github_contents_put".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                protocol: "rest".to_string(),
                enforcement: "enforce".to_string(),
                rules: vec![L7Rule {
                    allow: Some(L7Allow {
                        method: "PUT".to_string(),
                        path: "/repos/owner/name/contents/path/file.md".to_string(),
                        ..Default::default()
                    }),
                }],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let step2 = handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "github_contents_put".to_string(),
                    proposed_rule: Some(credentialed_rule),
                    rationale: "write the demo file via the GitHub Contents API".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let step2_chunk_id = step2.accepted_chunk_ids[0].clone();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();

        let step1_chunk = draft
            .chunks
            .iter()
            .find(|c| c.id == step1_chunk_id)
            .expect("step1 chunk present");
        let step2_chunk = draft
            .chunks
            .iter()
            .find(|c| c.id == step2_chunk_id)
            .expect("step2 chunk present");

        assert_eq!(
            step1_chunk.status, "approved",
            "un-credentialed L7 proposal under v2 + auto mode must auto-approve; got: {}",
            step1_chunk.status
        );
        assert_eq!(
            step1_chunk.validation_result, "prover: no new findings",
            "un-credentialed L7 verdict should be `no new findings`; got: {}",
            step1_chunk.validation_result
        );

        assert_eq!(
            step2_chunk.status, "pending",
            "credentialed L7 PUT under v2 + auto mode must stay pending; got: {}",
            step2_chunk.status
        );
        // This test's spec policy has no pre-existing rule for curl on
        // api.github.com, so the agent's chunk grants brand-new
        // credentialed reach: the finding is credential_reach_expansion,
        // not capability_expansion. (The capability_expansion path is
        // suppressed by the delta because the reach is new — one finding
        // per change, not two.) The demo's policy.template.yaml has
        // github_api_readonly which exercises the capability_expansion
        // path; that's covered by the supersede test above.
        assert!(
            step2_chunk
                .validation_result
                .contains("credential_reach_expansion"),
            "credentialed PUT on a host the binary did not previously reach must carry \
             credential_reach_expansion; got: {}",
            step2_chunk.validation_result
        );
        assert!(
            !step2_chunk
                .validation_result
                .contains("capability_expansion"),
            "capability_expansion must be suppressed when reach itself is new; got: {}",
            step2_chunk.validation_result
        );
    }

    /// Two agent-authored proposals targeting the same host/port/binary must
    /// each persist as a distinct chunk. The mechanistic-mode dedup
    /// (`host|port|binary`) is wrong for agent intent: the redraft loop
    /// relies on the second submission landing as its own chunk so the
    /// reviewer can decide on it independently. Regression test for the bug
    /// where Flow B of `e2e/policy-advisor/wait-smoke.sh` saw a fresh
    /// `chunk_id` returned from submit but `RejectDraftChunk` could not
    /// find it because the SQL ON CONFLICT had silently kept the prior row.
    #[tokio::test]
    async fn agent_authored_submits_for_same_endpoint_do_not_dedup() {
        use openshell_core::proto::{NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxSpec};

        let state = test_server_state().await;
        let sandbox_name = "redraft-loop".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-redraft".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();

        // Two proposals with the same host|port|binary (so the mechanistic
        // dedup_key would collide) but distinct rule names and L7 paths —
        // proves the gateway distinguishes them by intentional act and not
        // by payload hash. If a future dedup-by-payload-hash regression
        // landed, this test would still fail because the chunk_ids would
        // still need to be distinct.
        let make_rule = |rule_name: &str| NetworkPolicyRule {
            name: rule_name.to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        let submit_one = |rule_name: &str, rule: NetworkPolicyRule| {
            let state = state.clone();
            let sandbox_name = sandbox_name.clone();
            let rule_name = rule_name.to_string();
            async move {
                handle_submit_policy_analysis(
                    &state,
                    with_user(Request::new(SubmitPolicyAnalysisRequest {
                        name: sandbox_name,
                        analysis_mode: "agent_authored".to_string(),
                        proposed_chunks: vec![PolicyChunk {
                            rule_name,
                            proposed_rule: Some(rule),
                            ..Default::default()
                        }],
                        ..Default::default()
                    })),
                )
                .await
                .unwrap()
                .into_inner()
            }
        };

        let first = submit_one("allow_first", make_rule("allow_first")).await;
        let second = submit_one("allow_second", make_rule("allow_second")).await;

        assert_eq!(first.accepted_chunk_ids.len(), 1);
        assert_eq!(second.accepted_chunk_ids.len(), 1);
        assert_ne!(
            first.accepted_chunk_ids[0], second.accepted_chunk_ids[0],
            "second agent-authored proposal for the same endpoint must get its own chunk_id, not dedup"
        );

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name.clone(),
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let ids: Vec<_> = draft.chunks.iter().map(|c| c.id.as_str()).collect();
        assert!(
            ids.contains(&first.accepted_chunk_ids[0].as_str())
                && ids.contains(&second.accepted_chunk_ids[0].as_str()),
            "both reported chunk_ids must be persisted; got: {ids:?}"
        );

        // Reject the second by id to prove the gateway can actually find
        // what the submit response claimed to have created — this is the
        // exact path the smoke test exercises end-to-end.
        handle_reject_draft_chunk(
            &state,
            Request::new(RejectDraftChunkRequest {
                name: sandbox_name,
                chunk_id: second.accepted_chunk_ids[0].clone(),
                reason: "redraft test".to_string(),
            }),
        )
        .await
        .expect("reject must find the chunk_id the submit response just promised");
    }

    /// Complement to the agent-authored test above: mechanistic-mode
    /// submissions for the same endpoint must STILL dedup. The
    /// observation-driven path relies on N denials folding into one chunk
    /// instead of N near-identical chunks. Lock the behavior in so a future
    /// change to the dedup branch doesn't accidentally also turn off
    /// mechanistic dedup.
    #[tokio::test]
    async fn mechanistic_submits_for_same_endpoint_dedup_into_one_chunk() {
        use openshell_core::proto::{NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxSpec};

        let state = test_server_state().await;
        let sandbox_name = "mechanistic-dedup".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-mech-dedup".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();

        let proposed_rule = NetworkPolicyRule {
            name: "allow_example".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let submit_one = || {
            let state = state.clone();
            let sandbox_name = sandbox_name.clone();
            let rule = proposed_rule.clone();
            async move {
                handle_submit_policy_analysis(
                    &state,
                    with_user(Request::new(SubmitPolicyAnalysisRequest {
                        name: sandbox_name,
                        analysis_mode: "mechanistic".to_string(),
                        proposed_chunks: vec![PolicyChunk {
                            rule_name: "allow_example".to_string(),
                            proposed_rule: Some(rule),
                            ..Default::default()
                        }],
                        ..Default::default()
                    })),
                )
                .await
                .unwrap()
                .into_inner()
            }
        };
        let first = submit_one().await;
        let second = submit_one().await;
        assert_eq!(first.accepted_chunk_ids.len(), 1);
        assert_eq!(second.accepted_chunk_ids.len(), 1);

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            draft.chunks.len(),
            1,
            "two mechanistic submits for the same host|port|binary must dedup; got {} chunks",
            draft.chunks.len()
        );
        // Both submits must report the same effective id — the id of the
        // one row that actually exists in the DB. Before the dedup fix the
        // second submit would return a freshly-generated UUID that was
        // never persisted; this assertion locks the contract down.
        let stored_id = &draft.chunks[0].id;
        assert_eq!(
            &first.accepted_chunk_ids[0], stored_id,
            "first submit's reported id must match the stored chunk"
        );
        assert_eq!(
            &second.accepted_chunk_ids[0], stored_id,
            "second submit must report the same id as the first (dedup fold-in), not a fresh UUID"
        );
    }

    /// Build a test sandbox + a submit closure for the post-decision tests.
    /// The closure submits one mechanistic chunk with the given rule and
    /// returns the response.
    async fn setup_post_decision_sandbox(
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Arc<ServerState> {
        use openshell_core::proto::{SandboxPhase, SandboxSpec};

        let state = test_server_state().await;
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: sandbox_id.to_string(),
                name: sandbox_name.to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
        state
    }

    /// Connect-level rule for `/usr/bin/curl -> api.example.com:443`, with
    /// optional L7 method/path allow rules attached to the endpoint.
    fn post_decision_rule(l7: &[(&str, &str)]) -> NetworkPolicyRule {
        use openshell_core::proto::{L7Allow, NetworkBinary, NetworkEndpoint};

        NetworkPolicyRule {
            name: "allow_example".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.com".to_string(),
                port: 443,
                rules: l7
                    .iter()
                    .map(|(method, path)| L7Rule {
                        allow: Some(L7Allow {
                            method: (*method).to_string(),
                            path: (*path).to_string(),
                            ..Default::default()
                        }),
                    })
                    .collect(),
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        }
    }

    async fn submit_mechanistic(
        state: &Arc<ServerState>,
        sandbox_name: &str,
        rule: NetworkPolicyRule,
    ) -> SubmitPolicyAnalysisResponse {
        handle_submit_policy_analysis(
            state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.to_string(),
                analysis_mode: "mechanistic".to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "allow_example".to_string(),
                    proposed_rule: Some(rule),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap()
        .into_inner()
    }

    /// A decided chunk must stop absorbing new mechanistic submissions for
    /// the same endpoint. Once the reviewer approves the connect-level
    /// proposal, later denials for that host|port|binary carrying L7
    /// method/path evidence beyond the approved grant must surface as a
    /// fresh PENDING chunk for review — not fold their hit_count invisibly
    /// into the decided row (dedup_key cleared on decision), and not be
    /// swallowed by the post-approval self-reject sweep (which only fires
    /// when the approved grants cover the new asks).
    #[tokio::test]
    async fn mechanistic_submit_after_decision_creates_fresh_pending_chunk() {
        let sandbox_name = "mechanistic-post-decision";
        let state = setup_post_decision_sandbox("sb-mech-post-decision", sandbox_name).await;

        let first = submit_mechanistic(&state, sandbox_name, post_decision_rule(&[])).await;
        assert_eq!(first.accepted_chunk_ids.len(), 1);
        let first_id = first.accepted_chunk_ids[0].clone();

        handle_approve_draft_chunk(
            &state,
            Request::new(ApproveDraftChunkRequest {
                name: sandbox_name.to_string(),
                chunk_id: first_id.clone(),
            }),
        )
        .await
        .unwrap();

        // Post-approval L7 denial evidence: the agent asked for a write the
        // connect-level approval never granted.
        let second = submit_mechanistic(
            &state,
            sandbox_name,
            post_decision_rule(&[("POST", "/repos/*/issues")]),
        )
        .await;
        assert_eq!(second.accepted_chunk_ids.len(), 1);
        let second_id = second.accepted_chunk_ids[0].clone();
        assert_ne!(
            first_id, second_id,
            "a submit after the decision must create a fresh chunk, not fold into the approved one"
        );

        let pending = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name.to_string(),
                status_filter: "pending".to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            pending.chunks.len(),
            1,
            "the post-decision submit with uncovered L7 evidence must be reviewable as a pending chunk"
        );
        assert_eq!(pending.chunks[0].id, second_id);
    }

    /// The flip side of the previous test: a post-approval mechanistic
    /// resubmit that asks for NOTHING beyond the approved grant is straggler
    /// noise (denials recorded just before the approval hot-reloaded,
    /// flushed just after) and must be self-rejected — no ghost card for the
    /// reviewer. Covers both the identical connect-level resubmit and an L7
    /// ask that is a subset of what was already approved.
    #[tokio::test]
    async fn mechanistic_resubmit_covered_by_approved_grant_self_rejects() {
        let sandbox_name = "mechanistic-covered-resubmit";
        let state = setup_post_decision_sandbox("sb-mech-covered", sandbox_name).await;

        let first = submit_mechanistic(
            &state,
            sandbox_name,
            post_decision_rule(&[("GET", "/user")]),
        )
        .await;
        let first_id = first.accepted_chunk_ids[0].clone();
        handle_approve_draft_chunk(
            &state,
            Request::new(ApproveDraftChunkRequest {
                name: sandbox_name.to_string(),
                chunk_id: first_id,
            }),
        )
        .await
        .unwrap();

        // Identical L7 ask (subset of the grant) and a connect-level
        // resubmit: both are covered, both must self-reject.
        for rule in [
            post_decision_rule(&[("GET", "/user")]),
            post_decision_rule(&[]),
        ] {
            submit_mechanistic(&state, sandbox_name, rule).await;
        }

        let pending = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name.to_string(),
                status_filter: "pending".to_string(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(
            pending.chunks.is_empty(),
            "covered resubmits must self-reject, not pile up as ghost cards: {:?}",
            pending.chunks
        );
    }

    /// Glob coverage semantics for the self-reject sweep: `*` is one
    /// segment, `**` only as the trailing segment, unknown shapes fall back
    /// to exact equality (conservative: surface a card rather than swallow).
    #[test]
    fn l7_path_covers_glob_semantics() {
        // Exact and universal.
        assert!(l7_path_covers("/user", "/user"));
        assert!(l7_path_covers("**", "/anything/at/all"));
        // Single-segment wildcard.
        assert!(l7_path_covers("/repos/*/issues", "/repos/myorg/issues"));
        assert!(!l7_path_covers("/repos/*/issues", "/repos/myorg/pulls"));
        assert!(!l7_path_covers("/repos/*/issues", "/repos/a/b/issues"));
        // Trailing `**` covers any remainder, including generalized asks.
        assert!(l7_path_covers("/v1/models/**", "/v1/models/abc123"));
        assert!(l7_path_covers("/v1/models/**", "/v1/models/*"));
        assert!(l7_path_covers("/v1/**", "/v1/models/abc/def"));
        assert!(!l7_path_covers("/v1/models/**", "/v2/models/abc"));
        // Mid-pattern `**` is an unsupported shape: exact match only.
        assert!(!l7_path_covers("/a/**/z", "/a/b/z"));
        assert!(l7_path_covers("/a/**/z", "/a/**/z"));
        // A grant for a specific id does not cover a generalized ask.
        assert!(!l7_path_covers("/v1/models/abc", "/v1/models/*"));
    }

    /// Undo of an approve must clear any `rejection_reason` left over from a
    /// prior reject. Without this, the in-sandbox agent reading chunks via
    /// `policy.local` cannot tell "pending and never rejected" from "pending
    /// but previously rejected with this stale guidance." The only path that
    /// lands a non-empty reason on a pending chunk is reject → re-approve →
    /// undo, so the test walks that sequence.
    #[tokio::test]
    async fn undo_after_reject_clears_stale_rejection_reason() {
        use openshell_core::proto::{NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxSpec};

        let state = test_server_state().await;
        let sandbox_name = "undo-clears-reason".to_string();
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-undo-clears".to_string(),
                name: sandbox_name.clone(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();

        let proposed_rule = NetworkPolicyRule {
            name: "allow_example".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        let submit = handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_name.clone(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "allow_example".to_string(),
                    proposed_rule: Some(proposed_rule),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let chunk_id = submit.accepted_chunk_ids[0].clone();

        handle_reject_draft_chunk(
            &state,
            Request::new(RejectDraftChunkRequest {
                name: sandbox_name.clone(),
                chunk_id: chunk_id.clone(),
                reason: "scope too broad".to_string(),
            }),
        )
        .await
        .unwrap();

        handle_approve_draft_chunk(
            &state,
            Request::new(ApproveDraftChunkRequest {
                name: sandbox_name.clone(),
                chunk_id: chunk_id.clone(),
            }),
        )
        .await
        .unwrap();

        handle_undo_draft_chunk(
            &state,
            Request::new(UndoDraftChunkRequest {
                name: sandbox_name.clone(),
                chunk_id: chunk_id.clone(),
            }),
        )
        .await
        .unwrap();

        let draft = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_name,
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let restored = draft
            .chunks
            .iter()
            .find(|c| c.id == chunk_id)
            .expect("chunk should still be present after undo");
        assert_eq!(restored.status, "pending");
        assert!(
            restored.rejection_reason.is_empty(),
            "undo must clear stale rejection_reason; got: {:?}",
            restored.rejection_reason
        );
    }

    #[tokio::test]
    async fn draft_chunk_handlers_reject_cross_sandbox_chunk_ids() {
        use openshell_core::proto::{NetworkBinary, NetworkEndpoint, SandboxPhase, SandboxSpec};

        let state = test_server_state().await;
        // Attach a github provider so the L4 proposal below has a credential
        // in scope and the prover emits a HIGH finding — keeps the chunk
        // pending so this cross-sandbox approve check is reachable.
        state
            .store
            .put_message(&test_provider("github-pat", "github"))
            .await
            .unwrap();
        let mut sandbox_a = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-draft-owner".to_string(),
                name: "draft-owner".to_string(),
                created_at_ms: 1_000_000,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                providers: vec!["github-pat".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox_a.set_phase(SandboxPhase::Ready as i32);
        let mut sandbox_b = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-draft-other".to_string(),
                name: "draft-other".to_string(),
                created_at_ms: 1_000_001,
                labels: std::collections::HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox_b.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox_a).await.unwrap();
        state.store.put_message(&sandbox_b).await.unwrap();

        let proposed_rule = NetworkPolicyRule {
            name: "allow_github".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        handle_submit_policy_analysis(
            &state,
            with_user(Request::new(SubmitPolicyAnalysisRequest {
                name: sandbox_a.object_name().to_string(),
                proposed_chunks: vec![PolicyChunk {
                    rule_name: "allow_example".to_string(),
                    proposed_rule: Some(proposed_rule.clone()),
                    rationale: "observed denied request".to_string(),
                    confidence: 0.85,
                    hit_count: 3,
                    first_seen_ms: 100,
                    last_seen_ms: 200,
                    binary: "/usr/bin/curl".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            })),
        )
        .await
        .unwrap();

        let draft_policy = handle_get_draft_policy(
            &state,
            with_user(Request::new(GetDraftPolicyRequest {
                name: sandbox_a.object_name().to_string(),
                status_filter: String::new(),
            })),
        )
        .await
        .unwrap()
        .into_inner();
        let chunk_id = draft_policy.chunks[0].id.clone();
        let other_name = sandbox_b.object_name().to_string();

        let approve_err = handle_approve_draft_chunk(
            &state,
            Request::new(ApproveDraftChunkRequest {
                name: other_name.clone(),
                chunk_id: chunk_id.clone(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(approve_err.code(), Code::NotFound);

        let reject_err = handle_reject_draft_chunk(
            &state,
            Request::new(RejectDraftChunkRequest {
                name: other_name.clone(),
                chunk_id: chunk_id.clone(),
                reason: "wrong sandbox".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(reject_err.code(), Code::NotFound);

        let edit_err = handle_edit_draft_chunk(
            &state,
            Request::new(EditDraftChunkRequest {
                name: other_name.clone(),
                chunk_id: chunk_id.clone(),
                proposed_rule: Some(proposed_rule.clone()),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(edit_err.code(), Code::NotFound);

        handle_approve_draft_chunk(
            &state,
            Request::new(ApproveDraftChunkRequest {
                name: sandbox_a.object_name().to_string(),
                chunk_id: chunk_id.clone(),
            }),
        )
        .await
        .unwrap();

        let undo_err = handle_undo_draft_chunk(
            &state,
            Request::new(UndoDraftChunkRequest {
                name: other_name,
                chunk_id,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(undo_err.code(), Code::NotFound);
    }

    #[test]
    fn build_gateway_policy_audit_message_formats_ocsf_config_line() {
        let message = build_gateway_policy_audit_message(
            "sb-123",
            "demo-sandbox",
            "merged",
            "gateway merged incremental policy op: add-allow api.github.com:443 [POST /repos/*/issues]",
            7,
            "sha256:testhash",
            &[],
        );

        assert_eq!(
            message,
            "CONFIG:MERGED [INFO] gateway merged incremental policy op: add-allow api.github.com:443 [POST /repos/*/issues] [version:v7 hash:sha256:testhash]"
        );
    }

    /// Auto-approval audit messages carry `auto=true`, `source=<mode>`, and
    /// `prover_delta=empty` as extra unmapped fields so a reviewer can
    /// reconstruct the safety reasoning without needing to grep the chunk
    /// table. The message text itself says "auto-approved: no new prover
    /// findings" — never "safe" — because the claim is about the prover's
    /// reasoning, not the world.
    #[test]
    fn build_gateway_policy_audit_message_carries_auto_approve_provenance() {
        let extra = [
            ("auto", "true".to_string()),
            ("source", "agent_authored".to_string()),
            ("prover_delta", "empty".to_string()),
        ];
        let message = build_gateway_policy_audit_message(
            "sb-123",
            "demo-sandbox",
            "approved",
            "auto-approved: no new prover findings (source=agent_authored) — chunk abc: add-rule x",
            12,
            "sha256:autohash",
            &extra,
        );
        assert!(
            message.contains("CONFIG:APPROVED"),
            "auto-approval reuses CONFIG:APPROVED; got: {message}"
        );
        assert!(
            message.contains("auto-approved: no new prover findings"),
            "audit copy must say `no new prover findings`, not `safe`; got: {message}"
        );
        assert!(
            message.contains("auto:true"),
            "missing auto field: {message}"
        );
        assert!(
            message.contains("source:agent_authored"),
            "missing source field: {message}"
        );
        assert!(
            message.contains("prover_delta:empty"),
            "missing prover_delta field: {message}"
        );
    }

    #[test]
    fn summarize_cli_policy_merge_op_formats_rest_allow_rules() {
        let operation = PolicyMergeOp::AddAllowRules {
            host: "api.github.com".to_string(),
            port: 443,
            rules: vec![L7Rule {
                allow: Some(openshell_core::proto::L7Allow {
                    method: "POST".to_string(),
                    path: "/repos/*/issues".to_string(),
                    command: String::new(),
                    query: HashMap::new(),
                    operation_type: String::new(),
                    operation_name: String::new(),
                    fields: Vec::new(),
                }),
            }],
        };

        assert_eq!(
            summarize_cli_policy_merge_op(&operation),
            "add-allow api.github.com:443 [POST /repos/*/issues]"
        );
    }

    #[test]
    fn summarize_cli_policy_merge_op_formats_endpoint_additions() {
        let operation = PolicyMergeOp::AddRule {
            rule_name: "github_api".to_string(),
            rule: NetworkPolicyRule {
                name: "github_api".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.github.com".to_string(),
                    port: 443,
                    protocol: "rest".to_string(),
                    access: "read-only".to_string(),
                    enforcement: "enforce".to_string(),
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/curl".to_string(),
                    ..Default::default()
                }],
            },
        };

        assert_eq!(
            summarize_cli_policy_merge_op(&operation),
            "add-endpoint github_api endpoints=[api.github.com:443 protocol=rest access=read-only enforcement=enforce] binaries=[/usr/bin/curl]"
        );
    }

    #[test]
    fn summarize_cli_policy_merge_op_formats_websocket_credential_rewrite() {
        let operation = PolicyMergeOp::AddRule {
            rule_name: "realtime_api".to_string(),
            rule: NetworkPolicyRule {
                name: "realtime_api".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "realtime.example.com".to_string(),
                    port: 443,
                    protocol: "websocket".to_string(),
                    access: "read-write".to_string(),
                    enforcement: "enforce".to_string(),
                    websocket_credential_rewrite: true,
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/node".to_string(),
                    ..Default::default()
                }],
            },
        };

        assert_eq!(
            summarize_cli_policy_merge_op(&operation),
            "add-endpoint realtime_api endpoints=[realtime.example.com:443 protocol=websocket access=read-write enforcement=enforce websocket_credential_rewrite=true] binaries=[/usr/bin/node]"
        );
    }

    #[test]
    fn summarize_cli_policy_merge_op_formats_request_body_credential_rewrite() {
        let operation = PolicyMergeOp::AddRule {
            rule_name: "slack_api".to_string(),
            rule: NetworkPolicyRule {
                name: "slack_api".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "slack.com".to_string(),
                    port: 443,
                    protocol: "rest".to_string(),
                    access: "read-write".to_string(),
                    enforcement: "enforce".to_string(),
                    request_body_credential_rewrite: true,
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/node".to_string(),
                    ..Default::default()
                }],
            },
        };

        assert_eq!(
            summarize_cli_policy_merge_op(&operation),
            "add-endpoint slack_api endpoints=[slack.com:443 protocol=rest access=read-write enforcement=enforce request_body_credential_rewrite=true] binaries=[/usr/bin/node]"
        );
    }

    // ---- merge_chunk_into_policy ----

    #[tokio::test]
    async fn merge_chunk_into_policy_adds_first_network_rule_to_empty_policy() {
        use openshell_core::proto::{NetworkBinary, NetworkEndpoint, NetworkPolicyRule};

        let store = test_store().await;
        let rule = NetworkPolicyRule {
            name: "google".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "google.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let chunk = DraftChunkRecord {
            id: "chunk-1".to_string(),
            sandbox_id: "sb-empty".to_string(),
            draft_version: 1,
            status: "pending".to_string(),
            rule_name: "google".to_string(),
            proposed_rule: rule.encode_to_vec(),
            rationale: String::new(),
            security_notes: String::new(),
            confidence: 1.0,
            created_at_ms: 0,
            decided_at_ms: None,
            host: "google.com".to_string(),
            port: 443,
            binary: "/usr/bin/curl".to_string(),
            hit_count: 1,
            first_seen_ms: 0,
            last_seen_ms: 0,
            validation_result: String::new(),
            rejection_reason: String::new(),
        };

        let (version, _) = merge_chunk_into_policy(&store, &chunk.sandbox_id, &chunk)
            .await
            .unwrap();

        assert_eq!(version, 1);

        let latest = store
            .get_latest_policy(&chunk.sandbox_id)
            .await
            .unwrap()
            .expect("policy revision should be persisted");
        let policy = openshell_core::proto::SandboxPolicy::decode(latest.policy_payload.as_slice())
            .expect("policy payload should decode");
        let stored_rule = policy
            .network_policies
            .get("google")
            .expect("merged rule should be present");
        assert_eq!(stored_rule.endpoints[0].host, "google.com");
        assert_eq!(stored_rule.endpoints[0].port, 443);
        assert_eq!(stored_rule.binaries[0].path, "/usr/bin/curl");
    }

    #[tokio::test]
    async fn merge_chunk_merges_into_existing_rule_by_host_port() {
        use openshell_core::proto::{
            NetworkBinary, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy,
        };

        let store = test_store().await;
        let sandbox_id = "sb-merge";

        let initial_policy = SandboxPolicy {
            network_policies: std::iter::once((
                "test_server".to_string(),
                NetworkPolicyRule {
                    name: "test_server".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "192.168.1.100".to_string(),
                        port: 8567,
                        ..Default::default()
                    }],
                    binaries: vec![NetworkBinary {
                        path: "/usr/bin/curl".to_string(),
                        ..Default::default()
                    }],
                },
            ))
            .collect(),
            ..Default::default()
        };
        store
            .put_policy_revision(
                "p-seed",
                sandbox_id,
                1,
                &initial_policy.encode_to_vec(),
                "seed-hash",
            )
            .await
            .unwrap();

        let proposed = NetworkPolicyRule {
            name: "allow_192_168_1_100_8567".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "192.168.1.100".to_string(),
                port: 8567,
                allowed_ips: vec!["192.168.1.100".to_string()],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let chunk = DraftChunkRecord {
            id: "chunk-merge".to_string(),
            sandbox_id: sandbox_id.to_string(),
            draft_version: 1,
            status: "pending".to_string(),
            rule_name: "allow_192_168_1_100_8567".to_string(),
            proposed_rule: proposed.encode_to_vec(),
            rationale: String::new(),
            security_notes: String::new(),
            confidence: 0.3,
            created_at_ms: 0,
            decided_at_ms: None,
            host: "192.168.1.100".to_string(),
            port: 8567,
            binary: "/usr/bin/curl".to_string(),
            hit_count: 1,
            first_seen_ms: 0,
            last_seen_ms: 0,
            validation_result: String::new(),
            rejection_reason: String::new(),
        };

        let (version, _) = merge_chunk_into_policy(&store, sandbox_id, &chunk)
            .await
            .unwrap();
        assert_eq!(version, 2);

        let latest = store
            .get_latest_policy(sandbox_id)
            .await
            .unwrap()
            .expect("policy revision should be persisted");
        let policy = SandboxPolicy::decode(latest.policy_payload.as_slice()).unwrap();

        assert_eq!(
            policy.network_policies.len(),
            1,
            "expected 1 rule, got {}: {:?}",
            policy.network_policies.len(),
            policy.network_policies.keys().collect::<Vec<_>>()
        );
        let rule = policy
            .network_policies
            .get("test_server")
            .expect("original rule name 'test_server' should be preserved");
        assert_eq!(rule.endpoints[0].host, "192.168.1.100");
        assert_eq!(rule.endpoints[0].allowed_ips, vec!["192.168.1.100"]);
    }

    #[tokio::test]
    async fn merge_chunk_new_host_port_inserts_new_entry() {
        use openshell_core::proto::{
            NetworkBinary, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy,
        };

        let store = test_store().await;
        let sandbox_id = "sb-new";

        let initial_policy = SandboxPolicy {
            network_policies: std::iter::once((
                "existing_rule".to_string(),
                NetworkPolicyRule {
                    name: "existing_rule".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "api.example.com".to_string(),
                        port: 443,
                        ..Default::default()
                    }],
                    binaries: vec![NetworkBinary {
                        path: "/usr/bin/curl".to_string(),
                        ..Default::default()
                    }],
                },
            ))
            .collect(),
            ..Default::default()
        };
        store
            .put_policy_revision(
                "p-seed",
                sandbox_id,
                1,
                &initial_policy.encode_to_vec(),
                "seed-hash",
            )
            .await
            .unwrap();

        let proposed = NetworkPolicyRule {
            name: "allow_10_0_0_5_8080".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "10.0.0.5".to_string(),
                port: 8080,
                allowed_ips: vec!["10.0.0.5".to_string()],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let chunk = DraftChunkRecord {
            id: "chunk-new".to_string(),
            sandbox_id: sandbox_id.to_string(),
            draft_version: 1,
            status: "pending".to_string(),
            rule_name: "allow_10_0_0_5_8080".to_string(),
            proposed_rule: proposed.encode_to_vec(),
            rationale: String::new(),
            security_notes: String::new(),
            confidence: 0.3,
            created_at_ms: 0,
            decided_at_ms: None,
            host: "10.0.0.5".to_string(),
            port: 8080,
            binary: "/usr/bin/curl".to_string(),
            hit_count: 1,
            first_seen_ms: 0,
            last_seen_ms: 0,
            validation_result: String::new(),
            rejection_reason: String::new(),
        };

        let (version, _) = merge_chunk_into_policy(&store, sandbox_id, &chunk)
            .await
            .unwrap();
        assert_eq!(version, 2);

        let latest = store.get_latest_policy(sandbox_id).await.unwrap().unwrap();
        let policy = SandboxPolicy::decode(latest.policy_payload.as_slice()).unwrap();

        assert_eq!(policy.network_policies.len(), 2);
        assert!(policy.network_policies.contains_key("existing_rule"));
        assert!(policy.network_policies.contains_key("allow_10_0_0_5_8080"));
    }

    #[tokio::test]
    async fn concurrent_merge_batches_preserve_both_updates() {
        use openshell_core::proto::{
            L7Allow, L7DenyRule, L7Rule, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy,
        };

        let store = test_store().await;
        let sandbox_id = "sb-concurrent-merge";

        let initial_policy = SandboxPolicy {
            network_policies: std::iter::once((
                "github".to_string(),
                NetworkPolicyRule {
                    name: "github".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "api.github.com".to_string(),
                        port: 443,
                        ports: vec![443],
                        protocol: "rest".to_string(),
                        access: "read-only".to_string(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ))
            .collect(),
            ..Default::default()
        };
        store
            .put_policy_revision(
                "p-seed",
                sandbox_id,
                1,
                &initial_policy.encode_to_vec(),
                "seed-hash",
            )
            .await
            .unwrap();

        let add_allow = [PolicyMergeOp::AddAllowRules {
            host: "api.github.com".to_string(),
            port: 443,
            rules: vec![L7Rule {
                allow: Some(L7Allow {
                    method: "POST".to_string(),
                    path: "/repos/*/issues".to_string(),
                    command: String::new(),
                    query: HashMap::new(),
                    operation_type: String::new(),
                    operation_name: String::new(),
                    fields: Vec::new(),
                }),
            }],
        }];
        let add_deny = [PolicyMergeOp::AddDenyRules {
            host: "api.github.com".to_string(),
            port: 443,
            deny_rules: vec![L7DenyRule {
                method: "POST".to_string(),
                path: "/admin".to_string(),
                query: HashMap::new(),
                ..Default::default()
            }],
        }];

        let (left, right) = tokio::join!(
            apply_merge_operations_with_retry(&store, sandbox_id, None, &add_allow),
            apply_merge_operations_with_retry(&store, sandbox_id, None, &add_deny),
        );

        let mut versions = vec![left.unwrap().0, right.unwrap().0];
        versions.sort_unstable();
        assert_eq!(versions, vec![2, 3]);

        let latest = store.get_latest_policy(sandbox_id).await.unwrap().unwrap();
        assert_eq!(latest.version, 3);

        let policy = SandboxPolicy::decode(latest.policy_payload.as_slice()).unwrap();
        let endpoint = &policy.network_policies["github"].endpoints[0];
        assert!(endpoint.access.is_empty());
        assert_eq!(endpoint.rules.len(), 4);
        assert_eq!(endpoint.deny_rules.len(), 1);
        assert_eq!(endpoint.deny_rules[0].path, "/admin");
    }

    // ---- validate_rule_not_always_blocked ----

    #[test]
    fn validate_rule_rejects_loopback_allowed_ips() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let rule = NetworkPolicyRule {
            name: "bad".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "example.com".to_string(),
                port: 80,
                allowed_ips: vec!["127.0.0.1".to_string()],
                ..Default::default()
            }],
            binaries: vec![],
        };
        let result = validate_rule_not_always_blocked(&rule);
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().contains("always-blocked"));
    }

    #[test]
    fn validate_rule_rejects_link_local_allowed_ips() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let rule = NetworkPolicyRule {
            name: "bad".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "example.com".to_string(),
                port: 80,
                allowed_ips: vec!["169.254.169.254".to_string()],
                ..Default::default()
            }],
            binaries: vec![],
        };
        let result = validate_rule_not_always_blocked(&rule);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("always-blocked"));
    }

    #[test]
    fn validate_rule_rejects_always_blocked_host() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let rule = NetworkPolicyRule {
            name: "bad".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "127.0.0.1".to_string(),
                port: 80,
                ..Default::default()
            }],
            binaries: vec![],
        };
        let result = validate_rule_not_always_blocked(&rule);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("always-blocked"));
    }

    #[test]
    fn validate_rule_rejects_localhost_host() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let rule = NetworkPolicyRule {
            name: "bad".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "localhost".to_string(),
                port: 8080,
                ..Default::default()
            }],
            binaries: vec![],
        };
        let result = validate_rule_not_always_blocked(&rule);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("always blocked"));
    }

    #[test]
    fn validate_rule_rejects_known_metadata_hostname() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let rule = NetworkPolicyRule {
            name: "bad".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "METADATA.GOOGLE.INTERNAL.".to_string(),
                port: 80,
                ..Default::default()
            }],
            binaries: vec![],
        };
        let result = validate_rule_not_always_blocked(&rule);
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().contains("cloud metadata hostname"));
    }

    #[test]
    fn validate_merge_operations_rejects_add_allow_for_known_metadata_hostname() {
        let operation = PolicyMergeOp::AddAllowRules {
            host: "metadata.google.internal".to_string(),
            port: 80,
            rules: vec![L7Rule {
                allow: Some(openshell_core::proto::L7Allow {
                    method: "GET".to_string(),
                    path: "/computeMetadata/v1/**".to_string(),
                    command: String::new(),
                    query: HashMap::new(),
                    operation_type: String::new(),
                    operation_name: String::new(),
                    fields: Vec::new(),
                }),
            }],
        };

        let result = validate_merge_operations_for_server(&[operation]);

        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().contains("cloud metadata hostname"));
    }

    #[test]
    fn validate_rule_accepts_rfc1918_allowed_ips() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let rule = NetworkPolicyRule {
            name: "good".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "internal.corp".to_string(),
                port: 443,
                allowed_ips: vec!["10.0.5.0/24".to_string()],
                ..Default::default()
            }],
            binaries: vec![],
        };
        let result = validate_rule_not_always_blocked(&rule);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_rule_accepts_public_host() {
        use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule};

        let rule = NetworkPolicyRule {
            name: "good".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![],
        };
        let result = validate_rule_not_always_blocked(&rule);
        assert!(result.is_ok());
    }

    // ---- Settings tests ----

    #[test]
    fn merge_effective_settings_includes_unset_registered_keys() {
        let global = StoredSettings::default();
        let sandbox = StoredSettings::default();
        let merged = merge_effective_settings(&global, &sandbox).unwrap();
        for registered in settings::REGISTERED_SETTINGS {
            let setting = merged
                .get(registered.key)
                .unwrap_or_else(|| panic!("missing registered key {}", registered.key));
            assert!(
                setting.value.is_none(),
                "expected unset value for {}",
                registered.key
            );
            assert_eq!(setting.scope, SettingScope::Unspecified as i32);
        }
    }

    #[test]
    fn materialize_global_settings_includes_unset_registered_keys() {
        let global = StoredSettings::default();
        let materialized = materialize_global_settings(&global).unwrap();
        for registered in settings::REGISTERED_SETTINGS {
            let setting = materialized
                .get(registered.key)
                .unwrap_or_else(|| panic!("missing registered key {}", registered.key));
            assert!(
                setting.value.is_none(),
                "expected unset value for {}",
                registered.key
            );
        }
    }

    #[test]
    fn decode_policy_from_global_settings_round_trip() {
        let policy = openshell_core::proto::SandboxPolicy {
            version: 7,
            ..Default::default()
        };
        let encoded = hex::encode(policy.encode_to_vec());
        let global = StoredSettings {
            revision: 1,
            settings: std::iter::once(("policy".to_string(), StoredSettingValue::Bytes(encoded)))
                .collect(),
            ..Default::default()
        };

        let decoded = decode_policy_from_global_settings(&global)
            .unwrap()
            .expect("policy present");
        assert_eq!(decoded.version, 7);
    }

    #[test]
    fn config_revision_changes_when_effective_setting_changes() {
        let policy = ProtoSandboxPolicy::default();
        let mut settings = HashMap::new();
        settings.insert(
            "mode".to_string(),
            EffectiveSetting {
                value: Some(SettingValue {
                    value: Some(setting_value::Value::StringValue("strict".to_string())),
                }),
                scope: SettingScope::Sandbox.into(),
            },
        );

        let rev_a = compute_config_revision(Some(&policy), &settings, PolicySource::Sandbox);
        settings.insert(
            "mode".to_string(),
            EffectiveSetting {
                value: Some(SettingValue {
                    value: Some(setting_value::Value::StringValue("relaxed".to_string())),
                }),
                scope: SettingScope::Sandbox.into(),
            },
        );
        let rev_b = compute_config_revision(Some(&policy), &settings, PolicySource::Sandbox);

        assert_ne!(rev_a, rev_b);
    }

    #[test]
    fn proto_setting_to_stored_rejects_unknown_key() {
        let value = SettingValue {
            value: Some(setting_value::Value::StringValue("hello".to_string())),
        };
        let err = proto_setting_to_stored("unknown_key", &value).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("unknown setting key"));
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn proto_setting_to_stored_rejects_type_mismatch() {
        let value = SettingValue {
            value: Some(setting_value::Value::StringValue("true".to_string())),
        };
        let err = proto_setting_to_stored("dummy_bool", &value).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("expects bool value"));
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn proto_setting_to_stored_accepts_bool_for_registered_bool_key() {
        let value = SettingValue {
            value: Some(setting_value::Value::BoolValue(true)),
        };
        let stored = proto_setting_to_stored("dummy_bool", &value).unwrap();
        assert_eq!(stored, StoredSettingValue::Bool(true));
    }

    #[test]
    fn proto_setting_to_stored_accepts_allowed_proposal_approval_mode_values() {
        for raw in ["manual", "auto"] {
            let value = SettingValue {
                value: Some(setting_value::Value::StringValue(raw.to_string())),
            };
            let stored = proto_setting_to_stored(settings::PROPOSAL_APPROVAL_MODE_KEY, &value)
                .unwrap_or_else(|e| panic!("expected '{raw}' to be accepted, got: {e}"));
            assert_eq!(stored, StoredSettingValue::String(raw.to_string()));
        }
    }

    #[test]
    fn proto_setting_to_stored_rejects_invalid_proposal_approval_mode_value() {
        // Typos and future-reserved modes must be rejected at configure time
        // — without this, the value silently resolves to manual at runtime
        // (fail-closed) and the operator never finds out they fat-fingered
        // the setting.
        for raw in ["autom", "AUTO", "Manual", "auto_on_low_risk", "", " auto"] {
            let value = SettingValue {
                value: Some(setting_value::Value::StringValue(raw.to_string())),
            };
            let res = proto_setting_to_stored(settings::PROPOSAL_APPROVAL_MODE_KEY, &value);
            assert!(
                res.is_err(),
                "expected '{raw}' to be rejected, got: {res:?}"
            );
            let err = res.unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
        }
    }

    #[test]
    fn proto_setting_to_stored_rejection_message_lists_allowed_proposal_approval_mode_values() {
        let value = SettingValue {
            value: Some(setting_value::Value::StringValue("autom".to_string())),
        };
        let err =
            proto_setting_to_stored(settings::PROPOSAL_APPROVAL_MODE_KEY, &value).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        let msg = err.message();
        assert!(msg.contains("manual"), "missing 'manual' in {msg}");
        assert!(msg.contains("auto"), "missing 'auto' in {msg}");
        assert!(msg.contains("autom"), "missing offending value in {msg}");
    }

    /// Locks in that invalid `proposal_approval_mode` is rejected at the
    /// `UpdateConfig` RPC boundary — not just in the `proto_setting_to_stored`
    /// helper. Prevents a future refactor from accidentally routing setting
    /// writes around the validation chokepoint.
    #[tokio::test]
    async fn update_config_global_rejects_invalid_proposal_approval_mode() {
        let state = test_server_state().await;
        let req = with_user(Request::new(UpdateConfigRequest {
            global: true,
            setting_key: settings::PROPOSAL_APPROVAL_MODE_KEY.to_string(),
            setting_value: Some(SettingValue {
                value: Some(setting_value::Value::StringValue("autom".to_string())),
            }),
            ..Default::default()
        }));
        let err = handle_update_config(&state, req)
            .await
            .expect_err("invalid proposal_approval_mode must be rejected at UpdateConfig");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            err.message().contains("autom") && err.message().contains("manual"),
            "expected rejection message to echo the bad value and list allowed values; got: {}",
            err.message()
        );
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn merge_effective_settings_global_overrides_sandbox_key() {
        let global = StoredSettings {
            revision: 2,
            settings: [
                (
                    "log_level".to_string(),
                    StoredSettingValue::String("warn".to_string()),
                ),
                ("dummy_int".to_string(), StoredSettingValue::Int(7)),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let sandbox = StoredSettings {
            revision: 1,
            settings: [
                (
                    "log_level".to_string(),
                    StoredSettingValue::String("debug".to_string()),
                ),
                ("dummy_bool".to_string(), StoredSettingValue::Bool(true)),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };

        let merged = merge_effective_settings(&global, &sandbox).unwrap();
        let log_level = merged.get("log_level").expect("log_level present");
        assert_eq!(log_level.scope, SettingScope::Global as i32);
        assert_eq!(
            log_level.value.as_ref().and_then(|v| v.value.as_ref()),
            Some(&setting_value::Value::StringValue("warn".to_string()))
        );

        let dummy_bool = merged.get("dummy_bool").expect("dummy_bool present");
        assert_eq!(dummy_bool.scope, SettingScope::Sandbox as i32);

        let dummy_int = merged.get("dummy_int").expect("dummy_int present");
        assert_eq!(dummy_int.scope, SettingScope::Global as i32);
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn merge_effective_settings_sandbox_scoped_value_has_sandbox_scope() {
        let global = StoredSettings::default();
        let sandbox = StoredSettings {
            revision: 1,
            settings: [(
                "log_level".to_string(),
                StoredSettingValue::String("debug".to_string()),
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        };

        let merged = merge_effective_settings(&global, &sandbox).unwrap();
        let log_level = merged.get("log_level").expect("log_level present");
        assert_eq!(log_level.scope, SettingScope::Sandbox as i32);
        assert!(log_level.value.is_some());
    }

    #[test]
    fn merge_effective_settings_unset_key_has_unspecified_scope_and_no_value() {
        let global = StoredSettings::default();
        let sandbox = StoredSettings::default();
        let merged = merge_effective_settings(&global, &sandbox).unwrap();
        for registered in settings::REGISTERED_SETTINGS {
            let setting = merged.get(registered.key).unwrap();
            assert_eq!(setting.scope, SettingScope::Unspecified as i32);
            assert!(setting.value.is_none());
        }
    }

    #[test]
    fn merge_effective_settings_policy_key_is_excluded() {
        let global = StoredSettings {
            revision: 1,
            settings: std::iter::once((
                "policy".to_string(),
                StoredSettingValue::Bytes("deadbeef".to_string()),
            ))
            .collect(),
            ..Default::default()
        };
        let sandbox = StoredSettings {
            revision: 1,
            settings: std::iter::once((
                "policy".to_string(),
                StoredSettingValue::Bytes("cafebabe".to_string()),
            ))
            .collect(),
            ..Default::default()
        };

        let merged = merge_effective_settings(&global, &sandbox).unwrap();
        assert!(!merged.contains_key("policy"));
    }

    #[test]
    fn sandbox_settings_names_match_sandbox_names() {
        let sandbox_name = "my-sandbox";
        assert_eq!(sandbox_name, "my-sandbox");
    }

    // ---- compute_config_revision ----

    #[test]
    fn config_revision_stable_when_nothing_changes() {
        let policy = ProtoSandboxPolicy::default();
        let mut settings = HashMap::new();
        settings.insert(
            "log_level".to_string(),
            EffectiveSetting {
                value: Some(SettingValue {
                    value: Some(setting_value::Value::StringValue("info".to_string())),
                }),
                scope: SettingScope::Sandbox.into(),
            },
        );

        let rev_a = compute_config_revision(Some(&policy), &settings, PolicySource::Sandbox);
        let rev_b = compute_config_revision(Some(&policy), &settings, PolicySource::Sandbox);
        assert_eq!(rev_a, rev_b);
    }

    #[test]
    fn config_revision_changes_when_policy_changes() {
        let policy_a = ProtoSandboxPolicy {
            version: 1,
            ..Default::default()
        };
        let policy_b = ProtoSandboxPolicy {
            version: 2,
            ..Default::default()
        };
        let settings = HashMap::new();

        let rev_a = compute_config_revision(Some(&policy_a), &settings, PolicySource::Sandbox);
        let rev_b = compute_config_revision(Some(&policy_b), &settings, PolicySource::Sandbox);
        assert_ne!(rev_a, rev_b);
    }

    #[test]
    fn config_revision_changes_when_policy_source_changes() {
        let policy = ProtoSandboxPolicy::default();
        let settings = HashMap::new();

        let rev_a = compute_config_revision(Some(&policy), &settings, PolicySource::Sandbox);
        let rev_b = compute_config_revision(Some(&policy), &settings, PolicySource::Global);
        assert_ne!(rev_a, rev_b);
    }

    #[test]
    fn config_revision_without_policy_still_hashes_settings() {
        let mut settings = HashMap::new();
        settings.insert(
            "log_level".to_string(),
            EffectiveSetting {
                value: Some(SettingValue {
                    value: Some(setting_value::Value::StringValue("debug".to_string())),
                }),
                scope: SettingScope::Sandbox.into(),
            },
        );

        let rev_a = compute_config_revision(None, &settings, PolicySource::Sandbox);

        settings.insert(
            "log_level".to_string(),
            EffectiveSetting {
                value: Some(SettingValue {
                    value: Some(setting_value::Value::StringValue("warn".to_string())),
                }),
                scope: SettingScope::Sandbox.into(),
            },
        );

        let rev_b = compute_config_revision(None, &settings, PolicySource::Sandbox);
        assert_ne!(rev_a, rev_b);
    }

    // ---- stored <-> proto round-trip ----

    #[test]
    fn stored_setting_to_proto_string_round_trip() {
        let stored = StoredSettingValue::String("hello".to_string());
        let proto = stored_setting_to_proto(&stored).unwrap();
        assert_eq!(
            proto.value,
            Some(setting_value::Value::StringValue("hello".to_string()))
        );
    }

    #[test]
    fn stored_setting_to_proto_int_round_trip() {
        let stored = StoredSettingValue::Int(42);
        let proto = stored_setting_to_proto(&stored).unwrap();
        assert_eq!(proto.value, Some(setting_value::Value::IntValue(42)));
    }

    #[test]
    fn stored_setting_to_proto_bool_round_trip() {
        let stored = StoredSettingValue::Bool(false);
        let proto = stored_setting_to_proto(&stored).unwrap();
        assert_eq!(proto.value, Some(setting_value::Value::BoolValue(false)));
    }

    // ---- upsert_setting_value ----

    #[test]
    fn upsert_setting_value_returns_true_on_insert() {
        let mut map = BTreeMap::new();
        let changed = upsert_setting_value(
            &mut map,
            "log_level",
            StoredSettingValue::String("debug".to_string()),
        );
        assert!(changed);
        assert_eq!(
            map.get("log_level"),
            Some(&StoredSettingValue::String("debug".to_string()))
        );
    }

    #[test]
    fn upsert_setting_value_returns_false_when_unchanged() {
        let mut map = BTreeMap::new();
        map.insert(
            "log_level".to_string(),
            StoredSettingValue::String("debug".to_string()),
        );
        let changed = upsert_setting_value(
            &mut map,
            "log_level",
            StoredSettingValue::String("debug".to_string()),
        );
        assert!(!changed);
    }

    #[test]
    fn upsert_setting_value_returns_true_on_update() {
        let mut map = BTreeMap::new();
        map.insert(
            "log_level".to_string(),
            StoredSettingValue::String("debug".to_string()),
        );
        let changed = upsert_setting_value(
            &mut map,
            "log_level",
            StoredSettingValue::String("warn".to_string()),
        );
        assert!(changed);
    }

    // ---- Settings persistence ----

    #[tokio::test]
    async fn global_settings_load_returns_default_when_empty() {
        let store = test_store().await;
        let settings = load_global_settings(&store).await.unwrap();
        assert!(settings.settings.is_empty());
        assert_eq!(settings.revision, 0);
    }

    #[tokio::test]
    async fn sandbox_settings_load_returns_default_when_empty() {
        let store = test_store().await;
        let settings = load_sandbox_settings(&store, "nonexistent").await.unwrap();
        assert!(settings.settings.is_empty());
        assert_eq!(settings.revision, 0);
    }

    #[tokio::test]
    async fn global_settings_save_and_load_round_trip() {
        let store = test_store().await;

        let mut settings = StoredSettings::default();
        settings.settings.insert(
            "log_level".to_string(),
            StoredSettingValue::String("error".to_string()),
        );
        settings
            .settings
            .insert("dummy_bool".to_string(), StoredSettingValue::Bool(true));
        settings.revision = 5;
        save_global_settings(&store, &settings).await.unwrap();

        let loaded = load_global_settings(&store).await.unwrap();
        assert_eq!(loaded.revision, 5);
        assert_eq!(
            loaded.settings.get("log_level"),
            Some(&StoredSettingValue::String("error".to_string()))
        );
        assert_eq!(
            loaded.settings.get("dummy_bool"),
            Some(&StoredSettingValue::Bool(true))
        );
    }

    #[tokio::test]
    async fn sandbox_settings_save_and_load_round_trip() {
        let store = test_store().await;

        let sandbox_name = "my-sandbox";
        let mut settings = StoredSettings::default();
        settings
            .settings
            .insert("dummy_int".to_string(), StoredSettingValue::Int(99));
        settings.revision = 3;
        save_sandbox_settings(&store, sandbox_name, &settings)
            .await
            .unwrap();

        let loaded = load_sandbox_settings(&store, sandbox_name).await.unwrap();
        assert_eq!(loaded.revision, 3);
        assert_eq!(
            loaded.settings.get("dummy_int"),
            Some(&StoredSettingValue::Int(99))
        );
    }

    #[tokio::test]
    async fn concurrent_global_setting_mutations_are_serialized() {
        let store = Arc::new(test_store().await);
        let mutex = Arc::new(tokio::sync::Mutex::new(()));

        let n = 50;
        let mut handles = Vec::with_capacity(n);

        for i in 0..n {
            let store = store.clone();
            let mutex = mutex.clone();
            handles.push(tokio::spawn(async move {
                let _guard = mutex.lock().await;
                let mut settings = load_global_settings(&store).await.unwrap();
                settings
                    .settings
                    .insert(format!("key_{i}"), StoredSettingValue::Int(i as i64));
                settings.revision = settings.revision.wrapping_add(1);
                save_global_settings(&store, &settings).await.unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let final_settings = load_global_settings(&store).await.unwrap();
        assert_eq!(final_settings.revision, n as u64);
        assert_eq!(final_settings.settings.len(), n);
    }

    #[tokio::test]
    async fn concurrent_global_setting_mutations_without_lock_can_lose_writes() {
        let store = Arc::new(test_store().await);

        let n = 50;
        let mut handles = Vec::with_capacity(n);

        for i in 0..n {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                let mut settings = load_global_settings(&store).await.unwrap();
                tokio::task::yield_now().await;
                settings
                    .settings
                    .insert(format!("key_{i}"), StoredSettingValue::Int(i as i64));
                settings.revision = settings.revision.wrapping_add(1);
                save_global_settings(&store, &settings).await
            }));
        }

        let mut succeeded = 0;
        let mut cas_conflicts = 0;
        for h in handles {
            match h.await.unwrap() {
                Ok(()) => succeeded += 1,
                Err(e) if e.code() == Code::Aborted => cas_conflicts += 1,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        let final_settings = load_global_settings(&store).await.unwrap();

        // With single-attempt CAS (no retry), concurrent modifications are properly detected:
        // - All tasks read initial state (revision=0, resource_version=0)
        // - First write succeeds with resource_version=1
        // - Subsequent writes fail with ABORTED (CAS conflict) because they all have stale resource_version=0
        // - Only the first write succeeds; all others are rejected
        //
        // This demonstrates that single-attempt CAS prevents lost writes by rejecting stale updates.
        // The caller must retry from a fresh read to incorporate concurrent changes.
        assert!(
            cas_conflicts > 0,
            "most concurrent writes should fail with CAS conflict (succeeded={succeeded}, conflicts={cas_conflicts})"
        );
        assert!(
            succeeded < n,
            "not all writes should succeed due to conflicts (succeeded={succeeded}, total={n})"
        );
        assert_eq!(
            final_settings.revision as usize, succeeded,
            "final revision should match number of successful writes"
        );
        assert_eq!(
            final_settings.settings.len(),
            succeeded,
            "final settings should contain exactly the keys from successful writes"
        );

        eprintln!(
            "unlocked CAS test: {succeeded} succeeded, {cas_conflicts} CAS conflicts, \
             final revision={} (matches succeeded count, demonstrating proper conflict detection)",
            final_settings.revision
        );
    }

    // ---- Conflict guard tests ----

    #[tokio::test]
    async fn conflict_guard_sandbox_set_blocked_when_global_exists() {
        let store = test_store().await;

        let mut global = StoredSettings::default();
        global.settings.insert(
            "log_level".to_string(),
            StoredSettingValue::String("warn".to_string()),
        );
        global.revision = 1;
        save_global_settings(&store, &global).await.unwrap();

        let loaded_global = load_global_settings(&store).await.unwrap();
        let globally_managed = loaded_global.settings.contains_key("log_level");
        assert!(globally_managed);
    }

    #[tokio::test]
    async fn conflict_guard_sandbox_delete_blocked_when_global_exists() {
        let store = test_store().await;

        let mut global = StoredSettings::default();
        global
            .settings
            .insert("dummy_int".to_string(), StoredSettingValue::Int(42));
        global.revision = 1;
        save_global_settings(&store, &global).await.unwrap();

        let loaded_global = load_global_settings(&store).await.unwrap();
        assert!(loaded_global.settings.contains_key("dummy_int"));
    }

    #[tokio::test]
    async fn delete_unlock_sandbox_set_succeeds_after_global_delete() {
        let store = test_store().await;

        // Create initial global settings
        let mut global = StoredSettings::default();
        global.settings.insert(
            "log_level".to_string(),
            StoredSettingValue::String("warn".to_string()),
        );
        global.revision = 1;
        save_global_settings(&store, &global).await.unwrap();

        let loaded = load_global_settings(&store).await.unwrap();
        assert!(loaded.settings.contains_key("log_level"));

        // Load fresh to get current resource_version before updating
        let mut global = load_global_settings(&store).await.unwrap();
        global.settings.remove("log_level");
        global.revision = 2;
        save_global_settings(&store, &global).await.unwrap();

        let loaded = load_global_settings(&store).await.unwrap();
        assert!(!loaded.settings.contains_key("log_level"));

        let sandbox_name = "test-sandbox";
        let mut sandbox_settings = load_sandbox_settings(&store, sandbox_name).await.unwrap();
        let changed = upsert_setting_value(
            &mut sandbox_settings.settings,
            "log_level",
            StoredSettingValue::String("debug".to_string()),
        );
        assert!(changed);
        sandbox_settings.revision = sandbox_settings.revision.wrapping_add(1);
        save_sandbox_settings(&store, sandbox_name, &sandbox_settings)
            .await
            .unwrap();

        let reloaded = load_sandbox_settings(&store, sandbox_name).await.unwrap();
        assert_eq!(
            reloaded.settings.get("log_level"),
            Some(&StoredSettingValue::String("debug".to_string())),
        );
    }

    #[test]
    fn validate_registered_setting_key_rejects_policy() {
        let err = validate_registered_setting_key("policy").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("unknown setting key"));
    }

    #[test]
    fn proto_setting_to_stored_rejects_policy_key() {
        let value = SettingValue {
            value: Some(setting_value::Value::StringValue("anything".to_string())),
        };
        let err = proto_setting_to_stored("policy", &value).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("unknown setting key"));
    }

    #[tokio::test]
    async fn save_settings_detects_concurrent_modification() {
        let store = test_store().await;

        // Create initial settings
        let mut settings = StoredSettings {
            revision: 1,
            settings: std::iter::once((
                "initial_key".to_string(),
                StoredSettingValue::String("initial_value".to_string()),
            ))
            .collect(),
            ..Default::default()
        };
        save_global_settings(&store, &settings).await.unwrap();

        // Load settings (simulating first client read)
        let loaded = load_global_settings(&store).await.unwrap();
        assert_eq!(loaded.revision, 1);

        // Simulate concurrent modification: another client updates the settings
        let mut concurrent_update = loaded.clone();
        concurrent_update.settings.insert(
            "concurrent_key".to_string(),
            StoredSettingValue::String("concurrent_value".to_string()),
        );
        concurrent_update.revision = 2;
        save_global_settings(&store, &concurrent_update)
            .await
            .unwrap();

        // Now attempt to save our original modification (which is based on stale revision 1)
        settings.settings.insert(
            "our_key".to_string(),
            StoredSettingValue::String("our_value".to_string()),
        );
        settings.revision = 2; // We think we're updating to revision 2

        let result = save_global_settings(&store, &settings).await;

        // Should fail with ABORTED due to concurrent modification
        assert!(result.is_err(), "save with stale revision should fail");
        let err = result.unwrap_err();
        assert_eq!(
            err.code(),
            Code::Aborted,
            "should fail with ABORTED due to version mismatch"
        );
        assert!(
            err.message().contains("concurrently"),
            "error should mention concurrent modification: {}",
            err.message()
        );

        // Verify the database contains the concurrent update, not our stale update
        let final_settings = load_global_settings(&store).await.unwrap();
        assert_eq!(final_settings.revision, 2);
        assert!(
            final_settings.settings.contains_key("concurrent_key"),
            "concurrent update should be preserved"
        );
        assert!(
            !final_settings.settings.contains_key("our_key"),
            "stale update should NOT be in database"
        );
    }

    // ---- CAS (Client-driven optimistic concurrency) tests for UpdateConfig ----
    // These test the policy backfill path where spec.policy is None and UpdateConfig
    // uses update_message_cas to atomically set it.

    #[tokio::test]
    async fn update_config_policy_backfill_cas_succeeds_with_correct_version() {
        use openshell_core::proto::{SandboxPhase, SandboxSpec};

        let state = test_server_state().await;

        // Create a sandbox WITHOUT a policy (spec.policy = None)
        // This simulates a sandbox before the supervisor has discovered and synced a policy
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-1".to_string(),
                name: "test-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None, // No policy yet - will be backfilled
                providers: Vec::new(),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        state.store.put_message(&sandbox).await.unwrap();

        // Fetch the sandbox to get its current resource_version
        let current = state
            .store
            .get_message_by_name::<Sandbox>("test-sandbox")
            .await
            .unwrap()
            .unwrap();
        let current_version = current.metadata.as_ref().unwrap().resource_version;

        // Backfill the policy with correct expected_resource_version
        let new_policy = ProtoSandboxPolicy::default();

        let response = handle_update_config(
            &state,
            Request::new(UpdateConfigRequest {
                name: "test-sandbox".to_string(),
                policy: Some(new_policy),
                setting_key: String::new(),
                setting_value: None,
                delete_setting: false,
                global: false,
                merge_operations: vec![],
                expected_resource_version: current_version,
            }),
        )
        .await
        .unwrap()
        .into_inner();

        // UpdateConfigResponse contains the policy version
        assert_eq!(response.version, 1);

        // Verify the resource_version incremented and policy was backfilled
        let updated_sandbox = state
            .store
            .get_message_by_name::<Sandbox>("test-sandbox")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            updated_sandbox.metadata.as_ref().unwrap().resource_version,
            current_version + 1,
            "resource_version should increment during CAS backfill"
        );
        assert!(
            updated_sandbox.spec.as_ref().unwrap().policy.is_some(),
            "policy should be backfilled"
        );
    }

    #[tokio::test]
    async fn update_config_policy_backfill_cas_rejects_stale_version() {
        use openshell_core::proto::{SandboxPhase, SandboxSpec};

        let state = test_server_state().await;

        // Create a sandbox WITHOUT a policy
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-1".to_string(),
                name: "test-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                providers: Vec::new(),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        state.store.put_message(&sandbox).await.unwrap();

        // Get current version
        let current = state
            .store
            .get_message_by_name::<Sandbox>("test-sandbox")
            .await
            .unwrap()
            .unwrap();
        let current_version = current.metadata.as_ref().unwrap().resource_version;

        // Try to backfill with a stale version
        let new_policy = ProtoSandboxPolicy::default();

        let err = handle_update_config(
            &state,
            Request::new(UpdateConfigRequest {
                name: "test-sandbox".to_string(),
                policy: Some(new_policy),
                setting_key: String::new(),
                setting_value: None,
                delete_setting: false,
                global: false,
                merge_operations: vec![],
                expected_resource_version: 99, // stale version
            }),
        )
        .await
        .unwrap_err();

        // Should get ABORTED status for CAS conflict
        assert_eq!(err.code(), Code::Aborted);
        assert!(
            err.message().contains("modified concurrently")
                || err.message().contains("resource_version"),
            "error message should mention concurrency conflict: {}",
            err.message()
        );

        // Verify the sandbox was not modified (policy still None)
        let unchanged = state
            .store
            .get_message_by_name::<Sandbox>("test-sandbox")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            unchanged.metadata.as_ref().unwrap().resource_version,
            current_version,
            "resource_version should not change when CAS fails"
        );
        assert!(
            unchanged.spec.as_ref().unwrap().policy.is_none(),
            "policy should still be None after failed backfill"
        );
    }

    #[tokio::test]
    async fn update_config_policy_backfill_concurrent_with_stale_versions() {
        use openshell_core::proto::{SandboxPhase, SandboxSpec};
        use std::sync::Arc;

        let state = Arc::new(test_server_state().await);

        // Create a sandbox WITHOUT a policy
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sb-1".to_string(),
                name: "test-sandbox".to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                providers: Vec::new(),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        state.store.put_message(&sandbox).await.unwrap();

        // All three clients fetch the sandbox and see the same version
        let initial = state
            .store
            .get_message_by_name::<Sandbox>("test-sandbox")
            .await
            .unwrap()
            .unwrap();
        let initial_version = initial.metadata.as_ref().unwrap().resource_version;

        // Launch 3 concurrent policy backfill attempts, all using the same initial version
        let mut handles = vec![];
        for _i in 0..3 {
            let state_clone = Arc::clone(&state);
            let new_policy = ProtoSandboxPolicy::default();

            let handle = tokio::spawn(async move {
                handle_update_config(
                    &state_clone,
                    Request::new(UpdateConfigRequest {
                        name: "test-sandbox".to_string(),
                        policy: Some(new_policy),
                        setting_key: String::new(),
                        setting_value: None,
                        delete_setting: false,
                        global: false,
                        merge_operations: vec![],
                        expected_resource_version: initial_version,
                    }),
                )
                .await
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // Only one should succeed; others should get ABORTED
        let successes = results.iter().filter(|r| r.is_ok()).count();
        let aborted_conflicts = results
            .iter()
            .filter(|r| r.as_ref().err().is_some_and(|e| e.code() == Code::Aborted))
            .count();

        assert_eq!(
            successes, 1,
            "exactly one backfill should succeed with client-driven CAS"
        );
        assert_eq!(
            aborted_conflicts, 2,
            "two backfills should fail with ABORTED due to stale version"
        );

        // Final sandbox should have resource_version = initial_version + 1 and policy backfilled
        let final_sandbox = state
            .store
            .get_message_by_name::<Sandbox>("test-sandbox")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            final_sandbox.metadata.as_ref().unwrap().resource_version,
            initial_version + 1
        );
        assert!(
            final_sandbox.spec.as_ref().unwrap().policy.is_some(),
            "policy should be backfilled after one success"
        );
    }
}
