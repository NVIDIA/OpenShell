// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Secret-free provider receipts, status rendering, and bounded CLI waits.

use crate::tls::{GrpcClient, TlsOptions, grpc_client};
use futures::{StreamExt, stream};
use miette::{IntoDiagnostic, Result, miette};
use openshell_core::proto::{
    GetSandboxProviderStatusRequest, Provider, ProviderMutationKind, ProviderMutationReceipt,
    ProviderReadinessReason, ProviderReadinessState, ProviderReadinessStatus,
};
use openshell_sdk::provider_readiness::{
    ProviderWaitOutcome, persisted_status, provider_status, provider_wait_deadline,
    validate_provider_receipt, wait_for_provider_status_until,
};
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::Instant;

const PROVIDER_WAIT_CONCURRENCY: usize = 16;

/// Output and deadline choices shared by provider mutation and status commands.
#[derive(Clone, Copy)]
pub struct ProviderWaitOptions<'a> {
    /// Wait for current runtime installation after saving the desired mutation.
    pub wait: bool,
    /// One total deadline for all selected sandbox observations.
    pub timeout: Duration,
    /// CLI output format: table, JSON, or YAML.
    pub output: &'a str,
}

impl Default for ProviderWaitOptions<'_> {
    fn default() -> Self {
        Self {
            wait: false,
            timeout: Duration::from_secs(30),
            output: "table",
        }
    }
}

impl ProviderWaitOptions<'_> {
    /// Reject invalid wait settings before performing a provider mutation.
    pub fn validate(self) -> Result<()> {
        provider_wait_deadline(self.timeout).into_diagnostic()?;
        if !matches!(self.output, "table" | "json" | "yaml") {
            return Err(miette!("unsupported provider status output format"));
        }
        Ok(())
    }
}

struct DisplayStatus {
    status: ProviderReadinessStatus,
    outcome: &'static str,
    complete: bool,
}

/// Caller-selected authority that every returned mutation receipt must retain.
#[derive(Clone, Copy)]
pub(super) struct ProviderMutationExpectation<'a> {
    /// Workspace explicitly selected by the command.
    pub workspace: &'a str,
    /// Provider name explicitly selected by the command.
    pub provider_name: &'a str,
    /// Operation submitted to the gateway.
    pub kind: ProviderMutationKind,
    /// Requested sandbox name and previously fetched object ID for attach/detach.
    pub sandbox: Option<(&'a str, &'a str)>,
    /// Published provider object returned by an update, including its revision.
    pub provider: Option<&'a Provider>,
}

fn validate_mutation_receipts(
    mutation_id: &str,
    receipts: &[ProviderMutationReceipt],
    expected: &ProviderMutationExpectation<'_>,
) -> Result<()> {
    let invalid = || miette!("gateway returned an invalid provider mutation receipt");
    if mutation_id.is_empty() || expected.workspace.is_empty() || expected.provider_name.is_empty()
    {
        return Err(invalid());
    }
    let provider = match expected.kind {
        ProviderMutationKind::Attach | ProviderMutationKind::Detach => {
            if receipts.len() != 1
                || expected
                    .sandbox
                    .is_none_or(|(name, id)| name.is_empty() || id.is_empty())
            {
                return Err(invalid());
            }
            None
        }
        ProviderMutationKind::Update => {
            let metadata = expected
                .provider
                .and_then(|provider| provider.metadata.as_ref())
                .ok_or_else(invalid)?;
            if metadata.id.is_empty()
                || metadata.name != expected.provider_name
                || metadata.workspace != expected.workspace
            {
                return Err(invalid());
            }
            Some(metadata)
        }
        ProviderMutationKind::Unspecified | ProviderMutationKind::Observe => return Err(invalid()),
    };
    let mut receipt_ids = HashSet::new();
    let mut sandbox_ids = HashSet::new();
    for receipt in receipts {
        validate_provider_receipt(receipt).into_diagnostic()?;
        let desired = receipt.desired.as_ref().ok_or_else(invalid)?;
        // Validate the complete batch before polling or printing saved intent.
        // Otherwise a substituted receipt can redirect a wait to another scope.
        if receipt.mutation_id != mutation_id
            || receipt.workspace != expected.workspace
            || receipt.provider != expected.provider_name
            || receipt.kind != i32::from(expected.kind)
            || !receipt_ids.insert(receipt.receipt_id.as_str())
            || !sandbox_ids.insert(desired.sandbox_id.as_str())
            || expected
                .sandbox
                .is_some_and(|(name, id)| desired.sandbox != name || desired.sandbox_id != id)
            || provider.is_some_and(|provider| {
                desired.provider_id != provider.id
                    || desired.provider_resource_version != provider.resource_version
            })
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Display persisted targets and optionally wait for each original receipt.
///
/// Every target is reported even when another target fails. Concurrency is
/// bounded and all requests share one deadline, including queued targets.
pub(super) async fn finish_provider_mutation(
    client: &GrpcClient,
    mutation_id: &str,
    receipts: Vec<ProviderMutationReceipt>,
    expected: ProviderMutationExpectation<'_>,
    options: ProviderWaitOptions<'_>,
) -> Result<()> {
    options.validate()?;
    validate_mutation_receipts(mutation_id, &receipts, &expected)?;
    let deadline = provider_wait_deadline(options.timeout).into_diagnostic()?;
    let statuses = receipts.into_iter().map(persisted_status).collect();
    let results = if options.wait {
        wait_for_mutation_statuses(client, statuses, deadline).await
    } else {
        statuses
            .into_iter()
            .map(|status| DisplayStatus {
                status,
                outcome: "not_requested",
                complete: false,
            })
            .collect()
    };
    print_statuses(mutation_id, &results, options.output)?;
    if options.wait && results.iter().any(|result| !result.complete) {
        return Err(miette!(
            "provider readiness wait did not complete for every selected sandbox; inspect the reported outcomes"
        ));
    }
    Ok(())
}

async fn wait_for_mutation_statuses(
    client: &GrpcClient,
    statuses: Vec<ProviderReadinessStatus>,
    deadline: Instant,
) -> Vec<DisplayStatus> {
    let mut pending = statuses.into_iter().enumerate().collect::<Vec<_>>();
    let mut results = Vec::with_capacity(pending.len());
    while !pending.is_empty() && Instant::now() < deadline {
        // Divide the remaining time among actual queued batches. When every
        // target fits in one batch, healthy but slow RPCs get the full deadline;
        // queued targets still get a turn if the preceding batch stalls.
        let batches =
            u32::try_from(pending.len().div_ceil(PROVIDER_WAIT_CONCURRENCY)).unwrap_or(u32::MAX);
        let slice = deadline.saturating_duration_since(Instant::now()) / batches;
        if slice.is_zero() {
            break;
        }
        let round = stream::iter(pending.into_iter().map(|(index, status)| {
            let mut client = client.clone();
            async move {
                let slice_deadline = (Instant::now() + slice).min(deadline);
                let result =
                    wait_for_provider_status_until(&mut client, &status, slice_deadline).await;
                (index, status, result)
            }
        }))
        .buffer_unordered(PROVIDER_WAIT_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
        pending = Vec::new();
        for (index, previous, result) in round {
            match result {
                // The SDK pins the receipt in this status and retains its last
                // observation. Only unfinished targets enter the next round.
                Ok(result)
                    if result.outcome == ProviderWaitOutcome::TimedOut
                        && Instant::now() < deadline =>
                {
                    pending.push((index, result.status));
                }
                Ok(result) => {
                    results.push((
                        index,
                        DisplayStatus {
                            status: result.status,
                            outcome: match result.outcome {
                                ProviderWaitOutcome::Complete => "complete",
                                ProviderWaitOutcome::TimedOut => "timed_out",
                                ProviderWaitOutcome::Terminal => "terminal",
                            },
                            complete: result.outcome == ProviderWaitOutcome::Complete,
                        },
                    ));
                }
                // A transport error cannot prove installation failure. Preserve
                // the last observation and expose only the safe error category.
                Err(_) => {
                    results.push((
                        index,
                        DisplayStatus {
                            status: previous,
                            outcome: "observation_error",
                            complete: false,
                        },
                    ));
                }
            }
        }
    }
    results.extend(pending.into_iter().map(|(index, status)| {
        (
            index,
            DisplayStatus {
                status,
                outcome: "timed_out",
                complete: false,
            },
        )
    }));
    // Fair polling must not change the command's stable target output order.
    results.sort_unstable_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

/// Show desired/observed provider state, optionally waiting for that exact state.
pub async fn sandbox_provider_status(
    server: &str,
    name: &str,
    provider: &str,
    receipt_id: &str,
    workspace: &str,
    tls: &TlsOptions,
    options: ProviderWaitOptions<'_>,
) -> Result<()> {
    options.validate()?;
    let mut client = grpc_client(server, tls).await?;
    let deadline = provider_wait_deadline(options.timeout).into_diagnostic()?;
    let status = tokio::time::timeout_at(
        deadline,
        provider_status(
            &mut client,
            GetSandboxProviderStatusRequest {
                sandbox: name.to_string(),
                provider: provider.to_string(),
                receipt_id: receipt_id.to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    workspace.to_string(),
                )),
            },
        ),
    )
    .await
    .map_err(|_| miette!("provider status request timed out"))?
    .into_diagnostic()?;
    let receipt = status
        .receipt
        .as_ref()
        .ok_or_else(|| miette!("gateway returned no provider receipt"))?;
    let mutation_id = receipt.mutation_id.clone();
    let result = if options.wait {
        let result = wait_for_provider_status_until(&mut client, &status, deadline)
            .await
            .into_diagnostic()?;
        DisplayStatus {
            status: result.status,
            outcome: match result.outcome {
                ProviderWaitOutcome::Complete => "complete",
                ProviderWaitOutcome::TimedOut => "timed_out",
                ProviderWaitOutcome::Terminal => "terminal",
            },
            complete: result.outcome == ProviderWaitOutcome::Complete,
        }
    } else {
        DisplayStatus {
            status,
            outcome: "not_requested",
            complete: false,
        }
    };
    let complete = result.complete;
    print_statuses(&mutation_id, &[result], options.output)?;
    if options.wait && !complete {
        return Err(miette!(
            "provider readiness wait did not complete; inspect the reported outcome"
        ));
    }
    Ok(())
}

fn state_label(state: i32) -> &'static str {
    match ProviderReadinessState::try_from(state) {
        Ok(ProviderReadinessState::Persisted) => "persisted",
        Ok(ProviderReadinessState::Pending) => "pending",
        Ok(ProviderReadinessState::Ready) => "ready",
        Ok(ProviderReadinessState::Withheld) => "withheld",
        Ok(ProviderReadinessState::Revoked) => "revoked",
        Ok(ProviderReadinessState::Failed) => "failed",
        Ok(ProviderReadinessState::Superseded) => "superseded",
        _ => "unknown",
    }
}

fn reason_label(reason: i32) -> String {
    ProviderReadinessReason::try_from(reason).map_or_else(
        |_| "unknown".to_string(),
        |reason| {
            reason
                .as_str_name()
                .trim_start_matches("PROVIDER_READINESS_REASON_")
                .to_ascii_lowercase()
        },
    )
}

fn receipt_json(receipt: &ProviderMutationReceipt) -> serde_json::Value {
    let desired = receipt.desired.as_ref().map(|desired| {
        serde_json::json!({
            "sandbox_id": desired.sandbox_id,
            "sandbox": desired.sandbox,
            "attachment_epoch": desired.attachment_epoch,
            "provider_id": desired.provider_id,
            "provider_resource_version": desired.provider_resource_version.to_string(),
            "provider_env_revision": desired.provider_env_revision.to_string(),
            "config_revision": desired.config_revision.to_string(),
            "policy_hash": desired.policy_hash,
        })
    });
    serde_json::json!({
        "receipt_id": receipt.receipt_id,
        "mutation_id": receipt.mutation_id,
        "provider": receipt.provider,
        "workspace": receipt.workspace,
        "kind": receipt.kind().as_str_name().trim_start_matches("PROVIDER_MUTATION_KIND_").to_ascii_lowercase(),
        "desired": desired,
        "persisted_time": receipt.persisted_time.as_ref().map(ToString::to_string),
    })
}

fn status_json(result: &DisplayStatus) -> serde_json::Value {
    let observed = result.status.observed.as_ref().map(|observed| {
        serde_json::json!({
            "session_id": observed.session_id,
            "sequence": observed.sequence.to_string(),
            "attachment_epoch": observed.attachment_epoch,
            "provider_env_revision": observed.provider_env_revision.to_string(),
            "config_revision": observed.config_revision.to_string(),
            "policy_hash": observed.policy_hash,
            "credentials_installed": observed.credentials_installed,
            "policy_active": observed.policy_active,
            "launch_environment_installed": observed.launch_environment_installed,
            "process_instance_id": observed.process_instance_id,
            "reason": reason_label(observed.reason),
        })
    });
    serde_json::json!({
        "receipt": result.status.receipt.as_ref().map(receipt_json),
        "state": state_label(result.status.state),
        "reason": reason_label(result.status.reason),
        "observed": observed,
        "network_instance_id": result.status.network_instance_id,
        "observed_time": result.status.observed_time.as_ref().map(ToString::to_string),
        "evaluated_time": result.status.evaluated_time.as_ref().map(ToString::to_string),
        "wait_outcome": result.outcome,
    })
}

fn print_statuses(mutation_id: &str, results: &[DisplayStatus], output: &str) -> Result<()> {
    let value = serde_json::json!({
        "mutation_id": mutation_id,
        "targets": results.iter().map(status_json).collect::<Vec<_>>(),
    });
    if crate::output::print_output_single(output, &value, Clone::clone)? {
        return Ok(());
    }
    if results.is_empty() {
        println!("Provider mutation {mutation_id} persisted; no attached sandboxes were selected.");
        return Ok(());
    }
    for result in results {
        let Some(receipt) = result.status.receipt.as_ref() else {
            continue;
        };
        let sandbox = receipt
            .desired
            .as_ref()
            .map_or("unknown", |desired| desired.sandbox.as_str());
        println!(
            "{} / {}: {} ({})",
            sandbox,
            receipt.provider,
            state_label(result.status.state),
            reason_label(result.status.reason)
        );
        println!(
            "  Receipt: {}",
            if receipt.receipt_id.is_empty() {
                "current state"
            } else {
                &receipt.receipt_id
            }
        );
        println!(
            "  Persisted: {}",
            receipt
                .persisted_time
                .as_ref()
                .map_or_else(|| "-".to_string(), ToString::to_string)
        );
        if let Some(observed) = result.status.observed.as_ref() {
            println!(
                "  Installed: credentials={}, policy={}, future process environment={}",
                observed.credentials_installed,
                observed.policy_active,
                observed.launch_environment_installed
            );
        }
        if result.outcome != "not_requested" {
            println!("  Wait: {}", result.outcome);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::ProviderDesiredIdentity;

    #[test]
    fn mutation_receipts_reject_duplicate_targets_and_allow_initial_fingerprints() {
        let provider = Provider {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "provider-id".to_string(),
                name: "provider".to_string(),
                workspace: "default".to_string(),
                resource_version: 0,
                ..Default::default()
            }),
            ..Default::default()
        };
        let expected = ProviderMutationExpectation {
            workspace: "default",
            provider_name: "provider",
            kind: ProviderMutationKind::Update,
            sandbox: None,
            provider: Some(&provider),
        };
        let receipt = ProviderMutationReceipt {
            receipt_id: "receipt".to_string(),
            mutation_id: "mutation".to_string(),
            provider: "provider".to_string(),
            workspace: "default".to_string(),
            kind: ProviderMutationKind::Update.into(),
            persisted_time: Some(openshell_core::time::timestamp_from_millis(1).unwrap()),
            desired: Some(ProviderDesiredIdentity {
                sandbox_id: "sandbox-id".to_string(),
                sandbox: "sandbox".to_string(),
                provider_id: "provider-id".to_string(),
                ..Default::default()
            }),
        };
        assert!(
            validate_mutation_receipts("mutation", std::slice::from_ref(&receipt), &expected)
                .is_ok()
        );
        assert!(validate_mutation_receipts("mutation", &[], &expected).is_ok());
        let mut duplicate = receipt.clone();
        duplicate.receipt_id = "other-receipt".to_string();
        assert!(
            validate_mutation_receipts("mutation", &[receipt.clone(), duplicate], &expected)
                .is_err()
        );
        let mut duplicate = receipt.clone();
        duplicate
            .desired
            .as_mut()
            .expect("desired identity")
            .sandbox_id = "other-sandbox".to_string();
        assert!(validate_mutation_receipts("mutation", &[receipt, duplicate], &expected).is_err());
        assert!(
            validate_mutation_receipts(
                "mutation",
                &[],
                &ProviderMutationExpectation {
                    provider: None,
                    ..expected
                }
            )
            .is_err()
        );
    }

    #[test]
    fn structured_status_renders_rfc3339_timestamps_without_losing_nanos() {
        let timestamp = prost_types::Timestamp {
            seconds: 1_000,
            nanos: 123_456_789,
        };
        let receipt = ProviderMutationReceipt {
            persisted_time: Some(timestamp),
            ..Default::default()
        };
        let mut status = persisted_status(receipt);
        status.observed_time = Some(timestamp);
        status.evaluated_time = Some(timestamp);
        let value = status_json(&DisplayStatus {
            status,
            outcome: "not_requested",
            complete: false,
        });
        let expected = "1970-01-01T00:16:40.123456789Z";
        assert_eq!(value["receipt"]["persisted_time"], expected);
        assert_eq!(value["observed_time"], expected);
        assert_eq!(value["evaluated_time"], expected);
        assert!(value["receipt"].get("persisted_at_ms").is_none());
        assert!(value.get("observed_at_ms").is_none());
        assert!(value.get("evaluated_at_ms").is_none());

        let value = status_json(&DisplayStatus {
            status: persisted_status(ProviderMutationReceipt::default()),
            outcome: "not_requested",
            complete: false,
        });
        assert!(value["receipt"]["persisted_time"].is_null());
        assert!(value["observed_time"].is_null());
        assert!(value["evaluated_time"].is_null());
    }

    #[test]
    fn receipt_json_uses_canonical_entity_reference_names() {
        let receipt = ProviderMutationReceipt {
            provider: "provider".to_string(),
            desired: Some(ProviderDesiredIdentity {
                sandbox: "sandbox".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let value = receipt_json(&receipt);
        assert_eq!(value["provider"], "provider");
        assert_eq!(value["desired"]["sandbox"], "sandbox");
        assert!(value.get("provider_name").is_none());
        assert!(value["desired"].get("sandbox_name").is_none());
    }

    #[test]
    fn structured_status_preserves_opaque_revisions_and_separates_timeout() {
        let receipt = ProviderMutationReceipt {
            desired: Some(ProviderDesiredIdentity {
                provider_env_revision: u64::MAX,
                ..Default::default()
            }),
            ..Default::default()
        };
        let value = status_json(&DisplayStatus {
            status: persisted_status(receipt),
            outcome: "timed_out",
            complete: false,
        });
        assert_eq!(value["state"], "persisted");
        assert_eq!(value["wait_outcome"], "timed_out");
        assert_eq!(
            value["receipt"]["desired"]["provider_env_revision"],
            u64::MAX.to_string()
        );
        assert!(value.get("environment").is_none());
        assert!(value.get("load_error").is_none());
    }
}
