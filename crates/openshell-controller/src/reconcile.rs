// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reconciler for `OpenShellSandbox` CRs.
//!
//! Watches CRs in a single namespace, translates each spec into the
//! gateway's `CreateSandboxRequest`, and patches CR status to reflect the
//! gateway-side outcome. A finalizer keeps the CR alive until the
//! gateway-side sandbox is confirmed deleted.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use futures::StreamExt;
use kube::api::{ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Api, Client, ResourceExt};
use serde_json::json;
use tracing::{error, info, warn};

use crate::gateway::GatewayClient;
use crate::types::{OpenShellSandbox, Phase};

const FIELD_MANAGER: &str = "openshell-controller";
const FINALIZER: &str = "openshell.nvidia.com/finalizer";
const REQUEUE_INTERVAL: Duration = Duration::from_secs(30);
const ERROR_REQUEUE_INTERVAL: Duration = Duration::from_secs(15);

/// Shared context handed to every reconcile call.
struct ReconcileContext<G: GatewayClient> {
    client: Client,
    namespace: String,
    gateway: Arc<G>,
}

/// Run the reconciler until the watch stream terminates.
///
/// `client` is a kube client scoped to whatever credentials the controller
/// runs under (in-cluster service account in production). `gateway` is the
/// in-process handle the reconciler calls to actually create sandboxes.
/// `namespace` is the single namespace the controller watches.
///
/// # Errors
///
/// Returns any error from constructing the controller or pre-flighting the
/// CRD list. The reconcile loop itself never returns under normal
/// operation — it runs until cancelled.
pub async fn run<G: GatewayClient>(
    client: Client,
    gateway: Arc<G>,
    namespace: String,
) -> Result<()> {
    let api: Api<OpenShellSandbox> = Api::namespaced(client.clone(), &namespace);

    // Smoke-check that the CRD is installed before we start the controller —
    // a `list` against a missing CRD fails fast with a clear error, rather
    // than the controller spinning silently on a 404.
    api.list(&ListParams::default()).await.map_err(|e| {
        anyhow::anyhow!(
            "OpenShellSandbox CRD list failed in namespace {namespace}: {e}. \
             Is the CRD installed (deploy/helm/openshell/crds/)?"
        )
    })?;

    let ctx = Arc::new(ReconcileContext {
        client,
        namespace,
        gateway,
    });

    Controller::new(api, WatcherConfig::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|outcome| async {
            match outcome {
                Ok((obj_ref, _)) => info!(name = %obj_ref.name, "reconciled"),
                Err(e) => warn!(error = %e, "reconcile stream error"),
            }
        })
        .await;

    Ok(())
}

async fn reconcile<G: GatewayClient>(
    obj: Arc<OpenShellSandbox>,
    ctx: Arc<ReconcileContext<G>>,
) -> Result<Action, ReconcileError> {
    let name = obj.name_any();
    let generation = obj.metadata.generation.unwrap_or(0);
    let api: Api<OpenShellSandbox> = Api::namespaced(ctx.client.clone(), &ctx.namespace);

    // Deletion path: kubelet sets metadata.deletionTimestamp once the CR
    // is `kubectl delete`d. As long as our finalizer is on
    // metadata.finalizers, the apiserver holds the object alive so we can
    // clean up the gateway-side sandbox before the CR disappears.
    if obj.metadata.deletion_timestamp.is_some() {
        return handle_deletion(&api, &ctx, &obj).await;
    }

    // Creation path: make sure the finalizer is attached BEFORE we call
    // the gateway. Otherwise a `kubectl delete` between the gateway
    // create and the next reconcile would orphan the sandbox.
    if !has_finalizer(&obj) {
        attach_finalizer(&api, &name).await?;
        // Requeue to pick up the updated object. The new reconcile will
        // see the finalizer and proceed.
        return Ok(Action::requeue(Duration::from_secs(0)));
    }

    // Idempotency check — see [`is_already_handled`] for semantics.
    if is_already_handled(&obj, generation) {
        return Ok(Action::requeue(REQUEUE_INTERVAL));
    }

    info!(name = %name, generation, "reconciling");

    // Build the request from the CR. Translation failures are config bugs
    // (bad policyYaml, missing UID) and shouldn't be retried in tight
    // loops — they need a human to edit the CR.
    let req = match crate::translate::build_create_request(&obj) {
        Ok(req) => req,
        Err(e) => {
            patch_status_failed(&api, &name, generation, &format!("translate: {e}")).await?;
            return Ok(Action::requeue(REQUEUE_INTERVAL));
        }
    };

    // Step 1: announce Provisioning so kubectl shows the controller is
    // working on it. The early-return idempotency check above ensures
    // this only runs once per generation.
    patch_status_provisioning(&api, &name, generation).await?;

    // Step 2: hand the request to the gateway. The gateway runs all the
    // validation/persistence/JWT/compute-driver work itself; we just
    // observe the outcome.
    match ctx.gateway.create_sandbox(req).await {
        Ok(sandbox) => {
            let sandbox_id = sandbox
                .metadata
                .as_ref()
                .map(|m| m.id.clone())
                .unwrap_or_default();
            patch_status_running(&api, &name, generation, &sandbox_id).await?;
            Ok(Action::requeue(REQUEUE_INTERVAL))
        }
        Err(status) => {
            // tonic::Status carries a gRPC code; surface it as a CR
            // condition so users can see why the create failed.
            patch_status_failed(
                &api,
                &name,
                generation,
                &format!("gateway: code={:?} message={}", status.code(), status.message()),
            )
            .await?;
            Ok(Action::requeue(ERROR_REQUEUE_INTERVAL))
        }
    }
}

const APIV: &str = "openshell.nvidia.com/v1alpha1";
const KIND: &str = "OpenShellSandbox";

fn has_finalizer(obj: &OpenShellSandbox) -> bool {
    obj.metadata
        .finalizers
        .as_ref()
        .is_some_and(|f| f.iter().any(|s| s == FINALIZER))
}

/// Whether the controller has already finished a reconcile for the current
/// spec generation.
///
/// Returns true when `status.observedGeneration` matches the current
/// `metadata.generation` AND a phase is set — any phase, including
/// Provisioning, Running, or Failed. This guards against watch-event
/// echoes from our own status patches re-entering the gateway call.
///
/// KNOWN LIMITATION: if the controller crashes between the Provisioning
/// patch and the gateway call returning, the CR is stuck at Provisioning
/// until the user edits `.spec` to bump generation. A proper cr-uid
/// lookup against the gateway is the long-term fix.
fn is_already_handled(obj: &OpenShellSandbox, generation: i64) -> bool {
    obj.status
        .as_ref()
        .is_some_and(|s| s.observed_generation == Some(generation) && s.phase.is_some())
}

async fn attach_finalizer(
    api: &Api<OpenShellSandbox>,
    name: &str,
) -> Result<(), ReconcileError> {
    // SSA on `metadata.finalizers` so we own that key as a field manager
    // and won't fight other writers over the rest of metadata.
    let patch = json!({
        "apiVersion": APIV,
        "kind": KIND,
        "metadata": { "finalizers": [FINALIZER] },
    });
    // No `.force()`: our finalizer entry is unique to this field manager,
    // so we shouldn't trip another manager's ownership of the list.
    // Conflicts surface to the reconcile loop, which requeues.
    api.patch(
        name,
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Apply(&patch),
    )
    .await
    .map_err(ReconcileError::Kube)?;
    info!(name = %name, finalizer = FINALIZER, "attached finalizer");
    Ok(())
}

async fn detach_finalizer(
    api: &Api<OpenShellSandbox>,
    obj: &OpenShellSandbox,
) -> Result<(), ReconcileError> {
    // Remove our finalizer via a JSON merge patch on the full list. We
    // can't use SSA here because the value we want to apply is "absence"
    // — easiest expressed as a fresh list without our key.
    let remaining: Vec<&String> = obj
        .metadata
        .finalizers
        .as_ref()
        .map(|f| f.iter().filter(|s| s.as_str() != FINALIZER).collect())
        .unwrap_or_default();
    let patch = json!({ "metadata": { "finalizers": remaining } });
    api.patch(
        &obj.name_any(),
        &PatchParams::default(),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(ReconcileError::Kube)?;
    info!(name = %obj.name_any(), "detached finalizer; CR will now be removed");
    Ok(())
}

async fn handle_deletion<G: GatewayClient>(
    api: &Api<OpenShellSandbox>,
    ctx: &ReconcileContext<G>,
    obj: &OpenShellSandbox,
) -> Result<Action, ReconcileError> {
    let name = obj.name_any();

    // If our finalizer is gone, deletion already cleared and nothing more
    // to do — the apiserver will reap the CR on its own.
    if !has_finalizer(obj) {
        return Ok(Action::await_change());
    }

    // Best-effort delete on the gateway side. Treat `Ok(false)` (already
    // gone) the same as success.
    info!(name = %name, "handling deletion: calling gateway.delete_sandbox");
    match ctx.gateway.delete_sandbox(&name).await {
        Ok(deleted) => {
            info!(name = %name, deleted, "gateway delete returned");
            detach_finalizer(api, obj).await?;
            Ok(Action::await_change())
        }
        Err(status) => {
            // Keep the finalizer in place and retry. Never remove it
            // without proof the gateway-side sandbox is gone.
            warn!(name = %name, error = %status, "gateway delete failed; requeuing");
            Ok(Action::requeue(ERROR_REQUEUE_INTERVAL))
        }
    }
}

async fn patch_status_provisioning(
    api: &Api<OpenShellSandbox>,
    name: &str,
    generation: i64,
) -> Result<(), ReconcileError> {
    let now = Utc::now().to_rfc3339();
    let patch = json!({
        "apiVersion": APIV,
        "kind": KIND,
        "status": {
            "phase": Phase::Provisioning,
            "observedGeneration": generation,
            "message": "calling gateway to create sandbox",
            "lastUpdated": now,
            "conditions": [{
                "type": "Ready", "status": "False", "reason": "Provisioning",
                "message": "Gateway create-sandbox call in flight",
                "lastTransitionTime": now, "observedGeneration": generation,
            }],
        }
    });
    apply_status(api, name, patch).await
}

async fn patch_status_running(
    api: &Api<OpenShellSandbox>,
    name: &str,
    generation: i64,
    sandbox_id: &str,
) -> Result<(), ReconcileError> {
    let now = Utc::now().to_rfc3339();
    let patch = json!({
        "apiVersion": APIV,
        "kind": KIND,
        "status": {
            "phase": Phase::Running,
            "observedGeneration": generation,
            "sandboxId": sandbox_id,
            "message": "gateway sandbox created",
            "lastUpdated": now,
            "conditions": [{
                "type": "Ready", "status": "True", "reason": "Created",
                "message": "Gateway returned a sandbox",
                "lastTransitionTime": now, "observedGeneration": generation,
            }],
        }
    });
    apply_status(api, name, patch).await
}

async fn patch_status_failed(
    api: &Api<OpenShellSandbox>,
    name: &str,
    generation: i64,
    message: &str,
) -> Result<(), ReconcileError> {
    let now = Utc::now().to_rfc3339();
    let patch = json!({
        "apiVersion": APIV,
        "kind": KIND,
        "status": {
            "phase": Phase::Failed,
            "observedGeneration": generation,
            "message": message,
            "lastUpdated": now,
            "conditions": [{
                "type": "Ready", "status": "False", "reason": "Failed",
                "message": message,
                "lastTransitionTime": now, "observedGeneration": generation,
            }],
        }
    });
    apply_status(api, name, patch).await
}

async fn apply_status(
    api: &Api<OpenShellSandbox>,
    name: &str,
    patch: serde_json::Value,
) -> Result<(), ReconcileError> {
    // No `.force()`: other field managers (e.g. a future monitoring
    // sidecar contributing to `.status.conditions`) keep their entries.
    // SSA conflicts on fields we co-own surface as kube errors, which
    // the reconcile loop requeues with backoff.
    api.patch_status(
        name,
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Apply(&patch),
    )
    .await
    .map_err(ReconcileError::Kube)?;
    Ok(())
}

#[allow(clippy::needless_pass_by_value)] // signature dictated by kube-runtime
fn error_policy<G: GatewayClient>(
    obj: Arc<OpenShellSandbox>,
    err: &ReconcileError,
    _ctx: Arc<ReconcileContext<G>>,
) -> Action {
    error!(name = %obj.name_any(), error = %err, "reconcile failed");
    Action::requeue(ERROR_REQUEUE_INTERVAL)
}

#[derive(Debug, thiserror::Error)]
enum ReconcileError {
    #[error("kube error: {0}")]
    Kube(#[from] kube::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ExposeSpec, OpenShellSandboxSpec, OpenShellSandboxStatus};
    use kube::core::ObjectMeta;

    fn cr_with_metadata(meta: ObjectMeta) -> OpenShellSandbox {
        OpenShellSandbox {
            metadata: meta,
            spec: OpenShellSandboxSpec {
                image: "x".into(),
                start_command: None,
                policy_yaml: "version: 1\n".into(),
                expose: ExposeSpec { port: 80 },
                pod_customisations: None,
            },
            status: None,
        }
    }

    // --- has_finalizer ---

    #[test]
    fn has_finalizer_false_when_metadata_finalizers_is_none() {
        let cr = cr_with_metadata(ObjectMeta::default());
        assert!(!has_finalizer(&cr));
    }

    #[test]
    fn has_finalizer_false_when_list_is_empty() {
        let cr = cr_with_metadata(ObjectMeta {
            finalizers: Some(vec![]),
            ..Default::default()
        });
        assert!(!has_finalizer(&cr));
    }

    #[test]
    fn has_finalizer_false_when_only_other_finalizers_present() {
        let cr = cr_with_metadata(ObjectMeta {
            finalizers: Some(vec!["other-controller/finalizer".into()]),
            ..Default::default()
        });
        assert!(!has_finalizer(&cr));
    }

    #[test]
    fn has_finalizer_true_when_our_finalizer_present() {
        let cr = cr_with_metadata(ObjectMeta {
            finalizers: Some(vec![
                "other-controller/finalizer".into(),
                FINALIZER.to_owned(),
            ]),
            ..Default::default()
        });
        assert!(has_finalizer(&cr));
    }

    // --- is_already_handled ---

    #[test]
    fn is_already_handled_false_when_status_is_none() {
        let cr = cr_with_metadata(ObjectMeta {
            generation: Some(1),
            ..Default::default()
        });
        assert!(!is_already_handled(&cr, 1));
    }

    #[test]
    fn is_already_handled_false_when_status_phase_unset() {
        let mut cr = cr_with_metadata(ObjectMeta {
            generation: Some(1),
            ..Default::default()
        });
        cr.status = Some(OpenShellSandboxStatus {
            observed_generation: Some(1),
            phase: None,
            ..Default::default()
        });
        assert!(!is_already_handled(&cr, 1));
    }

    #[test]
    fn is_already_handled_false_when_observed_generation_stale() {
        let mut cr = cr_with_metadata(ObjectMeta {
            generation: Some(2),
            ..Default::default()
        });
        cr.status = Some(OpenShellSandboxStatus {
            observed_generation: Some(1),
            phase: Some(Phase::Running),
            ..Default::default()
        });
        // Current gen is 2; status was written for gen 1 → needs a fresh
        // reconcile.
        assert!(!is_already_handled(&cr, 2));
    }

    #[test]
    fn is_already_handled_true_at_current_generation_for_any_phase() {
        for phase in [
            Phase::Pending,
            Phase::Provisioning,
            Phase::Running,
            Phase::Failed,
            Phase::Terminating,
        ] {
            let mut cr = cr_with_metadata(ObjectMeta {
                generation: Some(1),
                ..Default::default()
            });
            cr.status = Some(OpenShellSandboxStatus {
                observed_generation: Some(1),
                phase: Some(phase),
                ..Default::default()
            });
            assert!(
                is_already_handled(&cr, 1),
                "phase {phase:?} at current generation should short-circuit"
            );
        }
    }
}
