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
/// Polling cadence while we're waiting for the gateway to observe the
/// pod transition to Ready. Faster than `REQUEUE_INTERVAL` because users
/// expect `kubectl get oshs` to converge quickly after a CR apply.
const OBSERVE_INTERVAL: Duration = Duration::from_secs(3);
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

    // cr-uid idempotency: before creating, look for a gateway-side
    // sandbox already tagged with this CR's uid. If one exists, reuse
    // its id. Closes three real bugs:
    //   - cross-namespace CR-name collisions (two CRs with the same
    //     metadata.name in different namespaces) get distinct sandboxes
    //     because each CR has a distinct unforgeable uid
    //   - spec edits bump generation but uid stays — we update the
    //     existing sandbox's status rather than calling create twice
    //   - controller crash recovery: status went None mid-call, but
    //     the gateway-side sandbox is already there
    //
    // metadata.uid is guaranteed by the apiserver for any CR that made
    // it through admission, so the unwrap path is unreachable in
    // practice.
    let uid = obj.metadata.uid.as_deref().unwrap_or("");
    let existing = ctx
        .gateway
        .find_sandbox_by_label(crate::translate::LABEL_CR_UID, uid)
        .await?;

    let sandbox = match existing {
        Some(sandbox) => {
            info!(
                name = %name,
                sandbox_id = ?sandbox.metadata.as_ref().map(|m| m.id.as_str()),
                "found existing gateway sandbox by cr-uid; skipping create"
            );
            sandbox
        }
        None => {
            // Hand the request to the gateway. We don't pre-patch a
            // Provisioning status — see is_already_handled for why a
            // crash mid-call would leave the CR stuck if we did.
            match ctx.gateway.create_sandbox(req).await {
                Ok(sandbox) => sandbox,
                Err(status) => {
                    patch_status_failed(
                        &api,
                        &name,
                        generation,
                        &format!(
                            "gateway: code={:?} message={}",
                            status.code(),
                            status.message()
                        ),
                    )
                    .await?;
                    return Ok(Action::requeue(ERROR_REQUEUE_INTERVAL));
                }
            }
        }
    };

    let sandbox_id = sandbox
        .metadata
        .as_ref()
        .map(|m| m.id.clone())
        .unwrap_or_default();
    let sandbox_name = sandbox
        .metadata
        .as_ref()
        .map_or_else(|| name.clone(), |m| m.name.clone());

    // Project the gateway's view of the pod into CR status. The gateway's
    // driver maintains a watch on the agent-sandbox `Sandbox` CR and
    // updates `Sandbox.status.phase`; re-fetching gives us the live
    // observation rather than the just-after-create snapshot. If the
    // get fails (rare — we just created/found it), fall back to the
    // sandbox we already have in hand.
    let observed = ctx.gateway.get_sandbox(&sandbox_name).await.unwrap_or(sandbox);
    let (phase, requeue) = phase_from_gateway(&observed);
    patch_status(&api, &name, generation, &sandbox_id, phase).await?;
    Ok(Action::requeue(requeue))
}

const APIV: &str = "openshell.nvidia.com/v1alpha1";
const KIND: &str = "OpenShellSandbox";

fn has_finalizer(obj: &OpenShellSandbox) -> bool {
    obj.metadata
        .finalizers
        .as_ref()
        .is_some_and(|f| f.iter().any(|s| s == FINALIZER))
}

/// Whether the controller has already reached a terminal state for the
/// current spec generation.
///
/// Returns true only for `Running` or `Failed` at the current
/// `metadata.generation`. Transitional phases (`Pending`, `Provisioning`,
/// `Terminating`) must continue to reconcile so the gateway-observed
/// phase gets projected into status as the pod converges.
fn is_already_handled(obj: &OpenShellSandbox, generation: i64) -> bool {
    obj.status.as_ref().is_some_and(|s| {
        s.observed_generation == Some(generation)
            && matches!(s.phase, Some(Phase::Running | Phase::Failed))
    })
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

/// Map the gateway-side `SandboxPhase` proto into the CR phase + a
/// requeue interval. Terminal states (Running, Failed) requeue on the
/// long heartbeat; transitional states poll faster so kubectl converges
/// quickly when the pod becomes Ready.
fn phase_from_gateway(sandbox: &openshell_core::proto::Sandbox) -> (Phase, Duration) {
    use openshell_core::proto::SandboxPhase as Gw;
    // `Sandbox.phase` is a raw i32 since proto3 enums round-trip via
    // their numeric tag. Unrecognised values map to Pending.
    match Gw::try_from(sandbox.phase()).unwrap_or(Gw::Unspecified) {
        Gw::Ready => (Phase::Running, REQUEUE_INTERVAL),
        Gw::Provisioning | Gw::Unspecified => (Phase::Provisioning, OBSERVE_INTERVAL),
        Gw::Deleting => (Phase::Terminating, OBSERVE_INTERVAL),
        Gw::Error => (Phase::Failed, REQUEUE_INTERVAL),
        Gw::Unknown => (Phase::Pending, OBSERVE_INTERVAL),
    }
}

async fn patch_status(
    api: &Api<OpenShellSandbox>,
    name: &str,
    generation: i64,
    sandbox_id: &str,
    phase: Phase,
) -> Result<(), ReconcileError> {
    let now = Utc::now().to_rfc3339();
    let (cond_status, reason, message) = match phase {
        Phase::Running => ("True", "Ready", "Gateway-observed sandbox is Ready"),
        Phase::Provisioning => ("False", "Provisioning", "Gateway-observed sandbox is Provisioning"),
        Phase::Terminating => ("False", "Terminating", "Sandbox is terminating"),
        Phase::Failed => ("False", "Failed", "Gateway reports sandbox error"),
        Phase::Pending | Phase::Deleted => ("Unknown", "Pending", "Awaiting gateway observation"),
    };
    let patch = json!({
        "apiVersion": APIV,
        "kind": KIND,
        "status": {
            "phase": phase,
            "observedGeneration": generation,
            "sandboxId": sandbox_id,
            "message": message,
            "lastUpdated": now,
            "conditions": [{
                "type": "Ready", "status": cond_status, "reason": reason,
                "message": message,
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
    #[error("gateway error: code={code:?} message={message}")]
    Gateway { code: tonic::Code, message: String },
}

impl From<tonic::Status> for ReconcileError {
    fn from(status: tonic::Status) -> Self {
        Self::Gateway {
            code: status.code(),
            message: status.message().to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OpenShellSandboxSpec, OpenShellSandboxStatus};
    use kube::core::ObjectMeta;

    fn cr_with_metadata(meta: ObjectMeta) -> OpenShellSandbox {
        OpenShellSandbox {
            metadata: meta,
            spec: OpenShellSandboxSpec {
                image: "x".into(),
                policy_yaml: "version: 1\n".into(),
                environment: std::collections::BTreeMap::default(),
                providers: Vec::new(),
                gpu: false,
                gpu_device: None,
                log_level: None,
                runtime_class_name: None,
                labels: std::collections::BTreeMap::default(),
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
    fn is_already_handled_true_only_for_terminal_phases() {
        // Running and Failed are terminal for the current generation and
        // short-circuit reconcile. Transitional phases (Pending,
        // Provisioning, Terminating) must continue to reconcile so the
        // gateway-observed phase keeps getting projected into status.
        let cases = [
            (Phase::Pending, false),
            (Phase::Provisioning, false),
            (Phase::Terminating, false),
            (Phase::Running, true),
            (Phase::Failed, true),
        ];
        for (phase, expected) in cases {
            let mut cr = cr_with_metadata(ObjectMeta {
                generation: Some(1),
                ..Default::default()
            });
            cr.status = Some(OpenShellSandboxStatus {
                observed_generation: Some(1),
                phase: Some(phase),
                ..Default::default()
            });
            assert_eq!(
                is_already_handled(&cr, 1),
                expected,
                "phase {phase:?} at current generation: expected is_already_handled={expected}"
            );
        }
    }
}
