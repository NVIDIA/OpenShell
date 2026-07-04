// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Controller reconciliation loop for `SandboxRuntime` CRDs.
//!
//! Watches `SandboxRuntime` custom resources and reconciles them to
//! Kubernetes Deployments and Services, using the kube-rs Controller
//! abstraction (the Rust equivalent of Go's `controller-runtime`).

use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Service;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{self, Event as FinalizerEvent};
use kube::runtime::watcher;
use kube::runtime::Controller;
use kube::Client;
use tracing::{error, info, warn};

use crate::config::OperatorConfig;
use crate::crd::{SandboxRuntime, SandboxRuntimeStatus};
use crate::error::OperatorError;
use crate::kube_service::KubeService;
use crate::labels;
use crate::manifests;

/// Shared context passed to the reconciler.
struct Context {
    kube: KubeService,
}

/// Run the controller loop.
pub async fn run(client: Client, config: OperatorConfig) -> anyhow::Result<()> {
    let runtime_api: Api<SandboxRuntime> = match &config.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    // Secondary watch: Deployments owned by SandboxRuntime.
    let deployment_api: Api<Deployment> = match &config.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    // Secondary watch: Services owned by SandboxRuntime.
    let service_api: Api<Service> = match &config.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    let ctx = Arc::new(Context {
        kube: KubeService::new(client),
    });

    info!(
        namespace = config.namespace.as_deref().unwrap_or("all"),
        "starting controller"
    );

    Controller::new(runtime_api, watcher::Config::default())
        .owns(deployment_api, watcher::Config::default())
        .owns(service_api, watcher::Config::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj_ref, _action)) => {
                    info!(
                        name = %obj_ref.name,
                        namespace = obj_ref.namespace.as_deref().unwrap_or("-"),
                        "reconciled"
                    );
                }
                Err(e) => {
                    error!(error = %e, "reconciliation error");
                }
            }
        })
        .await;

    Ok(())
}

/// Main reconcile function called for each `SandboxRuntime` event.
async fn reconcile(
    runtime: Arc<SandboxRuntime>,
    ctx: Arc<Context>,
) -> Result<Action, OperatorError> {
    let namespace = runtime
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("default");
    let name = runtime.metadata.name.as_deref().unwrap_or("unknown");

    info!(name, namespace, "reconciling SandboxRuntime");

    let api: Api<SandboxRuntime> = ctx.kube.sandbox_runtimes(namespace);

    // Use finalizer for cleanup logic.
    finalizer::finalizer(&api, labels::FINALIZER_NAME, runtime, |event| async {
        match event {
            FinalizerEvent::Apply(runtime) => apply(runtime, &ctx.kube).await,
            FinalizerEvent::Cleanup(runtime) => cleanup(runtime, &ctx.kube).await,
        }
    })
    .await
    .map_err(|e| OperatorError::Finalizer(Box::new(e)))
}

/// Apply (create or update) the desired state for a `SandboxRuntime`.
async fn apply(
    runtime: Arc<SandboxRuntime>,
    kube: &KubeService,
) -> Result<Action, OperatorError> {
    let namespace = runtime
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("default");
    let name = runtime.metadata.name.as_deref().unwrap_or("unknown");

    // Build desired workload based on target_ref.kind.
    match runtime.spec.target_ref.kind.as_str() {
        "Deployment" => {
            let deployment = manifests::build_deployment(&runtime);
            kube.apply_deployment(namespace, &deployment, labels::MANAGER_NAME)
                .await?;

            // Create or update the associated Service.
            if !runtime.spec.service_ports.is_empty() {
                let service = manifests::build_service(&runtime);
                kube.apply_service(namespace, &service, labels::MANAGER_NAME)
                    .await?;
            }
        }
        "StatefulSet" | "Sandbox" => {
            // Future: implement StatefulSet and Sandbox builders.
            warn!(
                name,
                kind = runtime.spec.target_ref.kind,
                "workload kind not yet implemented, skipping"
            );
        }
        other => {
            warn!(name, kind = other, "unsupported target_ref.kind");
            return update_status(
                kube,
                &runtime,
                "Error",
                &format!("unsupported targetRef kind: {other}"),
            )
            .await;
        }
    }

    // Update status to reflect successful reconciliation.
    update_status(kube, &runtime, "Ready", "reconciliation complete").await
}

/// Clean up resources owned by a `SandboxRuntime` being deleted.
async fn cleanup(
    runtime: Arc<SandboxRuntime>,
    kube: &KubeService,
) -> Result<Action, OperatorError> {
    let namespace = runtime
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("default");
    let name = runtime.metadata.name.as_deref().unwrap_or("unknown");

    info!(name, namespace, "cleaning up SandboxRuntime resources");

    // OwnerReferences handle cascade deletion for Deployment and Service.
    // This explicit cleanup is belt-and-suspenders.
    kube.delete_deployment(namespace, name).await?;
    kube.delete_service(namespace, name).await?;

    info!(name, namespace, "cleanup complete");
    Ok(Action::await_change())
}

/// Update the status subresource of a `SandboxRuntime`.
async fn update_status(
    kube: &KubeService,
    runtime: &SandboxRuntime,
    phase: &str,
    message: &str,
) -> Result<Action, OperatorError> {
    let namespace = runtime
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("default");
    let name = runtime.metadata.name.as_deref().unwrap_or("unknown");

    let mut updated = runtime.clone();
    let generation = runtime.metadata.generation.unwrap_or(0);

    updated.status = Some(SandboxRuntimeStatus {
        phase: phase.to_string(),
        message: message.to_string(),
        observed_generation: generation,
        ..runtime.status.clone().unwrap_or_default()
    });

    match kube.update_status(namespace, name, &updated).await {
        Ok(_) => Ok(Action::requeue(std::time::Duration::from_secs(300))),
        Err(e) => {
            warn!(name, namespace, error = %e, "failed to update status, will retry");
            Ok(Action::requeue(std::time::Duration::from_secs(30)))
        }
    }
}

/// Error policy: requeue with backoff.
fn error_policy(
    _runtime: Arc<SandboxRuntime>,
    error: &OperatorError,
    _ctx: Arc<Context>,
) -> Action {
    warn!(error = %error, "reconciliation failed, will retry");
    Action::requeue(std::time::Duration::from_secs(30))
}
