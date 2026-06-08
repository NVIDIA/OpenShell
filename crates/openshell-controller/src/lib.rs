// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` CRD controller.
//!
//! Reconciles [`OpenShellSandbox`](types::OpenShellSandbox) CRs in a single
//! namespace, translating each into a sandbox-create call against the gateway
//! it runs alongside. Spawned as a tokio task by `openshell-server` on the
//! ordinal-0 `StatefulSet` replica when the chart-set
//! `OPENSHELL_CONTROLLER_WATCH_NAMESPACE` env var is present.

pub mod config;
pub mod gateway;
mod reconcile;
pub mod translate;
pub mod types;

use std::sync::Arc;

use anyhow::{Context, Result};
use kube::Client;
use tracing::info;

pub use config::ControllerConfig;
pub use gateway::{GatewayClient, NoopGateway};
pub use types::OpenShellSandbox;

/// Entry point spawned by `openshell-server`.
///
/// Builds a kube client from the ambient environment (in-cluster service
/// account in production, `~/.kube/config` for local dev) and runs the
/// reconciler until the watch stream terminates. The caller should treat
/// completion of this function as fatal.
///
/// `gateway` is the in-process handle to the gateway's create-sandbox core.
/// In production `openshell-server` passes a real `GatewayHandle`; the
/// standalone dev example passes [`NoopGateway`].
///
/// # Errors
///
/// Returns any error from constructing the kube client or pre-flighting the
/// CRD list. The reconcile loop itself never returns under normal
/// operation.
pub async fn run<G: GatewayClient>(gateway: Arc<G>, config: ControllerConfig) -> Result<()> {
    // Fail fast on empty watch_namespace. An empty string would silently
    // produce a cluster-wide watch via `Api::namespaced("")`, which the
    // controller's RBAC isn't scoped for — we'd flap on 403s deep in the
    // reconcile loop instead of erroring at startup.
    if config.watch_namespace.is_empty() {
        return Err(anyhow::anyhow!(
            "OPENSHELL_CONTROLLER_WATCH_NAMESPACE is empty; controller requires a namespace"
        ));
    }
    info!(
        namespace = %config.watch_namespace,
        "openshell-controller starting"
    );

    let client = Client::try_default()
        .await
        .context("constructing kube client (in-cluster or ~/.kube/config)")?;

    reconcile::run(client, gateway, config.watch_namespace).await
}
