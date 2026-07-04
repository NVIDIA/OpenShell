// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell Kubernetes Operator library.
//!
//! Provides a `SandboxRuntime` CRD and controller that reconciles declarative
//! sandbox specifications into Kubernetes workloads (Deployments, Services).
//!
//! Ported from Kagenti's AgentRuntime CRD + operator pattern, adapted to
//! OpenShell's Rust/kube-rs conventions.

pub mod config;
pub mod controller;
pub mod crd;
pub mod error;
pub mod kube_service;
pub mod labels;
pub mod manifests;
pub mod webhooks;

pub use config::OperatorConfig;
pub use crd::{SandboxRuntime, SandboxRuntimeSpec, SandboxRuntimeStatus};
pub use error::OperatorError;

/// Run the operator with the given configuration.
///
/// Uses `tokio::select!` so that if either the controller or webhook server
/// exits (error or otherwise), the other is dropped and the error propagates
/// immediately (V1 review fix).
pub async fn run(config: OperatorConfig) -> anyhow::Result<()> {
    let client = kube::Client::try_default().await?;

    // Start controller and webhook server concurrently.
    let controller_fut = controller::run(client.clone(), config.clone());

    if config.tls_cert_path.is_some() && config.tls_key_path.is_some() {
        let webhook_fut = webhooks::run_webhook_server(config.clone());
        // Run both concurrently -- if either exits, the other is dropped.
        tokio::select! {
            result = controller_fut => {
                result?;
            }
            result = webhook_fut => {
                result?;
            }
        }
    } else {
        tracing::info!("webhook TLS not configured, skipping webhook server");
        controller_fut.await?;
    }

    Ok(())
}
