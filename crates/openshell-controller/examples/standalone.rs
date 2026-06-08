// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone runner used for local iteration against a kind cluster.
//!
//! Not shipped — the production path is in-process inside `openshell-server`.
//! This binary just installs a tracing subscriber and calls
//! [`openshell_controller::run`] so you can `cargo run --example standalone`
//! against `~/.kube/config` while iterating on the reconciler.

use std::sync::Arc;

use openshell_controller::{ControllerConfig, NoopGateway};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ControllerConfig::from_env();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&config.log_filter)),
        )
        .init();
    openshell_controller::run(Arc::new(NoopGateway), config).await
}
