// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime configuration for the controller, sourced from environment
//! variables set by the Helm chart.

use std::env;

/// All knobs the controller needs at startup.
#[derive(Debug, Clone)]
pub struct ControllerConfig {
    /// Namespace the controller watches. v1 enforces a single-namespace
    /// contract — one Helm release ⇒ one watched namespace.
    pub watch_namespace: String,

    /// `RUST_LOG`-style filter for the controller's tracing subscriber.
    /// Applied by the caller; the controller itself does not install a
    /// subscriber.
    pub log_filter: String,
}

impl ControllerConfig {
    /// Build the config from the environment variables the chart sets.
    ///
    /// - `OPENSHELL_CONTROLLER_WATCH_NAMESPACE` — namespace to watch. Falls
    ///   back to `OPENSHELL_SANDBOX_NAMESPACE`, then to `default`.
    /// - `OPENSHELL_CONTROLLER_LOG_FILTER` — `RUST_LOG` filter string.
    ///   Defaults to `info,openshell_controller=info,kube=warn`.
    #[must_use]
    pub fn from_env() -> Self {
        let watch_namespace = env::var("OPENSHELL_CONTROLLER_WATCH_NAMESPACE")
            .or_else(|_| env::var("OPENSHELL_SANDBOX_NAMESPACE"))
            .unwrap_or_else(|_| "default".to_owned());

        let log_filter = env::var("OPENSHELL_CONTROLLER_LOG_FILTER")
            .unwrap_or_else(|_| "info,openshell_controller=info,kube=warn".to_owned());

        Self {
            watch_namespace,
            log_filter,
        }
    }
}
