// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration types for the operator binary.

/// Configuration for the operator binary.
#[derive(Clone, Debug)]
pub struct OperatorConfig {
    /// Namespace to watch. `None` = all namespaces.
    pub namespace: Option<String>,

    /// Metrics server bind address.
    pub metrics_addr: String,

    /// Webhook server bind address.
    pub webhook_addr: String,

    /// Path to TLS certificate for webhook server.
    pub tls_cert_path: Option<String>,

    /// Path to TLS private key for webhook server.
    pub tls_key_path: Option<String>,
}
