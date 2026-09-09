// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenTelemetry tracing identity for the Podman compute driver.

pub const TRACING: openshell_otel::ComputeDriverTracing = openshell_otel::compute_driver_tracing!();

#[cfg(test)]
mod tests {
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn driver_spans_reach_otlp_collector_with_resource_identity() {
        openshell_otel_test_support::assert_compute_driver_tracing(
            super::TRACING,
            openshell_core::VERSION,
            "podman.create",
        )
        .await;
    }
}
