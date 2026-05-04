// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use metrics::{Unit, describe_counter, describe_gauge, describe_histogram, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;

/// Verify that /metrics is non-empty from the first scrape after startup.
///
/// metrics-exporter-prometheus only emits a metric once a value has been recorded;
/// `describe_*` alone is not sufficient. The server records `openshell_server_start_time_seconds`
/// immediately after `install_recorder()` so the body is never empty.
#[test]
fn metrics_are_non_empty_before_any_request() {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install prometheus recorder");

    describe_gauge!(
        "openshell_server_start_time_seconds",
        Unit::Seconds,
        "Unix timestamp of when the gateway server started"
    );
    gauge!("openshell_server_start_time_seconds").set(1_000_000.0_f64);

    describe_counter!(
        "openshell_server_grpc_requests_total",
        "Total number of gRPC requests handled"
    );
    describe_histogram!(
        "openshell_server_grpc_request_duration_seconds",
        Unit::Seconds,
        "gRPC request duration in seconds"
    );
    describe_counter!(
        "openshell_server_http_requests_total",
        "Total number of HTTP requests handled"
    );
    describe_histogram!(
        "openshell_server_http_request_duration_seconds",
        Unit::Seconds,
        "HTTP request duration in seconds"
    );

    let output = handle.render();
    assert!(
        !output.is_empty(),
        "/metrics body should be non-empty after startup gauge is set"
    );
    assert!(
        output.contains("openshell_server_start_time_seconds"),
        "/metrics body missing startup gauge"
    );
}
