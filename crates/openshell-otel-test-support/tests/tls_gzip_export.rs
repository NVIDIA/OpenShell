// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The shared exporter delivers gzip-compressed spans to a collector over TLS.

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn gzip_spans_reach_a_collector_trusted_through_platform_roots() {
    let (flushed, received) = common::export_span_over_tls(true).await;

    assert!(flushed);
    assert!(received.spans.iter().any(|span| span.name == "tls.span"));
    assert_eq!(received.encodings, ["gzip"]);
}
