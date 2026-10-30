// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The shared exporter refuses a collector whose certificate is not trusted.

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn spans_do_not_reach_a_collector_with_an_untrusted_certificate() {
    let (flushed, received) = common::export_span_over_tls(false).await;

    assert!(!flushed, "export to an untrusted collector must fail");
    assert!(received.spans.is_empty());
}
