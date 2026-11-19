// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Conformance suite: sandbox behavior that every compute driver must
//! provide. Each module is one suite.
//!
//! `cargo test` and nextest run the tests as this library's unit tests.
//! `#[testkit::test]` also registers them, so the `openshell-conformance`
//! program in `src/main.rs` runs them by linking this library.

mod attach;
mod cli;
mod create_upload;
mod credential_gating;
mod exec_cli;
mod file_transfer;
mod filesystem_policy;
mod image;
mod labels;
mod lifecycle;
mod network;
mod network_egress;
mod network_l7;
mod persistent_workspace;
mod policy_advisor;
mod policy_update;
mod port_forward;
mod process;
mod settings;
mod smoke;
mod ssh;
mod templates;
mod workspaces;

/// Names the number of gateway replicas when an environment runs more than
/// one.
const GATEWAY_REPLICAS_ENV: &str = "OPENSHELL_TEST_GATEWAY_REPLICAS";

/// Whether a test that reads sandbox logs should skip itself, and says so
/// when it should: a gateway replica holds only the logs of the sandboxes
/// connected to it, and a read can reach another one (#5462). Remove this
/// once #5462 is fixed or an environment can skip tests itself (#5752).
fn skip_reading_sandbox_logs(test: &str) -> bool {
    let replicas = std::env::var(GATEWAY_REPLICAS_ENV)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1);
    if replicas > 1 {
        eprintln!(
            "[{test}] skipping: the gateway has {replicas} replicas and sandbox logs \
             are read from only one (#5462, #5752)"
        );
    }
    replicas > 1
}
