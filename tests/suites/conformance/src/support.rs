// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers shared by the suites in this crate.

use testkit::sdk::raw::proto;
use testkit::{Context, Result, Sandbox};

/// Create a long-running sandbox from the Python image
/// ([`testkit::python_image`]) with `policy` and `providers`, and wait until
/// it is ready.
pub(crate) async fn python_sandbox(
    cx: &Context,
    suffix: &str,
    policy: proto::SandboxPolicy,
    providers: &[&str],
) -> Result<Sandbox> {
    let sandbox = cx
        .sandbox(suffix)
        .policy(policy)
        .spec(|spec| {
            spec.image = Some(testkit::python_image());
            spec.providers = providers.iter().map(ToString::to_string).collect();
        })
        .command(["sleep", "infinity"])
        .create()
        .await?;
    sandbox.wait_ready().await?;
    Ok(sandbox)
}
