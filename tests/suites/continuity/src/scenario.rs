// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What a scenario's `seed` and `verify` share.

use testkit::Result;

/// The variable the runner sets to the id shared by one run's `seed` and
/// `verify` tests.
pub const ID_ENV: &str = "CONTINUITY_RUN_ID";

/// The id of this run. Fails when the tests were not started by the runner's
/// `--disruption` mode, because a `seed` without a `verify` proves nothing.
pub fn id() -> Result<String> {
    let id = std::env::var(ID_ENV).unwrap_or_default();
    testkit::ensure!(
        !id.is_empty(),
        "{ID_ENV} is not set: run the continuity family with \
         `openshell-test-runner run --family continuity --disruption <name>`"
    );
    Ok(id)
}

/// The name of a resource a scenario creates in `seed` and reads in
/// `verify`. Sandbox names are at most 19 characters.
pub fn name(suffix: &str) -> Result<String> {
    Ok(format!("cont-{}-{suffix}", id()?))
}
