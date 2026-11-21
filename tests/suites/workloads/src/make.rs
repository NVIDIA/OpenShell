// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! make and gcc building the small C project in the make workload's image
//! (`make/Dockerfile`).

use testkit::{Context, ResultExt as _, policy};

const PROJECT: &str = "/sandbox/project";

/// `make` builds a C program in a sandbox, the program runs, and `make -q`
/// then finds nothing to rebuild.
#[testkit::test]
async fn make_builds_a_c_program(cx: &mut Context) -> testkit::Result {
    let image = std::env::var("OPENSHELL_TEST_WORKLOAD_MAKE_IMAGE").map_err(|_| {
        testkit::Error::msg(
            "OPENSHELL_TEST_WORKLOAD_MAKE_IMAGE is not set; it names the make workload's \
             image (see tests/suites/workloads/README.md)",
        )
    })?;
    let sandbox = cx
        .sandbox("make")
        .image(image)
        .policy(policy::base())
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;

    sandbox.exec(["make", "--version"]).await?.success()?;
    sandbox
        .exec(["make", "-C", PROJECT])
        .await?
        .success()
        .context("build the project")?;
    sandbox
        .exec([&format!("{PROJECT}/hello")])
        .await?
        .expect_stdout("hello from make\n")?;
    sandbox
        .exec(["make", "-C", PROJECT, "-q"])
        .await?
        .success()
        .context("make -q after the build: something needs rebuilding")?;
    Ok(())
}
