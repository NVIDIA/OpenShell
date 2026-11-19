// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! make and gcc building a small C project.
//!
//! The project lives in `make/project` and is compiled into the test, so a
//! change to it needs no image rebuild. The image (`make/Dockerfile`) only
//! has the toolchain.

use std::fs;

use testkit::{Context, ResultExt as _, policy};

/// Names the image built from `make/Dockerfile`.
const IMAGE_ENV: &str = "OPENSHELL_TEST_WORKLOAD_MAKE_IMAGE";

/// Where the project is uploaded to; the upload keeps the directory's name.
const PROJECT: &str = "/sandbox/project";

const SOURCES: &[(&str, &str)] = &[
    ("Makefile", include_str!("../make/project/Makefile")),
    ("main.c", include_str!("../make/project/main.c")),
    ("greet.c", include_str!("../make/project/greet.c")),
    ("greet.h", include_str!("../make/project/greet.h")),
    ("sum.c", include_str!("../make/project/sum.c")),
    ("sum.h", include_str!("../make/project/sum.h")),
];

/// `make -j4` builds a small C project in a sandbox, the program it builds
/// runs and prints the expected output, and a second `make -q` finds nothing
/// to rebuild.
#[testkit::test]
async fn make_builds_a_c_program(cx: &mut Context) -> testkit::Result {
    let image = crate::workload_image(IMAGE_ENV)?;
    let local = tempfile::tempdir().context("create a scratch directory")?;
    let project = local.path().join("project");
    fs::create_dir(&project).context("create the project directory")?;
    for (name, contents) in SOURCES {
        fs::write(project.join(name), contents).context(format!("write {name}"))?;
    }

    let sandbox = cx
        .sandbox("make")
        .image(image)
        .policy(policy::base())
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;

    // Step 1: the toolchain starts.
    sandbox.exec(["make", "--version"]).await?.success()?;
    sandbox.exec(["gcc", "--version"]).await?.success()?;

    // Step 2: build, run, and check that the build is up to date.
    cx.cli([
        "sandbox",
        "upload",
        sandbox.name(),
        &project.display().to_string(),
        "/sandbox",
        "--no-git-ignore",
    ])
    .await?
    .success()?;
    sandbox
        .exec(["make", "-C", PROJECT, "-j4"])
        .await?
        .success()
        .context("build the project")?;
    sandbox
        .exec([&format!("{PROJECT}/hello")])
        .await?
        .expect_stdout("hello, sandbox\nsum(1..100) = 5050\n")?;
    sandbox
        .exec(["make", "-C", PROJECT, "-q"])
        .await?
        .success()
        .context("make -q after the build: something needs rebuilding")?;
    Ok(())
}
