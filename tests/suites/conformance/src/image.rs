// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox image suite: a sandbox runs the image it is created from.

use testkit::{Context, Sandbox};

/// A sandbox created with an explicit image runs that image.
#[testkit::test]
async fn explicit_image_is_used(cx: &mut Context) -> testkit::Result {
    let image = testkit::base_image();
    let sandbox = cx
        .sandbox("ei")
        .command(["sleep", "infinity"])
        .spec(|spec| spec.image = Some(image.clone()))
        .create()
        .await?;
    sandbox.wait_ready().await?;
    expect_ubuntu(&sandbox)
        .await
        .map_err(|error| error.context(format!("sandbox from image {image}")))
}

/// Fail unless the sandbox's `/etc/os-release` names Ubuntu and a version,
/// as OpenShell's base image does.
pub(crate) async fn expect_ubuntu(sandbox: &Sandbox) -> testkit::Result {
    let output = sandbox.exec(["cat", "/etc/os-release"]).await?;
    testkit::ensure!(
        output.exit_code == 0,
        "reading /etc/os-release exited {}; stderr: {}",
        output.exit_code,
        output.stderr
    );
    let field = |key: &str| {
        output.stdout.lines().find_map(|line| {
            line.strip_prefix(key)
                .and_then(|rest| rest.strip_prefix('='))
                .map(|value| value.trim_matches('"'))
        })
    };
    testkit::ensure!(
        field("ID") == Some("ubuntu"),
        "/etc/os-release has ID {:?}; expected \"ubuntu\":\n{}",
        field("ID"),
        output.stdout
    );
    testkit::ensure!(
        field("VERSION_ID").is_some_and(|version| !version.is_empty()),
        "/etc/os-release has no VERSION_ID:\n{}",
        output.stdout
    );
    Ok(())
}
