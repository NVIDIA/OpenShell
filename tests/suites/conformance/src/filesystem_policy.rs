// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Filesystem policy suite: Landlock enforcement of a sandbox's filesystem
//! policy.

use std::collections::HashMap;
use std::time::Duration;

use testkit::sdk::raw::proto;
use testkit::{Context, ResultExt as _, with_deadline};

/// A rejected launch must close promptly instead of hanging the exec.
const REJECTED_LAUNCH_TIMEOUT: Duration = Duration::from_secs(20);

/// The filesystem policy the tests start from, with `extra_read_write` added
/// to the writable paths. It names no device paths; the sandbox adds the ones
/// every process needs, such as `/dev/urandom`.
///
/// It sets no process identity, so the workload runs as the image's `USER`:
/// Landlock applies whatever the identity, and the test image need not have a
/// particular user.
fn policy(compatibility: &str, extra_read_write: &[&str]) -> proto::SandboxPolicy {
    let paths = |paths: &[&str]| paths.iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut read_write = paths(&["/sandbox"]);
    read_write.extend(paths(extra_read_write));
    read_write.push("/tmp".to_string());
    proto::SandboxPolicy {
        version: 1,
        filesystem: Some(proto::FilesystemPolicy {
            include_workdir: true,
            read_only: paths(&["/usr", "/lib", "/etc", "/proc"]),
            read_write,
        }),
        landlock: Some(proto::LandlockPolicy {
            compatibility: compatibility.to_string(),
        }),
        network_policies: HashMap::from([(
            "landlock_regression".to_string(),
            proto::NetworkPolicyRule {
                name: "landlock_regression".to_string(),
                endpoints: vec![proto::NetworkEndpoint {
                    host: "example.com".to_string(),
                    port: 443,
                    ..proto::NetworkEndpoint::default()
                }],
                binaries: vec![proto::NetworkBinary {
                    path: "/**".to_string(),
                }],
            },
        )]),
        ..proto::SandboxPolicy::default()
    }
}

/// Under `hard_requirement`, the device paths the sandbox adds to the policy
/// don't make Landlock setup fail: processes start, read `/dev/urandom`, and
/// write to a writable path.
#[testkit::test]
async fn hard_requirement_accepts_added_device_paths(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("ld")
        .command(["sleep", "infinity"])
        .policy(policy("hard_requirement", &[]))
        .create_ready()
        .await?;

    sandbox
        .exec([
            "sh",
            "-c",
            "set -eu; \
             bytes=$(head -c 16 /dev/urandom | wc -c); \
             test \"$bytes\" -eq 16; \
             printf landlock-ok > /tmp/landlock-check; \
             test \"$(cat /tmp/landlock-check)\" = landlock-ok",
        ])
        .await?
        .success()
        .context("the hard_requirement sandbox must read /dev/urandom and write /tmp")?;
    Ok(())
}

/// When a workload replaces a policy path, or one of its ancestors, with a
/// symlink, the next launch is rejected rather than following the symlink,
/// in both Landlock compatibility modes.
#[testkit::test]
async fn replaced_policy_path_rejects_next_launch(cx: &mut Context) -> testkit::Result {
    const LEAF: &str = "/sandbox/policy-parent/leaf";
    let cases = [
        ("lbp", "best_effort", false),
        ("lhp", "hard_requirement", false),
        ("lba", "best_effort", true),
        ("lha", "hard_requirement", true),
    ];

    let mut sandboxes = Vec::new();
    for (suffix, compatibility, ancestor) in cases {
        let sandbox = cx
            .sandbox(suffix)
            .command(["sleep", "infinity"])
            .policy(policy(compatibility, &[LEAF]))
            .create()
            .await?;
        sandboxes.push((sandbox, compatibility, ancestor));
    }

    for (sandbox, compatibility, ancestor) in &sandboxes {
        let case = format!(
            "{compatibility}, replacing the {}",
            if *ancestor { "ancestor" } else { "path" }
        );
        sandbox.wait_ready().await?;
        for script in [
            format!("mkdir -p {LEAF}"),
            // A normal directory stays usable on the next launch.
            format!("echo allowed > {LEAF}/check"),
            if *ancestor {
                "mv /sandbox/policy-parent /sandbox/original-parent; \
                 ln -s /var/tmp /sandbox/policy-parent"
                    .to_string()
            } else {
                format!("mv {LEAF} /sandbox/original-leaf; ln -s /var/tmp {LEAF}")
            },
        ] {
            sandbox
                .exec(["sh", "-c", script.as_str()])
                .await?
                .success()
                .context(format!("({case}) prepare the policy path"))?;
        }

        // The exec's own error is the rejection report, so keep it apart from
        // the deadline's.
        let next = with_deadline(
            &format!("({case}) the rejected launch"),
            REJECTED_LAUNCH_TIMEOUT,
            async { Ok(sandbox.exec(["true"]).await) },
        )
        .await?;
        let report = match next {
            Ok(output) if output.exit_code == 0 => {
                return Err(testkit::Error::msg(format!(
                    "({case}) a launch succeeded after a policy path was replaced with a symlink"
                )));
            }
            Ok(output) => output.stderr,
            Err(error) => error.to_string(),
        };
        testkit::ensure!(
            report.to_lowercase().contains("symlink"),
            "({case}) the rejected launch does not say a policy path is a symlink: {report}"
        );
    }
    Ok(())
}
