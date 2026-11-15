// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy enforcement inside the sandbox: the filesystem rules Landlock
//! applies to exec'd processes, the identity they run as, and connections
//! the network policy doesn't allow.
//!
//! Ported from `e2e/python/test_sandbox_landlock.py`,
//! `e2e/python/test_sandbox_policy.py` and the Landlock part of
//! `e2e/python/test_sandbox_venv.py`.

use testkit::Context;
use testkit::policy;

use crate::support::python_sandbox;

/// Probes the filesystem from inside the sandbox and prints one
/// `<probe> <result>` line each. `OK` means allowed; `EACCES`, `EPERM` and
/// `ERROR:<errno>` mean refused.
const FILESYSTEM_PROBES: &str = r#"
import errno, os, pwd

def outcome(action):
    try:
        action()
        return "OK"
    except OSError as error:
        return errno.errorcode.get(error.errno, f"ERROR:{error.errno}")

def write(directory):
    with open(os.path.join(directory, ".landlock-probe"), "w") as f:
        f.write("probe")

def rename_across_directories():
    os.makedirs("/sandbox/refer-src", exist_ok=True)
    os.makedirs("/sandbox/refer-dst", exist_ok=True)
    with open("/sandbox/refer-src/file", "w") as f:
        f.write("probe")
    os.rename("/sandbox/refer-src/file", "/sandbox/refer-dst/file")

print("user", pwd.getpwuid(os.getuid()).pw_name)
for path in ["/usr", "/tmp", "/sandbox", "/home/sandbox"]:
    print("write", path, outcome(lambda: write(path)))
for path in ["/usr", "/etc", "/opt", "/root"]:
    print("read", path, outcome(lambda: os.listdir(path)))
print("rename /sandbox", outcome(rename_across_directories))
home = os.stat("/home/sandbox").st_uid == os.getuid() if os.path.isdir("/home/sandbox") else False
print("owns /home/sandbox", home)
"#;

/// Exec'd commands run as the policy's user. Landlock lets them read and
/// write the policy's read-write paths, read but not write its read-only
/// paths, and touch nothing outside the policy, even a directory the user
/// owns. Renames between directories work, which uv and pip rely on
/// (Landlock ABI v2's refer right).
#[testkit::test]
async fn landlock_enforces_filesystem_policy(cx: &mut Context) -> testkit::Result {
    let sandbox = python_sandbox(cx, "ll", policy::base(), &[]).await?;
    let output = sandbox
        .exec(["python3", "-c", FILESYSTEM_PROBES])
        .await?
        .success()?;
    let probes: Vec<(String, String)> = output
        .stdout
        .lines()
        .filter_map(|line| line.rsplit_once(' '))
        .map(|(probe, result)| (probe.to_string(), result.to_string()))
        .collect();
    let result = |probe: &str| {
        probes
            .iter()
            .find(|(name, _)| name == probe)
            .map(|(_, result)| result.as_str())
    };
    let refused = |probe: &str| {
        result(probe).is_some_and(|result| {
            matches!(result, "EACCES" | "EPERM") || result.starts_with("ERROR:")
        })
    };

    testkit::ensure!(
        result("user") == Some("sandbox"),
        "exec ran as {:?}; expected the policy's user sandbox\n{}",
        result("user"),
        output.stdout
    );
    for allowed in [
        "write /tmp",
        "write /sandbox",
        "read /usr",
        "read /etc",
        "rename /sandbox",
    ] {
        testkit::ensure!(
            result(allowed) == Some("OK"),
            "{allowed} was {:?}; expected OK\n{}",
            result(allowed),
            output.stdout
        );
    }
    for denied in ["write /usr", "read /opt", "read /root"] {
        testkit::ensure!(
            refused(denied),
            "{denied} was {:?}; expected a refusal\n{}",
            result(denied),
            output.stdout
        );
    }
    // Not every image has a home directory for the sandbox user. When it
    // does, owning it doesn't get around Landlock.
    if result("owns /home/sandbox") == Some("True") {
        testkit::ensure!(
            refused("write /home/sandbox"),
            "write /home/sandbox was {:?}; Landlock should refuse it although the user owns it\n{}",
            result("write /home/sandbox"),
            output.stdout
        );
    }
    Ok(())
}

/// Prints the errno of a TCP connect to each `host:port` argument, or 0 if
/// it connected.
const CONNECT_ERRNO: &str = r"
import socket, sys
for target in sys.argv[1:]:
    host, port = target.rsplit(':', 1)
    try:
        with socket.create_connection((host, int(port)), timeout=5):
            print(target, 0)
    except OSError as error:
        print(target, error.errno or -1)
";

/// A workload's own socket fails fast with a permission error when it
/// connects to a destination no rule allows, to an allowed host on a port
/// the rule doesn't list, or to an allowed endpoint from a binary the rule
/// doesn't list. Nothing leaves the sandbox, so the destinations needn't be
/// reachable.
#[testkit::test]
async fn transparent_tcp_denies_unauthorized_connections(cx: &mut Context) -> testkit::Result {
    let mut policy = policy::base();
    policy::allow(&mut policy, "wrong_port", "1.1.1.1", 80, &["/**"]);
    policy::allow(&mut policy, "wrong_binary", "1.0.0.1", 443, &["/bin/false"]);
    let sandbox = python_sandbox(cx, "tcp", policy, &[]).await?;

    // 9.9.9.9 has no rule, 1.1.1.1 is allowed only on port 80, and 1.0.0.1
    // only for /bin/false.
    let targets = ["9.9.9.9:443", "1.1.1.1:443", "1.0.0.1:443"];
    let mut command = vec!["python3", "-c", CONNECT_ERRNO];
    command.extend(targets);
    let output = sandbox.exec(command).await?.success()?;
    for target in targets {
        let errno = output
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix(target))
            .map(str::trim);
        // EPERM is 1 and EACCES is 13 on Linux.
        testkit::ensure!(
            matches!(errno, Some("1" | "13")),
            "connect to {target} ended with errno {errno:?}; expected EPERM or EACCES\n{}",
            output.stdout
        );
    }
    Ok(())
}
