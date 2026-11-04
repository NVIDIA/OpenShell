// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks of `testkit::main()`, as a test program.
//!
//! This binary is three programs, chosen by `TESTKIT_FIXTURE`:
//!
//! - unset: the checks below, run by `cargo test` and nextest through the
//!   program's libtest interface;
//! - `fixtures`: tests that pass, fail, hang, ignore `SIGTERM`, or leave
//!   processes behind, which the checks run through the program's
//!   subcommands;
//! - `registered`: `testkit::main()` over the `#[testkit::test]`s below;
//! - `empty`: a program with no tests.

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match std::env::var("TESTKIT_FIXTURE").as_deref() {
        Ok("fixtures") => testkit::program::main_with(&unix::FIXTURES),
        Ok("registered") => testkit::main(),
        Ok("empty") => testkit::program::main_with(&[]),
        _ => testkit::program::main_with(&unix::CHECKS),
    }
}

#[cfg(not(unix))]
fn main() {}

/// Needs a gateway.
#[testkit::test]
async fn registered_needs_a_gateway(cx: &mut testkit::Context) -> testkit::Result {
    cx.cli(["status"]).await?.success()?;
    Ok(())
}

/// Ignored until later.
#[testkit::test]
#[ignore = "https://github.com/NVIDIA/OpenShell/issues/1"]
async fn registered_ignored(_cx: &mut testkit::Context) -> testkit::Result {
    Ok(())
}

#[cfg(unix)]
mod unix {
    use std::future::Future;
    use std::os::unix::process::CommandExt as _;
    use std::pin::Pin;
    use std::process::{Command, Output, Stdio};
    use std::time::Duration;

    use testkit::{Test, TestInfo};

    const PID_FILE_ENV: &str = "FIXTURE_PID_FILE";

    type Run = fn() -> Pin<Box<dyn Future<Output = ()>>>;

    const fn test(module_path: &'static str, name: &'static str, run: Run) -> Test {
        Test {
            info: TestInfo {
                name,
                description: "A fixture.",
            },
            family: Some("fixtures"),
            module_path,
            ignored: false,
            ignore_reason: None,
            run,
        }
    }

    const fn fixture(name: &'static str, run: Run) -> Test {
        test("program::fixture", name, run)
    }

    const fn check(name: &'static str, run: Run) -> Test {
        test("program::check", name, run)
    }

    fn spawn_helper_and_record_its_pid() {
        // A helper in the test's process group, like a CLI process. It is
        // never waited on: the supervisor must kill it.
        #[allow(clippy::zombie_processes)]
        let helper = Command::new("sleep")
            .arg("300")
            .spawn()
            .expect("spawn sleep");
        let pid_file = std::env::var(PID_FILE_ENV).expect("pid file");
        std::fs::write(pid_file, helper.id().to_string()).expect("write pid");
    }

    pub static FIXTURES: [Test; 7] = [
        fixture("passes", || {
            Box::pin(async {
                println!("passes: stdout");
                eprintln!("passes: stderr");
            })
        }),
        fixture("fails", || Box::pin(async { panic!("fixture failure") })),
        fixture("hangs", || {
            Box::pin(async {
                spawn_helper_and_record_its_pid();
                std::thread::sleep(Duration::from_secs(300));
            })
        }),
        fixture("leaves_a_helper", || {
            Box::pin(async { spawn_helper_and_record_its_pid() })
        }),
        fixture("interrupts_after_exit", || {
            Box::pin(async {
                // Signal the supervisor once this test has exited, while it
                // waits for the test's output to close. The helper leaves
                // the test's process group so that it survives the test, and
                // holds the output open until it has sent the signal.
                let supervisor = std::os::unix::process::parent_id();
                #[allow(clippy::zombie_processes)]
                let _signaller = Command::new("sh")
                    .args(["-c", &format!("sleep 1; kill -TERM {supervisor}")])
                    .process_group(0)
                    .spawn()
                    .expect("spawn the signaller");
            })
        }),
        fixture("ignores_sigterm", || {
            Box::pin(async {
                // SAFETY: plain syscall.
                unsafe {
                    libc::signal(libc::SIGTERM, libc::SIG_IGN);
                }
                std::thread::sleep(Duration::from_secs(300));
            })
        }),
        Test {
            ignored: true,
            ignore_reason: Some("not today"),
            ..fixture("ignored", || Box::pin(async {}))
        },
    ];

    pub static CHECKS: [Test; 3] = [
        check("nextest_interface", || {
            Box::pin(async { nextest_interface() })
        }),
        check("list_shows_name_and_description", || {
            Box::pin(async { list_shows_name_and_description() })
        }),
        check("a_program_without_tests_fails", || {
            Box::pin(async { a_program_without_tests_fails() })
        }),
    ];

    fn program(fixture: &str, args: &[&str]) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("current exe"));
        command
            .args(args)
            .env("TESTKIT_FIXTURE", fixture)
            .env_remove("TESTKIT_SUPERVISED")
            .stdin(Stdio::null());
        command
    }

    fn output(mut command: Command) -> Output {
        let output = command.output().expect("run the program");
        eprintln!(
            "{command:?}: {}\n--- stdout\n{}--- stderr\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn stdout(output: &Output) -> &str {
        std::str::from_utf8(&output.stdout).expect("utf-8")
    }

    fn stderr(output: &Output) -> &str {
        std::str::from_utf8(&output.stderr).expect("utf-8")
    }

    /// nextest lists with `--list --format terse [--ignored]` and runs each
    /// test with `<name> --exact --nocapture`.
    fn nextest_interface() {
        let list = output(program("fixtures", &["--list", "--format", "terse"]));
        assert!(list.status.success());
        assert_eq!(
            stdout(&list),
            "fixture::fails: test\nfixture::hangs: test\nfixture::ignored: test\n\
             fixture::ignores_sigterm: test\nfixture::interrupts_after_exit: test\n\
             fixture::leaves_a_helper: test\nfixture::passes: test\n"
        );
        let ignored = output(program(
            "fixtures",
            &["--list", "--format", "terse", "--ignored"],
        ));
        assert_eq!(stdout(&ignored), "fixture::ignored: test\n");

        let pass = output(program(
            "fixtures",
            &["fixture::passes", "--exact", "--nocapture"],
        ));
        assert!(pass.status.success());
        assert!(stdout(&pass).contains("passes: stdout"));
        assert!(stdout(&pass).contains("1 passed"));

        let fail = output(program(
            "fixtures",
            &["fixture::fails", "--exact", "--nocapture"],
        ));
        assert_eq!(fail.status.code(), Some(101));
        assert!(stderr(&fail).contains("fixture failure"));

        // An ignored test runs only when asked for.
        let skip = output(program("fixtures", &["fixture::ignored", "--exact"]));
        assert!(stdout(&skip).contains("1 ignored"));
        let run = output(program(
            "fixtures",
            &["fixture::ignored", "--exact", "--ignored"],
        ));
        assert!(stdout(&run).contains("1 passed"));
    }

    fn list_shows_name_and_description() {
        let list = output(program("registered", &["list"]));
        assert!(list.status.success());
        let lines: Vec<_> = stdout(&list).lines().collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(
            lines[0],
            "registered_ignored          Ignored until later. \
             [ignored: https://github.com/NVIDIA/OpenShell/issues/1]"
        );
        assert_eq!(lines[1], "registered_needs_a_gateway  Needs a gateway.");

        let filtered = output(program("fixtures", &["list", "pass"]));
        assert_eq!(stdout(&filtered), "fixture::passes  A fixture.\n");
    }

    /// A program whose suites were not linked fails rather than passing with
    /// no tests, under every interface.
    fn a_program_without_tests_fails() {
        for args in [
            &["list"][..],
            &["run"],
            &["--list", "--format", "terse"],
            &[],
        ] {
            let empty = output(program("empty", args));
            assert_eq!(empty.status.code(), Some(2), "{args:?}");
            assert!(
                stderr(&empty).contains("no tests are linked into this program"),
                "{args:?}"
            );
        }
    }

}
