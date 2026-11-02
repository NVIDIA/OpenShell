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
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::process::{Child, Command, Output, Stdio};
    use std::time::{Duration, Instant};

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

    pub static CHECKS: [Test; 12] = [
        check("nextest_interface", || {
            Box::pin(async { nextest_interface() })
        }),
        check("list_shows_name_and_description", || {
            Box::pin(async { list_shows_name_and_description() })
        }),
        check("run_reports_every_outcome", || {
            Box::pin(async { run_reports_every_outcome() })
        }),
        check("run_exit_codes", || Box::pin(async { run_exit_codes() })),
        check("a_program_without_tests_fails", || {
            Box::pin(async { a_program_without_tests_fails() })
        }),
        check("timeout_kills_the_process_group", || {
            Box::pin(async { timeout_kills_the_process_group() })
        }),
        check("sigterm_is_followed_by_sigkill", || {
            Box::pin(async { sigterm_is_followed_by_sigkill() })
        }),
        check("interrupt_stops_the_test_and_the_run", || {
            Box::pin(async { interrupt_stops_the_test_and_the_run() })
        }),
        check("interrupt_between_tests_ends_the_run", || {
            Box::pin(async { interrupt_between_tests_ends_the_run() })
        }),
        check("a_passing_test_leaves_nothing_behind", || {
            Box::pin(async { a_passing_test_leaves_nothing_behind() })
        }),
        check("registered_tests_run_through_testkit", || {
            Box::pin(async { registered_tests_run_through_testkit() })
        }),
        check("ready_fails_without_a_gateway", || {
            Box::pin(async { ready_fails_without_a_gateway() })
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

    fn junit(dir: &Path) -> (PathBuf, String) {
        let path = dir.join("results").join("junit.xml");
        (path.clone(), path.to_str().expect("utf-8 path").to_string())
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

    fn run_reports_every_outcome() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (path, junit_arg) = junit(dir.path());
        let run = output(program(
            "fixtures",
            &["run", "passes", "fails", "ignored", "--junit", &junit_arg],
        ));
        assert_eq!(run.status.code(), Some(1));
        // Test output is passed through.
        assert!(stdout(&run).contains("passes: stdout"));
        assert!(stderr(&run).contains("passes: stderr"));
        assert!(stderr(&run).contains("1 passed, 1 failed, 1 skipped"));
        assert!(stderr(&run).contains("FAIL fixture::fails: test failed"));

        let xml = std::fs::read_to_string(path).expect("junit report");
        for expected in [
            r#"<testsuites name="program-"#,
            r#"tests="3" skipped="1" failures="1" errors="0">"#,
            r#"<testsuite name="fixtures" tests="3""#,
            r#"<testcase name="fixture::fails" classname="program::fixture""#,
            r#"<failure message="test failed" type="failure"/>"#,
            r#"<skipped message="ignored: not today"/>"#,
            "<system-out>",
            "passes: stdout",
            "fixture failure",
        ] {
            assert!(xml.contains(expected), "missing {expected} in\n{xml}");
        }
    }

    fn run_exit_codes() {
        let pass = output(program("fixtures", &["run", "passes"]));
        assert_eq!(pass.status.code(), Some(0));
        let ignored = output(program(
            "fixtures",
            &["run", "ignored", "--include-ignored"],
        ));
        assert_eq!(ignored.status.code(), Some(0));
        assert!(stderr(&ignored).contains("1 passed, 0 failed"));
        // Selecting nothing to run is not a pass.
        for args in [&["run", "nothing-matches"][..], &["run", "ignored"]] {
            let none = output(program("fixtures", args));
            assert_eq!(none.status.code(), Some(2), "{args:?}");
            assert!(stderr(&none).contains("no tests to run"));
        }
        let usage = output(program("fixtures", &["run", "--timeout", "0"]));
        assert_eq!(usage.status.code(), Some(2));
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

    fn is_alive(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 only checks the process exists.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    /// Wait for a killed helper to go: once its parent is gone, init reaps it.
    fn assert_gone(pid: libc::pid_t) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while is_alive(pid) {
            assert!(Instant::now() < deadline, "helper {pid} outlived its test");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn read_pid(path: &Path) -> libc::pid_t {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(pid) = std::fs::read_to_string(path)
                && let Ok(pid) = pid.trim().parse()
            {
                return pid;
            }
            assert!(Instant::now() < deadline, "the hanging test never started");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn timeout_kills_the_process_group() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("pid");
        let (path, junit_arg) = junit(dir.path());
        let mut command = program(
            "fixtures",
            &[
                "run",
                "hangs",
                "--timeout",
                "1",
                "--grace",
                "5",
                "--junit",
                &junit_arg,
            ],
        );
        command.env(PID_FILE_ENV, &pid_file);
        let started = Instant::now();
        let run = output(command);
        assert_eq!(run.status.code(), Some(1));
        // `SIGTERM` stops the test well inside the grace period.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(stderr(&run).contains("TIMEOUT fixture::hangs: timed out after 1s"));
        assert_gone(read_pid(&pid_file));
        let xml = std::fs::read_to_string(path).expect("junit report");
        assert!(xml.contains(r#"type="timeout""#), "{xml}");
    }

    fn sigterm_is_followed_by_sigkill() {
        let started = Instant::now();
        let run = output(program(
            "fixtures",
            &[
                "run",
                "ignores_sigterm",
                "--timeout",
                "0.2",
                "--grace",
                "0.5",
            ],
        ));
        assert_eq!(run.status.code(), Some(1));
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(700), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
        assert!(stderr(&run).contains("TIMEOUT fixture::ignores_sigterm"));
    }

    fn interrupt_stops_the_test_and_the_run() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("pid");
        let (path, junit_arg) = junit(dir.path());
        let mut command = program(
            "fixtures",
            &[
                "run", "hangs", "passes", "--grace", "5", "--junit", &junit_arg,
            ],
        );
        command
            .env(PID_FILE_ENV, &pid_file)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child: Child = command.spawn().expect("start the run");
        let helper = read_pid(&pid_file);
        // SAFETY: plain syscall to our own child, not yet reaped.
        unsafe {
            libc::kill(
                libc::pid_t::try_from(child.id()).expect("pid"),
                libc::SIGTERM,
            );
        }
        let run = child.wait_with_output().expect("wait for the run");
        eprintln!("{}", String::from_utf8_lossy(&run.stderr));
        assert_eq!(run.status.code(), Some(2));
        assert!(stderr(&run).contains("ERROR fixture::hangs: interrupted"));
        assert_gone(helper);
        let xml = std::fs::read_to_string(path).expect("junit report");
        assert!(xml.contains(r#"type="interrupted""#), "{xml}");
        assert!(!xml.contains("fixture::passes"), "{xml}");
    }

    fn interrupt_between_tests_ends_the_run() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (path, junit_arg) = junit(dir.path());
        let run = output(program(
            "fixtures",
            &[
                "run",
                "interrupts_after_exit",
                "passes",
                "--junit",
                &junit_arg,
            ],
        ));
        assert_eq!(run.status.code(), Some(2));
        assert!(stderr(&run).contains("<== PASS fixture::interrupts_after_exit"));
        assert!(stderr(&run).contains("interrupted; 1 later test did not run"));
        assert!(!stdout(&run).contains("passes: stdout"));
        let xml = std::fs::read_to_string(path).expect("junit report");
        assert!(!xml.contains("fixture::passes"), "{xml}");
    }

    fn a_passing_test_leaves_nothing_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("pid");
        let mut command = program("fixtures", &["run", "leaves_a_helper"]);
        command.env(PID_FILE_ENV, &pid_file);
        let run = output(command);
        assert_eq!(run.status.code(), Some(0));
        assert_gone(read_pid(&pid_file));
    }

    /// Point the gateway lookup at a closed port, away from any registered
    /// gateways.
    fn without_gateway(mut command: Command, config: &Path) -> Command {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let endpoint = format!("http://{}", closed.local_addr().expect("address"));
        drop(closed);
        command
            .env("XDG_CONFIG_HOME", config)
            .env("OPENSHELL_GATEWAY_ENDPOINT", endpoint)
            .env_remove("OPENSHELL_GATEWAY")
            .env("OPENSHELL_BIN", config.join("no-openshell"));
        command
    }

    fn registered_tests_run_through_testkit() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (path, junit_arg) = junit(dir.path());
        let run = output(without_gateway(
            program("registered", &["run", "--junit", &junit_arg]),
            dir.path(),
        ));
        assert_eq!(run.status.code(), Some(1));
        // `testkit::run` logs the description and the gateway.
        assert!(stderr(&run).contains("[registered_needs_a_gateway] Needs a gateway."));
        assert!(stderr(&run).contains("1 failed, 1 skipped"));
        let xml = std::fs::read_to_string(path).expect("junit report");
        assert!(
            xml.contains(r#"<testcase name="registered_needs_a_gateway" classname="program""#),
            "{xml}"
        );
        assert!(
            xml.contains(r#"<property name="description" value="Needs a gateway."/>"#),
            "{xml}"
        );
    }

    fn ready_fails_without_a_gateway() {
        let dir = tempfile::tempdir().expect("temp dir");
        let started = Instant::now();
        let ready = output(without_gateway(
            program("registered", &["ready", "--timeout", "1"]),
            dir.path(),
        ));
        assert_eq!(ready.status.code(), Some(2));
        assert!(stderr(&ready).contains("not ready after 1s"));
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
