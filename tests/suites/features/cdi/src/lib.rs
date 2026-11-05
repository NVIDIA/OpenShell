// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Scenario support for the CDI injection tests.
//!
//! The `cdi_fixtures` role in the tmachine Docker and Podman environments
//! creates one CDI device per scenario, together with the host files it
//! references, and publishes each scenario's expectations as `scenarios.json`
//! (see `vars/scenarios.yaml` in the role). The document names the device kind
//! the devices belong to, so the suite assumes no kind of its own. [`scenario`]
//! creates a sandbox that selects one scenario device, runs a probe in it, and
//! compares what the workload observed with the published expectations. The
//! sandbox only reports what it sees. Every assertion is made here, so a
//! failure names the check that disagreed.
//!
//! The expectations characterize what the sandbox does today. They are not a
//! specification of what CDI should do, so a change in behavior updates them.
//!
//! The probes run in the workload image with `sh`, and `echo-socket` also needs
//! `perl` there. The default workload image has both.
//!
//! The environment variable [`SCENARIOS_ENV`] holds the path of that document.
//! The role publishes it through `playbooks/test-env.yaml`, and any other
//! environment that creates matching devices can set it the same way. The tests
//! fail when it is unset.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{Value, json};
use testkit::{Context, Error, Result, ResultExt as _};

/// The path of the scenario expectations, published by the environment.
pub const SCENARIOS_ENV: &str = "OPENSHELL_TEST_CDI_SCENARIOS";
/// The compute drivers that take a `cdi_devices` driver option.
const DRIVERS: [&str; 2] = ["docker", "podman"];

/// Whether an operation on a path is expected to work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    Ok,
    Denied,
}

impl Access {
    fn result(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
        }
    }
}

/// The kinds of file [`Check::FileType`] distinguishes.
const FILE_TYPES: [&str; 6] = [
    "file",
    "directory",
    "character-device",
    "block-device",
    "socket",
    "fifo",
];

/// A fact the workload observes, together with its expected value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Check {
    /// An environment variable, `None` when it must be unset.
    Env {
        name: String,
        expect: Option<String>,
    },
    /// Whether `path` exists.
    Exists { path: String, expect: bool },
    /// The contents of the file at `path`.
    Contents { path: String, expect: String },
    /// The kind of file at `path`, one of [`FILE_TYPES`].
    FileType { path: String, expect: String },
    /// Opening `path` for reading works.
    Read { path: String, expect: Access },
    /// The file at `path` exists and opening it for append works. Nothing is
    /// written, so a host fixture is left as it was. A path that does not exist
    /// is reported as `missing`, which no check expects, so a check on the wrong
    /// path fails instead of passing.
    Write { path: String, expect: Access },
    /// Whether the workload runs as a non-root user.
    NonRoot { expect: bool },
    /// Whether the workload's groups include the group that owns `path`.
    InGroupOf { path: String, expect: bool },
    /// Connecting to the unix socket at `path` works and it echoes what is
    /// sent. The probe needs `perl`, which the default workload image has.
    EchoSocket { path: String, expect: Access },
}

impl Check {
    /// Parse a check as written in `scenarios.yaml`.
    fn from_json(value: &Value) -> Result<Self> {
        let text = |key: &str| {
            value[key]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| Error::msg(format!("check {value} needs a string `{key}`")))
        };
        let optional = |key: &str| match &value[key] {
            Value::Null => Ok(None),
            Value::String(text) => Ok(Some(text.clone())),
            _ => Err(Error::msg(format!(
                "check {value} needs a string or null `{key}`"
            ))),
        };
        // True when omitted.
        let flag = |key: &str| match &value[key] {
            Value::Null => Ok(true),
            Value::Bool(flag) => Ok(*flag),
            _ => Err(Error::msg(format!("check {value} needs a boolean `{key}`"))),
        };
        let access = || match text("expect")?.as_str() {
            "ok" => Ok(Access::Ok),
            "denied" => Ok(Access::Denied),
            other => Err(Error::msg(format!(
                "check {value}: expected ok or denied, got {other:?}"
            ))),
        };
        match value["type"].as_str() {
            Some("env") => Ok(Self::Env {
                name: text("name")?,
                expect: optional("expect")?,
            }),
            Some("exists") => Ok(Self::Exists {
                path: text("path")?,
                expect: flag("expect")?,
            }),
            Some("contents") => Ok(Self::Contents {
                path: text("path")?,
                expect: text("expect")?,
            }),
            Some("filetype") => {
                let expect = text("expect")?;
                if !FILE_TYPES.contains(&expect.as_str()) {
                    return Err(Error::msg(format!(
                        "check {value}: file type must be one of {FILE_TYPES:?}"
                    )));
                }
                Ok(Self::FileType {
                    path: text("path")?,
                    expect,
                })
            }
            Some("read") => Ok(Self::Read {
                path: text("path")?,
                expect: access()?,
            }),
            Some("write") => Ok(Self::Write {
                path: text("path")?,
                expect: access()?,
            }),
            Some("non-root") => Ok(Self::NonRoot {
                expect: flag("expect")?,
            }),
            Some("in-group-of") => Ok(Self::InGroupOf {
                path: text("path")?,
                expect: flag("expect")?,
            }),
            Some("echo-socket") => Ok(Self::EchoSocket {
                path: text("path")?,
                expect: access()?,
            }),
            other => Err(Error::msg(format!(
                "unknown check type {other:?} in {value}"
            ))),
        }
    }

    /// Stable identifier used in the probe output and in failure reports.
    fn id(&self) -> String {
        match self {
            Self::Env { name, .. } => format!("env:{name}"),
            Self::Exists { path, .. } => format!("exists:{path}"),
            Self::Contents { path, .. } => format!("contents:{path}"),
            Self::FileType { path, .. } => format!("filetype:{path}"),
            Self::Read { path, .. } => format!("read:{path}"),
            Self::Write { path, .. } => format!("write:{path}"),
            Self::NonRoot { .. } => "non-root".to_string(),
            Self::InGroupOf { path, .. } => format!("in-group-of:{path}"),
            Self::EchoSocket { path, .. } => format!("echo-socket:{path}"),
        }
    }

    /// Shell that prints the observed result for this check.
    fn observe(&self) -> String {
        match self {
            Self::Env { name, .. } => format!(
                r#"if [ "${{{name}+x}}" ]; then printf 'set:%s' "${name}"; else printf unset; fi"#
            ),
            Self::Exists { path, .. } => {
                format!(r"if [ -e '{path}' ]; then printf present; else printf missing; fi")
            }
            Self::Contents { path, .. } => format!(
                r#"if [ -e '{path}' ]; then printf 'content:%s' "$(cat '{path}' 2>&1)"; else printf missing; fi"#
            ),
            Self::FileType { path, .. } => format!(
                "if [ -S '{path}' ]; then printf socket; \
                 elif [ -c '{path}' ]; then printf character-device; \
                 elif [ -b '{path}' ]; then printf block-device; \
                 elif [ -p '{path}' ]; then printf fifo; \
                 elif [ -d '{path}' ]; then printf directory; \
                 elif [ -f '{path}' ]; then printf file; \
                 else printf missing; fi"
            ),
            Self::Read { path, .. } => {
                format!(r"if ( : < '{path}' ) 2>/dev/null; then printf ok; else printf denied; fi")
            }
            Self::Write { path, .. } => format!(
                "if [ ! -e '{path}' ]; then printf missing; \\
                 elif ( : >> '{path}' ) 2>/dev/null; then printf ok; else printf denied; fi"
            ),
            Self::NonRoot { .. } => {
                r#"if [ "$(id -u)" != 0 ]; then printf ok; else printf root; fi"#.to_string()
            }
            Self::InGroupOf { path, .. } => format!(
                r#"set -- $(ls -ln '{path}' 2>/dev/null); case " $(id -G) " in *" $4 "*) printf ok ;; *) printf missing-group ;; esac"#
            ),
            // `no-client` and `no-echo` are not expected by any scenario, so a
            // workload without perl or a socket that does not echo fails the
            // check with a result that says why.
            Self::EchoSocket { path, .. } => format!(
                r#"if command -v perl >/dev/null 2>&1; then perl -MIO::Socket::UNIX -e '$s = IO::Socket::UNIX->new(Peer => $ARGV[0]) or print("denied") and exit; print $s "ping\n"; $s->shutdown(1); $r = <$s>; print((defined $r && $r eq "ping\n") ? "ok" : "no-echo")' '{path}'; else printf no-client; fi"#
            ),
        }
    }

    /// The result [`Check::observe`] prints when the expectation holds.
    fn expected(&self) -> String {
        match self {
            Self::Env { expect, .. } => expect
                .as_ref()
                .map_or_else(|| "unset".to_string(), |value| format!("set:{value}")),
            Self::Exists { expect, .. } => if *expect { "present" } else { "missing" }.to_string(),
            Self::Contents { expect, .. } => format!("content:{expect}"),
            Self::FileType { expect, .. } => expect.clone(),
            Self::Read { expect, .. }
            | Self::Write { expect, .. }
            | Self::EchoSocket { expect, .. } => expect.result().to_string(),
            Self::NonRoot { expect } => if *expect { "ok" } else { "root" }.to_string(),
            Self::InGroupOf { expect, .. } => {
                if *expect { "ok" } else { "missing-group" }.to_string()
            }
        }
    }
}

/// What a scenario expects of the workload.
#[derive(Debug)]
struct Scenario {
    /// The CDI device to select, `<kind>=<name>`.
    device: String,
    /// Facts the workload must observe once the sandbox is created.
    checks: Vec<Check>,
}

/// Read a scenario's expectations, and the checks every scenario carries, from
/// the published document.
fn scenario_expectations(document: &Value, name: &str) -> Result<Scenario> {
    let expect = document["scenarios"].get(name).ok_or_else(|| {
        Error::msg(format!(
            "scenario {name:?} is not defined in the published expectations"
        ))
    })?;
    let checks_from = |value: &Value| -> Result<Vec<Check>> {
        // An absent list means no checks; a list of any other type is a
        // mistake that would silently drop coverage.
        match value {
            Value::Null => Ok(Vec::new()),
            Value::Array(checks) => checks.iter().map(Check::from_json).collect(),
            other => Err(Error::msg(format!(
                "scenario {name:?}: checks must be a list, found {other}"
            ))),
        }
    };
    let kind = document["kind"]
        .as_str()
        .filter(|kind| !kind.is_empty())
        .ok_or_else(|| Error::msg("the published expectations name no device kind"))?;
    // Every scenario creates a sandbox that starts. Ignoring a key that asked
    // for something else would silently drop the expectation.
    testkit::ensure!(
        expect.get("rejected").is_none(),
        "scenario {name:?}: `rejected` is not supported; scenarios must create a sandbox"
    );
    let mut checks = checks_from(&document["common_checks"])?;
    checks.extend(checks_from(&expect["checks"])?);
    Ok(Scenario {
        device: format!("{kind}={name}"),
        checks,
    })
}

fn load(name: &str) -> Result<Scenario> {
    let path = std::env::var(SCENARIOS_ENV).map_err(|_| {
        Error::msg(format!(
            "{SCENARIOS_ENV} is not set; the environment must publish the scenario expectations"
        ))
    })?;
    let text = std::fs::read_to_string(&path)
        .map_err(Error::from_display)
        .context(format!("read scenario expectations {path}"))?;
    let document: Value = serde_json::from_str(&text)
        .map_err(Error::from_display)
        .context(format!("parse scenario expectations {path}"))?;
    scenario_expectations(&document, name)
}

/// Shell that prints one `check=<id> result=<observed>` line per check.
fn probe_script(checks: &[Check]) -> String {
    let mut script = String::new();
    for check in checks {
        writeln!(
            script,
            "printf 'check=%s result=' '{}'; {}; printf '\\n'",
            check.id(),
            check.observe()
        )
        .expect("writing to a String cannot fail");
    }
    script
}

fn parse_observations(stdout: &str) -> BTreeMap<&str, &str> {
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("check="))
        .filter_map(|line| line.split_once(" result="))
        .collect()
}

/// Describe every check whose observed result differs from its expectation.
fn mismatches(checks: &[Check], observed: &BTreeMap<&str, &str>) -> Vec<String> {
    checks
        .iter()
        .filter_map(|check| {
            let expected = check.expected();
            let actual = observed.get(check.id().as_str()).copied();
            (actual != Some(expected.as_str())).then(|| {
                format!(
                    "{}\n       expected: {expected}\n       observed: {}",
                    check.id(),
                    actual.unwrap_or("<no output>")
                )
            })
        })
        .collect()
}

/// The compute driver the gateway runs, when it is one of [`DRIVERS`].
async fn compute_driver(cx: &Context) -> Result<&'static str> {
    for driver in DRIVERS {
        if cx.expect_compute_driver(driver).await.is_ok() {
            return Ok(driver);
        }
    }
    Err(Error::msg(format!(
        "the gateway must run exactly one of the compute drivers {DRIVERS:?}"
    )))
}

/// Create a sandbox that selects the named scenario device on the gateway's
/// compute driver and check it against the scenario's published expectations.
///
/// The sandbox must create, and the workload must observe each of the
/// scenario's checks, including the checks every scenario carries.
///
/// # Errors
///
/// Fails when the expectations cannot be read, the gateway does not run the
/// Docker or Podman driver, or the sandbox does not behave as the scenario expects.
pub async fn scenario(cx: &Context, name: &str) -> Result {
    let Scenario { device, checks } = load(name)?;
    let driver = compute_driver(cx).await?;

    let sandbox = cx.name("cdi");
    cx.track(&sandbox);
    let config = json!({driver: {"cdi_devices": [device]}}).to_string();
    let probe = probe_script(&checks);
    let output = cx
        .cli([
            "sandbox",
            "create",
            "--name",
            &sandbox,
            "--no-tty",
            "--gpu",
            "1",
            "--driver-config-json",
            &config,
            "--",
            "sh",
            "-c",
            &probe,
        ])
        .await?;

    let output = output
        .success()
        .context(format!("sandbox with scenario device {name} starts"))?;
    let failures = mismatches(&checks, &parse_observations(&output.stdout));
    testkit::ensure!(
        failures.is_empty(),
        "scenario {name}: checks that disagree:\n  FAIL {}\nworkload output:\n{}",
        failures.join("\n  FAIL "),
        output.stdout
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    fn document() -> Value {
        json!({
            "kind": "vendor.example/scenario",
            "common_checks": [{"type": "env", "name": "COMMON", "expect": "yes"}],
            "scenarios": {
                "plain": {"checks": [
                    {"type": "contents", "path": "/a", "expect": "hello"},
                    {"type": "write", "path": "/a", "expect": "denied"},
                    {"type": "non-root"},
                ]},
                "refused": {"rejected": "no such device"},
            },
        })
    }

    fn checks(values: &[Value]) -> Vec<Check> {
        values
            .iter()
            .map(|v| Check::from_json(v).unwrap())
            .collect()
    }

    #[test]
    fn scenario_includes_common_checks_first() {
        let scenario = scenario_expectations(&document(), "plain").unwrap();
        let ids: Vec<_> = scenario.checks.iter().map(Check::id).collect();
        assert_eq!(ids, ["env:COMMON", "contents:/a", "write:/a", "non-root"]);
    }

    #[test]
    fn rejected_scenarios_are_not_supported() {
        assert!(scenario_expectations(&document(), "refused").is_err());
    }

    #[test]
    fn scenario_selects_a_device_of_the_published_kind() {
        let scenario = scenario_expectations(&document(), "plain").unwrap();
        assert_eq!(scenario.device, "vendor.example/scenario=plain");
    }

    #[test]
    fn missing_or_empty_kind_is_an_error() {
        for kind in [json!(null), json!(""), json!(3)] {
            let mut doc = document();
            doc["kind"] = kind;
            assert!(scenario_expectations(&doc, "plain").is_err());
        }
    }

    #[test]
    fn unknown_scenario_and_check_type_are_errors() {
        assert!(scenario_expectations(&document(), "missing").is_err());
        let bad =
            json!({"kind": "k.example/c", "scenarios": {"x": {"checks": [{"type": "nope"}]}}});
        assert!(scenario_expectations(&bad, "x").is_err());
    }

    #[test]
    fn non_list_checks_are_errors() {
        for bad in [
            json!({"kind": "k.example/c", "scenarios": {"x": {"checks": {"type": "non-root"}}}}),
            json!({"kind": "k.example/c", "scenarios": {"x": {"checks": "non-root"}}}),
            json!({"kind": "k.example/c", "common_checks": {"type": "non-root"}, "scenarios": {"x": {}}}),
        ] {
            assert!(scenario_expectations(&bad, "x").is_err(), "{bad}");
        }
        let absent = json!({"kind": "k.example/c", "scenarios": {"x": {}}});
        assert!(
            scenario_expectations(&absent, "x")
                .unwrap()
                .checks
                .is_empty()
        );
    }

    #[test]
    fn malformed_checks_are_errors() {
        for bad in [
            // Contents need a string; absence is the `exists` check.
            json!({"type": "contents", "path": "/a", "expect": null}),
            json!({"type": "filetype", "path": "/a", "expect": "chardev"}),
            json!({"type": "read", "path": "/a", "expect": "maybe"}),
            json!({"type": "non-root", "expect": "yes"}),
            // The retired names are not accepted.
            json!({"type": "group-of", "path": "/d"}),
        ] {
            assert!(Check::from_json(&bad).is_err(), "{bad} should not parse");
        }
    }

    #[test]
    fn new_check_types_parse() {
        let parsed = checks(&[
            json!({"type": "exists", "path": "/a", "expect": false}),
            json!({"type": "exists", "path": "/a"}),
            json!({"type": "filetype", "path": "/s", "expect": "socket"}),
            json!({"type": "non-root", "expect": false}),
            json!({"type": "in-group-of", "path": "/d"}),
            json!({"type": "echo-socket", "path": "/s", "expect": "denied"}),
        ]);
        assert_eq!(
            parsed[0],
            Check::Exists {
                path: "/a".into(),
                expect: false
            }
        );
        // Existence is expected unless stated.
        assert_eq!(parsed[1].expected(), "present");
        assert_eq!(parsed[2].expected(), "socket");
        assert_eq!(parsed[3].expected(), "root");
        assert_eq!(parsed[4].expected(), "ok");
        assert_eq!(parsed[5].expected(), "denied");
        assert_eq!(parsed[5].id(), "echo-socket:/s");
    }

    #[test]
    fn observations_are_compared_to_expectations() {
        let scenario = scenario_expectations(&document(), "plain").unwrap();
        let stdout = "check=env:COMMON result=set:yes\n\
                      check=contents:/a result=content:hello\n\
                      check=write:/a result=ok\n\
                      check=non-root result=ok\n";
        let failures = mismatches(&scenario.checks, &parse_observations(stdout));
        assert_eq!(failures.len(), 1);
        assert!(failures[0].starts_with("write:/a"));
        assert!(failures[0].contains("expected: denied"));
        assert!(failures[0].contains("observed: ok"));
    }

    #[test]
    fn missing_observation_is_reported() {
        let scenario = scenario_expectations(&document(), "plain").unwrap();
        let failures = mismatches(&scenario.checks, &BTreeMap::new());
        assert_eq!(failures.len(), 4);
        assert!(failures.iter().all(|f| f.contains("<no output>")));
    }

    #[test]
    fn probe_script_prints_one_line_per_check() {
        let scenario = scenario_expectations(&document(), "plain").unwrap();
        let script = probe_script(&scenario.checks);
        assert_eq!(
            script.lines().filter(|l| l.starts_with("printf")).count(),
            4
        );
        assert!(script.contains("check=%s result="));
    }

    /// A directory of fixtures for running the probe shell in this process's
    /// own filesystem, so the generated shell is exercised and not only read.
    struct Fixtures(PathBuf);

    impl Fixtures {
        fn new(test: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("cdi-probe-{test}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("dir")).unwrap();
            std::fs::write(dir.join("file"), "marker\n").unwrap();
            let fifo = Command::new("mkfifo")
                .arg(dir.join("fifo"))
                .status()
                .unwrap();
            assert!(fifo.success());
            Self(dir)
        }

        fn path(&self, name: &str) -> String {
            self.0.join(name).to_str().unwrap().to_string()
        }

        /// What the probe observes for `check`, as the guest would print it.
        fn observe(&self, check: &Check) -> String {
            let output = Command::new("sh")
                .arg("-c")
                .arg(check.observe())
                .output()
                .unwrap();
            String::from_utf8(output.stdout).unwrap()
        }
    }

    impl Drop for Fixtures {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn probe_shell_observes_echo_socket() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let fx = Fixtures::new("echo");
        let observe = |path: &str| {
            fx.observe(
                &checks(&[json!({"type": "echo-socket", "path": path, "expect": "ok"})]).remove(0),
            )
        };
        let serve = |name: &str, echo: bool| {
            let path = fx.path(name);
            let listener = UnixListener::bind(&path).unwrap();
            std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut data = Vec::new();
                stream.read_to_end(&mut data).unwrap();
                if echo {
                    stream.write_all(&data).unwrap();
                }
            });
            path
        };

        assert_eq!(observe(&serve("echo.sock", true)), "ok");
        assert_eq!(observe(&serve("mute.sock", false)), "no-echo");
        // A path that is not a listening socket cannot be connected to.
        assert_eq!(observe(&fx.path("nope.sock")), "denied");
        assert_eq!(observe(&fx.path("file")), "denied");
    }

    #[test]
    fn probe_shell_observes_files() {
        let fx = Fixtures::new("files");
        let check = |value: Value| checks(&[value]).remove(0);
        let observe = |value: Value| fx.observe(&check(value));
        let (file, dir, fifo) = (fx.path("file"), fx.path("dir"), fx.path("fifo"));
        let missing = fx.path("nope");

        assert_eq!(observe(json!({"type": "exists", "path": file})), "present");
        assert_eq!(
            observe(json!({"type": "exists", "path": missing})),
            "missing"
        );
        assert_eq!(
            observe(json!({"type": "contents", "path": file, "expect": "x"})),
            "content:marker"
        );
        assert_eq!(
            observe(json!({"type": "contents", "path": missing, "expect": "x"})),
            "missing"
        );
        for (path, kind) in [
            (&file, "file"),
            (&dir, "directory"),
            (&fifo, "fifo"),
            (&"/dev/null".to_string(), "character-device"),
            (&missing, "missing"),
        ] {
            assert_eq!(
                observe(json!({"type": "filetype", "path": path, "expect": "file"})),
                kind,
                "{path}"
            );
        }
        assert_eq!(
            observe(json!({"type": "read", "path": file, "expect": "ok"})),
            "ok"
        );
        assert_eq!(
            observe(json!({"type": "read", "path": missing, "expect": "ok"})),
            "denied"
        );
        // A path that does not exist is reported as such, never created, even
        // where it could be.
        assert_eq!(
            observe(json!({"type": "write", "path": missing, "expect": "ok"})),
            "missing"
        );
        assert!(!std::path::Path::new(&missing).exists());
        assert_eq!(
            observe(json!({"type": "write", "path": file, "expect": "ok"})),
            "ok"
        );
        // Opening for append never creates a directory.
        assert_eq!(
            observe(json!({"type": "write", "path": dir, "expect": "ok"})),
            "denied"
        );
    }

    #[test]
    fn probe_shell_observes_identity() {
        let fx = Fixtures::new("identity");
        let uid = String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout).unwrap();
        let observe = |value: Value| fx.observe(&checks(&[value]).remove(0));

        // The probe reports root only when this process is uid 0.
        let expected = if uid.trim() == "0" { "root" } else { "ok" };
        assert_eq!(observe(json!({"type": "non-root"})), expected);
        // The fixtures belong to the current user, so their group is one of its groups.
        assert_eq!(
            observe(json!({"type": "in-group-of", "path": fx.path("file")})),
            "ok"
        );
        assert_eq!(
            observe(json!({"type": "in-group-of", "path": fx.path("nope")})),
            "missing-group"
        );
    }
}
