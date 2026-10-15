// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hardware-free CDI injection checks against the installed tmachine gateway.
//!
//! Each test creates a sandbox that explicitly selects one named scenario
//! device, then checks what the workload observes (`Check`) or that creation is
//! rejected. The sandbox only reports what it observes; every assertion is made
//! here, so a failure names the check that disagreed.
//!
//! The scenarios' fixtures, CDI edits and expectations are all defined in the
//! `cdi_fixtures` Ansible role
//! (`tests/ansible/roles/cdi_fixtures/vars/scenarios.yaml`), which publishes the
//! expectations as `scenarios.json` on the guest.

use openshell_conformance::OpenShellRunner;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

/// Where the `cdi_fixtures` role publishes scenario expectations.
const SCENARIOS_PATH: &str = "/var/lib/openshell-test-inputs/cdi/scenarios.json";
const SCENARIO_KIND: &str = "tmachine.example/cdi-scenario";

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

/// A fact observed inside the sandbox together with its expected value.
#[derive(Clone, Debug)]
enum Check {
    /// An environment variable, `None` when it must be unset.
    Env {
        name: String,
        expect: Option<String>,
    },
    /// File contents, `None` when the path must not exist.
    Contents {
        path: String,
        expect: Option<String>,
    },
    /// Opening `path` for reading works.
    Read { path: String, expect: Access },
    /// Opening `path` for append works. Nothing is written, so a writable host
    /// fixture is left as it was.
    Write { path: String, expect: Access },
    /// Whether the workload runs as a non-root user.
    NonRoot { expect: bool },
    /// Whether the workload's groups include the group that owns `path`.
    HasGroupOf { path: String, expect: bool },
    /// Whether a directory is an entry of the workload's `PATH`.
    PathHas { dir: String, expect: bool },
}

impl Check {
    fn env(name: &str, expect: Option<&str>) -> Self {
        Self::Env {
            name: name.to_string(),
            expect: expect.map(str::to_string),
        }
    }

    fn contents(path: &str, expect: Option<&str>) -> Self {
        Self::Contents {
            path: path.to_string(),
            expect: expect.map(str::to_string),
        }
    }

    /// Parse a check as written in `scenarios.yaml`.
    fn from_json(value: &Value) -> Result<Self, String> {
        let text = |key: &str| {
            value[key]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("check {value} needs a string `{key}`"))
        };
        let optional = |key: &str| match &value[key] {
            Value::Null => Ok(None),
            Value::String(text) => Ok(Some(text.clone())),
            _ => Err(format!("check {value} needs a string or null `{key}`")),
        };
        // Defaults to true when omitted.
        let flag = |key: &str| match &value[key] {
            Value::Null => Ok(true),
            Value::Bool(flag) => Ok(*flag),
            _ => Err(format!("check {value} needs a boolean `{key}`")),
        };
        match value["type"].as_str() {
            Some("env") => Ok(Self::Env {
                name: text("name")?,
                expect: optional("expect")?,
            }),
            Some("contents") => Ok(Self::Contents {
                path: text("path")?,
                expect: optional("expect")?,
            }),
            Some(kind @ ("read" | "write")) => {
                let path = text("path")?;
                let expect = match text("expect")?.as_str() {
                    "ok" => Access::Ok,
                    "denied" => Access::Denied,
                    other => {
                        return Err(format!(
                            "{kind} expectation must be ok or denied, got {other:?}"
                        ));
                    }
                };
                Ok(if kind == "read" {
                    Self::Read { path, expect }
                } else {
                    Self::Write { path, expect }
                })
            }
            Some("non-root") => Ok(Self::NonRoot {
                expect: flag("expect")?,
            }),
            Some("group-of") => Ok(Self::HasGroupOf {
                path: text("path")?,
                expect: flag("expect")?,
            }),
            Some("path-has") => Ok(Self::PathHas {
                dir: text("dir")?,
                expect: flag("expect")?,
            }),
            other => Err(format!("unknown check type {other:?} in {value}")),
        }
    }

    /// Stable identifier used in the probe output and in failure reports.
    fn id(&self) -> String {
        match self {
            Self::Env { name, .. } => format!("env:{name}"),
            Self::Contents { path, .. } => format!("contents:{path}"),
            Self::Read { path, .. } => format!("read:{path}"),
            Self::Write { path, .. } => format!("write:{path}"),
            Self::NonRoot { .. } => "non-root".to_string(),
            Self::HasGroupOf { path, .. } => format!("group-of:{path}"),
            Self::PathHas { dir, .. } => format!("path-has:{dir}"),
        }
    }

    /// Shell that prints the observed result for this check.
    fn observe(&self) -> String {
        match self {
            Self::Env { name, .. } => format!(
                r#"if [ "${{{name}+x}}" ]; then printf 'set:%s' "${name}"; else printf unset; fi"#
            ),
            Self::Contents { path, .. } => format!(
                r#"if [ -e '{path}' ]; then printf 'content:%s' "$(cat '{path}' 2>&1)"; else printf missing; fi"#
            ),
            Self::Read { path, .. } => {
                format!(r"if ( : < '{path}' ) 2>/dev/null; then printf ok; else printf denied; fi")
            }
            Self::Write { path, .. } => {
                format!(r"if ( : >> '{path}' ) 2>/dev/null; then printf ok; else printf denied; fi")
            }
            Self::NonRoot { .. } => {
                r#"if [ "$(id -u)" != 0 ]; then printf ok; else printf root; fi"#.to_string()
            }
            Self::HasGroupOf { path, .. } => format!(
                r#"set -- $(ls -ln '{path}' 2>/dev/null); case " $(id -G) " in *" $4 "*) printf ok ;; *) printf missing-group ;; esac"#
            ),
            Self::PathHas { dir, .. } => format!(
                r#"case ":$PATH:" in *:'{dir}':*) printf ok ;; *) printf absent ;; esac"#
            ),
        }
    }

    fn expected(&self) -> String {
        match self {
            Self::Env { expect, .. } => expect
                .as_ref()
                .map_or_else(|| "unset".to_string(), |value| format!("set:{value}")),
            Self::Contents { expect, .. } => expect.as_ref().map_or_else(
                || "missing".to_string(),
                |content| format!("content:{content}"),
            ),
            Self::Read { expect, .. } | Self::Write { expect, .. } => expect.result().to_string(),
            Self::NonRoot { expect } => if *expect { "ok" } else { "root" }.to_string(),
            Self::HasGroupOf { expect, .. } => {
                if *expect { "ok" } else { "missing-group" }.to_string()
            }
            Self::PathHas { expect, .. } => if *expect { "ok" } else { "absent" }.to_string(),
        }
    }
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
        .unwrap();
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

/// What a scenario expects of sandbox creation and the workload.
struct Scenario {
    /// Facts the workload must observe once the sandbox is created. Observed,
    /// but not asserted, when creation is expected to fail.
    checks: Vec<Check>,
    /// Creation must fail with a diagnostic containing this text.
    rejected: Option<String>,
}

/// Read a scenario's expectations from the published document.
fn scenario_expectations(document: &Value, name: &str) -> Result<Scenario, String> {
    let expect = document["scenarios"]
        .get(name)
        .ok_or_else(|| format!("scenario {name:?} is not defined in the published expectations"))?;
    let checks_from = |value: &Value| -> Result<Vec<Check>, String> {
        value.as_array().map_or_else(
            || Ok(Vec::new()),
            |checks| checks.iter().map(Check::from_json).collect(),
        )
    };
    let mut checks = checks_from(&document["common_checks"])?;
    checks.extend(checks_from(&expect["checks"])?);
    Ok(Scenario {
        checks,
        rejected: expect["rejected"].as_str().map(str::to_string),
    })
}

fn load_scenario(name: &str) -> Result<Scenario, String> {
    let path = std::env::var("OPENSHELL_CDI_SCENARIOS").unwrap_or_else(|_| SCENARIOS_PATH.into());
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("read scenario expectations {path}: {error}"))?;
    let document: Value = serde_json::from_str(&text)
        .map_err(|error| format!("parse scenario expectations {path}: {error}"))?;
    scenario_expectations(&document, name)
}

async fn run_scenario(name: &str, scenario: Scenario) {
    let Scenario { checks, rejected } = scenario;
    let case = format!("cdi-scenario-{name}");
    let mut runner =
        OpenShellRunner::from_env(&case).expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let info = runner
            .step("preflight/driver")
            .description("gateway has one Docker compute driver")
            .with_timeout(Duration::from_secs(10))
            .run(&["gateway", "info", "--output", "json"])
            .await
            .map_err(|error| error.to_string())?;
        info.require_success()?;
        let info_json: Value = info.json().map_err(|error| error.to_string())?;
        let drivers = info_json["compute_drivers"]
            .as_array()
            .ok_or_else(|| "gateway did not report compute drivers".to_string())?;
        let driver = match drivers.as_slice() {
            [driver] => driver["name"].as_str().unwrap_or_default(),
            _ => return Err("CDI suite requires exactly one compute driver".to_string()),
        };
        if driver != "docker" {
            return Err(format!("CDI suite requires Docker, got {driver:?}"));
        }

        // Capture mode reports what happens instead of asserting, to record the
        // behavior a scenario currently has.
        let capture = std::env::var_os("OPENSHELL_CDI_CAPTURE").is_some();
        let probe = if rejected.is_some() && !capture {
            "exit 0".to_string()
        } else {
            probe_script(&checks)
        };
        let sandbox = format!("cdi-{}", runner.id());
        runner.track_sandbox(&sandbox);
        let config =
            json!({driver: {"cdi_devices": [format!("{SCENARIO_KIND}={name}")]}}).to_string();
        let run = runner
            .step("cdi/injection")
            .description(&case)
            .with_timeout(Duration::from_secs(300))
            .run(&[
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
            .await
            .map_err(|error| error.to_string())?;

        if capture {
            println!("CAPTURE scenario={name} created={}", run.success());
            if !run.success() {
                let diagnostic = run
                    .stderr()
                    .lines()
                    .rev()
                    .find(|line| !line.trim().is_empty());
                println!(
                    "CAPTURE diagnostic={:?}",
                    diagnostic.unwrap_or_default().trim()
                );
            }
            let observed = parse_observations(run.stdout());
            for check in &checks {
                let id = check.id();
                println!(
                    "CAPTURE check={id} result={}",
                    observed.get(id.as_str()).copied().unwrap_or("<no output>")
                );
            }
            return Ok(());
        }

        if let Some(expected_error) = &rejected {
            if run.success()
                || !format!("{}\n{}", run.stdout(), run.stderr()).contains(expected_error.as_str())
            {
                return Err(run.failure_diagnostic(&format!(
                    "creation fails with a CDI diagnostic containing {expected_error:?}"
                )));
            }
            return Ok(());
        }

        run.require_success()?;
        let failures = mismatches(&checks, &parse_observations(run.stdout()));
        if failures.is_empty() {
            Ok(())
        } else {
            Err(run.failure_diagnostic(&format!(
                "all sandbox checks hold; failing:\n  FAIL {}",
                failures.join("\n  FAIL ")
            )))
        }
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("CDI test failed:\n{error}");
    }
}

async fn check_scenario(name: &str) {
    match load_scenario(name) {
        Ok(scenario) => run_scenario(name, scenario).await,
        Err(error) => panic!("CDI scenario {name}: {error}"),
    }
}

/// Defines one `#[tokio::test]` per scenario in `scenarios.yaml`, so nextest
/// runs and reports each independently.
macro_rules! cdi_scenarios {
    ($($name:ident => $scenario:literal,)*) => {
        $(
            #[tokio::test]
            async fn $name() {
                check_scenario($scenario).await;
            }
        )*
    };
}

cdi_scenarios! {
    scenario_mount_under_read_only_baseline => "mount-under-read-only-baseline",
    scenario_read_only_file => "read-only-file",
    scenario_read_only_directory => "read-only-directory",
    scenario_library_parent => "library-parent",
    scenario_broad_library_parent => "broad-library-parent",
    scenario_writable_file => "writable-file",
    scenario_writable_directory => "writable-directory",
    scenario_omitted_access_file => "omitted-access-file",
    scenario_mps_pipe_directory => "mps-pipe-directory",
    scenario_mps_pipe_directory_without_noexec => "mps-pipe-directory-without-noexec",
    scenario_sbin_path => "sbin-path",
    scenario_device_node => "device-node",
    scenario_device_node_with_gid => "device-node-with-gid",
    scenario_unix_socket => "unix-socket",
}

#[cfg(test)]
mod probe {
    use super::*;
    use std::process::Command;

    fn run_probe(checks: &[Check]) -> String {
        let output = Command::new("sh")
            .arg("-c")
            .arg(probe_script(checks))
            .env("PROBE_SET", "value")
            .env_remove("PROBE_UNSET")
            .output()
            .expect("sh runs");
        String::from_utf8(output.stdout).expect("probe output is UTF-8")
    }

    #[test]
    fn probe_observes_environment_and_files() {
        let dir = std::env::temp_dir().join(format!("cdi-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("marker");
        std::fs::write(&file, "marker-content\n").unwrap();
        let path = file.to_str().unwrap();
        let missing = dir.join("missing");
        let unwritable = dir.join("no-such-directory/file");

        let checks = [
            Check::env("PROBE_SET", Some("value")),
            Check::env("PROBE_UNSET", None),
            Check::contents(path, Some("marker-content")),
            Check::contents(missing.to_str().unwrap(), None),
            Check::Read {
                path: path.to_string(),
                expect: Access::Ok,
            },
            Check::Read {
                path: missing.to_str().unwrap().to_string(),
                expect: Access::Denied,
            },
            Check::Write {
                path: path.to_string(),
                expect: Access::Ok,
            },
            Check::Write {
                path: unwritable.to_str().unwrap().to_string(),
                expect: Access::Denied,
            },
            // A file the test just created belongs to one of the user's groups.
            Check::HasGroupOf {
                path: path.to_string(),
                expect: true,
            },
            Check::PathHas {
                dir: "/bin".to_string(),
                expect: true,
            },
            Check::PathHas {
                dir: "/no/such/directory".to_string(),
                expect: false,
            },
        ];
        let stdout = run_probe(&checks);
        let observed = parse_observations(&stdout);
        let failures = mismatches(&checks, &observed);
        assert!(failures.is_empty(), "unexpected failures: {failures:?}");

        let wrong = [Check::env("PROBE_SET", None)];
        let failures = mismatches(&wrong, &parse_observations(&run_probe(&wrong)));
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("expected: unset"));
        assert!(failures[0].contains("observed: set:value"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_output_is_reported_as_a_mismatch() {
        let checks = [Check::NonRoot { expect: true }];
        let failures = mismatches(&checks, &BTreeMap::new());
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("<no output>"));
    }

    #[test]
    fn scenario_expectations_are_read_from_the_document() {
        let document = json!({
            "common_checks": [{"type": "env", "name": "SPEC", "expect": "fixture"}],
            "scenarios": {
                "read-only": {"checks": [
                    {"type": "contents", "path": "/p", "expect": "x"},
                    {"type": "write", "path": "/p", "expect": "denied"},
                    {"type": "contents", "path": "/q", "expect": null},
                    {"type": "non-root", "expect": false},
                    {"type": "group-of", "path": "/d"},
                ]},
                "refused": {"rejected": "writable", "checks": [{"type": "non-root"}]},
            },
        });

        let scenario = scenario_expectations(&document, "read-only").unwrap();
        assert!(scenario.rejected.is_none());
        let ids: Vec<_> = scenario.checks.iter().map(Check::id).collect();
        assert_eq!(
            ids,
            [
                "env:SPEC",
                "contents:/p",
                "write:/p",
                "contents:/q",
                "non-root",
                "group-of:/d"
            ]
        );
        assert_eq!(scenario.checks[3].expected(), "missing");
        assert_eq!(scenario.checks[4].expected(), "root");
        assert_eq!(scenario.checks[5].expected(), "ok");

        let refused = scenario_expectations(&document, "refused").unwrap();
        assert_eq!(refused.rejected.as_deref(), Some("writable"));
        // Observed even though creation is expected to fail, for capture mode.
        assert_eq!(refused.checks.len(), 2);

        assert!(scenario_expectations(&document, "absent").is_err());
    }

    #[test]
    fn malformed_checks_are_rejected() {
        for check in [
            json!({"type": "nonsense"}),
            json!({"type": "write", "path": "/p", "expect": "maybe"}),
            json!({"type": "contents", "expect": "x"}),
        ] {
            assert!(
                Check::from_json(&check).is_err(),
                "{check} should not parse"
            );
        }
    }
}
