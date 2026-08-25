// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reusable support for portable `OpenShell` CLI conformance scenarios.

pub mod executor;
mod scenarios;

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tokio::time::sleep;

use self::executor::{CliExecutionError, CliExecutor, ProcessCli};

pub use scenarios::SMOKE_SCENARIO;

/// An installed conformance scenario.
#[derive(Debug)]
pub struct Scenario {
    pub name: &'static str,
    pub description: &'static str,
    run: for<'a> fn(&'a mut OpenShellRunner) -> ScenarioFuture<'a>,
}

pub type ScenarioFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

impl Scenario {
    pub async fn run(&self, runner: &mut OpenShellRunner) -> Result<(), String> {
        (self.run)(runner).await
    }
}

const SCENARIOS: &[Scenario] = &[SMOKE_SCENARIO];

/// Returns every scenario compiled into this distribution.
pub fn scenarios() -> &'static [Scenario] {
    SCENARIOS
}

/// Finds a scenario by its stable command-line name.
pub fn scenario(name: &str) -> Option<&'static Scenario> {
    scenarios().iter().find(|candidate| candidate.name == name)
}

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(120);
pub const STATUS_TIMEOUT: Duration = Duration::from_secs(30);
const GATEWAY_STATUS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
const GATEWAY_STATUS_INTERVAL: Duration = Duration::from_secs(2);

/// Generate the suite-owned identifier used in resource names and diagnostics.
fn generate_run_id() -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::rng();
    (0..10)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}

/// The completed outcome of one `OpenShell` CLI process.
#[derive(Debug)]
pub struct CommandResult {
    run_id: String,
    scenario: String,
    step: String,
    expectation: String,
    command: String,
    status: ExitStatus,
    elapsed: Duration,
    stdout: String,
    stderr: String,
}

impl CommandResult {
    pub fn success(&self) -> bool {
        self.status.success()
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.status.code()
    }

    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    pub fn stderr(&self) -> &str {
        &self.stderr
    }

    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    pub fn json<T: DeserializeOwned>(&self) -> Result<T, RunnerError> {
        serde_json::from_str(&self.stdout).map_err(|source| RunnerError::InvalidJson {
            context: self.context(),
            source,
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
        })
    }

    pub fn require_success(&self) -> Result<(), String> {
        if self.success() {
            return Ok(());
        }
        Err(self.failure_diagnostic(&self.expectation))
    }

    pub fn failure_diagnostic(&self, expectation: &str) -> String {
        format!(
            "{}\nexpected: {expectation}\nactual: exit {} after {:.1?}\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
            self.context(),
            exit_description(self.status),
            self.elapsed,
            self.command,
            self.stdout,
            self.stderr,
        )
    }

    fn context(&self) -> String {
        format!("[run {}][{}/{}]", self.run_id, self.scenario, self.step)
    }
}

/// Failures in reusable runner mechanics rather than scenario assertions.
#[derive(Debug)]
pub enum RunnerError {
    BinaryUnavailable(String),
    Spawn {
        context: String,
        command: String,
        source: std::io::Error,
    },
    Timeout {
        context: String,
        command: String,
        timeout: Duration,
    },
    InvalidJson {
        context: String,
        source: serde_json::Error,
        stdout: String,
        stderr: String,
    },
    PollTimeout {
        context: String,
        timeout: Duration,
        last_observation: String,
    },
    ObservationFailed {
        context: String,
        diagnostic: String,
    },
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BinaryUnavailable(message) => write!(f, "{message}"),
            Self::Spawn {
                context,
                command,
                source,
            } => write!(
                f,
                "{context} failed to spawn command: {source}\ncommand: {command}"
            ),
            Self::Timeout {
                context,
                command,
                timeout,
            } => write!(
                f,
                "{context} timed out after {timeout:.1?}\ncommand: {command}"
            ),
            Self::InvalidJson {
                context,
                source,
                stdout,
                stderr,
            } => write!(
                f,
                "{context} returned invalid JSON: {source}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            ),
            Self::PollTimeout {
                context,
                timeout,
                last_observation,
            } => write!(
                f,
                "{context} did not satisfy the observation within {timeout:.1?}\nlast observation:\n{last_observation}"
            ),
            Self::ObservationFailed {
                context,
                diagnostic,
            } => write!(f, "{context} observation failed early:\n{diagnostic}"),
        }
    }
}

impl Error for RunnerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Spawn { source, .. } => Some(source),
            Self::InvalidJson { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Result of one read-only polling observation.
pub enum Poll<T> {
    Ready(T),
    Pending(String),
    Failed(String),
}

#[derive(Debug, Deserialize)]
struct StatusOutput {
    gateway: Option<String>,
    server: Option<String>,
    status: String,
    version: Option<String>,
    authentication: Option<AuthenticationOutput>,
}

#[derive(Debug, Deserialize)]
struct AuthenticationOutput {
    status: String,
}

/// Runs `OpenShell` commands for one conformance scenario and owns its cleanup.
pub struct OpenShellRunner {
    cli: Arc<dyn CliExecutor>,
    run_id: String,
    scenario: String,
    known_sandboxes: BTreeSet<String>,
    finished: bool,
}

/// A runner command with diagnostic context but no timeout yet.
pub struct CommandStep<'a> {
    runner: &'a OpenShellRunner,
    step: String,
    description: Option<String>,
}

/// A fully configured runner command ready to execute.
pub struct OpenShellCommand<'a> {
    runner: &'a OpenShellRunner,
    step: String,
    description: String,
    timeout: Duration,
}

impl OpenShellRunner {
    pub fn new(scenario: &str) -> Result<Self, RunnerError> {
        Ok(Self::with_executor(
            Arc::new(ProcessCli::new(PathBuf::from("openshell"))),
            scenario,
        ))
    }

    /// Uses an explicit `openshell` binary rather than resolving it on `PATH`.
    pub fn with_binary(binary: PathBuf, scenario: &str) -> Result<Self, RunnerError> {
        if !binary.is_file() {
            return Err(RunnerError::BinaryUnavailable(format!(
                "OpenShell CLI binary not found at {}",
                binary.display()
            )));
        }
        Ok(Self::with_executor(
            Arc::new(ProcessCli::new(binary)),
            scenario,
        ))
    }

    /// Creates a runner with an injected executor. This is useful for harness tests.
    pub fn with_executor(cli: Arc<dyn CliExecutor>, scenario: &str) -> Self {
        Self {
            cli,
            run_id: generate_run_id(),
            scenario: scenario.to_string(),
            known_sandboxes: BTreeSet::new(),
            finished: false,
        }
    }

    pub fn id(&self) -> &str {
        &self.run_id
    }

    pub fn scenario(&self) -> &str {
        &self.scenario
    }

    pub fn step(&self, step: impl Into<String>) -> CommandStep<'_> {
        CommandStep {
            runner: self,
            step: step.into(),
            description: None,
        }
    }

    /// Confirm that the configured gateway is reachable before a scenario runs.
    pub async fn check_gateway_status(&mut self) -> Result<(), String> {
        let status = self
            .poll_until(
                "preflight",
                STATUS_TIMEOUT,
                GATEWAY_STATUS_INTERVAL,
                async |runner| match runner
                    .step("status/json")
                    .description("machine-readable gateway status succeeds")
                    .with_timeout(GATEWAY_STATUS_ATTEMPT_TIMEOUT)
                    .run(&["status", "--output", "json"])
                    .await
                {
                    Ok(result) if !result.success() => Poll::Pending(
                        result.failure_diagnostic("gateway status command succeeds"),
                    ),
                    Ok(result) => match result.json::<StatusOutput>() {
                        Ok(status) if status.status == "connected" => Poll::Ready(status),
                        Ok(status) if status.status == "not_configured" => Poll::Failed(
                            "no active gateway; register and select a gateway before running conformance"
                                .to_string(),
                        ),
                        Ok(status) => Poll::Pending(format!(
                            "gateway status is {:?}; expected \"connected\"\nstderr:\n{}",
                            status.status,
                            result.stderr()
                        )),
                        Err(error) => Poll::Failed(error.to_string()),
                    },
                    Err(error) => Poll::Pending(error.to_string()),
                },
            )
            .await
            .map_err(|error| error.to_string())?;

        eprintln!(
            "gateway preflight connected: gateway={}, server={}, version={}, authentication={}",
            status.gateway.as_deref().unwrap_or("unknown"),
            status.server.as_deref().unwrap_or("unknown"),
            status.version.as_deref().unwrap_or("unknown"),
            status
                .authentication
                .as_ref()
                .map_or("unknown", |authentication| authentication.status.as_str()),
        );
        Ok(())
    }

    /// Register a sandbox name for cleanup.
    ///
    /// Call this before running the command that may create the sandbox. The
    /// scenario remains responsible for constructing and running that command.
    pub fn track_sandbox(&mut self, name: &str) {
        self.known_sandboxes.insert(name.to_string());
    }

    /// Stop tracking a sandbox after the scenario confirms it is absent.
    pub fn forget_sandbox(&mut self, name: &str) {
        self.known_sandboxes.remove(name);
    }

    pub async fn poll_until<T, F>(
        &mut self,
        step: &str,
        poll_timeout: Duration,
        interval: Duration,
        mut observe: F,
    ) -> Result<T, RunnerError>
    where
        F: AsyncFnMut(&mut Self) -> Poll<T>,
    {
        let started = Instant::now();
        let context = self.context(step);

        loop {
            match observe(self).await {
                Poll::Ready(value) => return Ok(value),
                Poll::Pending(diagnostic) => {
                    if started.elapsed() >= poll_timeout {
                        return Err(RunnerError::PollTimeout {
                            context,
                            timeout: poll_timeout,
                            last_observation: diagnostic,
                        });
                    }
                }
                Poll::Failed(diagnostic) => {
                    return Err(RunnerError::ObservationFailed {
                        context,
                        diagnostic,
                    });
                }
            }
            sleep(interval).await;
        }
    }

    pub async fn finish(mut self, scenario_result: Result<(), String>) -> Result<(), String> {
        let cleanup_result = self.cleanup().await;
        self.finished = true;
        combine_results(scenario_result, cleanup_result)
    }

    async fn run_strings(
        &self,
        step: &str,
        expectation: &str,
        args: Vec<String>,
        command_timeout: Duration,
    ) -> Result<CommandResult, RunnerError> {
        let context = self.context(step);
        let command = sanitized_command(&args);
        eprintln!("{context} running: {command}");

        let started = Instant::now();
        let output =
            self.cli
                .execute(args, command_timeout)
                .await
                .map_err(|error| match error {
                    CliExecutionError::Timeout => RunnerError::Timeout {
                        context: context.clone(),
                        command: command.clone(),
                        timeout: command_timeout,
                    },
                    CliExecutionError::Spawn(source) => RunnerError::Spawn {
                        context: context.clone(),
                        command: command.clone(),
                        source,
                    },
                })?;
        let elapsed = started.elapsed();
        eprintln!(
            "{context} completed in {:.1?}: exit {}",
            elapsed,
            exit_description(output.status)
        );

        Ok(CommandResult {
            run_id: self.run_id.clone(),
            scenario: self.scenario.clone(),
            step: step.to_string(),
            expectation: expectation.to_string(),
            command,
            status: output.status,
            elapsed,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    async fn cleanup(&self) -> Result<(), String> {
        if self.known_sandboxes.is_empty() {
            return Ok(());
        }

        let cleanup_started = Instant::now();
        let mut failures = Vec::new();
        for name in self.known_sandboxes.clone() {
            let remaining = remaining_cleanup_time(cleanup_started);
            if remaining.is_zero() {
                failures.push(format!(
                    "{} cleanup budget expired before deleting sandbox '{name}'",
                    self.context("cleanup/delete")
                ));
                break;
            }
            match self
                .step("cleanup/delete")
                .description(format!("sandbox '{name}' is deleted or already absent"))
                .with_timeout(remaining)
                .run(&["sandbox", "delete", &name])
                .await
            {
                Ok(result) if result.success() || output_reports_not_found(&result) => {}
                Ok(result) => {
                    failures.push(result.failure_diagnostic(&format!(
                        "sandbox '{name}' is deleted or already absent"
                    )));
                }
                Err(error) => failures.push(error.to_string()),
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("\n\n"))
        }
    }

    fn context(&self, step: &str) -> String {
        format!("[run {}][{}/{}]", self.run_id, self.scenario, step)
    }
}

impl<'a> CommandStep<'a> {
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_timeout(self, timeout: Duration) -> OpenShellCommand<'a> {
        let description = self
            .description
            .unwrap_or_else(|| format!("step '{}' succeeds", self.step));
        OpenShellCommand {
            runner: self.runner,
            step: self.step,
            description,
            timeout,
        }
    }
}

impl OpenShellCommand<'_> {
    pub async fn run(&self, args: &[&str]) -> Result<CommandResult, RunnerError> {
        self.runner
            .run_strings(
                &self.step,
                &self.description,
                args.iter().map(|arg| (*arg).to_string()).collect(),
                self.timeout,
            )
            .await
    }
}

impl Drop for OpenShellRunner {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let resources = if self.known_sandboxes.is_empty() {
            "none explicitly tracked".to_string()
        } else {
            self.known_sandboxes
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        };
        eprintln!(
            "[run {}][{}] WARNING: runner dropped without finish(); known sandboxes: {}",
            self.run_id, self.scenario, resources
        );
    }
}

fn combine_results(
    scenario_result: Result<(), String>,
    cleanup_result: Result<(), String>,
) -> Result<(), String> {
    match (scenario_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(functional), Ok(())) => Err(functional),
        (Ok(()), Err(cleanup)) => Err(format!("cleanup failed:\n{cleanup}")),
        (Err(functional), Err(cleanup)) => Err(format!(
            "{functional}\n\nsecondary cleanup failure:\n{cleanup}"
        )),
    }
}

fn remaining_cleanup_time(started: Instant) -> Duration {
    CLEANUP_TIMEOUT.saturating_sub(started.elapsed())
}

fn output_reports_not_found(result: &CommandResult) -> bool {
    result.stderr().to_ascii_lowercase().contains("not found")
        || result.stdout().to_ascii_lowercase().contains("not found")
}

fn exit_description(status: ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated by signal".to_string(),
        |code| code.to_string(),
    )
}

fn sanitized_command(args: &[String]) -> String {
    let mut redact_next = false;
    let rendered = args.iter().map(|arg| {
        let rendered = if redact_next {
            redact_next = false;
            "<redacted>".to_string()
        } else if sensitive_flag(arg) {
            redact_next = !arg.contains('=');
            arg.split_once('=')
                .map_or_else(|| arg.clone(), |(flag, _)| format!("{flag}=<redacted>"))
        } else {
            arg.clone()
        };
        shell_escape(&rendered)
    });
    std::iter::once("openshell".to_string())
        .chain(rendered)
        .collect::<Vec<_>>()
        .join(" ")
}

fn sensitive_flag(arg: &str) -> bool {
    let flag = arg.split_once('=').map_or(arg, |(flag, _)| flag);
    matches!(
        flag,
        "--credential"
            | "--credentials"
            | "--env"
            | "--header"
            | "--material"
            | "--password"
            | "--secret"
            | "--token"
    ) || flag.contains("client-secret")
        || flag.contains("private-key")
        || flag.ends_with("-token")
}

fn shell_escape(arg: &str) -> String {
    if arg
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-_./:@=,".contains(character))
    {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', "'\\''"))
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::VecDeque;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Output;
    use std::sync::Mutex;

    use serde::Deserialize;

    use super::executor::CliExecution;
    use super::*;

    struct MockCli {
        state: Mutex<MockCliState>,
    }

    struct MockCliState {
        responses: VecDeque<MockResponse>,
        invocations: Vec<Vec<String>>,
    }

    enum MockResponse {
        Output {
            exit_code: i32,
            stdout: String,
            stderr: String,
        },
        Timeout,
    }

    impl MockResponse {
        fn output(exit_code: i32, stdout: &str, stderr: &str) -> Self {
            Self::Output {
                exit_code,
                stdout: stdout.to_string(),
                stderr: stderr.to_string(),
            }
        }

        fn success(stdout: &str) -> Self {
            Self::output(0, stdout, "")
        }
    }

    impl MockCli {
        fn new(responses: Vec<MockResponse>) -> Self {
            Self {
                state: Mutex::new(MockCliState {
                    responses: responses.into(),
                    invocations: Vec::new(),
                }),
            }
        }

        fn invocations(&self) -> Vec<Vec<String>> {
            self.state
                .lock()
                .expect("lock mock CLI state")
                .invocations
                .clone()
        }
    }

    impl CliExecutor for MockCli {
        fn execute(&self, args: Vec<String>, _command_timeout: Duration) -> CliExecution<'_> {
            let response = {
                let mut state = self.state.lock().expect("lock mock CLI state");
                state.invocations.push(args);
                state
                    .responses
                    .pop_front()
                    .expect("mock CLI received an unexpected invocation")
            };

            Box::pin(async move {
                match response {
                    MockResponse::Output {
                        exit_code,
                        stdout,
                        stderr,
                    } => Ok(Output {
                        status: ExitStatus::from_raw(exit_code << 8),
                        stdout: stdout.into_bytes(),
                        stderr: stderr.into_bytes(),
                    }),
                    MockResponse::Timeout => Err(CliExecutionError::Timeout),
                }
            })
        }
    }

    fn test_runner(responses: Vec<MockResponse>) -> (OpenShellRunner, Arc<MockCli>) {
        let cli = Arc::new(MockCli::new(responses));
        let runner = OpenShellRunner::with_executor(cli.clone(), "smoke");
        (runner, cli)
    }

    #[test]
    fn with_binary_rejects_a_missing_file() {
        let directory = tempfile::tempdir().expect("create missing CLI directory");
        let Err(error) = OpenShellRunner::with_binary(directory.path().join("missing"), "smoke")
        else {
            panic!("missing CLI should be rejected");
        };

        assert!(matches!(error, RunnerError::BinaryUnavailable(_)));
    }

    #[test]
    fn exposes_generated_identity() {
        let (mut runner, _cli) = test_runner(Vec::new());

        assert_eq!(runner.id().len(), 10);
        assert_eq!(runner.scenario(), "smoke");
        runner.finished = true;
    }

    #[tokio::test]
    async fn captures_streams_and_nonzero_exit_as_result() {
        let (mut runner, _cli) = test_runner(vec![MockResponse::output(7, "stdout", "stderr")]);

        let result = runner
            .step("capture")
            .description("sandbox list succeeds")
            .with_timeout(Duration::from_secs(1))
            .run(&["sandbox", "list"])
            .await
            .expect("completed nonzero exit is a result");

        assert_eq!(result.exit_code(), Some(7));
        assert_eq!(result.stdout(), "stdout");
        assert_eq!(result.stderr(), "stderr");
        assert!(
            result
                .require_success()
                .expect_err("nonzero result should fail its expectation")
                .contains("expected: sandbox list succeeds")
        );
        runner.finished = true;
    }

    #[tokio::test]
    async fn reports_timeout_as_typed_error() {
        let (mut runner, _cli) = test_runner(vec![MockResponse::Timeout]);

        let error = runner
            .step("timeout")
            .with_timeout(Duration::from_millis(10))
            .run(&["status"])
            .await
            .expect_err("command should time out");

        assert!(matches!(error, RunnerError::Timeout { .. }));
        runner.finished = true;
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct JsonFixture {
        status: String,
    }

    #[tokio::test]
    async fn deserializes_stdout_json_without_stderr() {
        let (mut runner, _cli) = test_runner(vec![MockResponse::output(
            0,
            "{\"status\":\"connected\"}",
            "diagnostic",
        )]);

        let result = runner
            .step("json")
            .with_timeout(Duration::from_secs(1))
            .run(&["status"])
            .await
            .expect("run fake CLI");

        assert_eq!(
            result.json::<JsonFixture>().expect("parse JSON"),
            JsonFixture {
                status: "connected".to_string()
            }
        );
        runner.finished = true;
    }

    #[tokio::test]
    async fn accepts_connected_gateway_status() {
        let (mut runner, _cli) =
            test_runner(vec![MockResponse::success("{\"status\":\"connected\"}")]);

        runner
            .check_gateway_status()
            .await
            .expect("connected gateway should satisfy preflight");

        runner.finished = true;
    }

    #[tokio::test]
    async fn polling_returns_ready_value() {
        let (mut runner, _cli) = test_runner(Vec::new());
        let mut attempts = 0;

        let value = runner
            .poll_until(
                "poll",
                Duration::from_secs(1),
                Duration::from_millis(1),
                async |_runner| {
                    attempts += 1;
                    if attempts == 2 {
                        Poll::Ready("ready")
                    } else {
                        Poll::Pending("not ready".to_string())
                    }
                },
            )
            .await
            .expect("poll should become ready");

        assert_eq!(value, "ready");
        runner.finished = true;
    }

    #[tokio::test]
    async fn polling_timeout_preserves_last_observation() {
        let (mut runner, _cli) = test_runner(Vec::new());

        let error = runner
            .poll_until(
                "poll",
                Duration::from_millis(1),
                Duration::from_millis(1),
                async |_runner| Poll::<()>::Pending("still pending".to_string()),
            )
            .await
            .expect_err("poll should time out");

        assert!(matches!(
            error,
            RunnerError::PollTimeout {
                last_observation,
                ..
            } if last_observation == "still pending"
        ));
        runner.finished = true;
    }

    #[tokio::test]
    async fn finish_skips_cleanup_commands_without_registered_resources() {
        let (runner, cli) = test_runner(Vec::new());

        let error = runner
            .finish(Err("preflight failed".to_string()))
            .await
            .expect_err("functional failure should be preserved");

        assert_eq!(error, "preflight failed");
        assert!(cli.invocations().is_empty());
    }

    #[test]
    fn tracks_sandbox_for_cleanup() {
        let (mut runner, _cli) = test_runner(Vec::new());

        runner.track_sandbox("ct-0123456789-01");

        assert!(runner.known_sandboxes.contains("ct-0123456789-01"));
        runner.finished = true;
    }

    #[test]
    fn forgets_exact_name_cleanup() {
        let (mut runner, _cli) = test_runner(Vec::new());

        runner.track_sandbox("ct-0123456789-01");
        runner.forget_sandbox("ct-0123456789-01");

        assert!(runner.known_sandboxes.is_empty());
        runner.finished = true;
    }

    #[tokio::test]
    async fn finish_deletes_explicitly_tracked_resources() {
        let (mut runner, cli) = test_runner(vec![MockResponse::success("")]);
        runner.track_sandbox("ct-0123456789-01");

        runner
            .finish(Ok(()))
            .await
            .expect("owned resource cleanup should succeed");

        assert_eq!(
            cli.invocations(),
            vec![vec![
                "sandbox".to_string(),
                "delete".to_string(),
                "ct-0123456789-01".to_string(),
            ]]
        );
    }

    #[test]
    fn functional_failure_remains_primary_when_cleanup_also_fails() {
        let error = combine_results(
            Err("functional failure".to_string()),
            Err("cleanup failure".to_string()),
        )
        .expect_err("combined result should fail");

        assert!(error.starts_with("functional failure"));
        assert!(error.contains("secondary cleanup failure:\ncleanup failure"));
    }

    #[test]
    fn generated_run_id_is_portable_and_compact() {
        let run_id = generate_run_id();
        assert_eq!(run_id.len(), 10);
        assert!(
            run_id
                .chars()
                .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        );
    }

    #[test]
    fn sanitizes_sensitive_cli_arguments() {
        let command = sanitized_command(&[
            "provider".to_string(),
            "create".to_string(),
            "--credential".to_string(),
            "TOKEN=secret".to_string(),
            "--client-secret=hunter2".to_string(),
        ]);

        assert!(!command.contains("TOKEN=secret"));
        assert!(!command.contains("hunter2"));
        assert!(command.contains("<redacted>"));
    }
}
