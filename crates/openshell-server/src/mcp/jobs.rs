// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Background jobs for the `exec` and `wait` tools: one job per child at a
//! time, its state kept only in the child, under [`JOBS_ROOT`].
//!
//! Every step is a short `ExecSandbox` running [`JOBS_SCRIPT`]. The agent's
//! command reaches the script as arguments, which the gateway shell-escapes
//! like any exec argument; it is never part of the script text.

use super::{
    Call, CapturedOutput, ExecArgs, OUTPUT_EDGE_BYTES, Refusal, ToolError, arguments_object,
    run_in_child,
};
use openshell_core::proto::ExecSandboxRequest;
use serde_json::{Value, json};
use std::time::Duration;

const JOBS_SCRIPT: &str = include_str!("jobs.sh");
/// Where jobs live in a child. The default policy lets `/tmp` be written.
const JOBS_ROOT: &str = "/tmp/openshell/jobs";
/// Limit for each short exec that starts, checks or reads a job.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// How long past a step's limit the tool waits for its exit event.
const STEP_GRACE: Duration = Duration::from_secs(2);
const DEFAULT_WAIT_S: u64 = 30;
/// Polling stops by 40 s. With one last check's grace and a full output read
/// after it, a call still ends well inside the door's 60 s limit.
pub(super) const MAX_WAIT_S: u64 = 40;
const WAIT_POLL: Duration = Duration::from_secs(2);
/// A check needs at least this long; with less left, `wait` answers
/// "running" without one, and the caller calls again.
const MIN_CHECK: Duration = Duration::from_secs(1);

/// A job handle, `<n>-<token>`: `n` numbers the job in its child and
/// `token` is the gateway's, so an old handle never matches a newer job.
struct JobHandle {
    n: u32,
    token: String,
}

impl JobHandle {
    fn parse(handle: &str) -> Option<Self> {
        let (n, token) = handle.split_once('-')?;
        let n_ok = (1..=9).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit());
        let token_ok = token.len() == 8
            && token
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !(n_ok && token_ok) {
            return None;
        }
        Some(Self {
            n: n.parse().ok()?,
            token: token.to_string(),
        })
    }

    fn render(&self) -> String {
        format!("{}-{}", self.n, self.token)
    }
}

/// Start `args.command` as the child's background job and return its handle.
pub(super) async fn start(call: &Call<'_>, args: ExecArgs) -> Result<Value, ToolError> {
    let token = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let has_stdin = if args.stdin.is_empty() { "0" } else { "1" };
    let mut command = script_command("start");
    command.extend([token.clone(), has_stdin.to_string()]);
    command.extend(args.command);
    let request = ExecSandboxRequest {
        sandbox: args.name.clone(),
        command,
        workdir: args.workdir,
        stdin: args.stdin,
        ..Default::default()
    };
    let outcome = run_in_child(call, request, STEP_TIMEOUT, STEP_GRACE).await?;
    let stdout = outcome.stdout.into_bytes();
    let line = String::from_utf8_lossy(&stdout);
    let words: Vec<&str> = line.split_whitespace().collect();
    match (outcome.exit, words.as_slice()) {
        (Some((0, _)), ["started", n]) => {
            let handle = JobHandle {
                n: n.parse().map_err(|_| step_failed("start", &line))?,
                token,
            };
            Ok(json!({"job": handle.render(), "state": "running"}))
        }
        (Some((0, _)), ["busy", n, rest @ ..]) => Err(ToolError::Refused(Refusal {
            code: "failed_precondition",
            message: format!(
                "a job is already running in '{}' (job {n}-{}); wait for it, or delete the child to stop it",
                args.name,
                rest.first().unwrap_or(&"")
            ),
            retryable: false,
            withheld: None,
        })),
        (Some((0, _)), ["unusable", cause]) => Err(ToolError::Refused(Refusal {
            code: "failed_precondition",
            message: unusable_message(cause, &args.name),
            retryable: false,
            withheld: None,
        })),
        _ => {
            let stderr = outcome.stderr.into_bytes();
            Err(step_failed("start", &String::from_utf8_lossy(&stderr)))
        }
    }
}

/// Wait up to `timeout_s` for a job, checking every [`WAIT_POLL`]; a job
/// still running at the end is not an error.
pub(super) async fn wait(call: &Call<'_>, arguments: &Value) -> Result<Value, ToolError> {
    let (name, handle, timeout) = parse_wait_args(arguments)?;
    wait_with(
        &handle,
        timeout,
        |remaining| check(call, &name, &handle, remaining),
        |out_bytes, err_bytes| output(call, &name, &handle, out_bytes, err_bytes),
        || job_not_found(&name, &handle),
    )
    .await
}

/// The polling loop of [`wait`]. Each check is limited to what is left of
/// the wait, and none starts with less than [`MIN_CHECK`] left. The output
/// read keeps its own limit, so a job that finishes just before the end
/// still returns its output.
async fn wait_with<C, CF, O, OF>(
    handle: &JobHandle,
    timeout: Duration,
    mut check: C,
    output: O,
    not_found: impl FnOnce() -> ToolError,
) -> Result<Value, ToolError>
where
    C: FnMut(Duration) -> CF,
    CF: Future<Output = Result<JobState, ToolError>>,
    O: FnOnce(usize, usize) -> OF,
    OF: Future<Output = Result<(CapturedOutput, CapturedOutput), ToolError>>,
{
    let still_running = || {
        json!({
            "job": handle.render(),
            "state": "running",
            "message": "the job is still running; call wait again",
        })
    };
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining < MIN_CHECK {
            return Ok(still_running());
        }
        let state = check(remaining).await?;
        let reply = match state {
            JobState::Running => {
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                if left <= WAIT_POLL {
                    return Ok(still_running());
                }
                tokio::time::sleep(WAIT_POLL).await;
                continue;
            }
            JobState::Lost => json!({
                "job": handle.render(),
                "state": "lost",
                "message": "the job stopped without an exit code: it was killed, or the child restarted",
            }),
            JobState::Missing => return Err(not_found()),
            JobState::Completed {
                exit_code,
                out_bytes,
                err_bytes,
            } => {
                let (stdout, stderr) = output(out_bytes, err_bytes).await?;
                let (stdout, stdout_truncated, stdout_binary) = stdout.render();
                let (stderr, stderr_truncated, stderr_binary) = stderr.render();
                json!({
                    "job": handle.render(),
                    "state": "completed",
                    "exit_code": exit_code,
                    "stdout": stdout,
                    "stderr": stderr,
                    "stdout_truncated": stdout_truncated,
                    "stderr_truncated": stderr_truncated,
                    "binary_output": stdout_binary || stderr_binary,
                })
            }
        };
        return Ok(reply);
    }
}

fn parse_wait_args(arguments: &Value) -> Result<(String, JobHandle, Duration), ToolError> {
    let args = arguments_object(arguments)?;
    let name = super::required_name(&args, &["name", "job", "timeout_s"])?;
    let handle = args
        .get("job")
        .and_then(Value::as_str)
        .and_then(JobHandle::parse)
        .ok_or_else(|| ToolError::invalid("'job' must be a job id returned by exec"))?;
    let timeout_s = match args.get("timeout_s") {
        None => DEFAULT_WAIT_S,
        Some(value) => value
            .as_u64()
            .filter(|timeout| (1..=MAX_WAIT_S).contains(timeout))
            .ok_or_else(|| ToolError::invalid("'timeout_s' must be between 1 and 40"))?,
    };
    Ok((name, handle, Duration::from_secs(timeout_s)))
}

#[derive(Debug, PartialEq, Eq)]
enum JobState {
    Running,
    Completed {
        exit_code: i32,
        out_bytes: usize,
        err_bytes: usize,
    },
    Lost,
    Missing,
}

impl JobState {
    fn parse(line: &str) -> Option<Self> {
        let words: Vec<&str> = line.split_whitespace().collect();
        Some(match words.as_slice() {
            ["running"] => Self::Running,
            ["lost"] => Self::Lost,
            ["missing"] => Self::Missing,
            ["completed", exit_code, out_bytes, err_bytes] => Self::Completed {
                exit_code: exit_code.parse().ok()?,
                out_bytes: out_bytes.parse().ok()?,
                err_bytes: err_bytes.parse().ok()?,
            },
            _ => return None,
        })
    }
}

/// The limit of one check: what is left of the wait, at most a step's.
fn check_limit(remaining: Duration) -> Duration {
    remaining.min(STEP_TIMEOUT)
}

/// One check of a job, limited to what is left of the caller's wait.
async fn check(
    call: &Call<'_>,
    name: &str,
    handle: &JobHandle,
    remaining: Duration,
) -> Result<JobState, ToolError> {
    let mut command = script_command("check");
    command.extend([handle.n.to_string(), handle.token.clone()]);
    let request = ExecSandboxRequest {
        sandbox: name.to_string(),
        command,
        ..Default::default()
    };
    let outcome = run_in_child(call, request, check_limit(remaining), STEP_GRACE).await?;
    let stdout = outcome.stdout.into_bytes();
    let line = String::from_utf8_lossy(&stdout);
    if let Some((0, _)) = outcome.exit {
        return JobState::parse(&line).ok_or_else(|| step_failed("check", &line));
    }
    let stderr = outcome.stderr.into_bytes();
    Err(step_failed("check", &String::from_utf8_lossy(&stderr)))
}

/// The edges of a finished job's output. Only the bytes the reply keeps
/// leave the child.
async fn output(
    call: &Call<'_>,
    name: &str,
    handle: &JobHandle,
    out_bytes: usize,
    err_bytes: usize,
) -> Result<(CapturedOutput, CapturedOutput), ToolError> {
    let mut command = script_command("output");
    command.extend([
        handle.n.to_string(),
        handle.token.clone(),
        OUTPUT_EDGE_BYTES.to_string(),
    ]);
    let request = ExecSandboxRequest {
        sandbox: name.to_string(),
        command,
        ..Default::default()
    };
    let outcome = run_in_child(call, request, STEP_TIMEOUT, STEP_GRACE).await?;
    match outcome.exit {
        Some((0, _)) => Ok((
            CapturedOutput::from_edges(&outcome.stdout.into_bytes(), out_bytes),
            CapturedOutput::from_edges(&outcome.stderr.into_bytes(), err_bytes),
        )),
        // A newer job replaced it between the check and this read.
        Some((3, _)) => Err(job_not_found(name, handle)),
        _ => {
            let stderr = outcome.stderr.into_bytes();
            Err(step_failed("output", &String::from_utf8_lossy(&stderr)))
        }
    }
}

fn script_command(action: &str) -> Vec<String> {
    ["sh", "-c", JOBS_SCRIPT, "sh", action, JOBS_ROOT]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn job_not_found(name: &str, handle: &JobHandle) -> ToolError {
    ToolError::Refused(Refusal {
        code: "not_found",
        message: format!(
            "job '{}' not found in '{name}': a newer job replaced it, or the child restarted",
            handle.render()
        ),
        retryable: false,
        withheld: None,
    })
}

/// Why a child cannot run background jobs, by the cause the script named.
fn unusable_message(cause: &str, name: &str) -> String {
    let need = match cause {
        "tmp" => "a writable /tmp; a child uses its parent's filesystem policy",
        "proc" => "a readable /proc; a child uses its parent's filesystem policy",
        _ => "the stat command; use an image that has it",
    };
    format!("background jobs need {need} (in '{name}')")
}

/// A job step that did not answer as the script does: the child's own words,
/// cut short, since they are the child's data.
fn step_failed(step: &str, detail: &str) -> ToolError {
    ToolError::Refused(Refusal {
        code: "unavailable",
        message: format!(
            "the job {step} step failed in the child: {}",
            super::truncate_at_char_boundary(detail.trim(), 200)
        ),
        retryable: true,
        withheld: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completed() -> JobState {
        JobState::Completed {
            exit_code: 0,
            out_bytes: 2,
            err_bytes: 0,
        }
    }

    fn captured_ok() -> (CapturedOutput, CapturedOutput) {
        (
            CapturedOutput::from_edges(b"ok", 2),
            CapturedOutput::from_edges(b"", 0),
        )
    }

    /// The slowest cases: every check takes its whole limit plus the grace,
    /// and the read after the last one takes its whole limit plus the grace.
    /// Whenever the job finishes, the call ends inside the door's 60 s and a
    /// finished job's output is returned.
    #[tokio::test(start_paused = true)]
    async fn a_wait_stays_under_the_door_limit_whenever_the_job_finishes() {
        let handle = JobHandle::parse("1-0a1b2c3d").unwrap();
        let wait = Duration::from_secs(MAX_WAIT_S);
        for half_seconds in 0..=(MAX_WAIT_S * 2 + 4) {
            let started = tokio::time::Instant::now();
            let finishes_at = started + Duration::from_millis(half_seconds * 500);
            let short_check = std::cell::Cell::new(false);

            let reply = wait_with(
                &handle,
                wait,
                |remaining| {
                    short_check.set(short_check.get() || remaining < MIN_CHECK);
                    async move {
                        tokio::time::sleep(check_limit(remaining) + STEP_GRACE).await;
                        Ok(if tokio::time::Instant::now() >= finishes_at {
                            completed()
                        } else {
                            JobState::Running
                        })
                    }
                },
                |_, _| async {
                    tokio::time::sleep(STEP_TIMEOUT + STEP_GRACE).await;
                    Ok(captured_ok())
                },
                || panic!("not missing"),
            )
            .await
            .unwrap_or_else(|_| panic!("wait failed"));

            let took = started.elapsed();
            assert!(
                took < Duration::from_secs(58),
                "finish at {half_seconds}/2 s took {took:?}"
            );
            assert!(
                !short_check.get(),
                "a check started with less than a second left"
            );
            if reply["state"] == "completed" {
                assert_eq!(reply["stdout"], "ok", "the output is returned");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_with_too_little_time_left_answers_running_without_a_check() {
        let handle = JobHandle::parse("1-0a1b2c3d").unwrap();
        let checks = std::cell::Cell::new(0);

        let reply = wait_with(
            &handle,
            Duration::from_secs(3),
            |_| {
                checks.set(checks.get() + 1);
                // Each check uses up 2.5 s, so after the first only 0.5 s
                // is left.
                async {
                    tokio::time::sleep(Duration::from_millis(2500)).await;
                    Ok(JobState::Running)
                }
            },
            |_, _| async { Ok(captured_ok()) },
            || panic!("not missing"),
        )
        .await
        .unwrap_or_else(|_| panic!("wait failed"));

        assert_eq!(reply["state"], "running");
        assert_eq!(checks.get(), 1, "no check with less than a second left");
    }

    #[test]
    fn each_unusable_cause_has_its_own_message() {
        let tmp = unusable_message("tmp", "w1");
        let proc = unusable_message("proc", "w1");
        let stat = unusable_message("stat", "w1");
        assert!(
            tmp.contains("need a writable /tmp") && !tmp.contains("/proc"),
            "{tmp}"
        );
        assert!(
            proc.contains("need a readable /proc") && !proc.contains("/tmp"),
            "{proc}"
        );
        assert!(stat.contains("the stat command"), "{stat}");
        assert!(tmp.ends_with("(in 'w1')"));
    }

    #[test]
    fn handles_are_checked_before_use() {
        let handle = JobHandle::parse("12-0a1b2c3d").unwrap();
        assert_eq!((handle.n, handle.token.as_str()), (12, "0a1b2c3d"));
        assert_eq!(handle.render(), "12-0a1b2c3d");
        for bad in [
            "",
            "12",
            "12-0A1B2C3D",
            "12-0a1b2c3",
            "-0a1b2c3d",
            "1234567890-0a1b2c3d",
            "1;rm-0a1b2c3d",
            "12-0a1b2c3d-x",
        ] {
            assert!(JobHandle::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn check_lines_are_read_exactly() {
        assert_eq!(JobState::parse("running\n"), Some(JobState::Running));
        assert_eq!(JobState::parse("lost"), Some(JobState::Lost));
        assert_eq!(JobState::parse("missing"), Some(JobState::Missing));
        // busybox may pad wc's count.
        assert_eq!(
            JobState::parse("completed 7 3   4\n"),
            Some(JobState::Completed {
                exit_code: 7,
                out_bytes: 3,
                err_bytes: 4
            })
        );
        assert_eq!(JobState::parse("completed 7 3"), None);
        assert_eq!(JobState::parse("sh: not found"), None);
    }

    #[tokio::test]
    async fn wait_refuses_bad_arguments() {
        for (arguments, message) in [
            (
                json!({"name": "w"}),
                "'job' must be a job id returned by exec",
            ),
            (
                json!({"name": "w", "job": "1-zzzzzzzz"}),
                "'job' must be a job id returned by exec",
            ),
            (
                json!({"name": "w", "job": "1-0a1b2c3d", "timeout_s": 46}),
                "'timeout_s' must be between 1 and 40",
            ),
            (
                json!({"name": "w", "job": "1-0a1b2c3d", "lines": 3}),
                "unknown argument 'lines'",
            ),
        ] {
            let Err(ToolError::Refused(refusal)) = parse_wait_args(&arguments) else {
                panic!("{arguments} must be refused");
            };
            assert_eq!(refusal.message, message);
        }
    }

    /// The script's own scenarios (`jobs_test.sh`), on the test machine's
    /// `sh`: start returns at once, running then completed, a second start
    /// refused, racing starts, a killed job and a reused pid read as lost,
    /// the claim window, capped output, stdin, quoting, unwritable root.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_job_script_passes_its_scenarios() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mcp");
        let output = std::process::Command::new("sh")
            .arg(dir.join("jobs_test.sh"))
            .arg(dir.join("jobs.sh"))
            .output()
            .unwrap();
        let report = String::from_utf8_lossy(&output.stdout);
        assert!(report.trim_end().ends_with("ALL OK"), "{report}");
    }
}
