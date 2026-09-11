// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone policy maximum checker.

#[cfg(not(unix))]
use std::fs::File;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use openshell_prover::containment::{
    CheckOptions, CheckResult, CheckScope, ContainmentPolicy, Counterexample, parse_policy_str,
};
use serde::Serialize;

const MAX_POLICY_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "openshell-prover",
    about = "Verify OpenShell policy boundaries",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check whether a candidate policy is contained within a maximum policy.
    Check {
        /// Fully composed effective candidate policy.
        candidate: PathBuf,
        /// Operator-owned maximum policy.
        #[arg(long, value_name = "FILE")]
        maximum: PathBuf,
        /// Result output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
        /// Solver time budget (integer followed by ms, s, or m).
        #[arg(long, default_value = "10s", value_parser = parse_duration)]
        timeout: Duration,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Serialize)]
struct Envelope<'a> {
    schema_version: u32,
    prover_version: &'static str,
    check: &'static str,
    scope: Option<ScopeJson<'a>>,
    result: &'static str,
    exit_code: u8,
    inputs: InputsJson,
    counterexample: Option<CounterexampleJson<'a>>,
    reason_code: Option<&'a str>,
    reason: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct ScopeJson<'a> {
    model_version: &'a str,
    policy_version: u32,
    domains: Vec<&'a str>,
    assumptions: &'a [&'a str],
}

#[derive(Debug, Serialize)]
struct InputsJson {
    candidate: String,
    maximum: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "domain", rename_all = "snake_case")]
enum CounterexampleJson<'a> {
    Filesystem {
        access: &'a str,
        path: &'a str,
    },
    Network {
        binary: Option<&'a str>,
        ancestor_binary: Option<&'a str>,
        binary_identity_required: bool,
        host: &'a str,
        port: u16,
        protocol: &'a str,
        method: Option<&'a str>,
        path: Option<&'a str>,
    },
}

fn main() -> ExitCode {
    let cancelled = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    if let Err(error) =
        signal_hook::flag::register(signal_hook::consts::signal::SIGINT, Arc::clone(&cancelled))
    {
        let _ = writeln!(
            io::stderr().lock(),
            "openshell-prover: cannot install Ctrl-C handler: {error}"
        );
        return ExitCode::from(2);
    }
    let cli = Cli::parse();
    let outcome = cli
        .command
        .map_or_else(show_help, |command| execute(command, &cancelled));

    match outcome {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "openshell-prover: {error}");
            ExitCode::from(2)
        }
    }
}

fn show_help() -> Result<u8, String> {
    Cli::command()
        .print_help()
        .map_err(|error| format!("failed to write help: {error}"))?;
    writeln!(io::stdout().lock()).map_err(|error| format!("failed to write output: {error}"))?;
    Ok(0)
}

fn execute(command: Command, cancelled: &AtomicBool) -> Result<u8, String> {
    match command {
        Command::Check {
            candidate,
            maximum,
            output,
            timeout,
        } => check(&candidate, &maximum, output, timeout, cancelled),
    }
}

fn check(
    candidate_path: &Path,
    maximum_path: &Path,
    output: OutputFormat,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<u8, String> {
    let inputs = InputsJson {
        candidate: candidate_path.to_string_lossy().into_owned(),
        maximum: maximum_path.to_string_lossy().into_owned(),
    };

    let candidate_source = match read_policy(candidate_path) {
        Ok(source) => source,
        Err(error) => return render_input_error(output, inputs, &error),
    };
    if cancelled.load(Ordering::Relaxed) {
        return render_cancelled(output, inputs);
    }
    let maximum_source = match read_policy(maximum_path) {
        Ok(source) => source,
        Err(error) => return render_input_error(output, inputs, &error),
    };
    if cancelled.load(Ordering::Relaxed) {
        return render_cancelled(output, inputs);
    }
    let candidate = match parse_input("candidate", &candidate_source) {
        Ok(policy) => policy,
        Err(error) => return render_input_error(output, inputs, &error),
    };
    let maximum = match parse_input("maximum", &maximum_source) {
        Ok(policy) => policy,
        Err(error) => return render_input_error(output, inputs, &error),
    };
    if cancelled.load(Ordering::Relaxed) {
        return render_cancelled(output, inputs);
    }

    let result = openshell_prover::containment::check_within_maximum_cancellable(
        &maximum,
        &candidate,
        CheckOptions { timeout },
        cancelled,
    );
    let envelope = result_envelope(&result, inputs);
    render(output, &envelope)?;
    Ok(envelope.exit_code)
}

fn parse_input(label: &str, source: &str) -> Result<ContainmentPolicy, String> {
    parse_policy_str(source).map_err(|error| {
        format!(
            "invalid {label} policy: {}",
            escape_terminal(&error.to_string())
        )
    })
}

fn read_policy(path: &Path) -> Result<String, String> {
    // Reject unsupported inputs before opening them where possible. On Unix,
    // also use O_NONBLOCK to close the replacement race between this check and
    // open(): opening a FIFO must never hang the CLI before cancellation can be
    // observed. O_NONBLOCK has no effect on reads from regular files.
    let path_metadata = path.metadata().map_err(|error| {
        format!(
            "cannot open '{}': {error}",
            escape_terminal(&path.to_string_lossy())
        )
    })?;
    if !path_metadata.is_file() {
        return Err(format!(
            "policy path '{}' is not a regular file",
            escape_terminal(&path.to_string_lossy())
        ));
    }

    #[cfg(unix)]
    let open_result = {
        use std::os::unix::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(path)
    };
    #[cfg(not(unix))]
    let open_result = File::open(path);

    let mut file = open_result.map_err(|error| {
        format!(
            "cannot open '{}': {error}",
            escape_terminal(&path.to_string_lossy())
        )
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect policy file: {error}"))?;
    if !metadata.is_file() {
        return Err(format!(
            "policy path '{}' is not a regular file",
            escape_terminal(&path.to_string_lossy())
        ));
    }
    if metadata.len() > MAX_POLICY_BYTES {
        return Err(format!(
            "policy file exceeds the {MAX_POLICY_BYTES}-byte input limit"
        ));
    }

    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read policy file: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_POLICY_BYTES {
        return Err(format!(
            "policy file exceeds the {MAX_POLICY_BYTES}-byte input limit"
        ));
    }
    String::from_utf8(bytes).map_err(|_| "policy file is not valid UTF-8".to_owned())
}

fn render_input_error(
    output: OutputFormat,
    inputs: InputsJson,
    reason: &str,
) -> Result<u8, String> {
    if output == OutputFormat::Json {
        let envelope = Envelope {
            schema_version: 1,
            prover_version: env!("CARGO_PKG_VERSION"),
            check: "maximum_boundary",
            scope: None,
            result: "error",
            exit_code: 2,
            inputs,
            counterexample: None,
            reason_code: Some("invalid_input"),
            reason: Some(reason),
        };
        render(output, &envelope)?;
    } else {
        writeln!(io::stderr().lock(), "openshell-prover: {reason}")
            .map_err(|error| format!("failed to write diagnostic: {error}"))?;
    }
    Ok(2)
}

fn render_cancelled(output: OutputFormat, inputs: InputsJson) -> Result<u8, String> {
    let result = CheckResult::cancelled();
    let envelope = result_envelope(&result, inputs);
    render(output, &envelope)?;
    Ok(envelope.exit_code)
}

fn result_envelope(result: &CheckResult, inputs: InputsJson) -> Envelope<'_> {
    let (scope, result_name, exit_code, counterexample, reason_code, reason) = match result {
        CheckResult::Within(evidence) => (evidence.scope(), "within_max", 0, None, None, None),
        CheckResult::Exceeds(evidence) => (
            evidence.scope(),
            "exceeds_max",
            1,
            Some(counterexample_json(evidence.counterexample())),
            None,
            None,
        ),
        CheckResult::Unsupported(evidence) => (
            evidence.scope(),
            "unsupported",
            3,
            None,
            Some(evidence.reason_code().as_str()),
            Some(evidence.reason()),
        ),
        CheckResult::Inconclusive(evidence) => {
            let exit_code =
                if evidence.reason_code() == openshell_prover::containment::ReasonCode::Cancelled {
                    130
                } else {
                    3
                };
            (
                evidence.scope(),
                "inconclusive",
                exit_code,
                None,
                Some(evidence.reason_code().as_str()),
                Some(evidence.reason()),
            )
        }
    };
    Envelope {
        schema_version: 1,
        prover_version: env!("CARGO_PKG_VERSION"),
        check: "maximum_boundary",
        scope: Some(scope_json(scope)),
        result: result_name,
        exit_code,
        inputs,
        counterexample,
        reason_code,
        reason,
    }
}

fn scope_json(scope: &CheckScope) -> ScopeJson<'_> {
    ScopeJson {
        model_version: scope.model_version,
        policy_version: scope.policy_version,
        domains: scope.domains.iter().map(|domain| domain.as_str()).collect(),
        assumptions: scope.assumptions,
    }
}

fn counterexample_json(counterexample: &Counterexample) -> CounterexampleJson<'_> {
    match counterexample {
        Counterexample::Filesystem { access, path } => CounterexampleJson::Filesystem {
            access: access.as_str(),
            path,
        },
        Counterexample::Network {
            binary,
            ancestor_binary,
            binary_identity_required,
            host,
            port,
            protocol,
            method,
            path,
        } => CounterexampleJson::Network {
            binary: binary.as_deref(),
            ancestor_binary: ancestor_binary.as_deref(),
            binary_identity_required: *binary_identity_required,
            host,
            port: *port,
            protocol: protocol.as_str(),
            method: method.as_deref(),
            path: path.as_deref(),
        },
    }
}

fn render(output: OutputFormat, envelope: &Envelope<'_>) -> Result<(), String> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    match output {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut stdout, envelope)
                .map_err(|error| format!("failed to serialize result: {error}"))?;
            writeln!(stdout).map_err(|error| format!("failed to write output: {error}"))
        }
        OutputFormat::Text => render_text(&mut stdout, envelope),
    }
}

fn render_text(mut writer: impl Write, envelope: &Envelope<'_>) -> Result<(), String> {
    writeln!(writer, "result: {}", envelope.result)
        .map_err(|error| format!("failed to write output: {error}"))?;
    if let Some(scope) = &envelope.scope {
        writeln!(
            writer,
            "scope: model={} policy={} domains={}",
            escape_terminal(scope.model_version),
            scope.policy_version,
            scope.domains.join(",")
        )
        .map_err(|error| format!("failed to write output: {error}"))?;
        for assumption in scope.assumptions {
            writeln!(writer, "assumption: {}", escape_terminal(assumption))
                .map_err(|error| format!("failed to write output: {error}"))?;
        }
    }
    if let Some(counterexample) = &envelope.counterexample {
        match counterexample {
            CounterexampleJson::Filesystem { access, path } => writeln!(
                writer,
                "counterexample: filesystem {access} {}",
                escape_terminal(path)
            ),
            CounterexampleJson::Network {
                binary,
                ancestor_binary,
                binary_identity_required,
                host,
                port,
                protocol,
                method,
                path,
            } => writeln!(
                writer,
                "counterexample: network binary={} ancestor_binary={} binary_identity_required={} host={}:{} protocol={} method={} path={}",
                binary.map_or("-".to_owned(), escape_terminal),
                ancestor_binary.map_or("-".to_owned(), escape_terminal),
                binary_identity_required,
                escape_terminal(host),
                port,
                escape_terminal(protocol),
                method.map_or("-".to_owned(), escape_terminal),
                path.map_or("-".to_owned(), escape_terminal),
            ),
        }
        .map_err(|error| format!("failed to write output: {error}"))?;
    }
    if let Some(reason) = envelope.reason {
        writeln!(writer, "reason: {}", escape_terminal(reason))
            .map_err(|error| format!("failed to write output: {error}"))?;
    }
    Ok(())
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000)
    } else {
        return Err("duration must end in ms, s, or m".to_owned());
    };
    let amount = number
        .parse::<u64>()
        .map_err(|_| "duration must use a positive integer".to_owned())?;
    let millis = amount
        .checked_mul(multiplier)
        .ok_or_else(|| "duration is too large".to_owned())?;
    if millis == 0 {
        return Err("duration must be positive".to_owned());
    }
    if millis > u64::from(u32::MAX) {
        return Err(format!("duration must not exceed {}ms", u32::MAX));
    }
    Ok(Duration::from_millis(millis))
}

fn escape_terminal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    struct BrokenWriter;

    impl Write for BrokenWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn parses_supported_durations() {
        assert_eq!(parse_duration("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_duration("2s"), Ok(Duration::from_secs(2)));
        assert_eq!(parse_duration("3m"), Ok(Duration::from_mins(3)));
    }

    #[test]
    fn rejects_invalid_durations() {
        for value in ["0ms", "1", "1.5s", "-1s", "4294967296ms"] {
            assert!(parse_duration(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn escapes_terminal_control_characters() {
        assert_eq!(escape_terminal("a\u{1b}[31m\nb"), "a\\u{1b}[31m\\nb");
    }

    #[test]
    fn rejects_oversized_policy_before_parsing() {
        let path =
            std::env::temp_dir().join(format!("openshell-prover-oversized-{}", std::process::id()));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .expect("create oversized fixture");
        file.set_len(MAX_POLICY_BYTES + 1)
            .expect("size oversized fixture");
        drop(file);

        let error = read_policy(&path).expect_err("oversized input must fail");
        std::fs::remove_file(path).expect("remove oversized fixture");
        assert!(error.contains("input limit"));
    }

    #[test]
    fn output_failures_are_reported() {
        let envelope = Envelope {
            schema_version: 1,
            prover_version: env!("CARGO_PKG_VERSION"),
            check: "maximum_boundary",
            scope: None,
            result: "within_max",
            exit_code: 0,
            inputs: InputsJson {
                candidate: "candidate.yaml".to_owned(),
                maximum: "maximum.yaml".to_owned(),
            },
            counterexample: None,
            reason_code: None,
            reason: None,
        };
        assert!(render_text(BrokenWriter, &envelope).is_err());
    }
}
