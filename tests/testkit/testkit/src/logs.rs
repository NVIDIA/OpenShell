// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A sandbox's supervisor logs, as `openshell logs --source sandbox` shows
//! them.

use std::fmt;
use std::time::Duration;

use openshell_sdk::raw::proto;

use crate::context::Sandbox;
use crate::error::{Result, ResultExt as _};
use crate::poll::{Poll, poll_until};

/// The most lines [`Sandbox::logs`] returns, as `openshell logs -n 500`.
const LINES: u32 = 500;
/// How long [`Sandbox::logs_until`] waits. The supervisor pushes its logs to
/// the gateway in batches, so a line can appear a few seconds after the event.
pub const LOGS_TIMEOUT: Duration = Duration::from_secs(10);

/// Log lines from a sandbox's supervisor, oldest first.
#[derive(Debug, Clone, Default)]
pub struct Logs {
    lines: Vec<proto::SandboxLogLine>,
}

impl Logs {
    pub fn new(lines: Vec<proto::SandboxLogLine>) -> Self {
        Self { lines }
    }

    pub fn lines(&self) -> &[proto::SandboxLogLine] {
        &self.lines
    }

    /// Whether a line contains `needle` in its level, target, message, or a
    /// field name or value, as `openshell logs` prints the line.
    pub fn contains(&self, needle: &str) -> bool {
        self.lines
            .iter()
            .any(|line| Line(line).to_string().contains(needle))
    }
}

/// One line per log line, as `openshell logs` prints them.
impl fmt::Display for Logs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for line in &self.lines {
            writeln!(f, "{}", Line(line))?;
        }
        Ok(())
    }
}

/// `[<secs>.<millis>] [<source>] [<level>] [<target>] <message> <k=v ...>`,
/// with fields sorted by name.
struct Line<'a>(&'a proto::SandboxLogLine);

impl fmt::Display for Line<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let line = self.0;
        let source = if line.source.is_empty() {
            "gateway"
        } else {
            &line.source
        };
        let (secs, millis) = line.event_time.as_ref().map_or((0, 0), |time| {
            (time.seconds, time.nanos.clamp(0, 999_999_999) / 1_000_000)
        });
        write!(
            f,
            "[{secs}.{millis:03}] [{source:<7}] [{:<5}] [{}] {}",
            line.level, line.target, line.message
        )?;
        let mut fields: Vec<_> = line.fields.iter().collect();
        fields.sort_by_key(|(key, _)| key.as_str());
        for (key, value) in fields {
            write!(f, " {key}={value}")?;
        }
        Ok(())
    }
}

impl Sandbox {
    /// The last 500 lines the sandbox's supervisor logged, as `openshell logs
    /// <name> -n 500 --source sandbox` returns them.
    pub async fn logs(&self) -> Result<Logs> {
        let grpc = self.handles().grpc();
        let request = proto::GetSandboxLogsRequest {
            sandbox: self.name().to_string(),
            workspace_scope: grpc.scope(),
            lines: LINES,
            sources: vec!["sandbox".to_string()],
            ..proto::GetSandboxLogsRequest::default()
        };
        let response = grpc
            .client()
            .await?
            .get_sandbox_logs(request)
            .await
            .context(format!("get logs of sandbox {}", self.name()))?
            .into_inner();
        Ok(Logs::new(response.logs))
    }

    /// Read [`Sandbox::logs`] every 250 ms until `ready` accepts them, for up
    /// to [`LOGS_TIMEOUT`]. A timeout reports the last logs read.
    pub async fn logs_until(&self, what: &str, ready: impl Fn(&Logs) -> bool) -> Result<Logs> {
        poll_until(
            &format!("sandbox {} to log {what}", self.name()),
            LOGS_TIMEOUT,
            Duration::from_millis(250),
            async || {
                let logs = self.logs().await?;
                Ok(if ready(&logs) {
                    Poll::Ready(logs)
                } else {
                    Poll::Pending(format!("logs:\n{logs}"))
                })
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(message: &str, source: &str, fields: &[(&str, &str)]) -> proto::SandboxLogLine {
        proto::SandboxLogLine {
            event_time: Some(prost_types::Timestamp {
                seconds: 1234,
                nanos: 567_000_000,
            }),
            level: "INFO".to_string(),
            target: "openshell_supervisor".to_string(),
            message: message.to_string(),
            source: source.to_string(),
            fields: fields
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            ..proto::SandboxLogLine::default()
        }
    }

    #[test]
    fn renders_lines_like_the_cli() {
        let logs = Logs::new(vec![
            line("hello world", "sandbox", &[]),
            line("denied", "", &[("dst_port", "443"), ("action", "deny")]),
        ]);
        assert_eq!(
            logs.to_string(),
            "[1234.567] [sandbox] [INFO ] [openshell_supervisor] hello world\n\
             [1234.567] [gateway] [INFO ] [openshell_supervisor] denied action=deny dst_port=443\n"
        );
    }

    #[test]
    fn contains_searches_message_target_and_fields_per_line() {
        let logs = Logs::new(vec![
            line("first", "sandbox", &[("event", "endpoint_mismatch")]),
            line("second", "sandbox", &[]),
        ]);
        assert!(logs.contains("first"));
        assert!(logs.contains("openshell_supervisor"));
        assert!(logs.contains("event=endpoint_mismatch"));
        assert!(logs.contains("endpoint_mismatch"));
        assert!(!logs.contains("first\n"), "a needle doesn't span lines");
        assert!(!logs.contains("absent"));
    }
}
