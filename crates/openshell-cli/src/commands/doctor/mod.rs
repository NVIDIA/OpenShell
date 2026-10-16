// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Orchestration for runtime and system prerequisite checks.

mod docker;
mod process;

use futures::future::BoxFuture;
use miette::{IntoDiagnostic, Result};
use std::io::Write;

use process::command_output;

/// A prerequisite provider owns its checks and actionable diagnostics.
/// Additional runtimes can register providers without changing the runner.
trait PrerequisiteCheck: Sync {
    fn run<'a>(&'a self, out: &'a mut (dyn Write + Send)) -> BoxFuture<'a, Result<()>>;
}

pub async fn doctor_check() -> Result<()> {
    let docker = docker::DockerCheck::new();
    let checks: [&dyn PrerequisiteCheck; 1] = [&docker];
    // Do not hold a stdout lock across asynchronous commands.
    run_checks(&checks, &mut std::io::stdout()).await
}

async fn run_checks(checks: &[&dyn PrerequisiteCheck], out: &mut (dyn Write + Send)) -> Result<()> {
    writeln!(out, "Checking system prerequisites...\n").into_diagnostic()?;
    for check in checks {
        check.run(out).await?;
    }
    writeln!(out, "\nAll checks passed.").into_diagnostic()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCheck {
        name: &'static str,
        fails: bool,
    }

    impl PrerequisiteCheck for TestCheck {
        fn run<'a>(&'a self, out: &'a mut (dyn Write + Send)) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                writeln!(out, "{}", self.name).into_diagnostic()?;
                if self.fails {
                    return Err(miette::miette!("{} unavailable", self.name));
                }
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn runner_accepts_multiple_prerequisite_providers() {
        let first = TestCheck {
            name: "first",
            fails: false,
        };
        let second = TestCheck {
            name: "second",
            fails: false,
        };
        let mut out = Vec::new();
        run_checks(&[&first, &second], &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("first\nsecond\n"));
        assert!(text.contains("All checks passed"));
    }

    #[tokio::test]
    async fn failing_provider_prevents_success_summary() {
        let check = TestCheck {
            name: "runtime",
            fails: true,
        };
        let mut out = Vec::new();
        let error = run_checks(&[&check], &mut out).await.unwrap_err();
        assert!(error.to_string().contains("runtime unavailable"));
        assert!(
            !String::from_utf8(out)
                .unwrap()
                .contains("All checks passed")
        );
    }
}
