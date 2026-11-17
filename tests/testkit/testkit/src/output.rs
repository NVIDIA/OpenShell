// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The checks [`ExecOutput`](crate::ExecOutput) and
//! [`CliOutput`](crate::CliOutput) share, so both report failures the same
//! way.

use crate::error::Result;

/// A finished command, as the checks see it.
pub(crate) struct Outcome<'a> {
    /// The command, as failure messages name it.
    pub(crate) what: &'a str,
    pub(crate) exit_code: i32,
    pub(crate) stdout: &'a str,
    pub(crate) stderr: &'a str,
}

impl Outcome<'_> {
    pub(crate) fn success(&self) -> Result {
        crate::ensure!(
            self.exit_code == 0,
            "{} exited with {}; stdout: {}; stderr: {}",
            self.what,
            self.exit_code,
            self.stdout.trim(),
            self.stderr.trim()
        );
        Ok(())
    }

    pub(crate) fn failure(&self) -> Result {
        crate::ensure!(
            self.exit_code != 0,
            "{} succeeded but was expected to fail; stdout: {}; stderr: {}",
            self.what,
            self.stdout.trim(),
            self.stderr.trim()
        );
        Ok(())
    }

    pub(crate) fn stdout_is(&self, expected: &str) -> Result {
        self.success()?;
        crate::ensure!(
            self.stdout == expected,
            "{} printed {:?}; expected {expected:?}",
            self.what,
            self.stdout
        );
        Ok(())
    }
}
