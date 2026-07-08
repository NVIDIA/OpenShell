// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineOs {
    Ubuntu24_04,
    Ubuntu26_04,
}

impl MachineOs {
    pub const fn id(self) -> &'static str {
        match self {
            Self::Ubuntu24_04 => "ubuntu-24.04",
            Self::Ubuntu26_04 => "ubuntu-26.04",
        }
    }
}

pub fn parse_machine_os(value: &OsStr, option: &str) -> Result<MachineOs, String> {
    match value.to_str() {
        Some("ubuntu-24.04") => Ok(MachineOs::Ubuntu24_04),
        Some("ubuntu-26.04") => Ok(MachineOs::Ubuntu26_04),
        Some(value) => Err(format!(
            "unsupported machine OS: {value} (expected ubuntu-24.04 or ubuntu-26.04)"
        )),
        None => Err(format!("{option} must be valid UTF-8")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_target_operating_systems() {
        assert_eq!(
            parse_machine_os(OsStr::new("ubuntu-24.04"), "--os"),
            Ok(MachineOs::Ubuntu24_04)
        );
        assert_eq!(
            parse_machine_os(OsStr::new("ubuntu-26.04"), "--os"),
            Ok(MachineOs::Ubuntu26_04)
        );
    }

    #[test]
    fn rejects_unsupported_target_operating_systems() {
        let error = parse_machine_os(OsStr::new("debian-13"), "--os")
            .expect_err("unsupported machine OS should fail");
        assert!(error.contains("unsupported machine OS: debian-13"));
        assert!(error.contains("expected ubuntu-24.04 or ubuntu-26.04"));
    }
}
