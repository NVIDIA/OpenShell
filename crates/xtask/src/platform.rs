// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Amd64,
    Arm64,
}

pub fn parse_arch(value: &OsStr) -> Result<Arch, String> {
    match value.to_str() {
        Some("amd64" | "x86_64") => Ok(Arch::Amd64),
        Some("arm64" | "aarch64") => Ok(Arch::Arm64),
        Some(value) => Err(format!("unsupported architecture: {value}")),
        None => Err("--arch must be valid UTF-8".to_owned()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    CentosStream,
    Ubuntu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineOs {
    CentosStream10,
    Ubuntu24_04,
    Ubuntu26_04,
}

impl MachineOs {
    pub const fn id(self) -> &'static str {
        match self {
            Self::CentosStream10 => "centos-stream-10",
            Self::Ubuntu24_04 => "ubuntu-24.04",
            Self::Ubuntu26_04 => "ubuntu-26.04",
        }
    }

    pub const fn short_name(self) -> &'static str {
        match self {
            Self::CentosStream10 => "centos10",
            Self::Ubuntu24_04 => "ubuntu2404",
            Self::Ubuntu26_04 => "ubuntu2604",
        }
    }

    pub const fn family(self) -> OsFamily {
        match self {
            Self::CentosStream10 => OsFamily::CentosStream,
            Self::Ubuntu24_04 | Self::Ubuntu26_04 => OsFamily::Ubuntu,
        }
    }
}

pub fn parse_machine_os(value: &OsStr, option: &str) -> Result<MachineOs, String> {
    match value.to_str() {
        Some("centos-stream-10") => Ok(MachineOs::CentosStream10),
        Some("ubuntu-24.04") => Ok(MachineOs::Ubuntu24_04),
        Some("ubuntu-26.04") => Ok(MachineOs::Ubuntu26_04),
        Some(value) => Err(format!(
            "unsupported machine OS: {value} (expected centos-stream-10, ubuntu-24.04, or ubuntu-26.04)"
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
            parse_machine_os(OsStr::new("centos-stream-10"), "--os"),
            Ok(MachineOs::CentosStream10)
        );
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
        assert!(error.contains("expected centos-stream-10, ubuntu-24.04, or ubuntu-26.04"));
    }
}
