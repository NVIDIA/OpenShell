// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use crate::platform::{Arch, MachineOs};

pub const DEFAULT_MACHINE_OS: MachineOs = MachineOs::Ubuntu26_04;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Provider {
    #[default]
    Lima,
}

impl Provider {
    pub fn parse(value: &OsStr) -> Result<Self, String> {
        match value.to_str() {
            Some("lima") => Ok(Self::Lima),
            Some(value) => Err(format!(
                "unsupported machine provider: {value} (expected lima)"
            )),
            None => Err("--provider must be valid UTF-8".to_owned()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReusePolicy {
    Ephemeral,
    ReusePrepared { rebuild: bool, preparation_key: u32 },
}

impl ReusePolicy {
    pub const fn enabled(self) -> bool {
        matches!(self, Self::ReusePrepared { .. })
    }

    pub const fn rebuild(self) -> bool {
        match self {
            Self::Ephemeral => false,
            Self::ReusePrepared { rebuild, .. } => rebuild,
        }
    }

    pub const fn preparation_key(self) -> u32 {
        match self {
            Self::Ephemeral => 0,
            Self::ReusePrepared {
                preparation_key, ..
            } => preparation_key,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineOptions {
    pub arch: Option<Arch>,
    pub keep: bool,
    pub provider: Provider,
    pub rebuild: bool,
    pub snapshot: bool,
    pub os: MachineOs,
}

impl MachineOptions {
    pub const fn reuse_policy(&self, preparation_key: u32) -> ReusePolicy {
        if self.snapshot {
            ReusePolicy::ReusePrepared {
                rebuild: self.rebuild,
                preparation_key,
            }
        } else {
            ReusePolicy::Ephemeral
        }
    }
}

#[derive(Default)]
pub struct MachineOptionsBuilder {
    arch: Option<Arch>,
    keep: bool,
    provider: Option<Provider>,
    rebuild: bool,
    snapshot: bool,
}

impl MachineOptionsBuilder {
    pub fn parse_argument(
        &mut self,
        argument: &str,
        args: &mut impl Iterator<Item = OsString>,
    ) -> Result<bool, String> {
        match argument {
            "--arch" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--arch requires a value".to_owned())?;
                if self
                    .arch
                    .replace(crate::platform::parse_arch(&value)?)
                    .is_some()
                {
                    return Err("--arch may only be specified once".to_owned());
                }
            }
            "--provider" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--provider requires a value".to_owned())?;
                if self.provider.replace(Provider::parse(&value)?).is_some() {
                    return Err("--provider may only be specified once".to_owned());
                }
            }
            "--keep-machine" => self.keep = true,
            "--rebuild-machine" => self.rebuild = true,
            "--snapshot" => self.snapshot = true,
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub fn finish(self, os: Option<MachineOs>) -> Result<Option<MachineOptions>, String> {
        let os = match os {
            Some(os) => os,
            None if self.provider.is_some() => DEFAULT_MACHINE_OS,
            None => {
                let option = if self.arch.is_some() {
                    Some("--arch")
                } else if self.keep {
                    Some("--keep-machine")
                } else if self.rebuild {
                    Some("--rebuild-machine")
                } else if self.snapshot {
                    Some("--snapshot")
                } else {
                    None
                };
                return option.map_or(Ok(None), |option| {
                    Err(format!("{option} requires --os or --provider"))
                });
            }
        };

        if self.rebuild && !self.snapshot {
            return Err("--rebuild-machine requires --snapshot".to_owned());
        }

        Ok(Some(MachineOptions {
            arch: self.arch,
            keep: self.keep,
            provider: self.provider.unwrap_or_default(),
            rebuild: self.rebuild,
            snapshot: self.snapshot,
            os,
        }))
    }
}

pub(crate) fn path_hash(path: &Path) -> u32 {
    // FNV-1a keeps mounted-worktree names stable across processes and Rust
    // versions without pulling a hashing dependency into xtask.
    path.as_os_str()
        .as_encoded_bytes()
        .iter()
        .fold(0x811c9dc5_u32, |hash, byte| {
            (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
        })
}

pub(crate) fn stable_hash(parts: &[&[u8]]) -> u32 {
    parts.iter().fold(0x811c9dc5_u32, |hash, part| {
        let hash = part.iter().fold(hash, |hash, byte| {
            (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
        });
        (hash ^ 0xff).wrapping_mul(0x01000193)
    })
}

#[derive(Debug, Clone)]
pub struct MachineRequest {
    pub os: MachineOs,
    pub arch: Arch,
    pub purpose: &'static str,
    pub profile: &'static str,
    pub forward_env: Vec<&'static str>,
    pub keep_on_failure: bool,
    pub reuse: ReusePolicy,
    pub host_mounts: Vec<HostMount>,
    pub persistent_disks: Vec<PersistentDisk>,
}

pub(crate) fn hash_request_resources(hash: u32, request: &MachineRequest) -> u32 {
    let hash = request.host_mounts.iter().fold(hash, |hash, mount| {
        let hash = mount
            .path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .fold(hash, |hash, byte| {
                (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
            });
        [u8::from(mount.writable), 0xff]
            .iter()
            .fold(hash, |hash, byte| {
                (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
            })
    });
    request.persistent_disks.iter().fold(hash, |hash, disk| {
        let hash =
            [&disk.name, &disk.size, disk.filesystem]
                .into_iter()
                .fold(hash, |hash, value| {
                    let hash = value.as_bytes().iter().fold(hash, |hash, byte| {
                        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
                    });
                    (hash ^ 0xfe).wrapping_mul(0x01000193)
                });
        (hash ^ 0xff).wrapping_mul(0x01000193)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMount {
    pub path: PathBuf,
    pub writable: bool,
}

impl HostMount {
    pub fn read_only(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            writable: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentDisk {
    pub name: String,
    pub size: String,
    pub filesystem: &'static str,
}

impl PersistentDisk {
    pub fn ext4(name: impl Into<String>, size: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            size: size.into(),
            filesystem: "ext4",
        }
    }
}

pub trait MachineProvider {
    fn persistent_disk_mount_point(&self, disk: &PersistentDisk) -> String;

    fn acquire(
        &self,
        request: MachineRequest,
        setup_script: &str,
    ) -> Result<Box<dyn Machine>, String>;
}

pub trait Machine {
    fn name(&self) -> &str;

    fn copy_file(&self, source: &Path, destination: &str) -> Result<(), String>;

    fn run_script(&self, script: &str, description: &str) -> Result<ExitStatus, String>;

    fn release(&self) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_defaults_the_machine_provider() {
        assert_eq!(Provider::default(), Provider::Lima);
        assert_eq!(Provider::parse(OsStr::new("lima")), Ok(Provider::Lima));
        assert!(Provider::parse(OsStr::new("cloud")).is_err());
    }

    #[test]
    fn builds_shared_machine_options() {
        let options = MachineOptionsBuilder::default()
            .finish(Some(MachineOs::Ubuntu24_04))
            .expect("default machine options should be valid")
            .expect("an OS should produce machine options");

        assert_eq!(options.arch, None);
        assert_eq!(options.provider, Provider::Lima);
        assert_eq!(options.os, MachineOs::Ubuntu24_04);
        assert_eq!(options.reuse_policy(42), ReusePolicy::Ephemeral);
    }

    #[test]
    fn a_provider_uses_the_default_machine_target() {
        let builder = MachineOptionsBuilder {
            provider: Some(Provider::Lima),
            ..Default::default()
        };

        let options = builder
            .finish(None)
            .expect("provider-only machine options should be valid")
            .expect("a provider should request a machine");

        assert_eq!(options.os, MachineOs::Ubuntu26_04);
    }

    #[test]
    fn rebuilding_a_machine_requires_snapshots() {
        let builder = MachineOptionsBuilder {
            rebuild: true,
            ..Default::default()
        };

        let error = builder
            .finish(Some(MachineOs::Ubuntu24_04))
            .expect_err("rebuilding without snapshots should fail");
        assert!(error.contains("--rebuild-machine requires --snapshot"));
    }

    #[test]
    fn exposes_semantic_machine_reuse() {
        assert!(!ReusePolicy::Ephemeral.enabled());
        assert!(!ReusePolicy::Ephemeral.rebuild());
        assert_eq!(ReusePolicy::Ephemeral.preparation_key(), 0);

        let reuse = ReusePolicy::ReusePrepared {
            rebuild: true,
            preparation_key: 42,
        };
        assert!(reuse.enabled());
        assert!(reuse.rebuild());
        assert_eq!(reuse.preparation_key(), 42);
    }

    #[test]
    fn stable_hash_separates_inputs() {
        assert_ne!(stable_hash(&[b"ab", b"c"]), stable_hash(&[b"a", b"bc"]));
    }
}
