// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, ExitStatus};

use crate::machine::{
    DEFAULT_MACHINE_OS, MachineOptions, MachineOptionsBuilder, MachineProvider, MachineRequest,
};
use crate::platform::{Arch, MachineOs, OsFamily, parse_machine_os};
use crate::tasks::{TaskResult, exit_code, print_help_if_requested};

const RELEASE_SMOKE_UBUNTU_PODMAN_ROOTLESS_SCRIPT: &str =
    include_str!("../scripts/release-smoke/ubuntu-podman-rootless.sh");
const UBUNTU_OS_SETUP: &str = include_str!("../scripts/machine/os/ubuntu.sh");
const UBUNTU_PODMAN_SETUP: &str = include_str!("../scripts/machine/suites/podman/ubuntu.sh");
const COMMON_PODMAN_SETUP: &str = include_str!("../scripts/machine/suites/podman/common.sh");
const GUEST_RELEASE_ARTIFACT_PATH: &str = "/tmp/openshell-release.deb";
const HELP: &str = "Test a Debian release artifact on a target machine.

Usage:
  cargo xtask release-smoke-test --deb <path> [--provider <lima>] [--arch <amd64|arm64>] [--os <ubuntu-24.04|ubuntu-26.04>] [--snapshot] [--rebuild-machine] [--keep-machine]

Defaults:
  --provider lima
  --os ubuntu-26.04";

pub fn run(args: impl Iterator<Item = OsString>) -> TaskResult {
    let mut args = args.peekable();
    if print_help_if_requested(&mut args, HELP) {
        return Ok(ExitCode::SUCCESS);
    }

    let command = ReleaseSmokeTestCommand::parse(args)?;
    release_smoke_test(&command.machine.provider, &command).map(exit_code)
}

struct ReleaseSmokeTestCommand {
    deb: PathBuf,
    machine: MachineOptions,
}

impl ReleaseSmokeTestCommand {
    fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Self, String> {
        let mut deb = None;
        let mut machine = MachineOptionsBuilder::default();
        let mut os = None;

        while let Some(argument) = args.next() {
            match argument.to_str() {
                Some("--deb") => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--deb requires a path".to_owned())?;
                    if deb.replace(PathBuf::from(value)).is_some() {
                        return Err("--deb may only be specified once".to_owned());
                    }
                }
                Some("--os") => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--os requires a value".to_owned())?;
                    if os.replace(parse_machine_os(&value, "--os")?).is_some() {
                        return Err("--os may only be specified once".to_owned());
                    }
                }
                Some(value) if machine.parse_argument(value, &mut args)? => {}
                Some(value) => return Err(format!("unknown release-smoke-test option: {value}")),
                None => return Err("release-smoke-test options must be valid UTF-8".to_owned()),
            }
        }

        let os = os.unwrap_or(DEFAULT_MACHINE_OS);
        if !matches!(os.family(), OsFamily::Ubuntu) {
            return Err(format!(
                "release-smoke-test does not support --os {} (expected ubuntu-24.04 or ubuntu-26.04)",
                os.id()
            ));
        }

        Ok(Self {
            deb: deb.ok_or_else(|| "release-smoke-test requires --deb <path>".to_owned())?,
            machine: machine
                .finish(Some(os))?
                .expect("release smoke tests always request a target machine"),
        })
    }
}

fn release_smoke_test<P: MachineProvider>(
    provider: &P,
    command: &ReleaseSmokeTestCommand,
) -> Result<ExitStatus, String> {
    let deb = command.deb.canonicalize().map_err(|error| {
        format!(
            "cannot read Debian artifact {}: {error}",
            command.deb.display()
        )
    })?;
    if !deb.is_file() {
        return Err(format!("Debian artifact is not a file: {}", deb.display()));
    }

    let options = &command.machine;
    let arch = options.arch.unwrap_or_else(|| infer_deb_arch(&deb));
    let setup_script = release_setup_script(options.os)?;
    let test_script = release_smoke_guest_script(options.os)?;
    let machine = provider.acquire(
        MachineRequest {
            os: options.os,
            arch,
            purpose: "smoke",
            profile: "podman-rl",
            forward_env: Vec::new(),
            keep_on_failure: options.keep,
            reuse: options.reuse_policy(0),
            host_mounts: Vec::new(),
            persistent_disks: Vec::new(),
        },
        &setup_script,
    )?;

    println!("==> Testing {} with {}", deb.display(), machine.name());

    let test_result = (|| {
        machine.copy_file(&deb, GUEST_RELEASE_ARTIFACT_PATH)?;
        machine.run_script(&test_script, "release smoke test")
    })();

    if options.keep {
        eprintln!("Machine kept for inspection: {}", machine.name());
        return test_result;
    }

    let release_result = machine.release();
    match (test_result, release_result) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(release_error)) => {
            Err(format!("{error}; release also failed: {release_error}"))
        }
        (Ok(status), Err(error)) if status.success() => Err(error),
        (Ok(status), Err(error)) => {
            eprintln!("warning: {error}");
            Ok(status)
        }
    }
}

fn release_smoke_guest_script(os: MachineOs) -> Result<String, String> {
    match os.family() {
        OsFamily::CentosStream => Err(format!(
            "release-smoke-test does not support --os {}",
            os.id()
        )),
        OsFamily::Ubuntu => Ok(format!(
            "export OPENSHELL_RELEASE_ARTIFACT={GUEST_RELEASE_ARTIFACT_PATH}\n\
             {RELEASE_SMOKE_UBUNTU_PODMAN_ROOTLESS_SCRIPT}"
        )),
    }
}

fn release_setup_script(os: MachineOs) -> Result<String, String> {
    match os.family() {
        OsFamily::CentosStream => Err(format!(
            "release-smoke-test does not support --os {}",
            os.id()
        )),
        OsFamily::Ubuntu => {
            Ok([UBUNTU_OS_SETUP, UBUNTU_PODMAN_SETUP, COMMON_PODMAN_SETUP].join("\n"))
        }
    }
}

fn infer_deb_arch(path: &Path) -> Arch {
    let filename = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
    if filename.ends_with("_arm64.deb") || filename.ends_with("-arm64.deb") {
        return Arch::Arm64;
    }
    if filename.ends_with("_amd64.deb") || filename.ends_with("-amd64.deb") {
        return Arch::Amd64;
    }

    match env::consts::ARCH {
        "aarch64" => Arch::Arm64,
        _ => Arch::Amd64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::Provider;

    #[test]
    fn parses_release_smoke_test_options() {
        let command = ReleaseSmokeTestCommand::parse(
            [
                "--deb",
                "artifacts/openshell_1.2.3_arm64.deb",
                "--provider",
                "lima",
                "--arch",
                "arm64",
                "--keep-machine",
                "--rebuild-machine",
                "--snapshot",
                "--os",
                "ubuntu-24.04",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .expect("command should parse");

        assert_eq!(
            command.deb,
            PathBuf::from("artifacts/openshell_1.2.3_arm64.deb")
        );
        assert_eq!(command.machine.arch, Some(Arch::Arm64));
        assert!(command.machine.keep);
        assert_eq!(command.machine.provider, Provider::Lima);
        assert!(command.machine.rebuild);
        assert!(command.machine.snapshot);
        assert_eq!(command.machine.os, MachineOs::Ubuntu24_04);
    }

    #[test]
    fn release_smoke_test_requires_deb() {
        let error = ReleaseSmokeTestCommand::parse(std::iter::empty())
            .err()
            .expect("missing --deb should fail");

        assert!(error.contains("requires --deb"));
    }

    #[test]
    fn release_smoke_test_rejects_non_ubuntu_targets() {
        let error = ReleaseSmokeTestCommand::parse(
            [
                "--deb",
                "artifacts/openshell_1.2.3_arm64.deb",
                "--os",
                "centos-stream-10",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .err()
        .expect("Debian release tests should reject CentOS Stream");

        assert!(error.contains("release-smoke-test does not support --os centos-stream-10"));
    }

    #[test]
    fn release_smoke_test_defaults_to_ubuntu_26_04() {
        let command = ReleaseSmokeTestCommand::parse(
            ["--deb", "artifacts/openshell_1.2.3_arm64.deb"]
                .into_iter()
                .map(OsString::from),
        )
        .expect("command should parse");

        assert_eq!(command.machine.provider, Provider::Lima);
        assert_eq!(command.machine.os, MachineOs::Ubuntu26_04);
    }

    #[test]
    fn infers_debian_architecture_from_artifact_name() {
        assert_eq!(
            infer_deb_arch(Path::new("openshell_1.2.3_arm64.deb")),
            Arch::Arm64
        );
        assert_eq!(
            infer_deb_arch(Path::new("openshell_1.2.3_amd64.deb")),
            Arch::Amd64
        );
    }

    #[test]
    fn selects_the_release_smoke_script_by_os_and_driver() {
        let script = release_smoke_guest_script(MachineOs::Ubuntu24_04)
            .expect("Ubuntu release smoke test should be supported");

        assert!(script.contains("Creating a sandbox and verifying default-deny networking"));
        assert!(script.contains("Installing Ubuntu release artifact"));
        assert!(script.contains("export OPENSHELL_RELEASE_ARTIFACT=/tmp/openshell-release.deb"));
    }
}
