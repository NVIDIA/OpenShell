// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use crate::lima::LimaProvider;
use crate::vm::{Arch, ComputeDriver, GuestOs, ProvisionOptions, VmInstance, VmProvider, VmSpec};

const INSTALL_PODMAN_ROOTLESS_SCRIPT: &str = include_str!("../scripts/install-podman-rootless.sh");
const RELEASE_SMOKE_UBUNTU_PODMAN_ROOTLESS_SCRIPT: &str =
    include_str!("../scripts/release-smoke/ubuntu-podman-rootless.sh");
const GUEST_RELEASE_ARTIFACT_PATH: &str = "/tmp/openshell-release.deb";

pub fn run(args: impl Iterator<Item = OsString>) -> Result<ExitStatus, String> {
    let command = ReleaseSmokeTestCommand::parse(args)?;
    release_smoke_test(&LimaProvider, &command)
}

struct ReleaseSmokeTestCommand {
    deb: PathBuf,
    arch: Option<Arch>,
    keep_vm: bool,
    rebuild_vm: bool,
    snapshot: bool,
    guest_os: GuestOs,
}

impl ReleaseSmokeTestCommand {
    fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Self, String> {
        let mut deb = None;
        let mut arch = None;
        let mut keep_vm = false;
        let mut rebuild_vm = false;
        let mut snapshot = false;
        let mut guest_os = None;

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
                Some("--arch") => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--arch requires a value".to_owned())?;
                    if arch.replace(parse_arch(&value)?).is_some() {
                        return Err("--arch may only be specified once".to_owned());
                    }
                }
                Some("--guest-os") => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--guest-os requires a value".to_owned())?;
                    if guest_os.replace(parse_guest_os(&value)?).is_some() {
                        return Err("--guest-os may only be specified once".to_owned());
                    }
                }
                Some("--keep-vm") => keep_vm = true,
                Some("--rebuild-vm") => rebuild_vm = true,
                Some("--snapshot") => snapshot = true,
                Some(value) => return Err(format!("unknown release-smoke-test option: {value}")),
                None => return Err("release-smoke-test options must be valid UTF-8".to_owned()),
            }
        }

        if rebuild_vm && !snapshot {
            return Err("--rebuild-vm requires --snapshot".to_owned());
        }

        Ok(Self {
            deb: deb.ok_or_else(|| "release-smoke-test requires --deb <path>".to_owned())?,
            arch,
            keep_vm,
            rebuild_vm,
            snapshot,
            guest_os: guest_os.unwrap_or(GuestOs::new("ubuntu", "26.04")),
        })
    }
}

fn parse_arch(value: &OsStr) -> Result<Arch, String> {
    match value.to_str() {
        Some("amd64" | "x86_64") => Ok(Arch::Amd64),
        Some("arm64" | "aarch64") => Ok(Arch::Arm64),
        Some(value) => Err(format!("unsupported architecture: {value}")),
        None => Err("--arch must be valid UTF-8".to_owned()),
    }
}

fn parse_guest_os(value: &OsStr) -> Result<GuestOs, String> {
    match value.to_str() {
        Some("ubuntu-24.04") => Ok(GuestOs::new("ubuntu", "24.04")),
        Some("ubuntu-26.04") => Ok(GuestOs::new("ubuntu", "26.04")),
        Some(value) => Err(format!(
            "unsupported guest OS: {value} (expected ubuntu-24.04 or ubuntu-26.04)"
        )),
        None => Err("--guest-os must be valid UTF-8".to_owned()),
    }
}

fn release_smoke_test<P: VmProvider>(
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

    let arch = command.arch.unwrap_or_else(|| infer_deb_arch(&deb));
    let spec = VmSpec {
        guest_os: command.guest_os,
        arch,
        compute_driver: ComputeDriver::PodmanRootless,
    };
    let setup_script = compute_driver_setup_script(spec.compute_driver);
    let vm = provider.provision(
        spec,
        ProvisionOptions {
            snapshot: command.snapshot,
            rebuild: command.rebuild_vm,
        },
        setup_script,
    )?;

    println!("==> Testing {} with {}", deb.display(), vm.name());
    let test_script = release_smoke_guest_script(spec)?;

    let test_result = (|| {
        vm.copy_file(&deb, GUEST_RELEASE_ARTIFACT_PATH)?;
        vm.run_script(&test_script, "release smoke test")
    })();

    if command.keep_vm {
        eprintln!("VM kept for inspection: {}", vm.name());
        return test_result;
    }

    let cleanup_result = vm.cleanup();
    match (test_result, cleanup_result) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(error), _) => Err(error),
        (Ok(status), Err(error)) if status.success() => Err(error),
        (Ok(status), Err(error)) => {
            eprintln!("warning: {error}");
            Ok(status)
        }
    }
}

fn compute_driver_setup_script(compute_driver: ComputeDriver) -> &'static str {
    match compute_driver {
        ComputeDriver::PodmanRootless => INSTALL_PODMAN_ROOTLESS_SCRIPT,
    }
}

fn release_smoke_guest_script(spec: VmSpec) -> Result<String, String> {
    match (spec.guest_os.distribution, spec.compute_driver) {
        ("ubuntu", ComputeDriver::PodmanRootless) => Ok(format!(
            "export OPENSHELL_RELEASE_ARTIFACT={GUEST_RELEASE_ARTIFACT_PATH}\n\
             {RELEASE_SMOKE_UBUNTU_PODMAN_ROOTLESS_SCRIPT}"
        )),
        (distribution, ComputeDriver::PodmanRootless) => Err(format!(
            "unsupported release smoke test combination: {distribution}-{} with rootless Podman",
            spec.guest_os.version
        )),
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

    #[test]
    fn parses_release_smoke_test_options() {
        let command = ReleaseSmokeTestCommand::parse(
            [
                "--deb",
                "artifacts/openshell_1.2.3_arm64.deb",
                "--arch",
                "arm64",
                "--keep-vm",
                "--rebuild-vm",
                "--snapshot",
                "--guest-os",
                "ubuntu-26.04",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .expect("command should parse");

        assert_eq!(
            command.deb,
            PathBuf::from("artifacts/openshell_1.2.3_arm64.deb")
        );
        assert_eq!(command.arch, Some(Arch::Arm64));
        assert!(command.keep_vm);
        assert!(command.rebuild_vm);
        assert!(command.snapshot);
        assert_eq!(command.guest_os, GuestOs::new("ubuntu", "26.04"));
    }

    #[test]
    fn release_smoke_test_requires_deb() {
        let error = ReleaseSmokeTestCommand::parse(std::iter::empty())
            .err()
            .expect("missing --deb should fail");

        assert!(error.contains("requires --deb"));
    }

    #[test]
    fn release_smoke_test_defaults_to_latest_ubuntu() {
        let command = ReleaseSmokeTestCommand::parse(
            ["--deb", "artifacts/openshell_1.2.3_arm64.deb"]
                .into_iter()
                .map(OsString::from),
        )
        .expect("command should parse");

        assert_eq!(command.guest_os, GuestOs::new("ubuntu", "26.04"));
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
        let script = release_smoke_guest_script(VmSpec {
            guest_os: GuestOs::new("ubuntu", "26.04"),
            arch: Arch::Arm64,
            compute_driver: ComputeDriver::PodmanRootless,
        })
        .expect("ubuntu podman rootless smoke test should be supported");

        assert!(script.contains("Creating a sandbox and verifying default-deny networking"));
        assert!(script.contains("Installing Ubuntu release artifact"));
        assert!(script.contains("export OPENSHELL_RELEASE_ARTIFACT=/tmp/openshell-release.deb"));
    }

    #[test]
    fn rejects_unsupported_release_smoke_combinations() {
        let error = release_smoke_guest_script(VmSpec {
            guest_os: GuestOs::new("fedora", "42"),
            arch: Arch::Arm64,
            compute_driver: ComputeDriver::PodmanRootless,
        })
        .expect_err("fedora release smoke test should not be supported yet");

        assert!(error.contains("fedora-42 with rootless Podman"));
    }
}
