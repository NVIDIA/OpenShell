// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use crate::vm::{Arch, ComputeDriver, ProvisionOptions, VmInstance, VmProvider, VmSpec};

const BASE_SNAPSHOT: &str = "base-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Default,
    Qemu,
}

impl Backend {
    const fn name(self) -> &'static str {
        match self {
            Self::Default => "def",
            Self::Qemu => "qemu",
        }
    }

    const fn lima(self) -> Option<&'static str> {
        match self {
            Self::Default => None,
            Self::Qemu => Some("qemu"),
        }
    }
}

fn instance_name(spec: VmSpec, backend: Backend, ephemeral: bool) -> String {
    let arch = match spec.arch {
        Arch::Amd64 => "amd64",
        Arch::Arm64 => "arm64",
    };
    let compute_driver = match spec.compute_driver {
        ComputeDriver::PodmanRootless => "podman-rl",
    };
    let guest = format!(
        "{}{}",
        spec.guest_os.distribution,
        spec.guest_os.version.replace('.', "")
    );
    let base = format!("os-{guest}-{arch}-{}-{compute_driver}", backend.name());
    if ephemeral {
        format!("{base}-{}", std::process::id())
    } else {
        base
    }
}

pub struct LimaProvider;

pub struct LimaVm {
    name: String,
    reusable: bool,
}

impl VmProvider for LimaProvider {
    type Instance = LimaVm;

    fn provision(
        &self,
        spec: VmSpec,
        options: ProvisionOptions,
        setup_script: &str,
    ) -> Result<Self::Instance, String> {
        checked(
            Command::new("limactl").arg("--version"),
            "check the Lima installation",
        )?;

        let qemu_available = options.snapshot && driver_available("qemu")?;
        let reusable = options.snapshot && qemu_available;
        if options.snapshot && !qemu_available {
            eprintln!(
                "warning: QEMU is not available; using Lima's default backend without snapshots"
            );
        }

        let backend = if reusable {
            Backend::Qemu
        } else {
            Backend::Default
        };
        let name = instance_name(spec, backend, !reusable);

        prepare_instance(
            &name,
            spec,
            backend,
            options.rebuild,
            reusable,
            setup_script,
        )?;
        Ok(LimaVm { name, reusable })
    }
}

impl VmInstance for LimaVm {
    fn name(&self) -> &str {
        &self.name
    }

    fn copy_file(&self, source: &Path, destination: &str) -> Result<(), String> {
        let guest_path = format!("{}:{destination}", self.name);
        checked(
            Command::new("limactl")
                .args(["--tty=false", "copy", "--backend=scp"])
                .arg(source)
                .arg(guest_path),
            "copy a file into Lima",
        )
    }

    fn run_script(&self, script: &str, description: &str) -> Result<ExitStatus, String> {
        run_guest_script(&self.name, script, description)
    }

    fn cleanup(&self) -> Result<(), String> {
        if self.reusable {
            stop_instance(&self.name)
        } else {
            delete_instance(&self.name, "delete the Lima test instance")
        }
    }
}

fn prepare_instance(
    instance: &str,
    spec: VmSpec,
    backend: Backend,
    rebuild: bool,
    use_snapshot: bool,
    setup_script: &str,
) -> Result<(), String> {
    let status = instance_status(instance)?;
    let can_restore = use_snapshot
        && !rebuild
        && matches!(status.as_deref(), Some("Running" | "Stopped"))
        && snapshot_exists(instance, BASE_SNAPSHOT)?;

    if can_restore {
        stop_instance(instance)?;
        println!("==> Restoring Lima snapshot {BASE_SNAPSHOT}");
        checked(
            Command::new("limactl").args([
                "--tty=false",
                "snapshot",
                "apply",
                instance,
                "--tag",
                BASE_SNAPSHOT,
            ]),
            "restore the Lima test snapshot",
        )?;
    } else {
        if status.is_some() {
            println!("==> Rebuilding Lima instance {instance}");
            delete_instance(instance, "delete the stale Lima test instance")?;
        }

        start_new_instance(instance, spec, backend)?;
        let setup_status = run_guest_script(instance, setup_script, "VM setup")?;
        if !setup_status.success() {
            return Err(format!(
                "VM setup failed with exit code {}",
                display_exit_code(setup_status)
            ));
        }

        if use_snapshot {
            stop_instance(instance)?;
            println!("==> Creating Lima snapshot {BASE_SNAPSHOT}");
            checked(
                Command::new("limactl").args([
                    "--tty=false",
                    "snapshot",
                    "create",
                    instance,
                    "--tag",
                    BASE_SNAPSHOT,
                ]),
                "create the Lima test snapshot",
            )?;
        } else {
            return Ok(());
        }
    }

    checked(
        Command::new("limactl").args(["--tty=false", "start", instance]),
        "start the prepared Lima test instance",
    )
}

fn start_new_instance(instance: &str, spec: VmSpec, backend: Backend) -> Result<(), String> {
    println!("==> Creating Lima instance {instance}");
    let arch = match spec.arch {
        Arch::Amd64 => "x86_64",
        Arch::Arm64 => "aarch64",
    };
    let lima_template = format!(
        "template:{}-{}",
        spec.guest_os.distribution, spec.guest_os.version
    );
    let mut process = Command::new("limactl");
    process.args([
        "--tty=false",
        "start",
        "--plain",
        "--name",
        instance,
        "--arch",
        arch,
        "--cpus",
        "4",
        "--memory",
        "8",
        "--disk",
        "30",
    ]);
    if let Some(vm_type) = backend.lima() {
        process.args(["--vm-type", vm_type]);
    }
    process.arg(lima_template);
    checked(&mut process, "create the Lima test instance")
}

fn driver_available(driver: &str) -> Result<bool, String> {
    let output = Command::new("limactl")
        .args(["start", "--list-drivers"])
        .output()
        .map_err(|error| format!("failed to list Lima VM drivers: {error}"))?;
    if !output.status.success() {
        return Err("failed to list Lima VM drivers".to_owned());
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|available| available.trim() == driver))
}

fn instance_status(instance: &str) -> Result<Option<String>, String> {
    let output = Command::new("limactl")
        .args(["list", "--format", "{{.Name}}\t{{.Status}}"])
        .output()
        .map_err(|error| format!("failed to inspect Lima instance {instance}: {error}"))?;
    if !output.status.success() {
        return Err(format!("failed to inspect Lima instance {instance}"));
    }

    Ok(parse_instance_status(&output.stdout, instance))
}

fn parse_instance_status(output: &[u8], instance: &str) -> Option<String> {
    String::from_utf8_lossy(output).lines().find_map(|line| {
        let (name, status) = line.split_once('\t')?;
        (name == instance).then(|| status.to_owned())
    })
}

fn snapshot_exists(instance: &str, tag: &str) -> Result<bool, String> {
    let output = Command::new("limactl")
        .args(["snapshot", "list", instance, "--quiet"])
        .output()
        .map_err(|error| format!("failed to list Lima snapshots for {instance}: {error}"))?;
    if !output.status.success() {
        return Err(format!("failed to list Lima snapshots for {instance}"));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|snapshot| snapshot.trim() == tag))
}

fn stop_instance(instance: &str) -> Result<(), String> {
    if instance_status(instance)?.as_deref() != Some("Running") {
        return Ok(());
    }

    checked(
        Command::new("limactl").args(["--tty=false", "stop", instance]),
        "stop the Lima test instance",
    )
}

fn delete_instance(instance: &str, description: &str) -> Result<(), String> {
    checked(
        Command::new("limactl").args(["--tty=false", "delete", "--force", instance]),
        description,
    )
}

fn run_guest_script(instance: &str, script: &str, description: &str) -> Result<ExitStatus, String> {
    let mut child = Command::new("limactl")
        .args(["--tty=false", "shell", instance, "bash", "-s"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start the Lima guest {description}: {error}"))?;

    child
        .stdin
        .take()
        .ok_or_else(|| "failed to open stdin for the Lima guest command".to_owned())?
        .write_all(script.as_bytes())
        .map_err(|error| format!("failed to send the {description} to Lima: {error}"))?;

    child
        .wait()
        .map_err(|error| format!("failed to wait for the Lima guest {description}: {error}"))
}

fn checked(command: &mut Command, description: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|error| format!("failed to execute {description}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{description} failed with exit code {}",
            display_exit_code(status)
        ))
    }
}

fn display_exit_code(status: ExitStatus) -> String {
    status
        .code()
        .map_or_else(|| "signal".to_owned(), |code| code.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::GuestOs;

    #[test]
    fn names_the_vm_for_its_environment() {
        let spec = VmSpec {
            guest_os: GuestOs::new("ubuntu", "24.04"),
            arch: Arch::Arm64,
            compute_driver: ComputeDriver::PodmanRootless,
        };

        assert_eq!(
            instance_name(spec, Backend::Qemu, false),
            "os-ubuntu2404-arm64-qemu-podman-rl"
        );
        assert!(
            instance_name(spec, Backend::Qemu, true)
                .starts_with("os-ubuntu2404-arm64-qemu-podman-rl-")
        );
    }

    #[test]
    fn leaves_room_for_lima_socket_paths() {
        let spec = VmSpec {
            guest_os: GuestOs::new("ubuntu", "26.04"),
            arch: Arch::Arm64,
            compute_driver: ComputeDriver::PodmanRootless,
        };

        // Lima appends a PID and temporary socket suffix beneath ~/.lima. Keep
        // the stable portion bounded so common macOS home paths remain below
        // UNIX_PATH_MAX even with a ten-digit PID.
        assert!(instance_name(spec, Backend::Default, false).len() <= 40);
    }

    #[test]
    fn parses_matching_instance_status() {
        let output = b"other\tStopped\nos-ubuntu2404-arm64-qemu-podman-rl\tRunning\n";
        assert_eq!(
            parse_instance_status(output, "os-ubuntu2404-arm64-qemu-podman-rl"),
            Some("Running".to_owned())
        );
        assert_eq!(parse_instance_status(output, "missing"), None);
    }
}
