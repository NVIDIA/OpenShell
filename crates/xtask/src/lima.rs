// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use crate::machine::{
    HostMount, Machine, MachineProvider, MachineRequest, PersistentDisk, hash_request_resources,
    stable_hash,
};
use crate::platform::{Arch, MachineOs};

const BASE_SNAPSHOT_VERSION: &str = "base-v5";

#[derive(Debug, Clone)]
struct AttachedDisk {
    request: PersistentDisk,
    format: bool,
}

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

fn instance_name(request: &MachineRequest, backend: Backend, ephemeral: bool) -> String {
    let arch = match request.arch {
        Arch::Amd64 => "amd64",
        Arch::Arm64 => "arm64",
    };
    let pid = ephemeral.then(|| std::process::id().to_string());
    let hash = stable_hash(&[
        request.os.id().as_bytes(),
        request.purpose.as_bytes(),
        request.profile.as_bytes(),
        arch.as_bytes(),
        backend.name().as_bytes(),
        pid.as_deref().unwrap_or_default().as_bytes(),
    ]);
    let hash = hash_request_resources(hash, request);
    format!(
        "openshell-{}-{}-{hash:08x}",
        request.purpose,
        request.os.id()
    )
}

fn lima_template(os: MachineOs) -> &'static str {
    match os {
        MachineOs::CentosStream10 => "template:centos-stream-10",
        MachineOs::Ubuntu24_04 => "template:ubuntu-24.04",
        MachineOs::Ubuntu26_04 => "template:ubuntu-26.04",
    }
}

fn snapshot_tag(request: &MachineRequest, setup_script: &str) -> String {
    let preparation_key = request.reuse.preparation_key().to_le_bytes();
    let template = lima_template(request.os);
    let hash = stable_hash(&[
        request.os.id().as_bytes(),
        template.as_bytes(),
        request.profile.as_bytes(),
        setup_script.as_bytes(),
        &preparation_key,
    ]);
    let hash = hash_request_resources(hash, request);
    format!("{BASE_SNAPSHOT_VERSION}-{hash:08x}")
}

pub struct LimaProvider;

struct LimaMachine {
    name: String,
    reusable: bool,
    forward_env: Vec<&'static str>,
}

impl MachineProvider for LimaProvider {
    fn persistent_disk_mount_point(&self, disk: &PersistentDisk) -> String {
        format!("/mnt/lima-{}", disk.name)
    }

    fn acquire(
        &self,
        request: MachineRequest,
        setup_script: &str,
    ) -> Result<Box<dyn Machine>, String> {
        checked(
            Command::new("limactl").arg("--version"),
            "check the Lima installation",
        )?;
        let disks = ensure_disks(&request.persistent_disks)?;

        let qemu_available = request.reuse.enabled() && driver_available("qemu")?;
        let reusable = request.reuse.enabled() && qemu_available;
        if request.reuse.enabled() && !qemu_available {
            eprintln!(
                "warning: QEMU is not available; using Lima's default backend without snapshots"
            );
        }

        let backend = if reusable {
            Backend::Qemu
        } else {
            Backend::Default
        };
        let name = instance_name(&request, backend, !reusable);

        prepare_instance(&name, &request, &disks, backend, reusable, setup_script)?;
        Ok(Box::new(LimaMachine {
            name,
            reusable,
            forward_env: request.forward_env,
        }))
    }
}

impl Machine for LimaMachine {
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
        run_guest_script(&self.name, script, description, &self.forward_env)
    }

    fn release(&self) -> Result<(), String> {
        if self.reusable {
            stop_instance(&self.name)
        } else {
            delete_instance(&self.name, "delete the Lima test instance")
        }
    }
}

fn prepare_instance(
    instance: &str,
    request: &MachineRequest,
    disks: &[AttachedDisk],
    backend: Backend,
    use_snapshot: bool,
    setup_script: &str,
) -> Result<(), String> {
    let snapshot = snapshot_tag(request, setup_script);
    let status = instance_status(instance)?;
    let can_restore = use_snapshot
        && !request.reuse.rebuild()
        && matches!(status.as_deref(), Some("Running" | "Stopped"))
        && snapshot_exists(instance, &snapshot)?;

    if can_restore {
        let result = restore_prepared_instance(instance, &snapshot);
        return finish_preparation(
            result,
            instance,
            request.keep_on_failure,
            &format!("Stopping Lima instance {instance} after failed snapshot restore"),
            || stop_instance(instance),
        );
    }

    if status.is_some() {
        println!("==> Rebuilding Lima instance {instance}");
        delete_instance(instance, "delete the stale Lima test instance")?;
    }

    let result = prepare_new_instance(
        instance,
        request,
        disks,
        backend,
        use_snapshot,
        setup_script,
        &snapshot,
    );
    finish_preparation(
        result,
        instance,
        request.keep_on_failure,
        &format!("Removing incomplete Lima instance {instance}"),
        || delete_instance_if_exists(instance),
    )
}

fn restore_prepared_instance(instance: &str, snapshot: &str) -> Result<(), String> {
    stop_instance(instance)?;
    println!("==> Restoring Lima snapshot {snapshot}");
    checked(
        Command::new("limactl")
            .args(["--tty=false", "snapshot", "apply", instance, "--tag"])
            .arg(snapshot),
        "restore the Lima test snapshot",
    )?;
    checked(
        Command::new("limactl").args(["--tty=false", "start", instance]),
        "start the prepared Lima test instance",
    )
}

fn prepare_new_instance(
    instance: &str,
    request: &MachineRequest,
    disks: &[AttachedDisk],
    backend: Backend,
    use_snapshot: bool,
    setup_script: &str,
    snapshot: &str,
) -> Result<(), String> {
    start_new_instance(instance, request, disks, backend)?;
    let setup_status = run_guest_script(instance, setup_script, "VM setup", &request.forward_env)?;
    if !setup_status.success() {
        return Err(format!(
            "VM setup failed with exit code {}",
            display_exit_code(setup_status)
        ));
    }

    if !use_snapshot {
        return Ok(());
    }

    stop_instance(instance)?;
    disable_disk_format(instance, disks)?;
    println!("==> Creating Lima snapshot {snapshot}");
    checked(
        Command::new("limactl")
            .args(["--tty=false", "snapshot", "create", instance, "--tag"])
            .arg(snapshot),
        "create the Lima test snapshot",
    )?;
    checked(
        Command::new("limactl").args(["--tty=false", "start", instance]),
        "start the prepared Lima test instance",
    )
}

fn finish_preparation<T>(
    result: Result<T, String>,
    instance: &str,
    keep_on_failure: bool,
    description: &str,
    cleanup: impl FnOnce() -> Result<(), String>,
) -> Result<T, String> {
    match result {
        Ok(value) => Ok(value),
        Err(error) if keep_on_failure => {
            eprintln!("VM kept for inspection after provisioning failure: {instance}");
            Err(error)
        }
        Err(error) => {
            eprintln!("==> {description}");
            match cleanup() {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!("{error}; cleanup also failed: {cleanup_error}")),
            }
        }
    }
}

fn delete_instance_if_exists(instance: &str) -> Result<(), String> {
    if instance_status(instance)?.is_none() {
        return Ok(());
    }
    delete_instance(instance, "delete the incomplete Lima test instance")
}

fn start_new_instance(
    instance: &str,
    request: &MachineRequest,
    disks: &[AttachedDisk],
    backend: Backend,
) -> Result<(), String> {
    println!("==> Creating Lima instance {instance}");
    let arch = match request.arch {
        Arch::Amd64 => "x86_64",
        Arch::Arm64 => "aarch64",
    };
    let mut process = Command::new("limactl");
    process.args([
        "--tty=false",
        "start",
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
    configure_mount_mode(&mut process, &request.host_mounts);
    configure_disks(&mut process, disks)?;
    process.arg(lima_template(request.os));
    checked(&mut process, "create the Lima test instance")
}

fn configure_mount_mode(process: &mut Command, host_mounts: &[HostMount]) {
    if host_mounts.is_empty() {
        process.arg("--plain");
    } else {
        // Plain mode disables the guest agent and therefore ignores host mounts.
        // Keep Lima-managed containerd disabled while enabling only the
        // explicitly requested development host mounts.
        process.args(["--containerd", "none"]);
        for mount in host_mounts {
            process.arg("--mount-only").arg(mount_argument(mount));
        }
    }
}

fn mount_argument(mount: &HostMount) -> OsString {
    let mut argument = mount.path.as_os_str().to_os_string();
    if mount.writable {
        argument.push(":w");
    }
    argument
}

fn ensure_disks(disks: &[PersistentDisk]) -> Result<Vec<AttachedDisk>, String> {
    if disks.is_empty() {
        return Ok(Vec::new());
    }

    let output = Command::new("limactl")
        .args(["--tty=false", "disk", "list", "--json"])
        .output()
        .map_err(|error| format!("failed to list Lima disks: {error}"))?;
    if !output.status.success() {
        return Err("failed to list Lima disks".to_owned());
    }

    let mut attached = Vec::with_capacity(disks.len());
    for disk in disks {
        validate_disk_name(&disk.name)?;
        if disk_list_contains(&output.stdout, &disk.name) {
            attached.push(AttachedDisk {
                request: disk.clone(),
                format: false,
            });
            continue;
        }
        println!("==> Creating Lima disk {} ({})", disk.name, disk.size);
        checked(
            Command::new("limactl")
                .args(["--tty=false", "disk", "create"])
                .arg(&disk.name)
                .args(["--size", &disk.size]),
            "create the Lima development cache disk",
        )?;
        attached.push(AttachedDisk {
            request: disk.clone(),
            format: true,
        });
    }
    Ok(attached)
}

fn disk_list_contains(output: &[u8], name: &str) -> bool {
    let needle = format!(r#""name":"{name}""#);
    String::from_utf8_lossy(output)
        .lines()
        .any(|line| line.contains(&needle))
}

fn validate_disk_name(name: &str) -> Result<(), String> {
    if !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(format!("invalid Lima disk name: {name}"))
    }
}

fn configure_disks(process: &mut Command, disks: &[AttachedDisk]) -> Result<(), String> {
    if disks.is_empty() {
        return Ok(());
    }

    let mut entries = Vec::with_capacity(disks.len());
    for disk in disks {
        validate_disk_name(&disk.request.name)?;
        entries.push(format!(
            r#"{{"name":"{}","format":{},"fsType":"{}"}}"#,
            disk.request.name, disk.format, disk.request.filesystem
        ));
    }
    process
        .arg("--set")
        .arg(format!(".additionalDisks = [{}]", entries.join(",")));
    Ok(())
}

fn disable_disk_format(instance: &str, disks: &[AttachedDisk]) -> Result<(), String> {
    if !disks.iter().any(|disk| disk.format) {
        return Ok(());
    }
    checked(
        Command::new("limactl").args([
            "--tty=false",
            "edit",
            instance,
            "--set",
            ".additionalDisks[].format = false",
        ]),
        "disable repeated Lima development cache disk formatting",
    )
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

fn guest_shell_command(instance: &str, forward_env: &[&str]) -> Command {
    let mut command = Command::new("limactl");
    command.args(["--tty=false", "shell"]);
    if !forward_env.is_empty() {
        command
            .arg("--preserve-env")
            .env("LIMA_SHELLENV_BLOCK", "*")
            .env("LIMA_SHELLENV_ALLOW", forward_env.join(","));
    }
    command.args([instance, "bash", "-s"]);
    command
}

fn run_guest_script(
    instance: &str,
    script: &str,
    description: &str,
    forward_env: &[&str],
) -> Result<ExitStatus, String> {
    let mut child = guest_shell_command(instance, forward_env)
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
    use crate::machine::ReusePolicy;

    fn podman_request(os: MachineOs) -> MachineRequest {
        MachineRequest {
            os,
            arch: Arch::Arm64,
            purpose: "e2e",
            profile: "podman",
            forward_env: Vec::new(),
            keep_on_failure: false,
            reuse: ReusePolicy::ReusePrepared {
                rebuild: false,
                preparation_key: 0,
            },
            host_mounts: Vec::new(),
            persistent_disks: Vec::new(),
        }
    }

    #[test]
    fn owns_the_target_to_template_mapping() {
        assert_eq!(
            lima_template(MachineOs::CentosStream10),
            "template:centos-stream-10"
        );
        assert_eq!(
            lima_template(MachineOs::Ubuntu24_04),
            "template:ubuntu-24.04"
        );
        assert_eq!(
            lima_template(MachineOs::Ubuntu26_04),
            "template:ubuntu-26.04"
        );
    }

    #[test]
    fn forwards_only_requested_host_environment() {
        let command = guest_shell_command(
            "openshell-e2e-ubuntu-24.04-12345678",
            &["MISE_GITHUB_TOKEN"],
        );
        let args = command
            .get_args()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>();

        assert_eq!(
            args,
            [
                "--tty=false",
                "shell",
                "--preserve-env",
                "openshell-e2e-ubuntu-24.04-12345678",
                "bash",
                "-s",
            ]
        );
        assert!(command.get_envs().any(|(name, value)| {
            name == "LIMA_SHELLENV_BLOCK" && value == Some(std::ffi::OsStr::new("*"))
        }));
        assert!(command.get_envs().any(|(name, value)| {
            name == "LIMA_SHELLENV_ALLOW"
                && value == Some(std::ffi::OsStr::new("MISE_GITHUB_TOKEN"))
        }));
    }

    #[test]
    fn cleans_up_failed_provisioning_unless_the_vm_was_requested() {
        let cleaned = std::cell::Cell::new(false);
        let result: Result<(), String> = finish_preparation(
            Err("setup failed".to_owned()),
            "test-vm",
            false,
            "Cleaning test VM",
            || {
                cleaned.set(true);
                Ok(())
            },
        );
        assert_eq!(result.expect_err("setup should fail"), "setup failed");
        assert!(cleaned.get());

        cleaned.set(false);
        let result: Result<(), String> = finish_preparation(
            Err("setup failed".to_owned()),
            "test-vm",
            true,
            "Cleaning test VM",
            || {
                cleaned.set(true);
                Ok(())
            },
        );
        assert_eq!(result.expect_err("setup should fail"), "setup failed");
        assert!(!cleaned.get());
    }

    #[test]
    fn reports_a_provisioning_cleanup_failure() {
        let result: Result<(), String> = finish_preparation(
            Err("setup failed".to_owned()),
            "test-vm",
            false,
            "Cleaning test VM",
            || Err("delete failed".to_owned()),
        );

        assert_eq!(
            result.expect_err("setup and cleanup should fail"),
            "setup failed; cleanup also failed: delete failed"
        );
    }

    #[test]
    fn names_the_vm_for_its_environment() {
        let request = podman_request(MachineOs::Ubuntu24_04);
        let reusable = instance_name(&request, Backend::Qemu, false);
        let suffix = reusable
            .strip_prefix("openshell-e2e-ubuntu-24.04-")
            .expect("name should expose its purpose and machine OS");
        assert_eq!(suffix.len(), 8);
        assert!(suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(reusable, instance_name(&request, Backend::Qemu, true));
    }

    #[test]
    fn leaves_room_for_lima_socket_paths() {
        let request = podman_request(MachineOs::Ubuntu24_04);

        // Lima appends a PID and temporary socket suffix beneath ~/.lima. Keep
        // the stable portion bounded so common macOS home paths remain below
        // UNIX_PATH_MAX even with a ten-digit PID.
        assert!(instance_name(&request, Backend::Default, false).len() <= 40);
        let mut mounted = request.clone();
        mounted.host_mounts = vec![HostMount::read_only("/tmp/OpenShell")];
        assert!(instance_name(&mounted, Backend::Default, false).len() <= 40);
        let mut smoke = request;
        smoke.purpose = "smoke";
        assert!(instance_name(&smoke, Backend::Default, false).len() <= 40);
        assert!(
            instance_name(&smoke, Backend::Default, false)
                .starts_with("openshell-smoke-ubuntu-24.04-")
        );
    }

    #[test]
    fn keys_mounted_instances_to_the_source_path() {
        let mut first_request = podman_request(MachineOs::Ubuntu24_04);
        first_request.host_mounts = vec![HostMount::read_only("/work/first/OpenShell")];
        let mut second_request = first_request.clone();
        second_request.host_mounts = vec![HostMount::read_only("/work/second/OpenShell")];
        let mut cached_request = first_request.clone();
        cached_request.host_mounts.push(HostMount {
            path: "/cache/sccache".into(),
            writable: true,
        });

        let first = instance_name(&first_request, Backend::Qemu, false);
        let second = instance_name(&second_request, Backend::Qemu, false);
        let first_with_cache = instance_name(&cached_request, Backend::Qemu, false);

        assert_ne!(first, second);
        assert_ne!(first, first_with_cache);
        assert!(first.starts_with("openshell-e2e-ubuntu-24.04-"));
    }

    #[test]
    fn enables_the_guest_agent_only_for_mounted_instances() {
        let mut mounted = Command::new("limactl");
        configure_mount_mode(
            &mut mounted,
            &[
                HostMount::read_only("/work/OpenShell"),
                HostMount {
                    path: "/cache/sccache".into(),
                    writable: true,
                },
            ],
        );
        let mounted_args = mounted.get_args().collect::<Vec<_>>();
        assert!(mounted_args.contains(&std::ffi::OsStr::new("--mount-only")));
        assert!(mounted_args.contains(&std::ffi::OsStr::new("--containerd")));
        assert!(mounted_args.contains(&std::ffi::OsStr::new("/work/OpenShell")));
        assert!(mounted_args.contains(&std::ffi::OsStr::new("/cache/sccache:w")));
        assert!(!mounted_args.contains(&std::ffi::OsStr::new("--plain")));

        let mut unmounted = Command::new("limactl");
        configure_mount_mode(&mut unmounted, &[]);
        let unmounted_args = unmounted.get_args().collect::<Vec<_>>();
        assert!(unmounted_args.contains(&std::ffi::OsStr::new("--plain")));
        assert!(!unmounted_args.contains(&std::ffi::OsStr::new("--mount-only")));
    }

    #[test]
    fn keys_snapshots_to_the_complete_mount_configuration() {
        let request = podman_request(MachineOs::Ubuntu24_04);
        let source = HostMount::read_only("/work/OpenShell");
        let disk = PersistentDisk::ext4("cache-a64-12345678", "50GiB");
        let base = snapshot_tag(&request, "setup");
        assert!(base.starts_with("base-v5-"));

        let mut mounted = request.clone();
        mounted.host_mounts = vec![source];
        assert_ne!(snapshot_tag(&mounted, "setup"), base);

        let mut with_disk = mounted.clone();
        with_disk.persistent_disks = vec![disk];
        assert_ne!(
            snapshot_tag(&with_disk, "setup"),
            snapshot_tag(&mounted, "setup")
        );

        let mut larger_disk = mounted.clone();
        larger_disk.persistent_disks = vec![PersistentDisk::ext4("cache-a64-12345678", "60GiB")];
        assert_ne!(
            snapshot_tag(&with_disk, "setup"),
            snapshot_tag(&larger_disk, "setup")
        );
        assert_ne!(base, snapshot_tag(&request, "changed setup"));

        let mut changed_key = request.clone();
        changed_key.reuse = ReusePolicy::ReusePrepared {
            rebuild: false,
            preparation_key: 1,
        };
        assert_ne!(base, snapshot_tag(&changed_key, "setup"));

        let mut changed_profile = request.clone();
        changed_profile.profile = "another-suite";
        assert_ne!(base, snapshot_tag(&changed_profile, "setup"));
    }

    #[test]
    fn configures_and_detects_persistent_disks() {
        let disk = PersistentDisk::ext4("cache-a64-12345678", "50GiB");
        let attached = AttachedDisk {
            request: disk.clone(),
            format: false,
        };
        let mut command = Command::new("limactl");
        configure_disks(&mut command, std::slice::from_ref(&attached))
            .expect("disk should configure");
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>();

        assert_eq!(arguments[0], "--set");
        assert!(arguments[1].contains(r#""name":"cache-a64-12345678""#));
        assert!(arguments[1].contains(r#""fsType":"ext4""#));
        assert!(arguments[1].contains(r#""format":false"#));
        assert!(disk_list_contains(
            br#"{"name":"cache-a64-12345678","size":53687091200}"#,
            &disk.name
        ));
        assert!(!disk_list_contains(
            br#"{"name":"cache-a64-87654321","size":53687091200}"#,
            &disk.name
        ));

        let new_disk = AttachedDisk {
            request: disk.clone(),
            format: true,
        };
        let mut new_command = Command::new("limactl");
        configure_disks(&mut new_command, std::slice::from_ref(&new_disk))
            .expect("new disk should configure");
        assert!(
            new_command
                .get_args()
                .any(|argument| argument.to_string_lossy().contains(r#""format":true"#))
        );
        let mut request = podman_request(MachineOs::Ubuntu24_04);
        request.persistent_disks = vec![disk.clone()];
        let mut new_request = request.clone();
        new_request.persistent_disks = vec![disk];
        assert_eq!(
            snapshot_tag(&request, "setup"),
            snapshot_tag(&new_request, "setup")
        );
    }

    #[test]
    fn parses_matching_instance_status() {
        let output = b"other\tStopped\nopenshell-e2e-ubuntu-24.04-12345678\tRunning\n";
        assert_eq!(
            parse_instance_status(output, "openshell-e2e-ubuntu-24.04-12345678"),
            Some("Running".to_owned())
        );
        assert_eq!(parse_instance_status(output, "missing"), None);
    }
}
