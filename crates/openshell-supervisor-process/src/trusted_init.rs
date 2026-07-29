// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed execution of operator-registered workload initializers.
//!
//! Activation arrives only through the compute driver's fixed supervisor argv
//! flag. The root-only envelope carries the gateway-resolved plan and payload;
//! no image or sandbox environment variable can enable this path.

use miette::Result;
use std::path::Path;

/// Private one-shot mode used by the supervisor to cross an exec boundary
/// before performing privileged initializer setup.
pub const HELPER_SUBCOMMAND: &str = "__trusted-init-helper-v1";

/// Execute the trusted initializer when a compute driver supplied its fixed
/// activation flag.
// The Linux implementation awaits the isolated helper. Keep the same async
// interface on non-Linux hosts so cross-platform callers do not need cfg forks.
#[cfg_attr(not(target_os = "linux"), allow(clippy::unused_async))]
pub async fn run_if_requested(
    envelope_path: Option<&Path>,
    sandbox_id: Option<&str>,
) -> Result<()> {
    let Some(envelope_path) = envelope_path else {
        return Ok(());
    };

    #[cfg(target_os = "linux")]
    {
        linux::run(envelope_path, sandbox_id).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (envelope_path, sandbox_id);
        Err(miette::miette!(
            "trusted workload initialization is supported only on Linux"
        ))
    }
}

/// Run the single-threaded trusted initializer helper.
///
/// The main supervisor enters this mode before constructing a Tokio runtime,
/// so namespace, mount, capability, Landlock, and seccomp setup never runs in
/// a post-fork `pre_exec` closure.
pub fn run_helper() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run_helper()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(miette::miette!(
            "trusted workload initialization is supported only on Linux"
        ))
    }
}

/// Report whether a trusted-initialization sandbox is ready.
///
/// Container runtimes invoke this through the fixed side-loaded supervisor
/// binary, never through an image shell. Readiness requires both a successful
/// receipt bound to the expected sandbox and plan and the supervisor-owned SSH
/// socket created later in startup.
pub fn run_healthcheck(sandbox_id: &str, plan_sha256: &str, ssh_socket_path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run_healthcheck(sandbox_id, plan_sha256, ssh_socket_path)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (sandbox_id, plan_sha256, ssh_socket_path);
        Err(miette::miette!(
            "trusted workload initialization healthchecks are supported only on Linux"
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::HELPER_SUBCOMMAND;
    use crate::sandbox;
    use miette::{IntoDiagnostic, Result, WrapErr};
    use openshell_core::policy::{
        FilesystemPolicy, LandlockCompatibility, LandlockPolicy, NetworkPolicy, ProcessPolicy,
        SandboxPolicy,
    };
    use openshell_core::proto::compute::v1::{
        TrustedWorkloadInitEnvelope, TrustedWorkloadInitPlan,
    };
    use prost::Message;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, Write};
    use std::mem::size_of;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::path::{Component, Path, PathBuf};
    use std::process::{Command as StdCommand, Stdio};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::process::Command;
    use tokio::time::timeout;
    use tracing::info;

    const RECEIPT_SCHEMA_VERSION: u32 = 1;
    const MAX_RECEIPT_BYTES: usize = 64 * 1024;
    const MAX_RESULT_BYTES: usize = 64 * 1024;
    const INITIALIZER_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Receipt {
        schema_version: u32,
        sandbox_id: String,
        contract_id: String,
        registered_image: String,
        resolved_image_id: String,
        payload_sha256: String,
        plan_sha256: String,
        status: String,
        result_sha256: String,
    }

    impl Receipt {
        fn pending(envelope: &TrustedWorkloadInitEnvelope, plan: &TrustedWorkloadInitPlan) -> Self {
            Self {
                schema_version: RECEIPT_SCHEMA_VERSION,
                sandbox_id: envelope.sandbox_id.clone(),
                contract_id: plan.contract_id.clone(),
                registered_image: plan.image.clone(),
                resolved_image_id: envelope.resolved_image_id.clone(),
                payload_sha256: plan.payload_sha256.clone(),
                plan_sha256: openshell_core::trusted_workload_init::plan_sha256(plan),
                status: "running".to_string(),
                result_sha256: String::new(),
            }
        }

        fn binding_matches(&self, expected: &Self) -> bool {
            self.schema_version == expected.schema_version
                && self.sandbox_id == expected.sandbox_id
                && self.contract_id == expected.contract_id
                && self.registered_image == expected.registered_image
                && self.resolved_image_id == expected.resolved_image_id
                && self.payload_sha256 == expected.payload_sha256
                && self.plan_sha256 == expected.plan_sha256
        }
    }

    pub(super) async fn run(envelope_path: &Path, sandbox_id: Option<&str>) -> Result<()> {
        if envelope_path != Path::new(openshell_core::trusted_workload_init::ENVELOPE_MOUNT_PATH) {
            return Err(miette::miette!(
                "trusted initializer envelope path must be {}",
                openshell_core::trusted_workload_init::ENVELOPE_MOUNT_PATH
            ));
        }
        let sandbox_id = sandbox_id
            .filter(|value| !value.is_empty())
            .ok_or_else(|| miette::miette!("trusted initialization requires a sandbox ID"))?;

        let bytes = read_root_only_file(
            envelope_path,
            openshell_core::trusted_workload_init::MAX_ENVELOPE_BYTES,
        )
        .into_diagnostic()
        .wrap_err("read trusted initializer envelope")?;
        let envelope = openshell_core::trusted_workload_init::decode_envelope(&bytes, sandbox_id)
            .map_err(|error| miette::miette!("{error}"))?;
        let plan = envelope
            .plan
            .as_ref()
            .ok_or_else(|| miette::miette!("trusted initializer envelope plan is required"))?;

        // The initializer is a root child. Make the credential-bearing
        // supervisor non-dumpable before it is spawned so same-UID procfs
        // inspection cannot recover gateway/provider material.
        crate::process::harden_child_process()?;
        validate_initializer_executable(&plan.command[0])?;
        for path in &plan.writable_paths {
            ensure_directory_without_symlinks(Path::new(path))
                .wrap_err_with(|| format!("prepare trusted initializer writable path '{path}'"))?;
        }
        ensure_receipt_directory()?;

        let receipt_path = Path::new(openshell_core::trusted_workload_init::RECEIPT_PATH);
        let mut receipt = Receipt::pending(&envelope, plan);
        if let Some(existing) = read_receipt(receipt_path)? {
            if !existing.binding_matches(&receipt) {
                return Err(miette::miette!(
                    "trusted initializer receipt does not match the requested contract, payload, or image"
                ));
            }
            return match existing.status.as_str() {
                "success" if valid_sha256(&existing.result_sha256) => {
                    info!(
                        contract_id = %plan.contract_id,
                        payload_sha256 = %plan.payload_sha256,
                        "trusted workload initialization already completed"
                    );
                    Ok(())
                }
                status => Err(miette::miette!(
                    "trusted initializer receipt has terminal status '{status}'; refusing to rerun side effects"
                )),
            };
        }

        // Persist the running marker before allowing any side effects. If the
        // supervisor or host dies mid-initialization, restart is terminal
        // instead of silently repeating a partially applied operation.
        write_receipt(receipt_path, &receipt)?;

        match execute_initializer(plan).await {
            Ok(result) => {
                receipt.status = "success".to_string();
                receipt.result_sha256 = hex::encode(Sha256::digest(result));
                write_receipt(receipt_path, &receipt)?;
                info!(
                    contract_id = %plan.contract_id,
                    payload_sha256 = %plan.payload_sha256,
                    "trusted workload initialization completed"
                );
                Ok(())
            }
            Err(error) => {
                receipt.status = "failure".to_string();
                receipt.result_sha256.clear();
                if let Err(receipt_error) = write_receipt(receipt_path, &receipt) {
                    return Err(miette::miette!(
                        "trusted initializer failed and its terminal receipt could not be recorded: {error}; receipt: {receipt_error}"
                    ));
                }
                Err(miette::miette!("trusted initializer failed: {error}"))
            }
        }
    }

    pub(super) fn run_helper() -> Result<()> {
        verify_helper_parent()?;
        let plan = read_helper_plan()?;
        openshell_core::trusted_workload_init::validate_plan(&plan, &plan.image)
            .map_err(|error| miette::miette!("{error}"))?;
        validate_initializer_executable(&plan.command[0])?;
        for path in &plan.writable_paths {
            ensure_directory_without_symlinks(Path::new(path))
                .wrap_err_with(|| format!("prepare trusted initializer writable path '{path}'"))?;
        }

        let policy = initializer_policy(&plan);
        let prepared = sandbox::linux::prepare(&policy, Some("/"))
            .wrap_err("prepare trusted initializer sandbox")?;
        let sensitive_directories =
            sensitive_directories().wrap_err("resolve trusted initializer credential isolation")?;
        let writable_paths = plan
            .writable_paths
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let payload_stdin = sealed_payload_file(&plan.payload)
            .into_diagnostic()
            .wrap_err("seal trusted initializer payload")?;

        nix::unistd::setpgid(nix::unistd::Pid::from_raw(0), nix::unistd::Pid::from_raw(0))
            .into_diagnostic()
            .wrap_err("create trusted initializer process group")?;
        isolate_initializer_namespaces(&sensitive_directories, &writable_paths)
            .into_diagnostic()
            .wrap_err("isolate trusted initializer namespaces")?;
        crate::process::harden_child_process()?;
        restrict_capabilities(&plan.capabilities)
            .into_diagnostic()
            .wrap_err("restrict trusted initializer capabilities")?;
        sandbox::linux::enforce_trusted_initializer(prepared)
            .wrap_err("enforce trusted initializer sandbox")?;
        mark_non_stdio_close_on_exec()
            .into_diagnostic()
            .wrap_err("isolate trusted initializer file descriptors")?;

        let mut command = StdCommand::new(&plan.command[0]);
        command
            .args(&plan.command[1..])
            .current_dir("/")
            .env_clear()
            .env("PATH", INITIALIZER_PATH)
            .env("HOME", "/root")
            .env("LANG", "C")
            .env(
                openshell_core::trusted_workload_init::CHILD_CONTRACT_ENV,
                &plan.contract_id,
            )
            .env(
                openshell_core::trusted_workload_init::CHILD_RECEIPT_FILE_ENV,
                openshell_core::trusted_workload_init::RECEIPT_PATH,
            )
            .stdin(Stdio::from(payload_stdin))
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let error = command.exec();
        Err(error)
            .into_diagnostic()
            .wrap_err("execute trusted initializer")
    }

    pub(super) fn run_healthcheck(
        sandbox_id: &str,
        expected_plan_sha256: &str,
        ssh_socket_path: &Path,
    ) -> Result<()> {
        if sandbox_id.is_empty() || !valid_sha256(expected_plan_sha256) {
            return Err(miette::miette!(
                "trusted initializer healthcheck binding is invalid"
            ));
        }
        let receipt = read_receipt(Path::new(
            openshell_core::trusted_workload_init::RECEIPT_PATH,
        ))?
        .ok_or_else(|| miette::miette!("trusted initializer receipt is not present"))?;
        if receipt.sandbox_id != sandbox_id
            || receipt.plan_sha256 != expected_plan_sha256
            || receipt.status != "success"
            || !valid_sha256(&receipt.result_sha256)
        {
            return Err(miette::miette!(
                "trusted initializer receipt is not successful or does not match this sandbox"
            ));
        }
        if !ssh_socket_ready(ssh_socket_path)? {
            return Err(miette::miette!(
                "sandbox supervisor SSH socket is not ready"
            ));
        }
        Ok(())
    }

    fn verify_helper_parent() -> Result<()> {
        if !nix::unistd::Uid::effective().is_root() {
            return Err(miette::miette!(
                "trusted initializer helper requires effective uid 0"
            ));
        }
        let parent_pid = nix::unistd::getppid().as_raw();
        validate_helper_parent_pid(parent_pid)?;
        arm_parent_death_signal()?;
        if nix::unistd::getppid().as_raw() != parent_pid {
            return Err(miette::miette!(
                "trusted initializer helper parent exited during activation"
            ));
        }
        let current = std::fs::metadata("/proc/self/exe")
            .into_diagnostic()
            .wrap_err("inspect trusted initializer helper executable")?;
        let parent = std::fs::metadata(format!("/proc/{parent_pid}/exe"))
            .into_diagnostic()
            .wrap_err("inspect trusted initializer helper parent")?;
        if current.dev() != parent.dev() || current.ino() != parent.ino() {
            return Err(miette::miette!(
                "trusted initializer helper parent is not the running supervisor"
            ));
        }
        Ok(())
    }

    fn validate_helper_parent_pid(parent_pid: i32) -> Result<()> {
        if parent_pid != 1 {
            return Err(miette::miette!(
                "trusted initializer helper requires the supervisor to run as container PID 1"
            ));
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn arm_parent_death_signal() -> Result<()> {
        let result = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .into_diagnostic()
                .wrap_err("bind trusted initializer helper lifetime to supervisor");
        }
        Ok(())
    }

    fn ssh_socket_ready(path: &Path) -> Result<bool> {
        let raw = path.to_string_lossy();
        if let Some(name) = raw.strip_prefix('@') {
            if name.is_empty() || name.contains(char::is_whitespace) {
                return Err(miette::miette!(
                    "trusted initializer healthcheck abstract socket is invalid"
                ));
            }
            return active_unix_listener(&raw, None);
        }
        if !path.is_absolute()
            || raw == "/"
            || raw.ends_with('/')
            || raw.contains("//")
            || raw.contains(char::is_whitespace)
            || raw
                .split('/')
                .any(|component| component == "." || component == "..")
        {
            return Err(miette::miette!(
                "trusted initializer healthcheck socket path is invalid"
            ));
        }
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error).into_diagnostic(),
        };
        if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return Ok(false);
        }
        active_unix_listener(&raw, Some(metadata.ino()))
    }

    fn active_unix_listener(path: &str, inode: Option<u64>) -> Result<bool> {
        let sockets = std::fs::read_to_string("/proc/net/unix")
            .into_diagnostic()
            .wrap_err("inspect supervisor Unix sockets")?;
        Ok(proc_unix_has_listener(&sockets, path, inode))
    }

    fn proc_unix_has_listener(contents: &str, path: &str, inode: Option<u64>) -> bool {
        const SO_ACCEPTCON: u32 = 0x0001_0000;
        const SOCK_STREAM: u32 = 1;
        const STATE_UNCONNECTED: u32 = 1;

        contents.lines().skip(1).any(|line| {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() != 8 || fields[7] != path {
                return false;
            }
            let flags = u32::from_str_radix(fields[3], 16).ok();
            let socket_type = u32::from_str_radix(fields[4], 16).ok();
            let state = u32::from_str_radix(fields[5], 16).ok();
            let socket_inode = fields[6].parse::<u64>().ok();
            flags.is_some_and(|value| value & SO_ACCEPTCON != 0)
                && socket_type == Some(SOCK_STREAM)
                && state == Some(STATE_UNCONNECTED)
                && inode.is_none_or(|expected| socket_inode == Some(expected))
        })
    }

    fn read_helper_plan() -> Result<TrustedWorkloadInitPlan> {
        let mut bytes = Vec::new();
        std::io::stdin()
            .lock()
            .take(
                u64::try_from(openshell_core::trusted_workload_init::MAX_ENVELOPE_BYTES + 1)
                    .unwrap_or(u64::MAX),
            )
            .read_to_end(&mut bytes)
            .into_diagnostic()
            .wrap_err("read trusted initializer helper request")?;
        if bytes.len() > openshell_core::trusted_workload_init::MAX_ENVELOPE_BYTES {
            return Err(miette::miette!(
                "trusted initializer helper request exceeds platform limit"
            ));
        }
        TrustedWorkloadInitPlan::decode(bytes.as_slice())
            .into_diagnostic()
            .wrap_err("decode trusted initializer helper request")
    }

    #[allow(unsafe_code)]
    fn sealed_payload_file(payload: &[u8]) -> std::io::Result<File> {
        let name = CString::new("openshell-trusted-init-payload").expect("static memfd name");
        let descriptor = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        file.write_all(payload)?;
        file.seek(std::io::SeekFrom::Start(0))?;
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(file)
    }

    #[allow(unsafe_code)]
    fn mark_non_stdio_close_on_exec() -> std::io::Result<()> {
        const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
        let result =
            unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    async fn execute_initializer(
        plan: &TrustedWorkloadInitPlan,
    ) -> std::result::Result<Vec<u8>, String> {
        let helper_request = plan.encode_to_vec();
        if helper_request.len() > openshell_core::trusted_workload_init::MAX_ENVELOPE_BYTES {
            return Err("trusted initializer helper request exceeds platform limit".to_string());
        }

        let mut command = Command::new("/proc/self/exe");
        command
            .arg(HELPER_SUBCOMMAND)
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        command.process_group(0);

        let mut child = command
            .spawn()
            .map_err(|error| format!("spawn initializer failed: {error}"))?;
        let pid = child
            .id()
            .ok_or_else(|| "initializer spawned without a process ID".to_string())?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "initializer stdin pipe is unavailable".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "initializer stdout pipe is unavailable".to_string())?;
        let payload = helper_request;

        let mut stdin_task = tokio::spawn(async move {
            stdin.write_all(&payload).await?;
            stdin.shutdown().await
        });
        let mut stdout_task = tokio::spawn(async move {
            let mut result = Vec::new();
            stdout
                .take(u64::try_from(MAX_RESULT_BYTES + 1).unwrap_or(u64::MAX))
                .read_to_end(&mut result)
                .await?;
            Ok::<Vec<u8>, std::io::Error>(result)
        });

        let process_group = i32::try_from(pid)
            .map(nix::unistd::Pid::from_raw)
            .map_err(|_| "initializer process ID exceeds platform range".to_string())?;
        let operation = timeout(
            Duration::from_secs(u64::from(plan.timeout_seconds)),
            async {
                let status = child
                    .wait()
                    .await
                    .map_err(|error| format!("wait for initializer failed: {error}"))?;
                (&mut stdin_task)
                    .await
                    .map_err(|error| format!("initializer payload writer failed: {error}"))?
                    .map_err(|error| format!("write initializer payload failed: {error}"))?;
                let result = (&mut stdout_task)
                    .await
                    .map_err(|error| format!("initializer result reader failed: {error}"))?
                    .map_err(|error| format!("read initializer result failed: {error}"))?;
                Ok::<_, String>((status, result))
            },
        )
        .await;

        // A successful main process must not be able to leave privileged
        // descendants behind. Kill the whole group on every terminal path;
        // the leader has already been reaped on the normal path.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-process_group.as_raw()),
            nix::sys::signal::Signal::SIGKILL,
        );
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.wait().await;
        }
        stdin_task.abort();
        stdout_task.abort();

        let (status, result) = match operation {
            Ok(result) => result?,
            Err(_) => {
                return Err(format!(
                    "initializer exceeded {} second timeout",
                    plan.timeout_seconds
                ));
            }
        };

        if result.len() > MAX_RESULT_BYTES {
            return Err(format!(
                "initializer result exceeds {MAX_RESULT_BYTES} byte limit"
            ));
        }
        if !status.success() {
            return Err(format!(
                "initializer exited unsuccessfully ({})",
                status
                    .code()
                    .map_or_else(|| "signal".to_string(), |code| format!("code {code}"))
            ));
        }
        Ok(result)
    }

    fn initializer_policy(plan: &TrustedWorkloadInitPlan) -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy {
                read_only: vec![PathBuf::from("/")],
                read_write: plan.writable_paths.iter().map(PathBuf::from).collect(),
                include_workdir: false,
            },
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy {
                compatibility: LandlockCompatibility::HardRequirement,
            },
            process: ProcessPolicy::default(),
        }
    }

    fn validate_initializer_executable(path: &str) -> Result<()> {
        let path = Path::new(path);
        if !path.is_absolute() {
            return Err(miette::miette!(
                "trusted initializer executable must be absolute"
            ));
        }
        let mut current = PathBuf::from("/");
        let components = path.components().collect::<Vec<_>>();
        for (index, component) in components.iter().enumerate() {
            match component {
                Component::RootDir => continue,
                Component::Normal(component) => current.push(component),
                _ => {
                    return Err(miette::miette!(
                        "trusted initializer executable must be normalized"
                    ));
                }
            }
            let metadata = std::fs::symlink_metadata(&current)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!("inspect trusted initializer path '{}'", current.display())
                })?;
            let is_leaf = index + 1 == components.len();
            if metadata.file_type().is_symlink()
                || (is_leaf && !metadata.is_file())
                || (!is_leaf && !metadata.is_dir())
            {
                return Err(miette::miette!(
                    "trusted initializer path '{}' must contain real directories and end in a regular file",
                    current.display()
                ));
            }
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(miette::miette!(
                    "trusted initializer path '{}' must be root-owned and not group/world-writable",
                    current.display()
                ));
            }
        }
        Ok(())
    }

    fn read_root_only_file(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || usize::try_from(metadata.len()).map_or(true, |length| length > limit)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "file must be root-owned, regular, owner-only, and bounded",
            ));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(u64::try_from(limit + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "file exceeds size limit",
            ));
        }
        Ok(bytes)
    }

    fn read_receipt(path: &Path) -> Result<Option<Receipt>> {
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).into_diagnostic(),
        };
        let metadata = file.metadata().into_diagnostic()?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(miette::miette!(
                "trusted initializer receipt must be a root-owned, non-writable regular file"
            ));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(u64::try_from(MAX_RECEIPT_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)
            .into_diagnostic()?;
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(miette::miette!(
                "trusted initializer receipt exceeds size limit"
            ));
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .into_diagnostic()
            .wrap_err("parse trusted initializer receipt")
    }

    fn write_receipt(path: &Path, receipt: &Receipt) -> Result<()> {
        let bytes = serde_json::to_vec(receipt)
            .into_diagnostic()
            .wrap_err("serialize trusted initializer receipt")?;
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(miette::miette!(
                "trusted initializer receipt exceeds size limit"
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| miette::miette!("trusted initializer receipt has no parent"))?;
        let temporary = parent.join(format!(".receipt.{}.tmp", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .into_diagnostic()
            .wrap_err("create trusted initializer receipt")?;
        let result = (|| -> std::io::Result<()> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            file.set_permissions(std::fs::Permissions::from_mode(0o444))?;
            std::fs::rename(&temporary, path)?;
            File::open(parent)?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
            .into_diagnostic()
            .wrap_err("commit trusted initializer receipt")
    }

    fn ensure_receipt_directory() -> Result<()> {
        let receipt = Path::new(openshell_core::trusted_workload_init::RECEIPT_PATH);
        let parent = receipt
            .parent()
            .ok_or_else(|| miette::miette!("trusted initializer receipt has no parent"))?;
        ensure_directory_without_symlinks(parent)?;
        let mut current = PathBuf::from("/");
        for component in parent.components() {
            match component {
                Component::RootDir => continue,
                Component::Normal(component) => current.push(component),
                _ => {
                    return Err(miette::miette!(
                        "trusted initializer receipt path must be normalized"
                    ));
                }
            }
            let metadata = std::fs::symlink_metadata(&current)
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "inspect trusted initializer receipt ancestor '{}'",
                        current.display()
                    )
                })?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(miette::miette!(
                    "trusted initializer receipt ancestor '{}' must be a root-owned, non-writable directory",
                    current.display()
                ));
            }
        }
        Ok(())
    }

    fn ensure_directory_without_symlinks(path: &Path) -> Result<()> {
        if !path.is_absolute() {
            return Err(miette::miette!("path must be absolute"));
        }
        let mut current = PathBuf::from("/");
        for component in path.components() {
            match component {
                Component::RootDir => continue,
                Component::Normal(component) => current.push(component),
                _ => return Err(miette::miette!("path must be normalized")),
            }
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(miette::miette!(
                        "path '{}' contains a symlink",
                        current.display()
                    ));
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(miette::miette!(
                        "path '{}' is not a directory",
                        current.display()
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::create_dir(&current)
                        .into_diagnostic()
                        .wrap_err_with(|| format!("create directory '{}'", current.display()))?;
                    std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o755))
                        .into_diagnostic()?;
                }
                Err(error) => return Err(error).into_diagnostic(),
            }
        }
        Ok(())
    }

    fn sensitive_directories() -> Result<Vec<PathBuf>> {
        let mut directories = vec![
            PathBuf::from("/etc/openshell/auth"),
            PathBuf::from("/etc/openshell/tls"),
            PathBuf::from("/etc/openshell-tls"),
            PathBuf::from("/etc/openshell/trusted-init"),
            PathBuf::from("/run/secrets"),
        ];
        if let Some(socket) =
            std::env::var_os(openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET)
        {
            let socket = PathBuf::from(socket);
            let parent = socket.parent().ok_or_else(|| {
                miette::miette!("provider identity socket path has no parent directory")
            })?;
            if parent.components().count() < 3 || matches!(parent.to_str(), Some("/run" | "/var")) {
                return Err(miette::miette!(
                    "provider identity socket parent is too broad to isolate safely"
                ));
            }
            directories.push(parent.to_path_buf());
        }
        directories.sort();
        directories.dedup();
        Ok(directories)
    }

    #[allow(unsafe_code)]
    fn isolate_initializer_namespaces(
        sensitive_directories: &[PathBuf],
        writable_paths: &[PathBuf],
    ) -> std::io::Result<()> {
        if unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWNET) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let root = CString::new("/").expect("static path");
        if unsafe {
            libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        for directory in sensitive_directories {
            let metadata = match std::fs::symlink_metadata(directory) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "sensitive initializer path '{}' is not a real directory",
                        directory.display()
                    ),
                ));
            }
            mount_empty_tmpfs(directory)?;
        }
        for path in writable_paths {
            bind_mount_to_self(path)?;
        }
        set_mount_read_only(Path::new("/"), true, true)?;
        for path in writable_paths {
            set_mount_read_only(path, false, true)?;
        }
        for directory in sensitive_directories {
            if directory.exists() {
                set_mount_read_only(directory, true, true)?;
            }
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn bind_mount_to_self(path: &Path) -> std::io::Result<()> {
        let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "mount path contains NUL")
        })?;
        if unsafe {
            libc::mount(
                path.as_ptr(),
                path.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn set_mount_read_only(path: &Path, read_only: bool, recursive: bool) -> std::io::Result<()> {
        #[repr(C)]
        struct MountAttr {
            attr_set: u64,
            attr_clr: u64,
            propagation: u64,
            userns_fd: u64,
        }

        const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
        const AT_RECURSIVE: libc::c_int = 0x8000;

        let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "mount path contains NUL")
        })?;
        let attr = MountAttr {
            attr_set: if read_only { MOUNT_ATTR_RDONLY } else { 0 },
            attr_clr: if read_only { 0 } else { MOUNT_ATTR_RDONLY },
            propagation: 0,
            userns_fd: 0,
        };
        let flags = if recursive { AT_RECURSIVE } else { 0 };
        let result = unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                libc::AT_FDCWD,
                path.as_ptr(),
                flags,
                &raw const attr,
                size_of::<MountAttr>(),
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn mount_empty_tmpfs(target: &Path) -> std::io::Result<()> {
        let source = CString::new("tmpfs").expect("static source");
        let filesystem = CString::new("tmpfs").expect("static filesystem");
        let target = CString::new(target.as_os_str().as_encoded_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "mount path contains NUL")
        })?;
        let options = CString::new("size=4096,mode=000").expect("static options");
        let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                filesystem.as_ptr(),
                flags,
                options.as_ptr().cast(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn restrict_capabilities(capabilities: &[String]) -> std::io::Result<()> {
        use capctl::caps::{Cap, CapSet, CapState, ambient, bounding};

        let mut allowed = CapSet::empty();
        for capability in capabilities {
            match capability.as_str() {
                "CHOWN" => allowed.add(Cap::CHOWN),
                "FOWNER" => allowed.add(Cap::FOWNER),
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "unrecognized trusted initializer capability",
                    ));
                }
            }
        }
        let current =
            CapState::get_current().map_err(|error| std::io::Error::other(error.to_string()))?;
        if (allowed - current.permitted) != CapSet::empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "trusted initializer requested unavailable capabilities",
            ));
        }
        for capability in Cap::iter() {
            if !allowed.has(capability) {
                bounding::ensure_dropped(capability)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
            }
        }
        bounding::clear_unknown().map_err(|error| std::io::Error::other(error.to_string()))?;
        if ambient::is_supported() {
            ambient::clear().map_err(|error| std::io::Error::other(error.to_string()))?;
            ambient::clear_unknown().map_err(|error| std::io::Error::other(error.to_string()))?;
        }
        CapState {
            effective: allowed,
            permitted: allowed,
            inheritable: CapSet::empty(),
        }
        .set_current()
        .map_err(|error| std::io::Error::other(error.to_string()))
    }

    fn valid_sha256(value: &str) -> bool {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn receipt_binding_excludes_status_but_covers_plan_and_image() {
            let mut expected = Receipt {
                schema_version: 1,
                sandbox_id: "sandbox-id".to_string(),
                contract_id: "contract.v1".to_string(),
                registered_image: format!("sha256:{}", "a".repeat(64)),
                resolved_image_id: format!("sha256:{}", "b".repeat(64)),
                payload_sha256: "c".repeat(64),
                plan_sha256: "d".repeat(64),
                status: "running".to_string(),
                result_sha256: String::new(),
            };
            let mut actual = expected.clone();
            actual.status = "success".to_string();
            actual.result_sha256 = "e".repeat(64);
            assert!(actual.binding_matches(&expected));

            expected.resolved_image_id = format!("sha256:{}", "f".repeat(64));
            assert!(!actual.binding_matches(&expected));
        }

        #[test]
        fn sha256_shape_is_strict() {
            assert!(valid_sha256(&"a".repeat(64)));
            assert!(!valid_sha256(&"g".repeat(64)));
            assert!(!valid_sha256(&"a".repeat(63)));
        }

        #[test]
        fn helper_requires_pid_one_supervisor() {
            assert!(validate_helper_parent_pid(1).is_ok());
            assert!(validate_helper_parent_pid(2).is_err());
            assert!(validate_helper_parent_pid(0).is_err());
        }

        #[test]
        fn proc_unix_listener_requires_live_stream_listener_and_matching_inode() {
            let sockets = "\
Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 1761703 /run/openshell/ssh.sock
0000000000000000: 00000002 00000000 00000000 0001 01 1761704 /run/openshell/not-listening.sock
0000000000000000: 00000002 00000000 00010000 0002 01 1761705 @datagram
";
            assert!(proc_unix_has_listener(
                sockets,
                "/run/openshell/ssh.sock",
                Some(1_761_703)
            ));
            assert!(!proc_unix_has_listener(
                sockets,
                "/run/openshell/ssh.sock",
                Some(1_761_704)
            ));
            assert!(!proc_unix_has_listener(
                sockets,
                "/run/openshell/not-listening.sock",
                Some(1_761_704)
            ));
            assert!(!proc_unix_has_listener(sockets, "@datagram", None));
        }
    }
}
