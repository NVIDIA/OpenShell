// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Own image-preparation processes and the files they may still be writing.
//!
//! A lease is inherited by every preparation subprocess. Cancellation first
//! kills and reaps the worker; staging is removed only after the last lease
//! descriptor closes. A restarted driver uses the same proof of inactivity.

#![allow(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::Mutex;
use tonic::Status;

use super::{
    OverlayPreparation, RuntimeImagePlan, SandboxOwnerIdentity, VmDriverConfig,
    WorkloadIdentityRequest,
};

const ATTEMPTS_DIR: &str = "preparations";
const REQUEST_FILE: &str = "request.json";
const LEASE_MARKER: &[u8] = b"openshell-image-preparation-v1\n";
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub config: VmDriverConfig,
    pub sandbox_id: String,
    pub image_ref: String,
    pub rootfs_tar: Option<PathBuf>,
    pub bootstrap_only: bool,
    pub overlay: Option<OverlayRequest>,
    pub lease_fd: i32,
    pub parent_pid: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OverlayRequest {
    pub source_disk: PathBuf,
    pub preparation: OverlayPreparation,
    pub requested_identity: Option<WorkloadIdentitySelectors>,
}

/// Keep the requested selectors across the worker boundary. The worker must
/// validate them against the persisted overlay owner before changing any files;
/// the parent's current default identity cannot substitute for that owner.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkloadIdentitySelectors {
    user: String,
    group: String,
}

impl From<&WorkloadIdentityRequest> for WorkloadIdentitySelectors {
    fn from(request: &WorkloadIdentityRequest) -> Self {
        Self {
            user: request.user.clone(),
            group: request.group.clone(),
        }
    }
}

impl From<WorkloadIdentitySelectors> for WorkloadIdentityRequest {
    fn from(selectors: WorkloadIdentitySelectors) -> Self {
        Self {
            user: selectors.user,
            group: selectors.group,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) enum Output {
    Images(RuntimeImagePlan),
    Overlay(SandboxOwnerIdentity),
}

#[derive(Serialize, Deserialize)]
pub(super) enum Message {
    Event(Vec<u8>),
    Complete(Result<Output, String>),
}

pub(super) struct Attempt {
    pub directory: PathBuf,
    lease_path: PathBuf,
    lease: Option<File>,
    child: Option<Child>,
}

/// Cleanup survives cancellation of the provisioning future itself. Lifecycle
/// calls also await the same mutex, so they cannot report completion early.
pub(super) struct CleanupOnDrop(pub Arc<Mutex<Attempt>>);

impl Drop for CleanupOnDrop {
    fn drop(&mut self) {
        let attempt = self.0.clone();
        tokio::spawn(async move {
            if let Err(error) = attempt.lock().await.cleanup().await {
                tracing::warn!(%error, "image preparation cleanup incomplete; staging retained");
            }
        });
    }
}

impl Attempt {
    /// Create and lock the lease before publishing the directory. A concurrent
    /// reconciler can never observe this attempt without its ownership lock.
    pub fn create(cache_root: &Path) -> io::Result<Self> {
        let root = cache_root.join(ATTEMPTS_DIR);
        fs::create_dir_all(&root)?;
        let random =
            u128::from_ne_bytes(openshell_crypto::random_bytes::<16>().map_err(io::Error::other)?);
        let name = format!("attempt-{random:032x}");
        let directory = root.join(&name);
        let lease_path = root.join(format!("{name}.lease"));
        let mut lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lease_path)?;
        lock(&lease, false)?;
        lease.write_all(LEASE_MARKER)?;
        lease.sync_data()?;
        fs::create_dir(&directory)?;
        Ok(Self {
            directory,
            lease_path,
            lease: Some(lease),
            child: None,
        })
    }

    /// Spawn while the caller holds the sandbox registry lock, then register
    /// this attempt before yielding. Stop/delete cannot miss a live worker.
    pub fn spawn(&mut self, launcher: &Path, mut request: Request) -> io::Result<ChildStdout> {
        let lease = self
            .lease
            .as_ref()
            .ok_or_else(|| io::Error::other("preparation lease is closed"))?;
        let fd = lease.as_raw_fd();
        request.lease_fd = fd;
        request.parent_pid = std::process::id();
        let request_path = self.directory.join(REQUEST_FILE);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&request_path)?;
        serde_json::to_writer(&mut file, &request)?;
        file.flush()?;
        let mut command = Command::new(launcher);
        command.arg("--internal-prepare-image").arg(request_path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        command.process_group(0).kill_on_drop(true);
        // SAFETY: the child only makes an async-signal-safe fcntl call. The
        // parent keeps this descriptor open until the child has exited.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("preparation stdout is missing"))?;
        self.child = Some(child);
        Ok(stdout)
    }

    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        // EOF can precede observable process exit. Let normal worker teardown
        // finish before signaling, preserving its real status and reserving
        // its PID until any remaining descendants have been stopped.
        wait_for_worker_exit(self.child.as_ref().and_then(Child::id)).await?;
        self.kill_group()?;
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("preparation worker is missing"))?
            .wait()
            .await
    }

    /// Do not report successful cleanup while a formatter or other descendant
    /// still owns the lease. Preserve uncertain staging for the next reconcile.
    pub async fn cleanup(&mut self) -> Result<(), Status> {
        let signal_result = self.kill_group();
        #[cfg(target_os = "macos")]
        let signal_result = match signal_result {
            // Darwin can reject signaling an exiting process before waitid
            // exposes its terminal status. Keep immediate cancellation first,
            // then retry the same guarded signal only after observing exit.
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
                wait_for_worker_exit(self.child.as_ref().and_then(Child::id))
                    .await
                    .and_then(|()| self.kill_group())
            }
            result => result,
        };
        signal_result
            .map_err(|error| Status::internal(format!("terminate image preparation: {error}")))?;
        if let Some(child) = self.child.as_mut() {
            tokio::time::timeout(CLEANUP_TIMEOUT, child.wait())
                .await
                .map_err(|_| {
                    Status::deadline_exceeded("image preparation did not stop; staging retained")
                })?
                .map_err(|error| Status::internal(format!("reap image preparation: {error}")))?;
        }
        // Do not explicitly unlock: inherited descriptors must continue to
        // protect files until the last worker or descendant closes its copy.
        self.lease.take();
        let deadline = tokio::time::Instant::now() + CLEANUP_TIMEOUT;
        loop {
            match reclaim(&self.directory, &self.lease_path) {
                Ok(true) => return Ok(()),
                Ok(false) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Ok(false) => {
                    return Err(Status::deadline_exceeded(
                        "image preparation descendants still own staging; files retained",
                    ));
                }
                Err(error) => {
                    return Err(Status::internal(format!(
                        "reclaim image preparation staging: {error}"
                    )));
                }
            }
        }
    }

    // macOS may replace the staging lease when proving an exited process group
    // has no remaining owner; other platforms only read the worker state.
    #[cfg_attr(not(target_os = "macos"), allow(clippy::needless_pass_by_ref_mut))]
    fn kill_group(&mut self) -> io::Result<()> {
        if let Some(id) = self.child.as_ref().and_then(Child::id) {
            let pid = i32::try_from(id).map_err(io::Error::other)?;
            match killpg(Pid::from_raw(pid), Signal::SIGKILL) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                #[cfg(target_os = "macos")]
                Err(nix::errno::Errno::EPERM)
                    if self.exited_worker_has_no_descendant_owner(id)? => {}
                Err(error) => return Err(io::Error::from_raw_os_error(error as i32)),
            }
        }
        Ok(())
    }

    /// Darwin rejects signals to a group containing only an exited leader.
    /// Accept that case only while its PID remains reserved and no descendant
    /// owns the inherited staging lease. Live or uncertain ownership still fails.
    #[cfg(target_os = "macos")]
    fn exited_worker_has_no_descendant_owner(&mut self, id: u32) -> io::Result<bool> {
        if !worker_has_exited(id)? {
            return Ok(false);
        }

        // Open the probe before dropping our copy so a concurrent reconciler
        // cannot remove the lease pathname between release and open. Reacquire
        // ownership on success and retain it until the caller reaps the worker.
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.lease_path)?;
        self.lease.take();
        if !lock(&lease, true)? {
            return Ok(false);
        }
        self.lease = Some(lease);
        Ok(true)
    }
}

/// Observe termination without releasing the PID or process-group identity.
fn worker_has_exited(id: u32) -> io::Result<bool> {
    // SAFETY: waitid writes initialized storage. WNOWAIT leaves the owned
    // child unreaped, so its PID cannot be reused before descendant signaling.
    let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::waitid(
            libc::P_PID,
            id,
            &raw mut status,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(matches!(
        status.si_code,
        libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
    ))
}

/// Bound EOF-to-exit observation without blocking the runtime or reaping.
/// Dropping this future leaves the worker available to cancellation cleanup.
async fn wait_for_worker_exit(id: Option<u32>) -> io::Result<()> {
    let Some(id) = id else {
        return Ok(());
    };
    tokio::time::timeout(CLEANUP_TIMEOUT, async {
        loop {
            if worker_has_exited(id)? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "image preparation worker did not exit before cleanup deadline",
        )
    })?
}

impl Drop for Attempt {
    fn drop(&mut self) {
        // Runtime shutdown may prevent the asynchronous reaper from running.
        // Signal only this worker's still-unreaped process group; the lease
        // remains held by descendants until the kernel closes their files.
        let _ = self.kill_group();
    }
}

/// Remove only directories created by this protocol whose inherited lease has
/// no remaining owner. Legacy staging and shared committed images are outside
/// this namespace and are never inferred to be inactive from their age.
pub(super) fn reconcile(cache_root: &Path) -> io::Result<()> {
    let root = cache_root.join(ATTEMPTS_DIR);
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|name| valid_attempt_name(name)) else {
            continue;
        };
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if let Err(error) = reclaim(&entry.path(), &root.join(format!("{name}.lease"))) {
            tracing::warn!(path = %entry.path().display(), %error, "image preparation ownership uncertain; staging retained");
        }
    }
    Ok(())
}

fn valid_attempt_name(name: &str) -> bool {
    name.strip_prefix("attempt-").is_some_and(|suffix| {
        suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn reclaim(directory: &Path, lease_path: &Path) -> io::Result<bool> {
    if !directory.try_exists()? && !lease_path.try_exists()? {
        return Ok(true);
    }
    let lease = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lease_path)
    {
        Ok(lease) if lease.metadata()?.is_file() => lease,
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !lock(&lease, true)? {
        return Ok(false);
    }
    let mut marker = Vec::new();
    (&lease).take(64).read_to_end(&mut marker)?;
    if marker != LEASE_MARKER {
        return Ok(false);
    }
    match fs::remove_dir_all(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match fs::remove_file(lease_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(true)
}

fn lock(file: &File, nonblocking: bool) -> io::Result<bool> {
    let operation = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    // SAFETY: flock receives a valid borrowed file descriptor and no pointers.
    if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if nonblocking && error.kind() == io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error)
    }
}

pub(super) fn cache_lock(cache_root: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(cache_root.join("preparation.lock"))?;
    lock(&file, false)?;
    Ok(file)
}

/// Publish a complete staged image without replacing a ready cache entry.
/// Preparation stays outside this lock; only the readiness recheck and atomic
/// rename are serialized across workers. Call from a blocking task so the
/// lock remains owned until publication finishes even if its waiter is dropped.
pub(super) fn publish_cache_file(
    cache_root: &Path,
    staged: &Path,
    destination: &Path,
    expected_size: Option<u64>,
) -> io::Result<()> {
    let _lease = cache_lock(cache_root)?;
    match fs::metadata(destination) {
        Ok(metadata)
            if expected_size.is_none_or(|size| metadata.is_file() && metadata.len() == size) =>
        {
            return Ok(());
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::rename(staged, destination)
}

pub(super) fn read_request(path: &Path) -> Result<(Request, PathBuf), String> {
    use std::os::unix::fs::MetadataExt;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(
            "image preparation request must be a regular file no larger than 1 MiB".to_string(),
        );
    }
    let request: Request = serde_json::from_reader(file).map_err(|error| error.to_string())?;
    let directory = path
        .parent()
        .ok_or("preparation request has no directory")?;
    let name = directory
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| valid_attempt_name(name))
        .ok_or("invalid preparation directory name")?;
    let expected_root = super::image_cache_root_dir(&request.config.state_dir).join(ATTEMPTS_DIR);
    if path.file_name().and_then(|name| name.to_str()) != Some(REQUEST_FILE)
        || directory.parent() != Some(expected_root.as_path())
    {
        return Err("preparation request is outside the driver staging directory".to_string());
    }
    let lease_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(expected_root.join(format!("{name}.lease")))
        .map_err(|error| error.to_string())?;
    let lease = lease_file.metadata().map_err(|error| error.to_string())?;
    if !lease.is_file() {
        return Err("image preparation lease must be a regular file".to_string());
    }
    let mut marker = Vec::new();
    lease_file
        .take(64)
        .read_to_end(&mut marker)
        .map_err(|error| error.to_string())?;
    if marker != LEASE_MARKER {
        return Err("image preparation lease marker is invalid".to_string());
    }
    // SAFETY: fstat writes only to the supplied initialized stat storage. An
    // invalid inherited descriptor is rejected rather than taken into ownership.
    let mut inherited: libc::stat = unsafe { std::mem::zeroed() };
    if request.lease_fd < 3 || unsafe { libc::fstat(request.lease_fd, &raw mut inherited) } != 0 {
        return Err("image preparation lease was not inherited".to_string());
    }
    // Match MetadataExt::dev's representation: Darwin dev_t is signed, while
    // Linux dev_t is already u64. The cast intentionally preserves that API's
    // conversion, including the sign extension of a signed device identifier.
    #[allow(clippy::cast_sign_loss, trivial_numeric_casts)]
    let inherited_device = inherited.st_dev as u64;
    if inherited.st_ino != lease.ino() || inherited_device != lease.dev() {
        return Err("image preparation lease was not inherited".to_string());
    }
    Ok((request, directory.to_path_buf()))
}

/// A process-group watcher also covers host utilities on Linux, where a
/// parent-death signal on the worker alone cannot kill its children.
pub(super) fn watch_parent(parent_pid: u32) -> Result<(), String> {
    let expected = i32::try_from(parent_pid).map_err(|error| error.to_string())?;
    if nix::unistd::getpgrp() != nix::unistd::getpid() {
        return Err("preparation worker must own its process group".to_string());
    }
    std::thread::Builder::new()
        .name("image-prep-parent".to_string())
        .spawn(move || {
            loop {
                if nix::unistd::getppid().as_raw() != expected {
                    let _ = killpg(nix::unistd::getpgrp(), Signal::SIGKILL);
                    std::process::exit(1);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub(super) fn send(message: &Message) -> io::Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, message)?;
    output.write_all(b"\n")?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn request(root: &Path) -> Request {
        Request {
            config: VmDriverConfig {
                state_dir: root.to_path_buf(),
                ..VmDriverConfig::default()
            },
            sandbox_id: "test-sandbox".to_string(),
            image_ref: "test-image".to_string(),
            rootfs_tar: None,
            bootstrap_only: false,
            overlay: None,
            lease_fd: -1,
            parent_pid: 0,
        }
    }

    async fn wait_for_file(path: &Path) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("worker readiness");
    }

    async fn wait_for_worker_exit_without_reaping(attempt: &Attempt) {
        let id = attempt.child.as_ref().unwrap().id().unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let exited = {
                    // SAFETY: waitid writes initialized exit information and
                    // WNOWAIT leaves the owned child's PID reserved for cleanup.
                    let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
                    assert_eq!(
                        unsafe {
                            libc::waitid(
                                libc::P_PID,
                                id,
                                &raw mut status,
                                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                            )
                        },
                        0
                    );
                    matches!(
                        status.si_code,
                        libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
                    )
                };
                if exited {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("worker must exit without being reaped");
    }

    async fn worker_at_stdout_eof(temp: &tempfile::TempDir, script: &str) -> Attempt {
        let launcher = temp.path().join("worker");
        fs::write(&launcher, script).unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
        let cache = super::super::image_cache_root_dir(temp.path());
        let mut attempt = Attempt::create(&cache).unwrap();
        let mut stdout = attempt.spawn(&launcher, request(temp.path())).unwrap();
        let mut output = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_to_end(&mut stdout, &mut output),
        )
        .await
        .expect("worker must close stdout")
        .unwrap();
        attempt
    }

    #[tokio::test]
    async fn stdout_eof_keeps_successful_worker_exit_status() {
        let temp = tempfile::tempdir().unwrap();
        // stdout can close before the kernel exposes the final exit status.
        // Keep that interval deterministic without requiring scheduler timing.
        let mut attempt =
            worker_at_stdout_eof(&temp, "#!/bin/sh\nexec 1>&-\nsleep 0.1\nexit 0\n").await;
        let status = attempt.wait().await;
        attempt.cleanup().await.expect("cleanup EOF worker");

        let status = status.expect("wait after stdout EOF");
        assert!(status.success(), "worker exit after stdout EOF: {status}");
        assert!(!attempt.directory.exists());
    }

    #[tokio::test]
    async fn stdout_eof_with_live_descendant_cleans_group_after_worker_exit() {
        let temp = tempfile::tempdir().unwrap();
        let mut attempt = worker_at_stdout_eof(
            &temp,
            "#!/bin/sh\nsleep 300 >/dev/null &\nexec 1>&-\nsleep 0.1\nexit 0\n",
        )
        .await;
        let status = attempt.wait().await;
        attempt.cleanup().await.expect("stop inherited lease owner");

        let status = status.expect("preserve leader status");
        assert!(status.success(), "worker exit with descendant: {status}");
        assert!(!attempt.directory.exists());
        assert!(attempt.child.as_ref().unwrap().id().is_none());
    }

    #[tokio::test]
    async fn cancelling_stdout_eof_wait_leaves_worker_for_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let mut attempt = worker_at_stdout_eof(&temp, "#!/bin/sh\nexec 1>&-\nsleep 300\n").await;
        let result = tokio::time::timeout(Duration::from_millis(50), attempt.wait()).await;
        attempt
            .cleanup()
            .await
            .expect("cancelled wait cleans worker");

        assert!(result.is_err(), "waiting for exit must remain cancellable");
        assert!(!attempt.directory.exists());
        assert!(attempt.child.as_ref().unwrap().id().is_none());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn cleanup_after_stdout_eof_waits_for_exit_publication() {
        // Repeated natural exits exercise Darwin's short interval between
        // closing stdout and making terminal status observable to waitid.
        for _ in 0..8 {
            let temp = tempfile::tempdir().unwrap();
            let mut attempt = worker_at_stdout_eof(&temp, "#!/bin/sh\nexit 0\n").await;
            let result = attempt.cleanup().await;
            if result.is_err() {
                // Reap this owned worker even when checking faulty behavior.
                attempt.cleanup().await.expect("retry owned test cleanup");
            }
            result.expect("natural EOF must not fail cancellation cleanup");
            assert!(!attempt.directory.exists());
        }
    }

    #[tokio::test]
    async fn completed_worker_without_descendants_keeps_successful_exit_status() {
        let temp = tempfile::tempdir().unwrap();
        let cache = super::super::image_cache_root_dir(temp.path());
        let launcher = temp.path().join("worker");
        fs::write(&launcher, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
        let mut attempt = Attempt::create(&cache).unwrap();
        let directory = attempt.directory.clone();
        let _stdout = attempt.spawn(&launcher, request(temp.path())).unwrap();
        wait_for_worker_exit_without_reaping(&attempt).await;

        // macOS rejects killpg for a group containing only a zombie. The
        // completed worker must still return its original successful status.
        assert!(
            attempt
                .wait()
                .await
                .expect("completed worker status")
                .success()
        );
        attempt.cleanup().await.expect("reclaim completed attempt");
        assert!(!directory.exists());
        assert!(attempt.child.as_ref().unwrap().id().is_none());
    }

    #[tokio::test]
    async fn exited_worker_with_live_descendant_stops_writer_before_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let cache = super::super::image_cache_root_dir(temp.path());
        let launcher = temp.path().join("worker");
        fs::write(&launcher, "#!/bin/sh\nsleep 300 &\nexit 0\n").unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
        let mut attempt = Attempt::create(&cache).unwrap();
        let directory = attempt.directory.clone();
        let _stdout = attempt.spawn(&launcher, request(temp.path())).unwrap();
        wait_for_worker_exit_without_reaping(&attempt).await;

        #[cfg(target_os = "macos")]
        {
            let id = attempt.child.as_ref().unwrap().id().unwrap();
            assert!(
                !attempt.exited_worker_has_no_descendant_owner(id).unwrap(),
                "an exited leader cannot prove its live descendant stopped"
            );
            assert!(directory.exists());
        }
        attempt
            .cleanup()
            .await
            .expect("kill the live descendant before reclaiming its staging");
        assert!(!directory.exists());
        assert!(attempt.child.as_ref().unwrap().id().is_none());
    }

    #[tokio::test]
    async fn cleanup_kills_and_reaps_worker_and_formatter_before_removing_staging() {
        let temp = tempfile::tempdir().unwrap();
        let cache = super::super::image_cache_root_dir(temp.path());
        let launcher = temp.path().join("worker");
        // The shell and the simulated formatter both inherit the attempt lease.
        // Killing only the shell leaves the lease locked and makes cleanup fail.
        fs::write(&launcher, "#!/bin/sh\nroot=$(dirname \"$2\")\nsleep 300 &\nprintf '%s' \"$!\" > \"$root/ready\"\nwait\n").unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
        let mut attempt = Attempt::create(&cache).unwrap();
        let directory = attempt.directory.clone();
        let _stdout = attempt.spawn(&launcher, request(temp.path())).unwrap();
        wait_for_file(&directory.join("ready")).await;
        #[cfg(target_os = "macos")]
        {
            let id = attempt.child.as_ref().unwrap().id().unwrap();
            assert!(!attempt.exited_worker_has_no_descendant_owner(id).unwrap());
            assert!(attempt.lease.is_some(), "a live worker retains its lease");
        }
        reconcile(&cache).unwrap();
        assert!(directory.exists(), "a live formatter protects its staging");
        attempt
            .cleanup()
            .await
            .expect("stop and reclaim preparation");
        assert!(!directory.exists());
        assert!(!attempt.lease_path.exists());
        assert!(
            attempt
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_some()
        );
        attempt.cleanup().await.expect("cleanup is idempotent");
    }

    #[tokio::test]
    async fn aborting_provisioning_still_runs_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let cache = super::super::image_cache_root_dir(temp.path());
        let attempt = Arc::new(Mutex::new(Attempt::create(&cache).unwrap()));
        let directory = attempt.lock().await.directory.clone();
        fs::write(directory.join("partial.ext4"), b"unfinished image").unwrap();
        let (ready, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn({
            let attempt = attempt.clone();
            async move {
                let _cleanup = CleanupOnDrop(attempt);
                ready.send(()).unwrap();
                std::future::pending::<()>().await;
            }
        });
        started.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(5), async {
            while directory.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled future must reclaim its staging");
    }

    #[test]
    fn restart_reclaims_inactive_attempts_and_preserves_active_shared_and_unknown_data() {
        let temp = tempfile::tempdir().unwrap();
        let cache = super::super::image_cache_root_dir(temp.path());
        let inactive = Attempt::create(&cache).unwrap();
        let inactive_directory = inactive.directory.clone();
        fs::write(inactive_directory.join("partial.ext4"), b"unfinished").unwrap();
        drop(inactive);
        let active = Attempt::create(&cache).unwrap();
        let committed = cache.join("shared-image");
        fs::create_dir(&committed).unwrap();
        fs::write(committed.join("rootfs.ext4"), b"valid shared image").unwrap();
        let legacy = cache.join("image.staging-legacy");
        fs::create_dir(&legacy).unwrap();
        let unmarked = cache.join(ATTEMPTS_DIR).join(format!("attempt-{:032x}", 1));
        fs::create_dir(&unmarked).unwrap();
        let link = cache.join(ATTEMPTS_DIR).join(format!("attempt-{:032x}", 2));
        symlink(&committed, &link).unwrap();
        fs::write(unmarked.with_extension("lease"), b"unrelated lock").unwrap();

        reconcile(&cache).unwrap();

        assert!(!inactive_directory.exists());
        assert!(active.directory.exists());
        assert_eq!(
            fs::read(committed.join("rootfs.ext4")).unwrap(),
            b"valid shared image"
        );
        assert!(legacy.exists());
        assert!(unmarked.exists());
        assert!(link.is_symlink());
    }

    #[tokio::test]
    async fn separate_workers_serialize_cache_publication() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().to_path_buf();
        let first = cache_lock(&cache).unwrap();
        let (entered, mut receiver) = tokio::sync::mpsc::channel(1);
        let second = tokio::task::spawn_blocking(move || {
            let _second = cache_lock(&cache).unwrap();
            entered.blocking_send(()).unwrap();
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), receiver.recv())
                .await
                .is_err()
        );
        drop(first);
        tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        second.await.unwrap();
    }

    #[test]
    fn cache_lock_child_process_helper() {
        let Some(root) = std::env::var_os("OPENSHELL_TEST_PUBLICATION_LOCK_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let name = std::env::var("OPENSHELL_TEST_PUBLICATION_LOCK_NAME").unwrap();
        fs::write(root.join(format!("{name}.waiting")), b"waiting").unwrap();
        if name == "second" {
            let probe = OpenOptions::new()
                .read(true)
                .write(true)
                .open(root.join("preparation.lock"))
                .unwrap();
            assert!(
                !lock(&probe, true).unwrap(),
                "first process must own the kernel lock"
            );
            fs::write(root.join("second.contended"), b"contended").unwrap();
        }
        if name == "second" {
            publish_cache_file(
                &root,
                &root.join("second.staged"),
                &root.join("committed"),
                Some(5),
            )
            .unwrap();
            fs::write(root.join("second.acquired"), b"published").unwrap();
            return;
        }
        let _lock = cache_lock(&root).unwrap();
        fs::write(root.join(format!("{name}.acquired")), b"acquired").unwrap();
        let mut release = [0_u8; 1];
        io::stdin().read_exact(&mut release).unwrap();
    }

    struct LockHelper(std::process::Child);

    impl Drop for LockHelper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn publication_lock_is_exclusive_across_processes_and_released_on_death() {
        let root = tempfile::tempdir().unwrap();
        let spawn = |name: &str| {
            LockHelper(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "driver::preparation::tests::cache_lock_child_process_helper",
                        "--nocapture",
                    ])
                    .env("OPENSHELL_TEST_PUBLICATION_LOCK_ROOT", root.path())
                    .env("OPENSHELL_TEST_PUBLICATION_LOCK_NAME", name)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            )
        };
        let wait_for = |name: &str| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !root.path().join(name).exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "helper did not reach {name}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        fs::write(root.path().join("second.staged"), b"later").unwrap();
        let mut first = spawn("first");
        wait_for("first.acquired");
        let mut second = spawn("second");
        wait_for("second.contended");
        assert!(
            !root.path().join("second.acquired").exists(),
            "second process bypassed lock"
        );
        // The lock holder commits before dying. The queued publisher must read
        // readiness only after it owns the lock and preserve this complete image.
        fs::write(root.path().join("committed"), b"first").unwrap();
        first.0.kill().unwrap();
        first.0.wait().unwrap();
        wait_for("second.acquired");
        assert!(second.0.wait().unwrap().success());
        assert_eq!(fs::read(root.path().join("committed")).unwrap(), b"first");
        assert!(root.path().join("second.staged").exists());
        assert!(root.path().join("preparation.lock").exists());
        // An invalid-sized template can be replaced; a valid rootfs cannot.
        fs::write(root.path().join("second.staged"), b"new!").unwrap();
        publish_cache_file(
            root.path(),
            &root.path().join("second.staged"),
            &root.path().join("committed"),
            Some(4),
        )
        .unwrap();
        assert_eq!(fs::read(root.path().join("committed")).unwrap(), b"new!");
        fs::write(root.path().join("third.staged"), b"third").unwrap();
        publish_cache_file(
            root.path(),
            &root.path().join("third.staged"),
            &root.path().join("committed"),
            None,
        )
        .unwrap();
        assert_eq!(fs::read(root.path().join("committed")).unwrap(), b"new!");
    }

    #[test]
    fn worker_rejects_request_without_inherited_lease() {
        let temp = tempfile::tempdir().unwrap();
        let cache = super::super::image_cache_root_dir(temp.path());
        let attempt = Attempt::create(&cache).unwrap();
        let path = attempt.directory.join(REQUEST_FILE);
        fs::write(&path, serde_json::to_vec(&request(temp.path())).unwrap()).unwrap();
        let error = read_request(&path)
            .err()
            .expect("missing inherited fd rejected");
        assert!(error.contains("lease was not inherited"));
    }
}
