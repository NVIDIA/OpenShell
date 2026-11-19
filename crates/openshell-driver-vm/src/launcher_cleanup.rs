// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side ownership journal for launchers that manage their own VM resources.

use std::fs;
use std::io;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;
use tonic::Status;

pub(super) const RUN_ID_ENV: &str = "OPENSHELL_VM_LAUNCH_RUN_ID";
pub(super) const RUN_STATE_DIR_ENV: &str = "OPENSHELL_VM_LAUNCH_STATE_DIR";

const ACTIVE_FILE: &str = "launcher-active.json";
const OPERATION_LOCK: &str = ".launcher-operation.lock";
const RUN_RECORD: &str = ".openshell-owner.json";
const STOP_REQUESTED: &str = "stop-requested";
const STATUS_FILE: &str = "status";
const MAX_OWNER_BYTES: u64 = 32 * 1024;

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    id: String,
    launcher: PathBuf,
}

#[derive(Debug)]
pub(super) struct Run {
    state_dir: PathBuf,
    directory: PathBuf,
    owner: Owner,
}

impl Run {
    /// Publish ownership before spawning. A previous run's record must survive
    /// even a concurrent begin or an interrupted write.
    pub(super) async fn begin(state_dir: &Path, launcher: &Path) -> Result<Self, Status> {
        let state_dir = tokio::fs::canonicalize(state_dir)
            .await
            .map_err(|error| io_status("resolve VM sandbox state directory", error))?;
        let launcher = tokio::fs::canonicalize(launcher)
            .await
            .map_err(|error| io_status("resolve VM launcher", error))?;
        let random = openshell_crypto::random_bytes::<16>()
            .map_err(|error| io_status("generate VM launcher run ID", error))?;
        let id = format!("{:032x}", u128::from_be_bytes(random));
        let directory = run_directory(&state_dir, &id);
        let mut builder = tokio::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&directory)
            .await
            .map_err(|error| io_status("create VM launcher run directory", error))?;
        let run = Self {
            state_dir,
            directory,
            owner: Owner { id, launcher },
        };
        if let Err(error) = run.publish_owner().await {
            let _ = tokio::fs::remove_dir_all(&run.directory).await;
            return Err(error);
        }
        // After publication, keep the run and journal even if syncing fails.
        sync_directory(&run.state_dir).await?;
        Ok(run)
    }

    async fn publish_owner(&self) -> Result<(), Status> {
        let path = self.directory.join(RUN_RECORD);
        let data = serde_json::to_vec(&self.owner)
            .map_err(|error| io_status("encode VM launcher owner", error))?;
        if data.len() as u64 > MAX_OWNER_BYTES {
            return Err(Status::failed_precondition(
                "VM launcher ownership record exceeds size limit",
            ));
        }
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .await
            .map_err(|error| io_status("create VM launcher run record", error))?;
        file.write_all(&data)
            .await
            .map_err(|error| io_status("write VM launcher run record", error))?;
        file.sync_all()
            .await
            .map_err(|error| io_status("sync VM launcher run record", error))?;
        sync_directory(&self.directory).await?;
        match tokio::fs::hard_link(path, self.state_dir.join(ACTIVE_FILE)).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(
                Status::failed_precondition("previous VM launcher run still owns resources"),
            ),
            Err(error) => Err(io_status("publish VM launcher ownership", error)),
        }
    }

    /// Consult the journal independently of current launcher configuration.
    /// Malformed state must not reopen the retained disk.
    pub(super) async fn load(state_dir: &Path) -> Result<Option<Self>, Status> {
        let data = match read_small_file(&state_dir.join(ACTIVE_FILE), MAX_OWNER_BYTES).await {
            Ok(Some(data)) => data,
            // A legacy record can have an invalid state directory. Its normal
            // teardown still validates that path before attempting removal.
            Ok(None) => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::NotADirectory => return Ok(None),
            Err(error) => return Err(io_status("read active VM launcher ownership", error)),
        };
        let owner: Owner = serde_json::from_slice(&data)
            .map_err(|error| io_status("decode active VM launcher ownership", error))?;
        if owner.id.len() != 32
            || !owner
                .id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !owner.launcher.is_absolute()
        {
            return Err(Status::failed_precondition(
                "invalid active VM launcher ownership record",
            ));
        }
        let state_dir = tokio::fs::canonicalize(state_dir)
            .await
            .map_err(|error| io_status("resolve VM sandbox state directory", error))?;
        let directory = run_directory(&state_dir, &owner.id);
        let metadata = tokio::fs::symlink_metadata(&directory)
            .await
            .map_err(|error| io_status("read VM launcher run directory", error))?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(Status::failed_precondition(
                "VM launcher run directory must be private",
            ));
        }
        Ok(Some(Self {
            state_dir,
            directory,
            owner,
        }))
    }

    pub(super) fn configure(&self, command: &mut Command) {
        command
            .env(RUN_ID_ENV, &self.owner.id)
            .env(RUN_STATE_DIR_ENV, &self.directory);
    }

    pub(super) fn id(&self) -> &str {
        &self.owner.id
    }

    pub(super) fn launcher(&self) -> &Path {
        &self.owner.launcher
    }

    /// A surviving launcher may have no child handle in this driver. The
    /// request reaches that owner without guessing a PID or taking its lock.
    pub(super) async fn request_stop(&self) -> Result<(), Status> {
        let path = self.directory.join(STOP_REQUESTED);
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .await
        {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if read_small_file(&path, 0)
                    .await
                    .map_err(|error| io_status("read VM launcher stop request", error))?
                    .is_none()
                {
                    return Err(Status::failed_precondition(
                        "VM launcher stop request disappeared",
                    ));
                }
            }
            Err(error) => return Err(io_status("persist VM launcher stop request", error)),
        }
        sync_directory(&self.directory).await
    }

    pub(super) async fn require_complete(&self) -> Result<(), Status> {
        let id = &self.owner.id;
        let status = read_small_file(&self.directory.join(STATUS_FILE), 64)
            .await
            .map_err(|error| io_status(&format!("read VM launcher run {id} status"), error))?;
        match status
            .as_deref()
            .map(|status| status.strip_suffix(b"\n").unwrap_or(status))
        {
            Some(b"complete") => Ok(()),
            Some(b"compute-stopped") => Err(Status::unavailable(format!(
                "VM launcher run {id}: compute stopped, resource cleanup pending; retry Stop or Delete"
            ))),
            Some(b"cleanup-failed") => Err(Status::failed_precondition(format!(
                "VM launcher run {id}: compute stopped, resource cleanup failed; retry Stop or Delete"
            ))),
            Some(_) => Err(Status::failed_precondition(format!(
                "VM launcher run {id}: invalid cleanup status, compute exit unconfirmed; retry Stop or Delete"
            ))),
            None => Err(Status::unavailable(format!(
                "VM launcher run {id}: compute exit unconfirmed; retry Stop or Delete"
            ))),
        }
    }

    pub(super) async fn recover(&self, launcher: &Path, budget: Duration) -> Result<(), Status> {
        let Err(pending) = self.require_complete().await else {
            return Ok(());
        };
        if budget.is_zero() {
            return Err(pending);
        }
        let id = &self.owner.id;
        let launcher = tokio::fs::canonicalize(launcher)
            .await
            .map_err(|error| io_status(&format!("resolve VM launcher for run {id}"), error))?;
        if launcher != self.owner.launcher {
            return Err(Status::failed_precondition(format!(
                "VM launcher changed while run {id} owns resources; restore the original launcher and retry Stop or Delete"
            )));
        }
        let mut command = Command::new(&launcher);
        self.configure(&mut command);
        let mut child = command
            .arg("--internal-cleanup-vm")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(false)
            .spawn()
            .map_err(|error| {
                io_status(&format!("start VM launcher cleanup for run {id}"), error)
            })?;
        // The launcher owns its per-run lock. Returning to the caller must not
        // interrupt cleanup or allow another invocation to race the same run.
        match tokio::time::timeout(budget, child.wait()).await {
            Ok(Ok(exit)) => self.require_complete().await.map_err(|status| {
                if exit.success() {
                    status
                } else {
                    Status::new(status.code(), format!("{} ({exit})", status.message()))
                }
            }),
            Ok(Err(error)) => Err(io_status(
                &format!("wait for VM launcher cleanup for run {id}"),
                error,
            )),
            Err(_) => self.require_complete().await.map_err(|status| {
                Status::deadline_exceeded(format!(
                    "VM launcher cleanup deadline elapsed; {}",
                    status.message()
                ))
            }),
        }
    }

    /// The caller holds the sandbox operation lock. Confirm owner release
    /// before removing recovery state, and never unlink a newer journal.
    pub(super) async fn retire(self) -> Result<(), Status> {
        self.require_complete().await?;
        let current = Self::load(&self.state_dir).await?;
        if current.as_ref().map(|run| &run.owner) != Some(&self.owner) {
            return Err(Status::failed_precondition(
                "active VM launcher run changed during cleanup",
            ));
        }
        tokio::fs::remove_file(self.state_dir.join(ACTIVE_FILE))
            .await
            .map_err(|error| io_status("retire VM launcher ownership", error))?;
        sync_directory(&self.state_dir).await?;
        if let Err(error) = tokio::fs::remove_dir_all(&self.directory).await {
            tracing::warn!(run_id = %self.owner.id, %error, "remove completed VM launcher state");
        }
        Ok(())
    }
}

/// Serialize host operations on the stable sandbox path across driver calls.
/// Keep the lock file in place until the entire sandbox state is removed.
#[allow(clippy::result_large_err)]
pub(super) fn lock(state_dir: &Path) -> Result<fs::File, Status> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(state_dir.join(OPERATION_LOCK))
        .map_err(|error| io_status("open VM launcher operation lock", error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_status("inspect VM launcher operation lock", error))?;
    if !metadata.is_file() {
        return Err(Status::failed_precondition(
            "VM launcher operation lock must be a regular file",
        ));
    }
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(Status::unavailable(
            "VM launcher operation already in progress; retry",
        )),
        Err(error) => Err(io_status("lock VM launcher operation", error)),
    }
}

fn run_directory(state_dir: &Path, id: &str) -> PathBuf {
    state_dir.join(format!("launcher-run-{id}"))
}

async fn sync_directory(path: &Path) -> Result<(), Status> {
    let directory = tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .await
        .map_err(|error| io_status("open VM launcher state directory", error))?;
    directory
        .sync_all()
        .await
        .map_err(|error| io_status("sync VM launcher state directory", error))
}

async fn read_small_file(path: &Path, limit: u64) -> io::Result<Option<Vec<u8>>> {
    let file = match tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .await
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !file.metadata().await?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    let mut data = Vec::new();
    file.take(limit + 1).read_to_end(&mut data).await?;
    if data.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file is too large",
        ));
    }
    Ok(Some(data))
}

fn io_status(operation: &str, error: impl std::fmt::Display) -> Status {
    Status::failed_precondition(format!("{operation}: {error}"))
}
