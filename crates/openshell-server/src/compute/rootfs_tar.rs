// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-owned staging slots for rootfs tar archives.
//!
//! A sandbox created from a flat rootfs tar needs the archive on the gateway
//! host before the compute driver can turn it into a disk. Callers never name
//! that location. The gateway allocates a request-scoped directory inside the
//! driver-advertised staging root and hands back an opaque single-use token;
//! `CreateSandbox` carries the token, and the gateway substitutes the resolved
//! path into the driver-native request. A caller-supplied `rootfs_tar_path` is
//! rejected outright during request validation, so a raw host path can never
//! reach the privileged driver.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use openshell_core::time::now_ms;
use rand::RngCore;
use tonic::Status;
use tracing::{info, warn};

/// How long an allocated slot survives without being consumed.
const STAGING_TOKEN_TTL: Duration = Duration::from_secs(30 * 60);
/// Outstanding slots one caller may hold. Bounds the directories a single
/// authenticated caller can create by calling `begin` in a loop.
const MAX_SLOTS_PER_CALLER: usize = 4;
/// Outstanding slots across all callers. Per-caller alone would let enough
/// distinct callers exhaust the staging filesystem; a global cap alone would
/// let one caller starve everyone else.
const MAX_TOTAL_SLOTS: usize = 64;
const STAGING_DIR_PREFIX: &str = "req-";
const MAX_STAGED_FILE_NAME_LEN: usize = 128;

/// `driver_config.<driver>` key the CLI sets to redeem a staging slot.
pub const STAGING_TOKEN_FIELD: &str = "rootfs_tar_staging_token";
/// `driver_config.<driver>` key the gateway substitutes for the driver. Callers
/// may never set this themselves.
pub const ROOTFS_TAR_PATH_FIELD: &str = "rootfs_tar_path";

/// Deliberately identical for unknown and expired tokens: distinguishing them
/// would let a caller probe which tokens exist.
fn unknown_token() -> Status {
    Status::failed_precondition(
        "rootfs tar staging token is unknown or expired; re-stage the archive",
    )
}

/// A slot handed back to the client by `BeginRootfsTarStaging`.
#[derive(Debug, Clone)]
pub struct StagingSlot {
    pub token: String,
    pub upload_path: PathBuf,
    pub max_bytes: u64,
    pub expires_at_ms: i64,
}

#[derive(Debug)]
struct StagingEntry {
    dir: PathBuf,
    file: PathBuf,
    workspace: String,
    subject: String,
    expires_at: Instant,
}

/// Ownership of a consumed staging directory.
///
/// Removes the directory on drop so every failure path after the token is
/// consumed cleans up, unless [`StagedRootfsTar::disarm`] has transferred
/// ownership to the driver (which deletes it once the archive is extracted).
#[derive(Debug)]
pub struct StagedRootfsTar {
    path: PathBuf,
    dir: Option<PathBuf>,
}

impl StagedRootfsTar {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Hand the directory to the driver, which removes it after staging.
    pub fn disarm(&mut self) {
        self.dir = None;
    }
}

impl Drop for StagedRootfsTar {
    fn drop(&mut self) {
        let Some(dir) = self.dir.take() else {
            return;
        };
        // Unlinking is a syscall, but a multi-GiB file makes it worth keeping
        // off a reactor thread.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(move || remove_staging_dir(&dir));
            }
            Err(_) => remove_staging_dir(&dir),
        }
    }
}

fn remove_staging_dir(dir: &Path) {
    if let Err(err) = std::fs::remove_dir_all(dir)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        warn!(
            dir = %dir.display(),
            error = %err,
            "Failed to remove rootfs tar staging directory"
        );
    }
}

/// Request-scoped staging slots, keyed by opaque single-use token.
#[derive(Debug)]
pub struct RootfsTarStagingRegistry {
    /// `None` when the active driver does not support rootfs tar sources.
    staging_root: Option<PathBuf>,
    max_bytes: u64,
    entries: Mutex<HashMap<String, StagingEntry>>,
    ttl: Duration,
}

impl RootfsTarStagingRegistry {
    pub fn new(staging_root: Option<PathBuf>, max_bytes: u64) -> Self {
        Self::with_ttl(staging_root, max_bytes, STAGING_TOKEN_TTL)
    }

    fn with_ttl(staging_root: Option<PathBuf>, max_bytes: u64, ttl: Duration) -> Self {
        Self {
            staging_root,
            max_bytes,
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Registry for a driver that does not accept rootfs tar sources.
    #[cfg(test)]
    pub fn disabled() -> Self {
        Self::new(None, 0)
    }

    /// Allocate a request-scoped directory and return its single-use token.
    pub fn begin(
        &self,
        workspace: &str,
        subject: &str,
        file_name: &str,
        size_bytes: u64,
    ) -> Result<StagingSlot, Status> {
        let Some(staging_root) = self.staging_root.as_ref() else {
            return Err(Status::failed_precondition(
                "the active compute driver does not support rootfs tar sources",
            ));
        };

        if self.max_bytes > 0 && size_bytes > self.max_bytes {
            return Err(Status::invalid_argument(format!(
                "rootfs tar is {size_bytes} bytes, exceeding the driver limit of {} bytes",
                self.max_bytes
            )));
        }

        let file_name = sanitize_staged_file_name(file_name)?;

        let mut entries = self.entries.lock().expect("staging registry poisoned");
        Self::purge_expired(&mut entries);
        if entries.len() >= MAX_TOTAL_SLOTS {
            return Err(Status::resource_exhausted(
                "the gateway has too many outstanding rootfs tar staging slots; retry shortly",
            ));
        }
        let held_by_caller = entries
            .values()
            .filter(|entry| entry.workspace == workspace && entry.subject == subject)
            .count();
        if held_by_caller >= MAX_SLOTS_PER_CALLER {
            return Err(Status::resource_exhausted(
                "too many outstanding rootfs tar staging slots; retry once an earlier create completes",
            ));
        }

        // The directory name uses independent randomness so the token never
        // appears in a filesystem path, a directory listing, or a log field.
        let dir = staging_root.join(format!("{STAGING_DIR_PREFIX}{}", uuid::Uuid::new_v4()));
        create_private_dir(&dir).map_err(|err| {
            Status::internal(format!(
                "failed to create rootfs tar staging directory: {err}"
            ))
        })?;

        let file = dir.join(&file_name);
        let token = new_staging_token();
        let expires_at = Instant::now() + self.ttl;
        let expires_at_ms = now_ms() + i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX);

        entries.insert(
            token.clone(),
            StagingEntry {
                dir,
                file: file.clone(),
                workspace: workspace.to_string(),
                subject: subject.to_string(),
                expires_at,
            },
        );

        Ok(StagingSlot {
            token,
            upload_path: file,
            max_bytes: self.max_bytes,
            expires_at_ms,
        })
    }

    /// Confirm the token belongs to this caller. Does not consume it.
    ///
    /// This is what stops one caller redeeming a slot minted for another.
    pub fn authorize(&self, token: &str, workspace: &str, subject: &str) -> Result<(), Status> {
        let mut entries = self.entries.lock().expect("staging registry poisoned");
        Self::purge_expired(&mut entries);
        let entry = entries.get(token).ok_or_else(unknown_token)?;
        if entry.workspace != workspace || entry.subject != subject {
            return Err(Status::permission_denied(
                "rootfs tar staging token was issued to a different caller",
            ));
        }
        Ok(())
    }

    /// Resolve the staged path without consuming the token, for validation.
    pub fn peek(&self, token: &str) -> Result<PathBuf, Status> {
        let mut entries = self.entries.lock().expect("staging registry poisoned");
        Self::purge_expired(&mut entries);
        let entry = entries.get(token).ok_or_else(unknown_token)?;
        Ok(entry.file.clone())
    }

    /// Consume the token. A second redemption of the same token fails.
    pub fn consume(&self, token: &str) -> Result<StagedRootfsTar, Status> {
        let mut entries = self.entries.lock().expect("staging registry poisoned");
        Self::purge_expired(&mut entries);
        let entry = entries.remove(token).ok_or_else(unknown_token)?;
        drop(entries);

        if !entry.file.is_file() {
            // Nothing was uploaded, or it was replaced by a directory or link.
            remove_staging_dir(&entry.dir);
            return Err(Status::failed_precondition(format!(
                "no rootfs tar archive was uploaded to the staging slot at {}",
                entry.file.display()
            )));
        }

        Ok(StagedRootfsTar {
            path: entry.file,
            dir: Some(entry.dir),
        })
    }

    fn purge_expired(entries: &mut HashMap<String, StagingEntry>) {
        let now = Instant::now();
        let expired: Vec<String> = entries
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(token, _)| token.clone())
            .collect();
        for token in expired {
            if let Some(entry) = entries.remove(&token) {
                remove_staging_dir(&entry.dir);
            }
        }
    }

    /// Remove request directories nothing owns any more.
    ///
    /// Runs at startup and on each reconcile sweep. It catches two cases the
    /// token table cannot: directories left by a previous gateway process, and
    /// directories whose token was consumed but whose driver failed before it
    /// reached its own cleanup.
    ///
    /// Age-gated rather than an unconditional wipe, because a driver can still
    /// be copying a multi-gigabyte archive out of a directory whose gateway
    /// already restarted.
    pub fn sweep_orphans(&self) {
        let Some(staging_root) = self.staging_root.as_ref() else {
            return;
        };
        let Ok(read_dir) = std::fs::read_dir(staging_root) else {
            return;
        };

        let mut removed = 0usize;
        for entry in read_dir.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with(STAGING_DIR_PREFIX) {
                continue;
            }
            let stale = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .is_ok_and(|modified| modified.elapsed().is_ok_and(|age| age > self.ttl));
            if stale {
                remove_staging_dir(&entry.path());
                removed += 1;
            }
        }

        if removed > 0 {
            info!(
                removed,
                staging_root = %staging_root.display(),
                "Removed orphaned rootfs tar staging directories"
            );
        }
    }
}

fn new_staging_token() -> String {
    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    hex::encode(raw)
}

/// Reject anything that would let `dir.join(file_name)` escape the request
/// directory. This is the check that makes the joined path safe to trust.
fn sanitize_staged_file_name(file_name: &str) -> Result<String, Status> {
    let invalid = |reason: &str| Status::invalid_argument(format!("rootfs tar file_name {reason}"));

    if file_name.is_empty() {
        return Err(invalid("must not be empty"));
    }
    if file_name.len() > MAX_STAGED_FILE_NAME_LEN {
        return Err(invalid(&format!(
            "must be at most {MAX_STAGED_FILE_NAME_LEN} bytes"
        )));
    }
    if file_name.contains('/') || file_name.contains('\\') || file_name.contains('\0') {
        return Err(invalid("must not contain path separators"));
    }
    if file_name.starts_with('.') {
        return Err(invalid("must not start with '.'"));
    }

    let path = Path::new(file_name);
    let mut components = path.components();
    let Some(Component::Normal(only)) = components.next() else {
        return Err(invalid("must be a plain file name"));
    };
    if components.next().is_some() {
        return Err(invalid("must be a plain file name"));
    }
    if only != file_name {
        return Err(invalid("must be a plain file name"));
    }

    Ok(file_name.to_string())
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    fn registry(root: &Path) -> RootfsTarStagingRegistry {
        RootfsTarStagingRegistry::new(Some(root.to_path_buf()), 1024)
    }

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("create staging root")
    }

    fn upload(slot: &StagingSlot, contents: &[u8]) {
        std::fs::write(&slot.upload_path, contents).expect("write staged archive");
    }

    #[test]
    fn begin_allocates_private_request_dir_and_hides_the_token() {
        let root = temp_root();
        let registry = registry(root.path());

        let slot = registry
            .begin("default", "alice", "rootfs.tar", 128)
            .expect("slot allocated");

        let dir = slot.upload_path.parent().expect("upload dir");
        assert!(dir.starts_with(root.path()));
        assert!(
            dir.file_name()
                .and_then(|n| n.to_str())
                .expect("dir name")
                .starts_with(STAGING_DIR_PREFIX)
        );
        assert_eq!(slot.upload_path.file_name().unwrap(), "rootfs.tar");
        assert!(
            !slot.upload_path.to_string_lossy().contains(&slot.token),
            "the token must not be recoverable from a directory listing"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir)
                .expect("dir metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn begin_rejects_oversized_archive_before_allocating() {
        let root = temp_root();
        let registry = registry(root.path());

        let err = registry
            .begin("default", "alice", "rootfs.tar", 4096)
            .expect_err("oversized archive rejected");

        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            std::fs::read_dir(root.path()).unwrap().count(),
            0,
            "nothing may be allocated for a rejected request"
        );
    }

    /// `dir.join(file_name)` must not be able to escape the request directory.
    #[test]
    fn begin_rejects_traversal_file_names() {
        let root = temp_root();
        let registry = registry(root.path());

        let too_long = "x".repeat(MAX_STAGED_FILE_NAME_LEN + 1);
        for name in [
            "../../etc/passwd",
            "a/b.tar",
            "..",
            "",
            "\\evil.tar",
            ".hidden.tar",
            too_long.as_str(),
        ] {
            let err = match registry.begin("default", "alice", name, 16) {
                Ok(slot) => panic!("expected rejection for {name:?}, allocated {slot:?}"),
                Err(err) => err,
            };
            assert_eq!(err.code(), Code::InvalidArgument, "{name:?}: {err}");
        }

        assert_eq!(
            std::fs::read_dir(root.path()).unwrap().count(),
            0,
            "a rejected file name must not leave a directory behind"
        );
    }

    #[test]
    fn begin_rejects_when_driver_has_no_staging_dir() {
        let registry = RootfsTarStagingRegistry::disabled();

        let err = registry
            .begin("default", "alice", "rootfs.tar", 16)
            .expect_err("a driver without tar support rejects staging");

        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    #[test]
    fn begin_bounds_outstanding_slots_per_caller() {
        let root = temp_root();
        let registry = registry(root.path());

        for _ in 0..MAX_SLOTS_PER_CALLER {
            registry
                .begin("default", "alice", "rootfs.tar", 16)
                .expect("slot allocated");
        }

        let err = registry
            .begin("default", "alice", "rootfs.tar", 16)
            .expect_err("one caller's outstanding slots are bounded");
        assert_eq!(err.code(), Code::ResourceExhausted);
    }

    /// The per-caller cap must not become a way for one caller to lock others
    /// out of the feature.
    #[test]
    fn one_caller_at_its_cap_does_not_block_another() {
        let root = temp_root();
        let registry = registry(root.path());

        for _ in 0..MAX_SLOTS_PER_CALLER {
            registry
                .begin("default", "alice", "rootfs.tar", 16)
                .expect("slot allocated");
        }

        registry
            .begin("default", "bob", "rootfs.tar", 16)
            .expect("a different caller is unaffected");
        registry
            .begin("other-workspace", "alice", "rootfs.tar", 16)
            .expect("the same caller in another workspace is unaffected");
    }

    /// The replay regression test: a token redeemed twice must fail.
    #[test]
    fn consume_is_single_use() {
        let root = temp_root();
        let registry = registry(root.path());
        let slot = registry
            .begin("default", "alice", "rootfs.tar", 16)
            .expect("slot allocated");
        upload(&slot, b"payload");

        let mut staged = registry.consume(&slot.token).expect("first consume");
        staged.disarm();

        let err = registry
            .consume(&slot.token)
            .expect_err("a staging token may only be redeemed once");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    /// Validation peeks and creation consumes; peeking must not burn the token.
    #[test]
    fn peek_does_not_consume() {
        let root = temp_root();
        let registry = registry(root.path());
        let slot = registry
            .begin("default", "alice", "rootfs.tar", 16)
            .expect("slot allocated");
        upload(&slot, b"payload");

        assert_eq!(registry.peek(&slot.token).unwrap(), slot.upload_path);
        assert_eq!(registry.peek(&slot.token).unwrap(), slot.upload_path);

        let mut staged = registry.consume(&slot.token).expect("consume after peeks");
        staged.disarm();
    }

    #[test]
    fn unknown_token_is_rejected_the_same_way_as_an_expired_one() {
        let root = temp_root();
        let registry = registry(root.path());

        let unknown = registry
            .consume(&"0".repeat(64))
            .expect_err("unknown token");

        let expiring = RootfsTarStagingRegistry::with_ttl(
            Some(root.path().to_path_buf()),
            1024,
            Duration::ZERO,
        );
        let slot = expiring
            .begin("default", "alice", "rootfs.tar", 16)
            .expect("slot allocated");
        upload(&slot, b"payload");
        let expired = expiring.consume(&slot.token).expect_err("expired token");

        assert_eq!(unknown.code(), expired.code());
        assert_eq!(unknown.message(), expired.message());
    }

    #[test]
    fn expired_slot_directory_is_removed() {
        let root = temp_root();
        let registry = RootfsTarStagingRegistry::with_ttl(
            Some(root.path().to_path_buf()),
            1024,
            Duration::ZERO,
        );
        let slot = registry
            .begin("default", "alice", "rootfs.tar", 16)
            .expect("slot allocated");
        upload(&slot, b"payload");
        let dir = slot.upload_path.parent().unwrap().to_path_buf();

        let _ = registry.consume(&slot.token);

        assert!(!dir.exists(), "an expired slot must not leave data behind");
    }

    /// The cross-request regression test the review asked for by name.
    #[test]
    fn authorize_rejects_another_caller() {
        let root = temp_root();
        let registry = registry(root.path());
        let slot = registry
            .begin("team-a", "alice", "rootfs.tar", 16)
            .expect("slot allocated");

        for (workspace, subject) in [("team-b", "alice"), ("team-a", "bob")] {
            let err = registry
                .authorize(&slot.token, workspace, subject)
                .expect_err("a token minted for another caller must be refused");
            assert_eq!(err.code(), Code::PermissionDenied);
        }

        registry
            .authorize(&slot.token, "team-a", "alice")
            .expect("the rightful owner still holds the slot");
    }

    #[test]
    fn consume_rejects_a_slot_that_was_never_uploaded_to() {
        let root = temp_root();
        let registry = registry(root.path());
        let slot = registry
            .begin("default", "alice", "rootfs.tar", 16)
            .expect("slot allocated");

        let err = registry
            .consume(&slot.token)
            .expect_err("an empty slot cannot be created from");

        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    #[test]
    fn staged_guard_removes_directory_unless_disarmed() {
        let root = temp_root();
        let registry = registry(root.path());

        let slot = registry
            .begin("default", "alice", "rootfs.tar", 16)
            .expect("slot allocated");
        upload(&slot, b"payload");
        let dir = slot.upload_path.parent().unwrap().to_path_buf();
        drop(registry.consume(&slot.token).expect("consume"));
        assert!(!dir.exists(), "dropping the guard must clean up");

        let slot = registry
            .begin("default", "alice", "rootfs.tar", 16)
            .expect("slot allocated");
        upload(&slot, b"payload");
        let dir = slot.upload_path.parent().unwrap().to_path_buf();
        let mut staged = registry.consume(&slot.token).expect("consume");
        staged.disarm();
        drop(staged);
        assert!(
            dir.exists(),
            "a disarmed guard leaves the dir to the driver"
        );
    }

    #[test]
    fn orphan_sweep_removes_only_stale_request_dirs() {
        let root = temp_root();
        let stale = root.path().join("req-stale");
        let fresh = root.path().join("req-fresh");
        let unrelated = root.path().join("keep-me");
        for dir in [&stale, &fresh, &unrelated] {
            std::fs::create_dir(dir).expect("create dir");
        }

        // A long TTL means nothing on disk has aged out yet. This is what keeps
        // a restart from wiping a directory the driver is still copying from.
        let young = RootfsTarStagingRegistry::new(Some(root.path().to_path_buf()), 1024);
        young.sweep_orphans();
        assert!(stale.exists() && fresh.exists() && unrelated.exists());

        // A zero TTL ages everything out, but only request directories are ours.
        let aged = RootfsTarStagingRegistry::with_ttl(
            Some(root.path().to_path_buf()),
            1024,
            Duration::ZERO,
        );
        aged.sweep_orphans();

        assert!(!stale.exists());
        assert!(!fresh.exists());
        assert!(unrelated.exists(), "unrelated entries must be left alone");
    }
}
