// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
#[cfg(test)]
use std::io::BufWriter;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

const SANDBOX: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/openshell-sandbox.zst"));
const SUPERVISOR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/openshell-supervisor.zst"));
const SUPERVISOR_RUNTIME: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/openshell-runtime.tar.zst"));
const UMOCI: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/umoci.zst"));
const ROOTFS_VARIANT_MARKER: &str = ".openshell-rootfs-variant";
const SANDBOX_GUEST_INIT_PATH: &str = "/srv/openshell-vm-sandbox-init.sh";
const SANDBOX_SUPERVISOR_PATH: &str = openshell_core::driver_utils::SUPERVISOR_CONTAINER_BINARY;
const SANDBOX_UMOCI_PATH: &str = openshell_core::container_paths::VM_UMOCI_PATH;
const SANDBOX_OWNER_NORMALIZED_MARKER: &str =
    openshell_core::container_paths::VM_SANDBOX_OWNER_NORMALIZED_MARKER;
const SANDBOX_SUPERVISOR_RUNTIME_PATH: &str = "/opt/openshell/bin/openshell-runtime";
const ROOTFS_IMAGE_MIN_SIZE_BYTES: u64 = 512 * 1024 * 1024;
const ROOTFS_IMAGE_MIN_HEADROOM_BYTES: u64 = 256 * 1024 * 1024;
const EXT4_IMAGE_MIN_HEADROOM_BYTES: u64 = 16 * 1024 * 1024;
static INJECTION_COUNTER: AtomicU64 = AtomicU64::new(0);

pub const fn sandbox_guest_init_path() -> &'static str {
    SANDBOX_GUEST_INIT_PATH
}

/// Identity of every embedded artifact materialized into a bootstrap rootfs.
///
/// Including this in the image-cache key makes local, uncommitted guest-sandbox
/// changes invalidate the cache even when the `OpenShell` version is unchanged.
pub fn sandbox_guest_runtime_identity() -> String {
    let mut hasher = Sha256::new();
    hasher.update(SANDBOX);
    hasher.update(SUPERVISOR_RUNTIME);
    hasher.update(UMOCI);
    hasher.update(include_bytes!("../scripts/openshell-vm-sandbox-init.sh"));
    format!("{:x}", hasher.finalize())
}

/// Materialize the supervisor embedded in the VM driver for host-side use.
#[cfg(target_os = "linux")]
pub fn extract_host_supervisor(path: &Path) -> Result<(), String> {
    if SANDBOX.is_empty() {
        return Err(
            "host supervisor is not embedded; run `mise run vm:supervisor` and rebuild openshell-driver-vm"
                .to_string(),
        );
    }
    let supervisor = embedded_host_supervisor()?;
    install_host_supervisor_atomically(path, &supervisor)?;
    validate_host_supervisor(path)
}

#[cfg(target_os = "linux")]
pub fn validate_host_supervisor(path: &Path) -> Result<(), String> {
    validate_host_supervisor_digest(path, embedded_host_supervisor_digest()?)
}

#[cfg(target_os = "linux")]
fn validate_host_supervisor_digest(path: &Path, expected: [u8; 32]) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect cached host supervisor {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "cached host supervisor is not a regular file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(format!(
                "cached host supervisor is not executable: {}",
                path.display()
            ));
        }
    }
    let actual = sha256_reader(
        File::open(path)
            .map_err(|error| format!("open cached host supervisor {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("hash cached host supervisor {}: {error}", path.display()))?;
    if actual != expected {
        return Err(format!(
            "cached host supervisor content does not match embedded runtime: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn embedded_host_supervisor() -> Result<Vec<u8>, String> {
    zstd::decode_all(Cursor::new(SUPERVISOR))
        .map_err(|error| format!("decompress host supervisor: {error}"))
}

#[cfg(target_os = "linux")]
fn embedded_host_supervisor_digest() -> Result<[u8; 32], String> {
    static DIGEST: OnceLock<Result<[u8; 32], String>> = OnceLock::new();
    DIGEST
        .get_or_init(|| embedded_host_supervisor().map(|bytes| sha256_bytes(&bytes)))
        .clone()
}

#[cfg(target_os = "linux")]
fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(target_os = "linux")]
fn sha256_reader(mut reader: impl Read) -> std::io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(target_os = "linux")]
fn install_host_supervisor_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| format!("host supervisor path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| format!("create {}: {error}", parent.display()))?;
    let temporary = parent.join(format!(
        ".openshell-sandbox.tmp-{}-{}",
        std::process::id(),
        INJECTION_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o755);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| format!("create {}: {error}", temporary.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync {}: {error}", temporary.display()))?;
        fs::rename(&temporary, path).map_err(|error| {
            format!(
                "commit cached host supervisor {} to {}: {error}",
                temporary.display(),
                path.display()
            )
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("sync host supervisor cache {}: {error}", parent.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[allow(clippy::similar_names)]
pub fn prepare_sandbox_rootfs_from_image_root(
    rootfs: &Path,
    image_identity: &str,
    sandbox_uid: u32,
    sandbox_gid: u32,
) -> Result<(), String> {
    prepare_sandbox_rootfs(rootfs, sandbox_uid, sandbox_gid)?;
    validate_sandbox_rootfs(rootfs)?;
    fs::write(
        rootfs.join(ROOTFS_VARIANT_MARKER),
        format!("{}:image:{image_identity}\n", env!("CARGO_PKG_VERSION")),
    )
    .map_err(|e| format!("write rootfs variant marker: {e}"))?;
    Ok(())
}

pub fn extract_rootfs_archive_to(archive_path: &Path, dest: &Path) -> Result<(), String> {
    if dest.exists() {
        fs::remove_dir_all(dest)
            .map_err(|e| format!("remove old rootfs {}: {e}", dest.display()))?;
    }

    fs::create_dir_all(dest).map_err(|e| format!("create rootfs dir {}: {e}", dest.display()))?;
    let file =
        File::open(archive_path).map_err(|e| format!("open {}: {e}", archive_path.display()))?;
    let mut archive = tar::Archive::new(file);
    archive
        .unpack(dest)
        .map_err(|e| format!("extract rootfs tarball into {}: {e}", dest.display()))
}

#[cfg(test)]
pub fn create_rootfs_archive_from_dir(source: &Path, archive_path: &Path) -> Result<(), String> {
    if let Some(parent) = archive_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }

    let file = File::create(archive_path)
        .map_err(|e| format!("create {}: {e}", archive_path.display()))?;
    let writer = BufWriter::new(file);
    let mut builder = tar::Builder::new(writer);
    append_rootfs_tree_to_archive(&mut builder, source, Path::new("")).map_err(|e| {
        format!(
            "archive {} into {}: {e}",
            source.display(),
            archive_path.display()
        )
    })?;
    builder
        .finish()
        .map_err(|e| format!("finalize {}: {e}", archive_path.display()))
}

pub fn create_rootfs_image_from_dir(source: &Path, image_path: &Path) -> Result<(), String> {
    let image_size = rootfs_image_size_bytes(source)?;
    create_ext4_image_from_dir_with_size(source, image_path, image_size)?;
    if let Err(err) = normalize_sandbox_owner_in_rootfs_image(source, image_path) {
        let _ = fs::remove_file(image_path);
        return Err(err);
    }
    Ok(())
}

pub fn create_ext4_image_from_dir_with_size(
    source: &Path,
    image_path: &Path,
    image_size: u64,
) -> Result<(), String> {
    if let Some(parent) = image_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    if image_path.exists() {
        fs::remove_file(image_path)
            .map_err(|e| format!("remove old rootfs image {}: {e}", image_path.display()))?;
    }

    let required_size = ext4_image_min_size_bytes(source)?;
    if image_size < required_size {
        return Err(format!(
            "ext4 image size {} bytes is too small for {} (requires at least {} bytes)",
            image_size,
            source.display(),
            required_size
        ));
    }

    let image = File::create(image_path)
        .map_err(|e| format!("create rootfs image {}: {e}", image_path.display()))?;
    image
        .set_len(image_size)
        .map_err(|e| format!("size rootfs image {}: {e}", image_path.display()))?;
    drop(image);

    if let Err(err) = format_ext4_image_from_dir(source, image_path) {
        let _ = fs::remove_file(image_path);
        return Err(err);
    }

    Ok(())
}

pub fn clone_or_copy_sparse_file(source: &Path, dest: &Path) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    if dest.exists() {
        fs::remove_file(dest).map_err(|e| format!("remove old file {}: {e}", dest.display()))?;
    }

    let clone_error = match try_clone_file(source, dest) {
        Ok(()) => return Ok(()),
        Err(err) => {
            let _ = fs::remove_file(dest);
            err
        }
    };

    copy_sparse_file(source, dest).map_err(|copy_error| {
        format!(
            "clone {} to {} failed ({clone_error}); sparse copy failed: {copy_error}",
            source.display(),
            dest.display()
        )
    })
}

pub fn write_rootfs_image_file(
    image_path: &Path,
    guest_path: &str,
    contents: &[u8],
) -> Result<(), String> {
    ensure_rootfs_image_parent_dirs(image_path, guest_path);

    let tmp_path = temporary_injection_path(image_path);
    fs::write(&tmp_path, contents).map_err(|e| format!("write {}: {e}", tmp_path.display()))?;
    let Some(quoted_guest_path) = debugfs_quote_absolute_path(guest_path) else {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("invalid debugfs guest path '{guest_path}'"));
    };
    let Some(quoted_tmp_path) = debugfs_quote_argument(&tmp_path.to_string_lossy()) else {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "invalid debugfs injection path '{}'",
            tmp_path.display()
        ));
    };
    let _ = run_debugfs(image_path, &format!("rm {quoted_guest_path}"));
    let result = run_debugfs(
        image_path,
        &format!("write {quoted_tmp_path} {quoted_guest_path}"),
    );
    let _ = fs::remove_file(&tmp_path);
    result
}

pub fn set_rootfs_image_file_mode(
    image_path: &Path,
    guest_path: &str,
    mode: u32,
) -> Result<(), String> {
    let regular_file_mode = 0o100_000 | (mode & 0o7777);
    let Some(quoted_guest_path) = debugfs_quote_absolute_path(guest_path) else {
        return Err(format!("invalid debugfs guest path '{guest_path}'"));
    };
    run_debugfs(
        image_path,
        &format!("set_inode_field {quoted_guest_path} mode 0{regular_file_mode:o}"),
    )
}

/// Replay the ext4 journal and repair automatically correctable filesystem
/// state before the driver mutates a preserved guest disk offline.
pub fn recover_rootfs_image(image_path: &Path) -> Result<(), String> {
    let mut failures = Vec::new();
    let mut unavailable = Vec::new();

    for candidate in e2fs_tool_candidates("e2fsck") {
        let label = candidate.display().to_string();
        match Command::new(&candidate)
            .arg("-p")
            .arg("-f")
            .arg(image_path)
            .output()
        {
            Ok(output) if matches!(output.status.code(), Some(0..=2)) => return Ok(()),
            Ok(output) => failures.push(format!(
                "{label} failed with status {}\nstdout: {}\nstderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                unavailable.push(format!("{label} not found"));
            }
            Err(error) => failures.push(format!("run {label}: {error}")),
        }
    }

    Err(if failures.is_empty() {
        unavailable.join("\n")
    } else {
        failures.join("\n")
    })
}

#[cfg(target_os = "macos")]
fn try_clone_file(source: &Path, dest: &Path) -> Result<(), String> {
    let output = Command::new("cp")
        .arg("-c")
        .arg(source)
        .arg(dest)
        .output()
        .map_err(|e| format!("run cp -c: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "cp -c failed with status {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

#[cfg(target_os = "linux")]
fn try_clone_file(source: &Path, dest: &Path) -> Result<(), String> {
    let output = Command::new("cp")
        .arg("--reflink=auto")
        .arg("--sparse=always")
        .arg(source)
        .arg(dest)
        .output()
        .map_err(|e| format!("run cp --reflink=auto: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "cp --reflink=auto --sparse=always failed with status {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn try_clone_file(_source: &Path, _dest: &Path) -> Result<(), String> {
    Err("no platform clone command available".to_string())
}

fn copy_sparse_file(source: &Path, dest: &Path) -> Result<(), String> {
    const BUFFER_SIZE: usize = 1024 * 1024;

    let mut source_file =
        File::open(source).map_err(|e| format!("open {}: {e}", source.display()))?;
    let mut dest_file =
        File::create(dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut size = 0_u64;

    loop {
        let read = source_file
            .read(&mut buffer)
            .map_err(|e| format!("read {}: {e}", source.display()))?;
        if read == 0 {
            break;
        }

        if buffer[..read].iter().all(|byte| *byte == 0) {
            let skip =
                i64::try_from(read).map_err(|_| format!("sparse copy chunk too large: {read}"))?;
            dest_file
                .seek(SeekFrom::Current(skip))
                .map_err(|e| format!("seek {}: {e}", dest.display()))?;
        } else {
            dest_file
                .write_all(&buffer[..read])
                .map_err(|e| format!("write {}: {e}", dest.display()))?;
        }
        size += read as u64;
    }

    dest_file
        .set_len(size)
        .map_err(|e| format!("size {}: {e}", dest.display()))
}

#[cfg(test)]
fn append_rootfs_tree_to_archive(
    builder: &mut tar::Builder<BufWriter<File>>,
    source: &Path,
    archive_prefix: &Path,
) -> Result<(), String> {
    let mut entries = fs::read_dir(source)
        .map_err(|e| format!("read {}: {e}", source.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read {}: {e}", source.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);

    for entry in entries {
        let entry_name = entry.file_name();
        let source_path = entry.path();
        let archive_path = if archive_prefix.as_os_str().is_empty() {
            entry_name.into()
        } else {
            archive_prefix.join(entry_name)
        };
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|e| format!("stat {}: {e}", source_path.display()))?;
        let file_type = metadata.file_type();

        if file_type.is_dir() {
            builder
                .append_dir(&archive_path, &source_path)
                .map_err(|e| format!("append dir {}: {e}", source_path.display()))?;
            append_rootfs_tree_to_archive(builder, &source_path, &archive_path)?;
            continue;
        }

        if file_type.is_file() {
            let mut file = File::open(&source_path)
                .map_err(|e| format!("open {}: {e}", source_path.display()))?;
            builder
                .append_file(&archive_path, &mut file)
                .map_err(|e| format!("append file {}: {e}", source_path.display()))?;
            continue;
        }

        if file_type.is_symlink() {
            append_symlink_to_archive(builder, &source_path, &archive_path, &metadata)?;
            continue;
        }

        return Err(format!(
            "unsupported rootfs entry type at {}",
            source_path.display()
        ));
    }

    Ok(())
}

#[cfg(test)]
fn append_symlink_to_archive(
    builder: &mut tar::Builder<BufWriter<File>>,
    source_path: &Path,
    archive_path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), String> {
    let target = fs::read_link(source_path)
        .map_err(|e| format!("readlink {}: {e}", source_path.display()))?;
    let mut header = tar::Header::new_gnu();
    header.set_metadata(metadata);
    header.set_size(0);
    header.set_cksum();
    builder
        .append_link(&mut header, archive_path, target)
        .map_err(|e| format!("append symlink {}: {e}", source_path.display()))
}

#[allow(clippy::similar_names)]
fn prepare_sandbox_rootfs(rootfs: &Path, sandbox_uid: u32, sandbox_gid: u32) -> Result<(), String> {
    for relative in ["opt/openshell/.initialized", "opt/openshell/.rootfs-type"] {
        remove_rootfs_path(rootfs, relative)?;
    }

    let init_path = rootfs.join("srv/openshell-vm-sandbox-init.sh");
    if let Some(parent) = init_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    fs::write(
        &init_path,
        include_str!("../scripts/openshell-vm-sandbox-init.sh"),
    )
    .map_err(|e| format!("write {}: {e}", init_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(&init_path, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {e}", init_path.display()))?;
    }

    ensure_supervisor_binary(rootfs)?;
    ensure_supervisor_runtime(rootfs)?;
    ensure_guest_init_ip(rootfs)?;
    ensure_umoci_binary(rootfs)?;

    let opt_dir = rootfs.join("opt/openshell");
    fs::create_dir_all(&opt_dir).map_err(|e| format!("create {}: {e}", opt_dir.display()))?;
    fs::write(opt_dir.join(".rootfs-type"), "sandbox\n")
        .map_err(|e| format!("write sandbox rootfs marker: {e}"))?;
    ensure_sandbox_guest_user(rootfs, sandbox_uid, sandbox_gid)?;
    create_sandbox_mountpoint(&rootfs.join("sandbox"))?;
    create_sandbox_mountpoint(&rootfs.join("image-cache"))?;
    create_sandbox_mountpoint(&rootfs.join("lower"))?;
    create_sandbox_mountpoint(&rootfs.join("overlay"))?;
    create_sandbox_mountpoint(&rootfs.join("newroot"))?;

    Ok(())
}

fn ensure_guest_init_ip(rootfs: &Path) -> Result<(), String> {
    const IP_PATHS: [&str; 4] = ["sbin/ip", "usr/sbin/ip", "bin/ip", "usr/bin/ip"];
    if IP_PATHS.iter().any(|path| rootfs.join(path).is_file()) {
        return Ok(());
    }

    // Guest init runs before the sandbox can enter its trusted helper
    // runtime. Images such as stock Ubuntu do not ship iproute2, so install a
    // driver-owned launcher that executes the embedded musl helper explicitly.
    // The helper and loader are both materialized from the trusted runtime,
    // never from the workload image.
    let path = rootfs.join("usr/sbin/ip");
    let parent = path
        .parent()
        .ok_or_else(|| format!("guest ip launcher path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| format!("create {}: {error}", parent.display()))?;
    fs::write(
        &path,
        r#"#!/bin/sh
set -eu
runtime=/opt/openshell/bin/openshell-runtime
for loader in "$runtime"/lib/ld-musl-*.so.1; do
    if [ -x "$loader" ]; then
        for helper in "$runtime"/sbin/ip "$runtime"/usr/sbin/ip "$runtime"/bin/ip "$runtime"/usr/bin/ip; do
            if [ -x "$helper" ]; then
                exec "$loader" --library-path "$runtime/lib:$runtime/usr/lib" "$helper" "$@"
            fi
        done
    fi
done
echo "trusted OpenShell ip helper is unavailable" >&2
exit 127
"#,
    )
    .map_err(|error| format!("write {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("chmod {}: {error}", path.display()))?;
    }
    Ok(())
}

pub fn validate_sandbox_rootfs(rootfs: &Path) -> Result<(), String> {
    require_rootfs_path(rootfs, SANDBOX_GUEST_INIT_PATH)?;
    require_rootfs_path(rootfs, SANDBOX_SUPERVISOR_PATH)?;
    validate_supervisor_runtime(rootfs)?;
    require_rootfs_path(rootfs, SANDBOX_UMOCI_PATH)?;
    require_any_rootfs_path(rootfs, &["/bin/bash"])?;
    require_any_rootfs_path(rootfs, &["/bin/mount", "/usr/bin/mount"])?;
    require_any_rootfs_path(
        rootfs,
        &[
            "/usr/sbin/chroot",
            "/usr/bin/chroot",
            "/sbin/chroot",
            "/bin/chroot",
        ],
    )?;
    require_any_rootfs_path(
        rootfs,
        &["/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"],
    )?;
    require_any_rootfs_path(rootfs, &["/bin/sed", "/usr/bin/sed"])?;
    Ok(())
}

fn create_sandbox_mountpoint(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("create {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    Ok(())
}

fn rootfs_image_size_bytes(source: &Path) -> Result<u64, String> {
    let used = directory_size_bytes(source)?;
    let headroom = (used / 4).max(ROOTFS_IMAGE_MIN_HEADROOM_BYTES);
    let size = (used + headroom).max(ROOTFS_IMAGE_MIN_SIZE_BYTES);
    Ok(round_up_to_mib(size))
}

fn ext4_image_min_size_bytes(source: &Path) -> Result<u64, String> {
    let used = directory_size_bytes(source)?;
    Ok(round_up_to_mib(used + EXT4_IMAGE_MIN_HEADROOM_BYTES))
}

fn directory_size_bytes(path: &Path) -> Result<u64, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
    if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Ok(metadata.len());
    }
    if !metadata.file_type().is_dir() {
        return Ok(0);
    }

    let mut size = 4096;
    for entry in fs::read_dir(path).map_err(|e| format!("read {}: {e}", path.display()))? {
        let entry = entry.map_err(|e| format!("read {}: {e}", path.display()))?;
        size += directory_size_bytes(&entry.path())?;
    }
    Ok(size)
}

fn round_up_to_mib(bytes: u64) -> u64 {
    const MIB: u64 = 1024 * 1024;
    bytes.div_ceil(MIB) * MIB
}

enum FormatterAttempt {
    Succeeded,
    Failed(String),
    Unavailable(String),
}

fn format_ext4_image_from_dir(source: &Path, image_path: &Path) -> Result<(), String> {
    let candidates = ["mke2fs", "mkfs.ext4"]
        .into_iter()
        .flat_map(e2fs_tool_candidates);
    run_ext4_formatter_candidates(candidates, |candidate| {
            let label = candidate.display().to_string();
            let output = Command::new(candidate)
                .arg("-q")
                .arg("-F")
                .arg("-t")
                .arg("ext4")
                .arg("-E")
                .arg("root_owner=0:0")
                .arg("-d")
                .arg(source)
                .arg(image_path)
                .output();
            match output {
                Ok(output) if output.status.success() => FormatterAttempt::Succeeded,
                Ok(output) => FormatterAttempt::Failed(format!(
                        "{label} failed with status {}\nstdout: {}\nstderr: {}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    )),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    FormatterAttempt::Unavailable(format!("{label} not found"))
                }
                Err(err) => FormatterAttempt::Failed(format!("run {label}: {err}")),
            }
        })
        .map_err(|details| {
            format!(
                "failed to create ext4 rootfs image from {}: {details}. Install e2fsprogs (mke2fs/mkfs.ext4) and retry",
                source.display()
            )
        })
}

fn run_ext4_formatter_candidates(
    candidates: impl IntoIterator<Item = PathBuf>,
    mut run: impl FnMut(&Path) -> FormatterAttempt,
) -> Result<(), String> {
    let mut failures = Vec::new();
    let mut unavailable = Vec::new();

    for candidate in candidates {
        match run(&candidate) {
            FormatterAttempt::Succeeded => return Ok(()),
            FormatterAttempt::Failed(error) => failures.push(error),
            FormatterAttempt::Unavailable(error) => unavailable.push(error),
        }
    }

    if failures.is_empty() {
        Err(if unavailable.is_empty() {
            "no ext4 formatter candidates configured".to_string()
        } else {
            unavailable.join("\n")
        })
    } else {
        Err(failures.join("\n"))
    }
}

fn ensure_rootfs_image_parent_dirs(image_path: &Path, guest_path: &str) {
    let Some(parent) = Path::new(guest_path).parent() else {
        return;
    };
    let mut current = String::new();
    for component in parent.components() {
        let part = component.as_os_str().to_string_lossy();
        if part == "/" || part.is_empty() {
            continue;
        }
        current.push('/');
        current.push_str(&part);
        let _ = run_debugfs(image_path, &format!("mkdir {current}"));
    }
}

fn normalize_sandbox_owner_in_rootfs_image(source: &Path, image_path: &Path) -> Result<(), String> {
    let sandbox_dir = source.join("sandbox");
    if !sandbox_dir.exists() {
        return Ok(());
    }

    let Some((uid, gid)) = sandbox_guest_user_ids(source)? else {
        return Ok(());
    };

    let mut commands = Vec::new();
    if !collect_sandbox_owner_commands(&sandbox_dir, "/sandbox", uid, gid, &mut commands)? {
        return Ok(());
    }
    if commands.is_empty() {
        return Ok(());
    }

    run_debugfs_batch(image_path, &commands)?;
    write_rootfs_image_file(image_path, SANDBOX_OWNER_NORMALIZED_MARKER, b"1\n")
}

fn collect_sandbox_owner_commands(
    source_path: &Path,
    guest_path: &str,
    uid: u32,
    gid: u32,
    commands: &mut Vec<String>,
) -> Result<bool, String> {
    let metadata = fs::symlink_metadata(source_path).map_err(|e| {
        format!(
            "stat {} for rootfs ownership normalization: {e}",
            source_path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Ok(true);
    }

    let Some(quoted_guest_path) = debugfs_quote_absolute_path(guest_path) else {
        return Ok(false);
    };
    commands.push(format!("set_inode_field {quoted_guest_path} uid {uid}"));
    commands.push(format!("set_inode_field {quoted_guest_path} gid {gid}"));

    if !metadata.is_dir() {
        return Ok(true);
    }

    let mut entries = fs::read_dir(source_path)
        .map_err(|e| {
            format!(
                "read {} for rootfs ownership normalization: {e}",
                source_path.display()
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            format!(
                "read {} entry for rootfs ownership normalization: {e}",
                source_path.display()
            )
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);

    for entry in entries {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            return Ok(false);
        };
        let child_guest_path = format!("{guest_path}/{file_name}");
        if !collect_sandbox_owner_commands(&entry.path(), &child_guest_path, uid, gid, commands)? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn debugfs_quote_absolute_path(path: &str) -> Option<String> {
    if path.is_empty() || !path.starts_with('/') {
        return None;
    }

    debugfs_quote_argument(path)
}

fn debugfs_quote_argument(argument: &str) -> Option<String> {
    if argument.is_empty() {
        return None;
    }

    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('"');
    for ch in argument.chars() {
        match ch {
            '\0' | '\n' | '\r' => return None,
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            _ => quoted.push(ch),
        }
    }
    quoted.push('"');
    Some(quoted)
}

fn sandbox_guest_user_ids(rootfs: &Path) -> Result<Option<(u32, u32)>, String> {
    let passwd_path = rootfs.join("etc/passwd");
    if !passwd_path.exists() {
        return Ok(None);
    }

    let passwd = fs::read_to_string(&passwd_path)
        .map_err(|e| format!("read {}: {e}", passwd_path.display()))?;
    for line in passwd.lines() {
        let mut parts = line.split(':');
        if parts.next() != Some("sandbox") {
            continue;
        }
        let _password = parts.next();
        let uid = parts
            .next()
            .ok_or_else(|| format!("sandbox entry in {} is missing uid", passwd_path.display()))?
            .parse::<u32>()
            .map_err(|e| format!("sandbox uid in {} is invalid: {e}", passwd_path.display()))?;
        let gid = parts
            .next()
            .ok_or_else(|| format!("sandbox entry in {} is missing gid", passwd_path.display()))?
            .parse::<u32>()
            .map_err(|e| format!("sandbox gid in {} is invalid: {e}", passwd_path.display()))?;
        return Ok(Some((uid, gid)));
    }

    Ok(None)
}

fn run_debugfs_batch(image_path: &Path, commands: &[String]) -> Result<(), String> {
    let command_path = temporary_injection_path(image_path);
    let mut contents = commands.join("\n");
    contents.push('\n');
    fs::write(&command_path, contents)
        .map_err(|e| format!("write {}: {e}", command_path.display()))?;

    let result = run_debugfs_batch_file(image_path, &command_path);
    let _ = fs::remove_file(&command_path);
    result
}

fn run_debugfs_batch_file(image_path: &Path, command_path: &Path) -> Result<(), String> {
    let mut last_error = None;
    for candidate in e2fs_tool_candidates("debugfs") {
        let label = candidate.display().to_string();
        let output = Command::new(&candidate)
            .arg("-w")
            .arg("-f")
            .arg(command_path)
            .arg(image_path)
            .output();
        match output {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                last_error = Some(format!(
                    "{label} failed with status {}\nstdout: {}\nstderr: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                last_error = Some(format!("{label} not found"));
            }
            Err(err) => {
                last_error = Some(format!("run {label}: {err}"));
            }
        }
    }
    Err(format!(
        "debugfs batch {} failed for {}: {}. Install e2fsprogs (debugfs) and retry",
        command_path.display(),
        image_path.display(),
        last_error.unwrap_or_else(|| "debugfs not found".to_string())
    ))
}

fn run_debugfs(image_path: &Path, command: &str) -> Result<(), String> {
    let mut last_error = None;
    for candidate in e2fs_tool_candidates("debugfs") {
        let label = candidate.display().to_string();
        let output = Command::new(&candidate)
            .arg("-w")
            .arg("-R")
            .arg(command)
            .arg(image_path)
            .output();
        match output {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                last_error = Some(format!(
                    "{label} failed with status {}\nstdout: {}\nstderr: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                last_error = Some(format!("{label} not found"));
            }
            Err(err) => {
                last_error = Some(format!("run {label}: {err}"));
            }
        }
    }
    Err(format!(
        "debugfs command '{command}' failed for {}: {}. Install e2fsprogs (debugfs) and retry",
        image_path.display(),
        last_error.unwrap_or_else(|| "debugfs not found".to_string())
    ))
}

fn e2fs_tool_candidates(tool: &str) -> Vec<PathBuf> {
    let mut candidates = vec![PathBuf::from(tool)];
    for root in ["/opt/homebrew/opt/e2fsprogs", "/usr/local/opt/e2fsprogs"] {
        candidates.push(Path::new(root).join("sbin").join(tool));
        candidates.push(Path::new(root).join("bin").join(tool));
    }
    candidates
}

fn temporary_injection_path(image_path: &Path) -> PathBuf {
    let n = INJECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let parent = image_path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(
        ".openshell-rootfs-inject-{}-{n}",
        std::process::id()
    ))
}

#[allow(clippy::similar_names)]
fn ensure_sandbox_guest_user(
    rootfs: &Path,
    sandbox_uid: u32,
    sandbox_gid: u32,
) -> Result<(), String> {
    let etc_dir = rootfs.join("etc");
    fs::create_dir_all(&etc_dir).map_err(|e| format!("create {}: {e}", etc_dir.display()))?;

    replace_or_append_line(
        &etc_dir.join("group"),
        &format!("sandbox:x:{sandbox_gid}:"),
        |line| line.starts_with("sandbox:"),
    )?;
    replace_or_append_line(&etc_dir.join("gshadow"), "sandbox:!::", |line| {
        line.starts_with("sandbox:")
    })?;
    replace_or_append_line(
        &etc_dir.join("passwd"),
        &format!("sandbox:x:{sandbox_uid}:{sandbox_gid}:OpenShell Sandbox:/sandbox:/bin/bash"),
        |line| line.starts_with("sandbox:"),
    )?;
    replace_or_append_line(
        &etc_dir.join("shadow"),
        "sandbox:!:20123:0:99999:7:::",
        |line| line.starts_with("sandbox:"),
    )?;

    Ok(())
}

fn replace_or_append_line(
    path: &Path,
    line: &str,
    matches: impl Fn(&str) -> bool,
) -> Result<(), String> {
    let contents = if path.exists() {
        fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?
    } else {
        String::new()
    };
    let mut output = String::with_capacity(contents.len().max(line.len() + 1));
    let mut replaced = false;
    for existing in contents.lines() {
        if matches(existing) {
            if replaced {
                continue;
            }
            output.push_str(line);
            replaced = true;
        } else {
            output.push_str(existing);
        }
        output.push('\n');
    }
    if !replaced {
        output.push_str(line);
        output.push('\n');
    }

    fs::write(path, output).map_err(|e| format!("write {}: {e}", path.display()))
}

fn ensure_supervisor_binary(rootfs: &Path) -> Result<(), String> {
    let path = rootfs.join(SANDBOX_SUPERVISOR_PATH.trim_start_matches('/'));
    if SUPERVISOR.is_empty() {
        if !path.exists() {
            return Err(
                "sandbox supervisor not embedded. Build openshell-driver-vm with OPENSHELL_VM_RUNTIME_COMPRESSED_DIR set and run `mise run vm:setup && mise run vm:supervisor` first"
                    .to_string(),
            );
        }
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }

        let sandbox = zstd::decode_all(Cursor::new(SANDBOX))
            .map_err(|e| format!("decompress sandbox: {e}"))?;
        fs::write(&path, sandbox).map_err(|e| format!("write {}: {e}", path.display()))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }

    Ok(())
}

fn ensure_supervisor_runtime(rootfs: &Path) -> Result<(), String> {
    if SUPERVISOR_RUNTIME.is_empty() {
        return validate_supervisor_runtime(rootfs).map_err(|_| {
            "trusted supervisor helper runtime not embedded. Build openshell-driver-vm with OPENSHELL_VM_RUNTIME_COMPRESSED_DIR set and run `mise run vm:supervisor` first"
                .to_string()
        });
    }

    install_supervisor_runtime_archive(rootfs, SUPERVISOR_RUNTIME)
}

fn install_supervisor_runtime_archive(rootfs: &Path, archive_bytes: &[u8]) -> Result<(), String> {
    let destination = rootfs.join("opt/openshell/bin");
    fs::create_dir_all(&destination)
        .map_err(|e| format!("create {}: {e}", destination.display()))?;
    let runtime = rootfs.join(SANDBOX_SUPERVISOR_RUNTIME_PATH.trim_start_matches('/'));
    match fs::symlink_metadata(&runtime) {
        Ok(metadata) if metadata.file_type().is_dir() => fs::remove_dir_all(&runtime)
            .map_err(|e| format!("remove untrusted runtime {}: {e}", runtime.display()))?,
        Ok(_) => fs::remove_file(&runtime)
            .map_err(|e| format!("remove untrusted runtime {}: {e}", runtime.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect runtime {}: {error}", runtime.display())),
    }
    let decoder = zstd::Decoder::new(Cursor::new(archive_bytes))
        .map_err(|e| format!("decompress supervisor runtime: {e}"))?;
    let mut archive = tar::Archive::new(decoder);
    for entry in archive
        .entries()
        .map_err(|e| format!("open supervisor runtime archive: {e}"))?
    {
        let mut entry = entry.map_err(|e| format!("read supervisor runtime archive: {e}"))?;
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_dir() {
            return Err(
                "supervisor runtime archive contains a non-materialized link or special file"
                    .to_string(),
            );
        }
        if !entry
            .unpack_in(&destination)
            .map_err(|e| format!("extract supervisor runtime archive: {e}"))?
        {
            return Err("supervisor runtime archive contains a path outside its root".to_string());
        }
    }
    validate_supervisor_runtime(rootfs)
}

fn validate_supervisor_runtime(rootfs: &Path) -> Result<(), String> {
    let runtime = rootfs.join(SANDBOX_SUPERVISOR_RUNTIME_PATH.trim_start_matches('/'));
    let has_ip = ["sbin/ip", "usr/sbin/ip", "bin/ip", "usr/bin/ip"]
        .iter()
        .any(|path| runtime.join(path).is_file());
    let has_loader = fs::read_dir(runtime.join("lib"))
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("ld-musl-") && name.ends_with(".so.1"))
        });
    if has_ip && has_loader {
        Ok(())
    } else {
        Err(format!(
            "trusted supervisor helper runtime '{}' is incomplete",
            runtime.display()
        ))
    }
}

fn ensure_umoci_binary(rootfs: &Path) -> Result<(), String> {
    let path = rootfs.join(SANDBOX_UMOCI_PATH.trim_start_matches('/'));
    if UMOCI.is_empty() {
        if !path.exists() {
            return Err(
                "umoci not embedded. Build openshell-driver-vm with OPENSHELL_VM_RUNTIME_COMPRESSED_DIR set and run `mise run vm:setup` first"
                    .to_string(),
            );
        }
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }

        let umoci =
            zstd::decode_all(Cursor::new(UMOCI)).map_err(|e| format!("decompress umoci: {e}"))?;
        fs::write(&path, umoci).map_err(|e| format!("write {}: {e}", path.display()))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }

    Ok(())
}

fn require_rootfs_path(rootfs: &Path, relative: &str) -> Result<(), String> {
    let candidate = rootfs.join(relative.trim_start_matches('/'));
    if candidate.exists() {
        Ok(())
    } else {
        Err(format!(
            "prepared rootfs is missing {}",
            candidate.display()
        ))
    }
}

fn require_any_rootfs_path(rootfs: &Path, candidates: &[&str]) -> Result<(), String> {
    if candidates
        .iter()
        .any(|candidate| rootfs.join(candidate.trim_start_matches('/')).exists())
    {
        Ok(())
    } else {
        Err(format!(
            "prepared rootfs is missing one of: {}",
            candidates.join(", ")
        ))
    }
}

fn remove_rootfs_path(rootfs: &Path, relative: &str) -> Result<(), String> {
    let path = rootfs.join(relative);
    if !path.exists() {
        return Ok(());
    }

    let result = if path.is_dir() {
        fs::remove_dir_all(&path)
    } else {
        fs::remove_file(&path)
    };
    result.map_err(|e| format!("remove {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(target_os = "linux")]
    #[test]
    fn host_supervisor_cache_rejects_wrong_content_and_installs_atomically() {
        let directory = tempfile::tempdir().expect("cache directory");
        let destination = directory.path().join("openshell-sandbox");
        fs::write(&destination, b"stale executable").expect("write stale cache");
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))
            .expect("make stale cache executable");
        let expected = sha256_bytes(b"trusted supervisor");

        assert!(validate_host_supervisor_digest(&destination, expected).is_err());
        install_host_supervisor_atomically(&destination, b"trusted supervisor")
            .expect("atomically replace cache");
        validate_host_supervisor_digest(&destination, expected).expect("validate installed cache");
        assert_eq!(fs::read(&destination).unwrap(), b"trusted supervisor");
        assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")
        }));
    }

    #[test]
    fn guest_init_gets_driver_owned_ip_launcher_when_image_omits_iproute2() {
        let rootfs = tempfile::tempdir().expect("create rootfs");
        ensure_guest_init_ip(rootfs.path()).expect("install guest ip launcher");

        let launcher = rootfs.path().join("usr/sbin/ip");
        let contents = fs::read_to_string(&launcher).expect("read guest ip launcher");
        assert!(contents.contains("/opt/openshell/bin/openshell-runtime"));
        assert!(contents.contains("ld-musl-"));
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(launcher).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn prepare_sandbox_rootfs_rewrites_guest_layout() {
        let dir = unique_temp_dir();
        let rootfs = dir.join("rootfs");

        fs::create_dir_all(rootfs.join("etc")).expect("create etc");
        fs::create_dir_all(rootfs.join("opt/openshell/bin")).expect("create openshell bin");
        fs::write(rootfs.join("opt/openshell/.initialized"), b"yes").expect("write initialized");
        write_fake_runtime_binaries(&rootfs);
        fs::write(
            rootfs.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nsandbox:x:998:997:Sandbox:/sandbox:/bin/sh\n",
        )
        .expect("write passwd");
        fs::write(rootfs.join("etc/group"), "root:x:0:\nsandbox:x:997:\n").expect("write group");
        fs::write(rootfs.join("etc/hosts"), "127.0.0.1 localhost\n").expect("write hosts");
        fs::create_dir_all(rootfs.join("bin")).expect("create bin");
        fs::create_dir_all(rootfs.join("sbin")).expect("create sbin");
        fs::write(rootfs.join("bin/bash"), b"bash").expect("write bash");
        fs::write(rootfs.join("bin/mount"), b"mount").expect("write mount");
        fs::write(rootfs.join("bin/chroot"), b"chroot").expect("write chroot");
        fs::write(rootfs.join("bin/sed"), b"sed").expect("write sed");
        fs::write(rootfs.join("sbin/ip"), b"ip").expect("write ip");

        // Use a non-standard UID so the test doesn't collide with the default.
        let uid = 20001;
        prepare_sandbox_rootfs(&rootfs, uid, uid).expect("prepare sandbox rootfs");
        validate_sandbox_rootfs(&rootfs).expect("validate sandbox rootfs");

        assert!(rootfs.join("srv/openshell-vm-sandbox-init.sh").is_file());
        assert!(rootfs.join("opt/openshell/bin/umoci").is_file());
        validate_supervisor_runtime(&rootfs).expect("trusted helper runtime remains complete");
        let init_script = fs::read_to_string(rootfs.join("srv/openshell-vm-sandbox-init.sh"))
            .expect("read guest init");
        assert!(
            init_script.contains(
                "launch-capability-free \"$_sandbox_uid\" \"$_sandbox_gid\" \"$_sandbox_bootstrap_guest\""
            )
        );
        assert!(init_script.contains("OPENSHELL_VM_SANDBOX_BOOTSTRAP"));
        assert!(
            init_script
                .contains("chown \"${_sandbox_uid}:${_sandbox_gid}\" \"$_sandbox_state_dir\"")
        );
        assert!(init_script.contains("chmod 0700 \"$_sandbox_state_dir\""));
        assert!(!init_script.contains("--topology-backend-name=in-pod"));
        assert!(!init_script.contains("@ISOLATION_INTERFACE_VERSION@"));
        assert!(!init_script.contains("8.8.8.8"));
        assert!(!init_script.contains("VM_NET_"));
        assert!(rootfs.join("sandbox").is_dir());
        assert!(rootfs.join("image-cache").is_dir());
        assert!(rootfs.join("lower").is_dir());
        assert!(rootfs.join("overlay").is_dir());
        assert!(rootfs.join("newroot").is_dir());
        assert!(
            fs::read_dir(rootfs.join("sandbox"))
                .expect("read sandbox")
                .next()
                .is_none()
        );
        let passwd = fs::read_to_string(rootfs.join("etc/passwd")).expect("read passwd");
        assert!(passwd.contains(&format!(
            "sandbox:x:{uid}:{uid}:OpenShell Sandbox:/sandbox:/bin/bash"
        )));
        assert!(!passwd.contains("sandbox:x:998:997:"));
        let group = fs::read_to_string(rootfs.join("etc/group")).expect("read group");
        assert!(group.contains(&format!("sandbox:x:{uid}:")));
        assert!(!group.contains("sandbox:x:997:"));
        assert_eq!(
            fs::read_to_string(rootfs.join("etc/hosts")).expect("read hosts"),
            "127.0.0.1 localhost\n"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn supervisor_runtime_archive_materializes_below_the_trusted_path() {
        let dir = unique_temp_dir();
        let rootfs = dir.join("rootfs");
        let untrusted_runtime = rootfs.join("opt/openshell/bin/openshell-runtime");
        fs::create_dir_all(untrusted_runtime.join("usr/sbin")).expect("create untrusted runtime");
        fs::write(untrusted_runtime.join("usr/sbin/ip"), b"untrusted")
            .expect("write untrusted helper");
        fs::write(untrusted_runtime.join("untrusted-extra"), b"untrusted")
            .expect("write untrusted extra file");
        let mut tar_bytes = Vec::new();
        {
            let mut archive = tar::Builder::new(&mut tar_bytes);
            for (path, bytes, mode) in [
                ("openshell-runtime/usr/sbin/ip", b"ip".as_slice(), 0o755),
                (
                    "openshell-runtime/lib/ld-musl-test.so.1",
                    b"loader".as_slice(),
                    0o755,
                ),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_mode(mode);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_cksum();
                archive
                    .append_data(&mut header, path, bytes)
                    .expect("append runtime entry");
            }
            archive.finish().expect("finish runtime archive");
        }
        let compressed = zstd::encode_all(Cursor::new(tar_bytes), 1).expect("compress runtime");

        install_supervisor_runtime_archive(&rootfs, &compressed).expect("install runtime");
        validate_supervisor_runtime(&rootfs).expect("validate runtime");
        assert_eq!(
            fs::read(rootfs.join("opt/openshell/bin/openshell-runtime/usr/sbin/ip"))
                .expect("read installed helper"),
            b"ip"
        );
        assert!(
            !rootfs
                .join("opt/openshell/bin/openshell-runtime/untrusted-extra")
                .exists(),
            "embedded runtime replacement must discard bootstrap-image helpers"
        );
    }

    #[test]
    fn prepare_sandbox_rootfs_preserves_image_workdir_contents_in_rootfs() {
        let dir = unique_temp_dir();
        let rootfs = dir.join("rootfs");

        fs::create_dir_all(rootfs.join("opt/openshell/bin")).expect("create openshell bin");
        write_fake_runtime_binaries(&rootfs);
        fs::create_dir_all(rootfs.join("sandbox")).expect("create sandbox workdir");
        fs::write(rootfs.join("sandbox/app.py"), "print('hello')\n").expect("write app");

        prepare_sandbox_rootfs(&rootfs, 10001, 10001).expect("prepare sandbox rootfs");

        assert!(rootfs.join("sandbox").is_dir());
        assert_eq!(
            fs::read_to_string(rootfs.join("sandbox/app.py")).expect("read app"),
            "print('hello')\n"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn create_rootfs_archive_preserves_broken_symlinks() {
        let dir = unique_temp_dir();
        let rootfs = dir.join("rootfs");
        let extracted = dir.join("extracted");
        let archive = dir.join("rootfs.tar");

        fs::create_dir_all(rootfs.join("etc")).expect("create etc");
        fs::write(rootfs.join("etc/hosts"), "127.0.0.1 localhost\n").expect("write hosts");
        std::os::unix::fs::symlink("/proc/self/mounts", rootfs.join("etc/mtab"))
            .expect("create symlink");

        create_rootfs_archive_from_dir(&rootfs, &archive).expect("archive rootfs");
        extract_rootfs_archive_to(&archive, &extracted).expect("extract rootfs");

        let extracted_link = extracted.join("etc/mtab");
        assert!(
            fs::symlink_metadata(&extracted_link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_link(&extracted_link).expect("read extracted symlink"),
            PathBuf::from("/proc/self/mounts")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clone_or_copy_sparse_file_preserves_size_and_contents() {
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).expect("create temp dir");
        let source = dir.join("source.bin");
        let dest = dir.join("dest.bin");

        let mut source_file = File::create(&source).expect("create source");
        source_file.write_all(b"head").expect("write head");
        source_file
            .seek(SeekFrom::Start(1024 * 1024 + 7))
            .expect("seek source");
        source_file.write_all(b"tail").expect("write tail");
        source_file
            .set_len(2 * 1024 * 1024 + 3)
            .expect("size source");
        drop(source_file);

        clone_or_copy_sparse_file(&source, &dest).expect("copy sparse file");

        assert_eq!(
            fs::metadata(&dest).expect("stat dest").len(),
            2 * 1024 * 1024 + 3
        );
        let mut dest_file = File::open(&dest).expect("open dest");
        let mut head = [0_u8; 4];
        dest_file.read_exact(&mut head).expect("read head");
        assert_eq!(&head, b"head");
        dest_file
            .seek(SeekFrom::Start(1024 * 1024 + 7))
            .expect("seek dest");
        let mut tail = [0_u8; 4];
        dest_file.read_exact(&mut tail).expect("read tail");
        assert_eq!(&tail, b"tail");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recover_rootfs_image_accepts_clean_ext4_image() {
        let dir = unique_temp_dir();
        let source = dir.join("source");
        let image = dir.join("overlay.ext4");
        fs::create_dir_all(source.join("upper")).expect("create source upperdir");
        fs::create_dir_all(source.join("work")).expect("create source workdir");
        create_ext4_image_from_dir_with_size(&source, &image, 64 * 1024 * 1024)
            .expect("create ext4 image");

        recover_rootfs_image(&image).expect("recover clean ext4 image");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sandbox_guest_user_ids_reads_existing_sandbox_user() {
        let dir = unique_temp_dir();
        let rootfs = dir.join("rootfs");
        fs::create_dir_all(rootfs.join("etc")).expect("create etc");
        fs::write(
            rootfs.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nsandbox:x:998:997:Sandbox:/sandbox:/bin/sh\n",
        )
        .expect("write passwd");

        assert_eq!(
            sandbox_guest_user_ids(&rootfs).expect("read sandbox user"),
            Some((998, 997))
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_sandbox_owner_commands_quotes_guest_paths() {
        let dir = unique_temp_dir();
        let sandbox_dir = dir.join("sandbox");
        fs::create_dir_all(sandbox_dir.join("dir with space")).expect("create sandbox tree");
        fs::write(sandbox_dir.join("dir with space/file.txt"), "hello\n").expect("write file");

        let mut commands = Vec::new();
        assert!(
            collect_sandbox_owner_commands(&sandbox_dir, "/sandbox", 998, 997, &mut commands)
                .expect("collect commands")
        );

        assert!(commands.contains(&"set_inode_field \"/sandbox\" uid 998".to_string()));
        assert!(commands.contains(&"set_inode_field \"/sandbox\" gid 997".to_string()));
        assert!(
            commands.contains(
                &"set_inode_field \"/sandbox/dir with space/file.txt\" uid 998".to_string()
            )
        );
        assert!(
            commands.contains(
                &"set_inode_field \"/sandbox/dir with space/file.txt\" gid 997".to_string()
            )
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn debugfs_quote_argument_quotes_source_paths_with_spaces() {
        assert_eq!(
            debugfs_quote_argument("/tmp/openshell state/.openshell-rootfs-inject-123-0"),
            Some("\"/tmp/openshell state/.openshell-rootfs-inject-123-0\"".to_string())
        );
        assert_eq!(
            debugfs_quote_argument("/tmp/path/with\\backslash/and\"quote"),
            Some("\"/tmp/path/with\\\\backslash/and\\\"quote\"".to_string())
        );
        assert_eq!(debugfs_quote_argument("/tmp/bad\npath"), None);
    }

    #[test]
    fn formatter_candidates_preserve_executed_failure_over_missing_fallback() {
        let candidates = vec![PathBuf::from("mke2fs"), PathBuf::from("missing")];

        let err = run_ext4_formatter_candidates(candidates, |candidate| {
            if candidate == Path::new("mke2fs") {
                FormatterAttempt::Failed(
                    "mke2fs failed with status 1\nstdout: formatter output\nstderr: no space left"
                        .to_string(),
                )
            } else {
                FormatterAttempt::Unavailable("missing not found".to_string())
            }
        })
        .expect_err("formatter should fail");

        assert!(err.contains("mke2fs failed with status 1"));
        assert!(err.contains("no space left"));
        assert!(!err.contains("missing not found"));
    }

    #[test]
    fn formatter_candidates_report_all_missing_tools() {
        let candidates = vec![PathBuf::from("mke2fs"), PathBuf::from("mkfs.ext4")];

        let err = run_ext4_formatter_candidates(candidates, |candidate| {
            FormatterAttempt::Unavailable(format!("{} not found", candidate.display()))
        })
        .expect_err("formatter should be unavailable");

        assert!(err.contains("mke2fs not found"));
        assert!(err.contains("mkfs.ext4 not found"));
    }

    #[test]
    fn formatter_candidates_accept_successful_fallback() {
        let candidates = vec![PathBuf::from("first"), PathBuf::from("second")];
        let mut attempted = Vec::new();

        run_ext4_formatter_candidates(candidates, |candidate| {
            attempted.push(candidate.to_path_buf());
            if candidate == Path::new("second") {
                FormatterAttempt::Succeeded
            } else {
                FormatterAttempt::Failed("first failed".to_string())
            }
        })
        .expect("fallback should succeed");

        assert_eq!(
            attempted,
            vec![PathBuf::from("first"), PathBuf::from("second")]
        );
    }

    fn unique_temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        let suffix = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "openshell-driver-vm-rootfs-test-{}-{nanos}-{suffix}",
            std::process::id()
        ))
    }

    fn write_fake_runtime_binaries(rootfs: &Path) {
        let helper_runtime = rootfs.join("opt/openshell/bin/openshell-runtime");
        fs::create_dir_all(helper_runtime.join("usr/sbin")).expect("create helper bin directory");
        fs::create_dir_all(helper_runtime.join("lib")).expect("create helper lib directory");
        fs::write(helper_runtime.join("usr/sbin/ip"), b"ip").expect("write ip helper");
        fs::write(helper_runtime.join("lib/ld-musl-test.so.1"), b"loader")
            .expect("write helper loader");
        fs::write(
            rootfs.join("opt/openshell/bin/openshell-sandbox"),
            b"sandbox",
        )
        .expect("write openshell-sandbox");
        fs::write(rootfs.join("opt/openshell/bin/umoci"), b"umoci").expect("write umoci");
    }
}
