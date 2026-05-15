// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::fs::File;
#[cfg(test)]
use std::io::BufWriter;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const SUPERVISOR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/openshell-sandbox.zst"));
const UMOCI: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/umoci.zst"));
const ROOTFS_VARIANT_MARKER: &str = ".openshell-rootfs-variant";
const SANDBOX_GUEST_INIT_PATH: &str = "/srv/openshell-vm-sandbox-init.sh";
const SANDBOX_SUPERVISOR_PATH: &str = "/opt/openshell/bin/openshell-sandbox";
const SANDBOX_UMOCI_PATH: &str = "/opt/openshell/bin/umoci";
const SANDBOX_OWNER_NORMALIZED_MARKER: &str = "/opt/openshell/.sandbox-owner-normalized";
const ROOTFS_IMAGE_MIN_SIZE_BYTES: u64 = 512 * 1024 * 1024;
const ROOTFS_IMAGE_MIN_HEADROOM_BYTES: u64 = 256 * 1024 * 1024;
const EXT4_IMAGE_MIN_HEADROOM_BYTES: u64 = 16 * 1024 * 1024;
static INJECTION_COUNTER: AtomicU64 = AtomicU64::new(0);

pub const fn sandbox_guest_init_path() -> &'static str {
    SANDBOX_GUEST_INIT_PATH
}

pub fn prepare_sandbox_rootfs_from_image_root(
    rootfs: &Path,
    image_identity: &str,
) -> Result<(), String> {
    prepare_sandbox_rootfs(rootfs)?;
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

fn prepare_sandbox_rootfs(rootfs: &Path) -> Result<(), String> {
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
    ensure_umoci_binary(rootfs)?;

    let opt_dir = rootfs.join("opt/openshell");
    fs::create_dir_all(&opt_dir).map_err(|e| format!("create {}: {e}", opt_dir.display()))?;
    fs::write(opt_dir.join(".rootfs-type"), "sandbox\n")
        .map_err(|e| format!("write sandbox rootfs marker: {e}"))?;
    ensure_sandbox_guest_user(rootfs)?;
    create_sandbox_mountpoint(&rootfs.join("sandbox"))?;
    create_sandbox_mountpoint(&rootfs.join("lower"))?;
    create_sandbox_mountpoint(&rootfs.join("overlay"))?;
    create_sandbox_mountpoint(&rootfs.join("newroot"))?;

    Ok(())
}

pub fn validate_sandbox_rootfs(rootfs: &Path) -> Result<(), String> {
    require_rootfs_path(rootfs, SANDBOX_GUEST_INIT_PATH)?;
    require_rootfs_path(rootfs, SANDBOX_SUPERVISOR_PATH)?;
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

fn format_ext4_image_from_dir(source: &Path, image_path: &Path) -> Result<(), String> {
    let mut last_error = None;
    for tool in ["mke2fs", "mkfs.ext4"] {
        for candidate in e2fs_tool_candidates(tool) {
            let label = candidate.display().to_string();
            let output = Command::new(&candidate)
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
    }
    Err(format!(
        "failed to create ext4 rootfs image from {}: {}. Install e2fsprogs (mke2fs/mkfs.ext4) and retry",
        source.display(),
        last_error.unwrap_or_else(|| "no ext4 formatter found".to_string())
    ))
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

fn ensure_sandbox_guest_user(rootfs: &Path) -> Result<(), String> {
    const SANDBOX_UID: u32 = 10001;
    const SANDBOX_GID: u32 = 10001;

    let etc_dir = rootfs.join("etc");
    fs::create_dir_all(&etc_dir).map_err(|e| format!("create {}: {e}", etc_dir.display()))?;

    ensure_line_in_file(
        &etc_dir.join("group"),
        &format!("sandbox:x:{SANDBOX_GID}:"),
        |line| line.starts_with("sandbox:"),
    )?;
    ensure_line_in_file(&etc_dir.join("gshadow"), "sandbox:!::", |line| {
        line.starts_with("sandbox:")
    })?;
    ensure_line_in_file(
        &etc_dir.join("passwd"),
        &format!("sandbox:x:{SANDBOX_UID}:{SANDBOX_GID}:OpenShell Sandbox:/sandbox:/bin/bash"),
        |line| line.starts_with("sandbox:"),
    )?;
    ensure_line_in_file(
        &etc_dir.join("shadow"),
        "sandbox:!:20123:0:99999:7:::",
        |line| line.starts_with("sandbox:"),
    )?;

    Ok(())
}

fn ensure_line_in_file(
    path: &Path,
    line: &str,
    exists: impl Fn(&str) -> bool,
) -> Result<(), String> {
    let mut contents = if path.exists() {
        fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?
    } else {
        String::new()
    };

    if contents.lines().any(exists) {
        return Ok(());
    }

    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(line);
    contents.push('\n');

    fs::write(path, contents).map_err(|e| format!("write {}: {e}", path.display()))
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

        let supervisor = zstd::decode_all(Cursor::new(SUPERVISOR))
            .map_err(|e| format!("decompress supervisor: {e}"))?;
        fs::write(&path, supervisor).map_err(|e| format!("write {}: {e}", path.display()))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }

    Ok(())
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
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

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
            "root:x:0:0:root:/root:/bin/bash\n",
        )
        .expect("write passwd");
        fs::write(rootfs.join("etc/group"), "root:x:0:\n").expect("write group");
        fs::write(rootfs.join("etc/hosts"), "127.0.0.1 localhost\n").expect("write hosts");
        fs::create_dir_all(rootfs.join("bin")).expect("create bin");
        fs::create_dir_all(rootfs.join("sbin")).expect("create sbin");
        fs::write(rootfs.join("bin/bash"), b"bash").expect("write bash");
        fs::write(rootfs.join("bin/mount"), b"mount").expect("write mount");
        fs::write(rootfs.join("bin/chroot"), b"chroot").expect("write chroot");
        fs::write(rootfs.join("bin/sed"), b"sed").expect("write sed");
        fs::write(rootfs.join("sbin/ip"), b"ip").expect("write ip");

        prepare_sandbox_rootfs(&rootfs).expect("prepare sandbox rootfs");
        validate_sandbox_rootfs(&rootfs).expect("validate sandbox rootfs");

        assert!(rootfs.join("srv/openshell-vm-sandbox-init.sh").is_file());
        assert!(rootfs.join("opt/openshell/bin/umoci").is_file());
        assert!(rootfs.join("sandbox").is_dir());
        assert!(rootfs.join("lower").is_dir());
        assert!(rootfs.join("overlay").is_dir());
        assert!(rootfs.join("newroot").is_dir());
        assert!(
            fs::read_dir(rootfs.join("sandbox"))
                .expect("read sandbox")
                .next()
                .is_none()
        );
        assert!(
            fs::read_to_string(rootfs.join("etc/passwd"))
                .expect("read passwd")
                .contains("sandbox:x:10001:10001:OpenShell Sandbox:/sandbox:/bin/bash")
        );
        assert!(
            fs::read_to_string(rootfs.join("etc/group"))
                .expect("read group")
                .contains("sandbox:x:10001:")
        );
        assert_eq!(
            fs::read_to_string(rootfs.join("etc/hosts")).expect("read hosts"),
            "127.0.0.1 localhost\n"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepare_sandbox_rootfs_preserves_image_workdir_contents_in_rootfs() {
        let dir = unique_temp_dir();
        let rootfs = dir.join("rootfs");

        fs::create_dir_all(rootfs.join("opt/openshell/bin")).expect("create openshell bin");
        write_fake_runtime_binaries(&rootfs);
        fs::create_dir_all(rootfs.join("sandbox")).expect("create sandbox workdir");
        fs::write(rootfs.join("sandbox/app.py"), "print('hello')\n").expect("write app");

        prepare_sandbox_rootfs(&rootfs).expect("prepare sandbox rootfs");

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
        fs::write(
            rootfs.join("opt/openshell/bin/openshell-sandbox"),
            b"sandbox",
        )
        .expect("write openshell-sandbox");
        fs::write(rootfs.join("opt/openshell/bin/umoci"), b"umoci").expect("write umoci");
    }
}
