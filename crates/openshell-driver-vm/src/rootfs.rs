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
const ROOTFS_VARIANT_MARKER: &str = ".openshell-rootfs-variant";
const SANDBOX_GUEST_INIT_PATH: &str = "/srv/openshell-vm-sandbox-init.sh";
const SANDBOX_SUPERVISOR_PATH: &str = "/opt/openshell/bin/openshell-sandbox";
const ROOTFS_IMAGE_MIN_SIZE_BYTES: u64 = 512 * 1024 * 1024;
const ROOTFS_IMAGE_MIN_HEADROOM_BYTES: u64 = 256 * 1024 * 1024;
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
    if let Some(parent) = image_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    if image_path.exists() {
        fs::remove_file(image_path)
            .map_err(|e| format!("remove old rootfs image {}: {e}", image_path.display()))?;
    }

    let image_size = rootfs_image_size_bytes(source)?;
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

pub fn copy_rootfs_image_to(source: &Path, dest: &Path) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    if dest.exists() {
        fs::remove_file(dest)
            .map_err(|e| format!("remove old rootfs image {}: {e}", dest.display()))?;
    }

    let mut input = File::open(source)
        .map_err(|e| format!("open cached rootfs image {}: {e}", source.display()))?;
    let mut output =
        File::create(dest).map_err(|e| format!("create rootfs image {}: {e}", dest.display()))?;
    let mut buf = vec![0; 1024 * 1024];
    let mut total = 0_u64;

    loop {
        let len = input
            .read(&mut buf)
            .map_err(|e| format!("read rootfs image {}: {e}", source.display()))?;
        if len == 0 {
            break;
        }
        total += len as u64;
        if buf[..len].iter().all(|byte| *byte == 0) {
            let offset = i64::try_from(len).map_err(|e| {
                format!(
                    "convert sparse rootfs image seek offset for {}: {e}",
                    dest.display()
                )
            })?;
            output
                .seek(SeekFrom::Current(offset))
                .map_err(|e| format!("seek sparse rootfs image {}: {e}", dest.display()))?;
        } else {
            output
                .write_all(&buf[..len])
                .map_err(|e| format!("write rootfs image {}: {e}", dest.display()))?;
        }
    }

    output
        .set_len(total)
        .map_err(|e| format!("finalize rootfs image {}: {e}", dest.display()))
}

pub fn write_rootfs_image_file(
    image_path: &Path,
    guest_path: &str,
    contents: &[u8],
) -> Result<(), String> {
    ensure_rootfs_image_parent_dirs(image_path, guest_path);

    let tmp_path = temporary_injection_path(image_path);
    fs::write(&tmp_path, contents).map_err(|e| format!("write {}: {e}", tmp_path.display()))?;
    let _ = run_debugfs(image_path, &format!("rm {guest_path}"));
    let result = run_debugfs(
        image_path,
        &format!("write {} {}", tmp_path.display(), guest_path),
    );
    let _ = fs::remove_file(&tmp_path);
    result
}

pub fn set_rootfs_image_file_mode(
    image_path: &Path,
    guest_path: &str,
    mode: u32,
) -> Result<(), String> {
    run_debugfs(image_path, &format!("sif {guest_path} mode {mode:o}"))
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

    let opt_dir = rootfs.join("opt/openshell");
    fs::create_dir_all(&opt_dir).map_err(|e| format!("create {}: {e}", opt_dir.display()))?;
    fs::write(opt_dir.join(".rootfs-type"), "sandbox\n")
        .map_err(|e| format!("write sandbox rootfs marker: {e}"))?;
    ensure_sandbox_guest_user(rootfs)?;
    create_sandbox_mountpoint(&rootfs.join("sandbox"))?;

    Ok(())
}

pub fn validate_sandbox_rootfs(rootfs: &Path) -> Result<(), String> {
    require_rootfs_path(rootfs, SANDBOX_GUEST_INIT_PATH)?;
    require_rootfs_path(rootfs, "/opt/openshell/bin/openshell-sandbox")?;
    require_any_rootfs_path(rootfs, &["/bin/bash"])?;
    require_any_rootfs_path(rootfs, &["/bin/mount", "/usr/bin/mount"])?;
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
        fs::write(
            rootfs.join("opt/openshell/bin/openshell-sandbox"),
            b"sandbox",
        )
        .expect("write openshell-sandbox");
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
        fs::write(rootfs.join("bin/sed"), b"sed").expect("write sed");
        fs::write(rootfs.join("sbin/ip"), b"ip").expect("write ip");

        prepare_sandbox_rootfs(&rootfs).expect("prepare sandbox rootfs");
        validate_sandbox_rootfs(&rootfs).expect("validate sandbox rootfs");

        assert!(rootfs.join("srv/openshell-vm-sandbox-init.sh").is_file());
        assert!(rootfs.join("sandbox").is_dir());
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
        fs::write(
            rootfs.join("opt/openshell/bin/openshell-sandbox"),
            b"sandbox",
        )
        .expect("write openshell-sandbox");
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
}
