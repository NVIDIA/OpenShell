// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Cursor;
use std::path::Path;

const ROOTFS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rootfs.tar.zst"));
const ROOTFS_GPU: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rootfs-gpu.tar.zst"));
const ROOTFS_VARIANT_MARKER: &str = ".openshell-rootfs-variant";
const SANDBOX_GUEST_INIT_PATH: &str = "/srv/openshell-vm-sandbox-init.sh";

pub const fn sandbox_guest_init_path() -> &'static str {
    SANDBOX_GUEST_INIT_PATH
}

pub fn extract_sandbox_rootfs_to(dest: &Path) -> Result<(), String> {
    extract_variant(
        ROOTFS,
        "sandbox",
        "sandbox rootfs not embedded. Build openshell-driver-vm with OPENSHELL_VM_RUNTIME_COMPRESSED_DIR set or run `mise run vm:setup` first",
        dest,
    )
}

pub fn extract_gpu_sandbox_rootfs_to(dest: &Path) -> Result<(), String> {
    extract_variant(
        ROOTFS_GPU,
        "sandbox-gpu",
        "GPU sandbox rootfs not embedded. Build with `mise run vm:rootfs -- --gpu` first",
        dest,
    )
}

fn extract_variant(blob: &[u8], variant: &str, empty_msg: &str, dest: &Path) -> Result<(), String> {
    if blob.is_empty() {
        return Err(empty_msg.to_string());
    }

    let expected_marker = format!("{}:{variant}", env!("CARGO_PKG_VERSION"));
    let marker_path = dest.join(ROOTFS_VARIANT_MARKER);

    if dest.is_dir()
        && fs::read_to_string(&marker_path)
            .map(|value| value.trim() == expected_marker)
            .unwrap_or(false)
    {
        return Ok(());
    }

    if dest.exists() {
        fs::remove_dir_all(dest)
            .map_err(|e| format!("remove old rootfs {}: {e}", dest.display()))?;
    }

    unpack_zstd_tar(blob, variant, dest)?;
    prepare_sandbox_rootfs(dest)?;
    fs::write(marker_path, format!("{expected_marker}\n"))
        .map_err(|e| format!("write rootfs variant marker: {e}"))?;
    Ok(())
}

fn unpack_zstd_tar(blob: &[u8], label: &str, dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|e| format!("create rootfs dir {}: {e}", dest.display()))?;

    let decoder = zstd::Decoder::new(Cursor::new(blob))
        .map_err(|e| format!("decompress {label} rootfs: {e}"))?;
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(dest).map_err(|e| {
        format!(
            "extract {label} rootfs tarball into {}: {e}",
            dest.display()
        )
    })
}

fn prepare_sandbox_rootfs(rootfs: &Path) -> Result<(), String> {
    for relative in [
        "usr/local/bin/k3s",
        "usr/local/bin/kubectl",
        "var/lib/rancher",
        "etc/rancher",
        "opt/openshell/charts",
        "opt/openshell/manifests",
        "opt/openshell/.initialized",
        "opt/openshell/.rootfs-type",
    ] {
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

    let opt_dir = rootfs.join("opt/openshell");
    fs::create_dir_all(&opt_dir).map_err(|e| format!("create {}: {e}", opt_dir.display()))?;
    fs::write(opt_dir.join(".rootfs-type"), "sandbox\n")
        .map_err(|e| format!("write sandbox rootfs marker: {e}"))?;
    ensure_sandbox_guest_user(rootfs)?;
    fs::create_dir_all(rootfs.join("sandbox"))
        .map_err(|e| format!("create sandbox workdir: {e}"))?;

    Ok(())
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

        fs::create_dir_all(rootfs.join("usr/local/bin")).expect("create usr/local/bin");
        fs::create_dir_all(rootfs.join("etc")).expect("create etc");
        fs::create_dir_all(rootfs.join("var/lib/rancher")).expect("create var/lib/rancher");
        fs::create_dir_all(rootfs.join("opt/openshell/charts")).expect("create charts");
        fs::create_dir_all(rootfs.join("opt/openshell/manifests")).expect("create manifests");
        fs::write(rootfs.join("usr/local/bin/k3s"), b"k3s").expect("write k3s");
        fs::write(rootfs.join("usr/local/bin/kubectl"), b"kubectl").expect("write kubectl");
        fs::write(rootfs.join("opt/openshell/.initialized"), b"yes").expect("write initialized");
        fs::write(
            rootfs.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\n",
        )
        .expect("write passwd");
        fs::write(rootfs.join("etc/group"), "root:x:0:\n").expect("write group");
        fs::write(rootfs.join("etc/hosts"), "127.0.0.1 localhost\n").expect("write hosts");

        prepare_sandbox_rootfs(&rootfs).expect("prepare sandbox rootfs");

        assert!(!rootfs.join("usr/local/bin/k3s").exists());
        assert!(!rootfs.join("usr/local/bin/kubectl").exists());
        assert!(!rootfs.join("var/lib/rancher").exists());
        assert!(!rootfs.join("opt/openshell/charts").exists());
        assert!(!rootfs.join("opt/openshell/manifests").exists());
        assert!(rootfs.join("srv/openshell-vm-sandbox-init.sh").is_file());
        assert!(rootfs.join("sandbox").is_dir());
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
