// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Inject OpenShell compatibility files into a flattened OCI rootfs tree.
//!
//! Runs after [`crate::oci::flatten`] and before the squashfs build, so the
//! sandbox user and its expected directories are baked into the RO base image.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

/// Canonical sandbox user/group. Must match `openshell-sandbox`'s expectations.
pub const SANDBOX_UID: u32 = 10001;
pub const SANDBOX_GID: u32 = 10001;
pub const SANDBOX_USER: &str = "sandbox";

/// Apply all compat injections into `root`. Idempotent.
pub fn inject(root: &Path) -> io::Result<()> {
    ensure_passwd_entry(root)?;
    ensure_group_entry(root)?;
    ensure_dir(&root.join("sandbox"), 0o755)?;
    ensure_dir(&root.join("tmp"), 0o1777)?;
    ensure_empty_file(&root.join("etc/hosts"), 0o644)?;
    ensure_empty_file(&root.join("etc/resolv.conf"), 0o644)?;
    Ok(())
}

fn ensure_passwd_entry(root: &Path) -> io::Result<()> {
    let path = root.join("etc/passwd");
    let shell = pick_shell(root);
    let entry = format!(
        "{SANDBOX_USER}:x:{SANDBOX_UID}:{SANDBOX_GID}:OpenShell Sandbox:/sandbox:{shell}\n"
    );
    append_user_db_entry(&path, SANDBOX_USER, &entry)
}

fn ensure_group_entry(root: &Path) -> io::Result<()> {
    let path = root.join("etc/group");
    let entry = format!("{SANDBOX_USER}:x:{SANDBOX_GID}:\n");
    append_user_db_entry(&path, SANDBOX_USER, &entry)
}

/// Append `entry` to the colon-delimited user DB at `path` unless a line
/// already starts with `key:`. Creates `etc/` and the file if needed.
fn append_user_db_entry(path: &Path, key: &str, entry: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let existing = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err),
    };

    let prefix = format!("{key}:");
    if existing.lines().any(|line| line.starts_with(&prefix)) {
        return Ok(());
    }

    let mut combined = existing;
    if !combined.is_empty() && !combined.ends_with('\n') {
        combined.push('\n');
    }
    combined.push_str(entry);
    fs::write(path, combined)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

/// Pick the best shell path for the sandbox user.
///
/// Prefers `/bin/sh` if present; falls back to `/sbin/nologin`, then
/// `/bin/false`. This guarantees a valid shell field in `/etc/passwd`
/// even for minimal images.
fn pick_shell(root: &Path) -> String {
    for candidate in ["bin/sh", "sbin/nologin", "usr/sbin/nologin", "bin/false"] {
        if root.join(candidate).exists() {
            return format!("/{candidate}");
        }
    }
    "/sbin/nologin".to_string()
}

fn ensure_dir(path: &Path, mode: u32) -> io::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn ensure_empty_file(path: &Path, mode: u32) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        fs::write(path, "")?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_root() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn inject_populates_passwd_group_and_dirs_on_empty_root() {
        let tmp = fresh_root();
        inject(tmp.path()).unwrap();

        let passwd = fs::read_to_string(tmp.path().join("etc/passwd")).unwrap();
        assert!(passwd.contains(&format!("{SANDBOX_USER}:x:{SANDBOX_UID}:{SANDBOX_GID}:")));

        let group = fs::read_to_string(tmp.path().join("etc/group")).unwrap();
        assert!(group.contains(&format!("{SANDBOX_USER}:x:{SANDBOX_GID}:")));

        let sandbox_meta = fs::metadata(tmp.path().join("sandbox")).unwrap();
        assert!(sandbox_meta.is_dir());
        assert_eq!(sandbox_meta.permissions().mode() & 0o777, 0o755);

        let tmp_meta = fs::metadata(tmp.path().join("tmp")).unwrap();
        assert_eq!(tmp_meta.permissions().mode() & 0o7777, 0o1777);

        assert!(tmp.path().join("etc/hosts").exists());
        assert!(tmp.path().join("etc/resolv.conf").exists());
    }

    #[test]
    fn inject_is_idempotent_and_does_not_duplicate_entries() {
        let tmp = fresh_root();
        inject(tmp.path()).unwrap();
        inject(tmp.path()).unwrap();

        let passwd = fs::read_to_string(tmp.path().join("etc/passwd")).unwrap();
        let sandbox_lines = passwd
            .lines()
            .filter(|line| line.starts_with(&format!("{SANDBOX_USER}:")))
            .count();
        assert_eq!(sandbox_lines, 1, "sandbox user should appear exactly once");
    }

    #[test]
    fn inject_preserves_existing_passwd_entries() {
        let tmp = fresh_root();
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\n",
        )
        .unwrap();

        inject(tmp.path()).unwrap();

        let passwd = fs::read_to_string(tmp.path().join("etc/passwd")).unwrap();
        assert!(passwd.contains("root:x:0:0:"));
        assert!(passwd.contains(&format!("{SANDBOX_USER}:x:{SANDBOX_UID}:")));
    }

    #[test]
    fn inject_uses_nologin_when_no_shell_present() {
        let tmp = fresh_root();
        inject(tmp.path()).unwrap();
        let passwd = fs::read_to_string(tmp.path().join("etc/passwd")).unwrap();
        assert!(
            passwd.contains(":/sbin/nologin"),
            "expected nologin fallback, got: {passwd}"
        );
    }

    #[test]
    fn inject_uses_bin_sh_when_available() {
        let tmp = fresh_root();
        fs::create_dir_all(tmp.path().join("bin")).unwrap();
        fs::write(tmp.path().join("bin/sh"), "").unwrap();
        fs::set_permissions(tmp.path().join("bin/sh"), fs::Permissions::from_mode(0o755)).unwrap();

        inject(tmp.path()).unwrap();
        let passwd = fs::read_to_string(tmp.path().join("etc/passwd")).unwrap();
        assert!(passwd.contains(":/bin/sh"));
    }

    #[test]
    fn inject_does_not_truncate_existing_etc_hosts() {
        let tmp = fresh_root();
        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(tmp.path().join("etc/hosts"), "127.0.0.1 localhost\n").unwrap();
        inject(tmp.path()).unwrap();
        let hosts = fs::read_to_string(tmp.path().join("etc/hosts")).unwrap();
        assert!(hosts.contains("127.0.0.1"));
    }
}
