// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Race-resistant handles for an explicit Landlock root allow-list.

#![allow(unsafe_code)]
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{AtFlags, Mode, OFlags, Stat, fstat, open, openat, statat};

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;

/// Query the Landlock ABI admitted by the active kernel and outer seccomp
/// profile without installing a ruleset.
pub fn abi_version() -> io::Result<u32> {
    // SAFETY: the VERSION operation requires a null ruleset pointer and zero
    // size and returns one scalar ABI version.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        u32::try_from(result).map_err(|_| io::Error::other("Landlock ABI does not fit u32"))
    }
}
/// One verified immediate child of the sandbox root.
pub struct RootEntryHandle {
    name: OsString,
    fd: OwnedFd,
    stat: Stat,
}

impl RootEntryHandle {
    /// Immediate-root entry name.
    #[must_use]
    pub fn name(&self) -> &OsStr {
        &self.name
    }

    /// Open, no-follow handle suitable for a later Landlock `PathBeneath` rule.
    #[must_use]
    pub fn fd(&self) -> &OwnedFd {
        &self.fd
    }

    /// Device number captured when the entry was opened.
    #[must_use]
    pub fn device(&self) -> u64 {
        self.stat.st_dev
    }

    /// Inode number captured when the entry was opened.
    #[must_use]
    pub fn inode(&self) -> u64 {
        self.stat.st_ino
    }
}

/// Open exactly the named root entries while proving that none is the private
/// sandbox hierarchy, a symlink, or a raced replacement.
///
/// Unnamed root entries are deliberately not returned and therefore cannot be
/// admitted accidentally. The caller obtains the allow-list names from trusted
/// image/driver policy, not by blindly allowing everything present in `/`.
pub fn open_root_allowlist(
    root: &Path,
    allowed_names: &BTreeSet<OsString>,
    private_name: &OsStr,
) -> io::Result<Vec<RootEntryHandle>> {
    validate_component(private_name)?;
    if allowed_names.contains(private_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private sandbox root cannot appear in the Landlock allow-list",
        ));
    }

    let root_fd = open(
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut result = Vec::with_capacity(allowed_names.len());
    for name in allowed_names {
        validate_component(name)?;
        let before = statat(&root_fd, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if before.st_mode & libc::S_IFMT == libc::S_IFLNK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Landlock root entry {} is a symlink",
                    Path::new(name).display()
                ),
            ));
        }
        let fd = openat(
            &root_fd,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let after = fstat(&fd)?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_mode & libc::S_IFMT != after.st_mode & libc::S_IFMT
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Landlock root entry {} changed while it was opened",
                    Path::new(name).display()
                ),
            ));
        }
        result.push(RootEntryHandle {
            name: name.clone(),
            fd,
            stat: after,
        });
    }
    Ok(result)
}

fn validate_component(name: &OsStr) -> io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid immediate-root entry {}", Path::new(name).display()),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "openshell-landlock-root-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create temp root");
        path
    }

    #[test]
    fn opens_only_explicit_entries_and_omits_private_root() {
        let root = temp_root();
        fs::create_dir(root.join("bin")).expect("create bin");
        fs::create_dir(root.join("sandbox")).expect("create workspace");
        fs::create_dir(root.join(".openshell")).expect("create private root");
        fs::create_dir(root.join("unexpected")).expect("create unexpected root");

        let allowed = BTreeSet::from([OsString::from("bin"), OsString::from("sandbox")]);
        let entries = open_root_allowlist(&root, &allowed, OsStr::new(".openshell"))
            .expect("open allow-list");
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name().to_owned())
                .collect::<Vec<_>>(),
            vec![OsString::from("bin"), OsString::from("sandbox")]
        );

        fs::remove_dir_all(root).expect("remove temp root");
    }

    #[test]
    fn rejects_private_entry_and_symlink() {
        let root = temp_root();
        fs::create_dir(root.join(".openshell")).expect("create private root");
        symlink(".openshell", root.join("runtime")).expect("create symlink");

        let private = BTreeSet::from([OsString::from(".openshell")]);
        assert!(open_root_allowlist(&root, &private, OsStr::new(".openshell")).is_err());
        let symlinked = BTreeSet::from([OsString::from("runtime")]);
        assert!(open_root_allowlist(&root, &symlinked, OsStr::new(".openshell")).is_err());

        fs::remove_dir_all(root).expect("remove temp root");
    }
}
