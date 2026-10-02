// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Preloadable peer-address shim for legacy seccomp listeners.
//!
//! See `src/accept_shim.c` and this crate's README for why the shim exists.
//! The compiled object is embedded here so the sandbox can materialize it
//! into a workload whose image it does not control.

/// File name used when the shim is materialized into a workload.
pub const FILE_NAME: &str = "accept_shim.so";

/// Environment variable the workload's dynamic loader reads.
pub const PRELOAD_ENV: &str = "LD_PRELOAD";

/// The compiled shared object for this build's target architecture.
#[cfg(target_os = "linux")]
pub const SHIM_OBJECT: &[u8] = include_bytes!(env!("OPENSHELL_ACCEPT_SHIM"));

/// Probe and retain a private shim object in the boundary.
///
/// This descriptor is
/// close-on-exec; workloads receive their own anonymous inode via
/// [`create_child_shim`], so changes to file permissions cannot affect later
/// sessions. Anonymous inodes need no Landlock user-ruleset admission.
#[cfg(target_os = "linux")]
pub fn install_shim() -> Result<std::path::PathBuf, String> {
    use std::os::fd::AsRawFd as _;
    use std::sync::OnceLock;
    static OBJECT: OnceLock<std::fs::File> = OnceLock::new();
    if OBJECT.get().is_none() {
        let _ = OBJECT.set(create_object(true)?);
    }
    Ok(std::path::PathBuf::from(format!(
        "/proc/self/fd/{}",
        OBJECT.get().expect("installed object").as_raw_fd()
    )))
}

/// Create a fresh sealed object for one workload launch.
///
/// The descriptor is
/// close-on-exec in the boundary: the caller must retain the File until spawn
/// and clear CLOEXEC only in the forked child, so concurrent launches cannot
/// inherit and change permissions on one another's pending objects.
#[cfg(target_os = "linux")]
pub fn create_child_shim() -> Result<std::fs::File, String> {
    create_object(true)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn create_object(close_on_exec: bool) -> Result<std::fs::File, String> {
    use std::io::Write as _;
    use std::os::fd::FromRawFd as _;
    let flags = libc::MFD_ALLOW_SEALING | if close_on_exec { libc::MFD_CLOEXEC } else { 0 };
    // MFD_EXEC overrides vm.memfd_noexec=1 on 6.3+. Older kernels reject
    // that flag; retry with the original executable memfd ABI.
    let mut fd = unsafe { libc::memfd_create(c"openshell-accept-shim".as_ptr(), flags | 0x10) };
    if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        fd = unsafe { libc::memfd_create(c"openshell-accept-shim".as_ptr(), flags) };
    }
    if fd < 0 {
        return Err(format!(
            "create shim memfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(SHIM_OBJECT)
        .map_err(|error| format!("write shim memfd: {error}"))?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        return Err(format!(
            "seal shim memfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Check executable mapping before exporting LD_PRELOAD: some hosts
    // prohibit execution of anonymous files even when creation succeeds.
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            SHIM_OBJECT.len(),
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE,
            fd,
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        return Err(format!(
            "map executable shim: {}",
            std::io::Error::last_os_error()
        ));
    }
    unsafe {
        libc::munmap(mapping, SHIM_OBJECT.len());
    }
    Ok(file)
}

/// Compose an `LD_PRELOAD` value that keeps any workload-supplied entries.
///
/// The shim is placed first so it wins symbol resolution, and an existing
/// value is preserved rather than replaced: a workload that relies on its own
/// preload must keep working.
#[must_use]
pub fn compose_preload(shim_path: &str, existing: Option<&str>) -> String {
    match existing.map(str::trim).filter(|value| !value.is_empty()) {
        Some(existing) if preload_contains(existing, shim_path) => existing.to_string(),
        Some(existing) => format!("{shim_path}:{existing}"),
        None => shim_path.to_string(),
    }
}

/// Whether an `LD_PRELOAD` value already lists a path.
///
/// The loader separates entries by colon or whitespace, so both are honored.
fn preload_contains(value: &str, path: &str) -> bool {
    value
        .split([':', ' ', '\t'])
        .any(|entry| !entry.is_empty() && entry == path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The object is produced by a C compiler chosen at build time, so a
    /// misresolved cross-compiler yields a host-architecture object that the
    /// workload's loader rejects with a message that reads like a policy
    /// denial. Pin the shape of what actually got embedded.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_embedded_object_is_a_shared_object_for_the_build_target() {
        let expected_machine: u16 = if cfg!(target_arch = "x86_64") {
            0x3e // EM_X86_64
        } else if cfg!(target_arch = "aarch64") {
            0xb7 // EM_AARCH64
        } else {
            panic!("unsupported architecture for the accept shim");
        };

        let header = SHIM_OBJECT;
        assert!(header.len() > 20, "object is too short to be an ELF file");
        assert_eq!(&header[0..4], b"\x7fELF", "not an ELF object");
        assert_eq!(header[4], 2, "expected ELFCLASS64");
        assert_eq!(header[5], 1, "expected little-endian ELF");
        assert_eq!(
            u16::from_le_bytes([header[16], header[17]]),
            3,
            "expected ET_DYN; a non-shared object cannot be preloaded"
        );
        assert_eq!(
            u16::from_le_bytes([header[18], header[19]]),
            expected_machine,
            "object architecture does not match the build target"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn installed_object_cannot_be_replaced_or_rewritten() {
        use std::io::Write as _;
        let path = install_shim().expect("install sealed object");
        assert_eq!(std::fs::read(&path).unwrap(), SHIM_OBJECT);
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert_eq!(
            file.write(b"replacement").unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            file.set_len(0).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(install_shim().unwrap(), path);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn one_child_cannot_change_the_next_launch_object() {
        use std::os::unix::fs::PermissionsExt as _;
        let first = create_child_shim().unwrap();
        first
            .set_permissions(std::fs::Permissions::from_mode(0o000))
            .unwrap();
        let second = create_child_shim().unwrap();
        assert_ne!(second.metadata().unwrap().permissions().mode() & 0o444, 0);
        assert_eq!(std::fs::read(install_shim().unwrap()).unwrap(), SHIM_OBJECT);
    }

    #[test]
    fn preload_is_the_only_entry_when_the_workload_set_none() {
        assert_eq!(compose_preload("/run/shim.so", None), "/run/shim.so");
        assert_eq!(compose_preload("/run/shim.so", Some("")), "/run/shim.so");
        assert_eq!(compose_preload("/run/shim.so", Some("   ")), "/run/shim.so");
    }

    #[test]
    fn workload_supplied_preloads_are_kept_after_the_shim() {
        assert_eq!(
            compose_preload("/run/shim.so", Some("/opt/jemalloc.so")),
            "/run/shim.so:/opt/jemalloc.so"
        );
        assert_eq!(
            compose_preload("/run/shim.so", Some("/a.so:/b.so")),
            "/run/shim.so:/a.so:/b.so"
        );
    }

    #[test]
    fn an_already_listed_shim_is_not_added_twice() {
        // Children re-inherit the composed value; repeated spawns must not
        // grow LD_PRELOAD without bound.
        assert_eq!(
            compose_preload("/run/shim.so", Some("/run/shim.so")),
            "/run/shim.so"
        );
        assert_eq!(
            compose_preload("/run/shim.so", Some("/run/shim.so:/b.so")),
            "/run/shim.so:/b.so"
        );
        assert_eq!(
            compose_preload("/run/shim.so", Some("/a.so /run/shim.so")),
            "/a.so /run/shim.so"
        );
    }

    #[test]
    fn a_path_that_merely_shares_a_prefix_is_not_treated_as_present() {
        assert_eq!(
            compose_preload("/run/shim.so", Some("/run/shim.so.bak")),
            "/run/shim.so:/run/shim.so.bak"
        );
    }
}
