// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime-loaded bindings for the `openshell-containerd-shim` cgo library.
//!
//! Registry image resolution/pull and OCI layer unpacking are implemented
//! in Go (`crates/openshell-driver-vm/goshim/`) on top of containerd's
//! client libraries (`core/remotes/docker`, `pkg/archive`) rather than
//! hand-rolled in Rust. That Go code is compiled with
//! `go build -buildmode=c-shared` into a small shared library and loaded
//! dynamically here via `libloading`, the same way this crate loads
//! libkrun in `ffi.rs`. There is no live `containerd` daemon involved:
//! the shim links containerd's content/remotes/archive packages directly
//! and talks to registries itself.
//!
//! Every exported Go function returns `NULL` on success or a heap-allocated
//! C string describing the error on failure; failure strings are freed via
//! `ContainerdFreeString` immediately after being copied into a Rust
//! `String`.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::path::Path;
use std::ptr;
use std::sync::OnceLock;

use libc::c_char;
use libloading::Library;

pub fn required_shim_lib_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "libopenshell_containerd_shim.dylib"
    }
    #[cfg(not(target_os = "macos"))]
    {
        "libopenshell_containerd_shim.so"
    }
}

type ContainerdFreeString = unsafe extern "C" fn(*mut c_char);
type ContainerdResolveDigest = unsafe extern "C" fn(
    image_ref: *const c_char,
    platform_os: *const c_char,
    platform_arch: *const c_char,
    out_digest: *mut *mut c_char,
) -> *mut c_char;
type ContainerdPullImage = unsafe extern "C" fn(
    image_ref: *const c_char,
    dest_layout_dir: *const c_char,
    platform_os: *const c_char,
    platform_arch: *const c_char,
) -> *mut c_char;
type ContainerdUnpackLayout =
    unsafe extern "C" fn(layout_dir: *const c_char, dest_rootfs_dir: *const c_char) -> *mut c_char;

struct ContainerdShim {
    free_string: ContainerdFreeString,
    resolve_digest: ContainerdResolveDigest,
    pull_image: ContainerdPullImage,
    unpack_layout: ContainerdUnpackLayout,
}

static SHIM: OnceLock<ContainerdShim> = OnceLock::new();

fn shim(runtime_dir: &Path) -> Result<&'static ContainerdShim, String> {
    if let Some(shim) = SHIM.get() {
        return Ok(shim);
    }

    let loaded = ContainerdShim::load(runtime_dir)?;
    let _ = SHIM.set(loaded);
    Ok(SHIM.get().expect("containerd shim should be initialized"))
}

impl ContainerdShim {
    fn load(runtime_dir: &Path) -> Result<Self, String> {
        let lib_path = runtime_dir.join(required_shim_lib_name());
        let library = Box::leak(Box::new(unsafe {
            Library::new(&lib_path)
                .map_err(|e| format!("load containerd shim from {}: {e}", lib_path.display()))?
        }));

        Ok(Self {
            free_string: load_symbol(library, b"ContainerdFreeString\0", &lib_path)?,
            resolve_digest: load_symbol(library, b"ContainerdResolveDigest\0", &lib_path)?,
            pull_image: load_symbol(library, b"ContainerdPullImage\0", &lib_path)?,
            unpack_layout: load_symbol(library, b"ContainerdUnpackLayout\0", &lib_path)?,
        })
    }
}

fn load_symbol<T: Copy>(library: &'static Library, name: &[u8], path: &Path) -> Result<T, String> {
    unsafe {
        library.get::<T>(name).map(|symbol| *symbol).map_err(|e| {
            format!(
                "load symbol {} from {}: {e}",
                String::from_utf8_lossy(name).trim_end_matches('\0'),
                path.display()
            )
        })
    }
}

fn to_cstring(value: &str, what: &str) -> Result<CString, String> {
    CString::new(value).map_err(|e| format!("invalid {what} '{value}': {e}"))
}

/// Take ownership of an error string returned by the shim, converting it to
/// an owned Rust `String` and freeing the underlying C allocation.
unsafe fn take_error(shim: &ContainerdShim, err: *mut c_char) -> Option<String> {
    if err.is_null() {
        return None;
    }
    unsafe {
        let message = CStr::from_ptr(err).to_string_lossy().into_owned();
        (shim.free_string)(err);
        Some(message)
    }
}

/// Take ownership of a non-error output string returned via an out-param,
/// converting it to an owned Rust `String` and freeing the underlying C
/// allocation. Returns an error if the pointer is unexpectedly null.
unsafe fn take_output(
    shim: &ContainerdShim,
    out: *mut c_char,
    what: &str,
) -> Result<String, String> {
    if out.is_null() {
        return Err(format!("containerd shim returned no {what}"));
    }
    unsafe {
        let value = CStr::from_ptr(out).to_string_lossy().into_owned();
        (shim.free_string)(out);
        Ok(value)
    }
}

/// Resolve `image_ref` against its registry and return the digest of the
/// manifest that matches `platform_arch` (linux/<arch>), without
/// downloading any layer content. Used to check the driver's on-disk image
/// cache before committing to a full pull.
pub fn resolve_image_digest(
    runtime_dir: &Path,
    image_ref: &str,
    platform_arch: &str,
) -> Result<String, String> {
    let shim = shim(runtime_dir)?;
    let c_image_ref = to_cstring(image_ref, "image reference")?;
    let c_os = to_cstring("linux", "platform os")?;
    let c_arch = to_cstring(platform_arch, "platform arch")?;

    unsafe {
        let mut out_digest: *mut c_char = ptr::null_mut();
        let err = (shim.resolve_digest)(
            c_image_ref.as_ptr(),
            c_os.as_ptr(),
            c_arch.as_ptr(),
            &raw mut out_digest,
        );
        if let Some(message) = take_error(shim, err) {
            return Err(format!(
                "failed to resolve vm sandbox image '{image_ref}': {message}"
            ));
        }
        take_output(shim, out_digest, "digest")
    }
}

/// Pull `image_ref`'s manifest/config/layer blobs for `platform_arch`
/// (linux/<arch>) into a standard OCI Image Layout at `dest_layout_dir`.
pub fn pull_image_to_oci_layout(
    runtime_dir: &Path,
    image_ref: &str,
    dest_layout_dir: &Path,
    platform_arch: &str,
) -> Result<(), String> {
    let shim = shim(runtime_dir)?;
    let c_image_ref = to_cstring(image_ref, "image reference")?;
    let c_dest = to_cstring(&dest_layout_dir.to_string_lossy(), "OCI layout dir path")?;
    let c_os = to_cstring("linux", "platform os")?;
    let c_arch = to_cstring(platform_arch, "platform arch")?;

    unsafe {
        let err = (shim.pull_image)(
            c_image_ref.as_ptr(),
            c_dest.as_ptr(),
            c_os.as_ptr(),
            c_arch.as_ptr(),
        );
        if let Some(message) = take_error(shim, err) {
            return Err(format!(
                "failed to pull vm sandbox image '{image_ref}': {message}"
            ));
        }
    }
    Ok(())
}

/// Apply every layer of the single-manifest OCI Image Layout at
/// `layout_dir` onto `dest_rootfs_dir`, in order.
pub fn unpack_oci_layout_to_dir(
    runtime_dir: &Path,
    layout_dir: &Path,
    dest_rootfs_dir: &Path,
) -> Result<(), String> {
    let shim = shim(runtime_dir)?;
    let c_layout = to_cstring(&layout_dir.to_string_lossy(), "OCI layout dir path")?;
    let c_dest = to_cstring(&dest_rootfs_dir.to_string_lossy(), "rootfs dir path")?;

    unsafe {
        let err = (shim.unpack_layout)(c_layout.as_ptr(), c_dest.as_ptr());
        if let Some(message) = take_error(shim, err) {
            return Err(format!(
                "failed to unpack vm sandbox image layers into {}: {message}",
                dest_rootfs_dir.display()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        let suffix = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "openshell-driver-vm-containerd-shim-test-{label}-{}-{nanos}-{suffix}",
            std::process::id()
        ))
    }

    /// End-to-end check against the real containerd shim library and a real
    /// public registry: resolve a digest, pull the image into an OCI Image
    /// Layout, and unpack its layer onto disk. Requires the shim to be
    /// built (`mise run vm:setup`, which now also runs
    /// `build-containerd-shim.sh`) and network access to docker.io, so it
    /// is `#[ignore]`d by default; run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "requires network access and a built containerd shim library"]
    fn resolve_pull_and_unpack_a_real_image() {
        let runtime_dir = crate::runtime::configured_runtime_dir()
            .expect("runtime dir should be extracted (run `mise run vm:setup` first)");

        let digest = resolve_image_digest(
            &runtime_dir,
            "docker.io/library/busybox:latest",
            linux_test_arch(),
        )
        .expect("resolve digest");
        assert!(digest.starts_with("sha256:"), "digest was {digest}");

        let layout_dir = unique_temp_dir("layout");
        let rootfs_dir = unique_temp_dir("rootfs");
        let _cleanup = CleanupDirs(vec![layout_dir.clone(), rootfs_dir.clone()]);

        pull_image_to_oci_layout(
            &runtime_dir,
            "docker.io/library/busybox:latest",
            &layout_dir,
            linux_test_arch(),
        )
        .expect("pull image");
        assert!(layout_dir.join("index.json").is_file());
        assert!(layout_dir.join("oci-layout").is_file());

        unpack_oci_layout_to_dir(&runtime_dir, &layout_dir, &rootfs_dir).expect("unpack layout");
        assert!(rootfs_dir.join("bin").is_dir());
    }

    fn linux_test_arch() -> &'static str {
        match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        }
    }

    struct CleanupDirs(Vec<std::path::PathBuf>);

    impl Drop for CleanupDirs {
        fn drop(&mut self) {
            for dir in &self.0 {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }
}
