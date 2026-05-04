// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::fs::File;
use std::io::{BufWriter, Cursor};
use std::path::{Path, PathBuf};

const SUPERVISOR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/openshell-sandbox.zst"));
const ROOTFS_VARIANT_MARKER: &str = ".openshell-rootfs-variant";
const SANDBOX_GUEST_INIT_PATH: &str = "/srv/openshell-vm-sandbox-init.sh";
const SANDBOX_SUPERVISOR_PATH: &str = "/opt/openshell/bin/openshell-sandbox";

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

/// Re-inject the init script and supervisor binary into an already-prepared
/// rootfs. The image rootfs archive cache is keyed by image digest, so a
/// driver rebuild does not invalidate it. Calling this after extraction
/// ensures the guest always runs the init script and supervisor that match
/// the running driver binary.
pub fn refresh_runtime_artifacts(rootfs: &Path) -> Result<(), String> {
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

    ensure_supervisor_binary(rootfs)?;

    let opt_dir = rootfs.join("opt/openshell");
    fs::create_dir_all(&opt_dir).map_err(|e| format!("create {}: {e}", opt_dir.display()))?;
    fs::write(opt_dir.join(".rootfs-type"), "sandbox\n")
        .map_err(|e| format!("write sandbox rootfs marker: {e}"))?;
    ensure_sandbox_guest_user(rootfs)?;

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

/// Kernel version of the libkrunfw guest. Modules must be compiled against
/// this exact version; a mismatch causes `modprobe` failures at boot.
///
/// Keep in sync with:
///   - `tasks/scripts/vm/build-nvidia-modules.sh` (`KERNEL_TREE` path)
///   - `openshell-vm-sandbox-init.sh` `setup_gpu()` expected version
const GUEST_KERNEL_VERSION: &str = "6.12.76";

/// Inject NVIDIA kernel modules, firmware, and `kmod` tooling into a prepared
/// sandbox rootfs. Called by the driver when a sandbox requests GPU support.
///
/// Module source resolution order:
///   1. `OPENSHELL_GPU_MODULES_DIR` environment variable
///   2. `<state_dir>/gpu-modules/` (pre-provisioned by the operator)
///
/// Firmware source resolution (first match wins):
///   0. Rootfs already contains `.bin` files (e.g. from the image's `.run`
///      installer) — **skip injection entirely** to avoid version mismatch.
///   1. `<modules_dir>/../nvidia-firmware/`
///   2. Host `/lib/firmware/nvidia/`
///
/// Returns an error only if module injection is impossible (no source found
/// or a write fails). Missing firmware emits a warning and continues.
pub fn inject_gpu_modules(rootfs: &Path, state_dir: &Path) -> Result<(), String> {
    let modules_dir = resolve_gpu_modules_dir(state_dir)?;

    let ko_files: Vec<PathBuf> = fs::read_dir(&modules_dir)
        .map_err(|e| format!("read GPU modules dir {}: {e}", modules_dir.display()))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "ko") {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    if ko_files.is_empty() {
        return Err(format!(
            "GPU modules dir {} contains no .ko files",
            modules_dir.display()
        ));
    }

    let modules_dst = rootfs.join(format!(
        "lib/modules/{GUEST_KERNEL_VERSION}/kernel/drivers/nvidia"
    ));
    fs::create_dir_all(&modules_dst)
        .map_err(|e| format!("create {}: {e}", modules_dst.display()))?;

    for ko in &ko_files {
        let dest = modules_dst.join(ko.file_name().unwrap());
        let bytes_copied = fs::copy(ko, &dest)
            .map_err(|e| format!("copy {} -> {}: {e}", ko.display(), dest.display()))?;
        tracing::info!(
            module = %ko.file_name().unwrap().to_string_lossy(),
            size_bytes = bytes_copied,
            src = %ko.display(),
            "injected GPU kernel module"
        );
    }

    inject_gpu_firmware(rootfs, &modules_dir);
    ensure_kmod_symlinks(rootfs);
    warn_missing_gpu_userspace(rootfs);

    Ok(())
}

/// Check whether the rootfs contains essential GPU userspace binaries.
/// Emits actionable warnings when the sandbox image lacks nvidia-smi
/// or CUDA libraries — common when `--gpu` is used with a non-GPU base
/// image like `ubuntu:latest` instead of the GPU sandbox Dockerfile.
fn warn_missing_gpu_userspace(rootfs: &Path) {
    let nvidia_smi_candidates = [
        "usr/bin/nvidia-smi",
        "usr/local/bin/nvidia-smi",
        "bin/nvidia-smi",
    ];
    let has_nvidia_smi = nvidia_smi_candidates
        .iter()
        .any(|p| rootfs.join(p).exists());

    if !has_nvidia_smi {
        tracing::warn!(
            "GPU sandbox image does not contain nvidia-smi. The sandbox will \
             have GPU kernel modules but no NVIDIA userspace tools. Use a \
             GPU-enabled image (e.g. --from ./sandboxes/nvidia-gpu/Dockerfile) \
             or install the NVIDIA driver userspace in your image."
        );
    }
}

/// Locate the directory containing pre-built NVIDIA `.ko` files.
///
/// Resolution order:
///   1. `OPENSHELL_GPU_MODULES_DIR` env var (explicit override)
///   2. `<state_dir>/gpu-modules/` (operator pre-provisioned)
///   3. `<project_root>/target/libkrun-build/nvidia-modules/` (build tree,
///      discovered relative to the driver executable)
///   4. Host `/lib/modules/<GUEST_KERNEL_VERSION>/kernel/drivers/nvidia/`
fn resolve_gpu_modules_dir(state_dir: &Path) -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var("OPENSHELL_GPU_MODULES_DIR") {
        let p = PathBuf::from(&dir);
        if p.is_dir() {
            tracing::info!(path = %p.display(), "using GPU modules from OPENSHELL_GPU_MODULES_DIR");
            return Ok(p);
        }
        return Err(format!(
            "OPENSHELL_GPU_MODULES_DIR={dir} is not a directory"
        ));
    }

    let provisioned = state_dir.join("gpu-modules");
    if provisioned.is_dir() {
        tracing::info!(path = %provisioned.display(), "using pre-provisioned GPU modules");
        return Ok(provisioned);
    }

    // Auto-discover from the build tree. The driver binary lives at
    // `target/{debug,release}/openshell-driver-vm`, so the project root
    // is two levels up. The old GPU rootfs script places modules at
    // `target/libkrun-build/nvidia-modules/`.
    if let Some(build_tree_dir) = discover_build_tree_modules() {
        return Ok(build_tree_dir);
    }

    // Check common host-installed module paths.
    for candidate in [
        format!("/lib/modules/{GUEST_KERNEL_VERSION}/kernel/drivers/nvidia"),
        format!("/lib/modules/{GUEST_KERNEL_VERSION}/extra/nvidia"),
    ] {
        let p = PathBuf::from(&candidate);
        if dir_has_ko_files(&p) {
            tracing::info!(path = %p.display(), "using host-installed GPU modules");
            return Ok(p);
        }
    }

    Err(format!(
        "No GPU kernel modules found. Searched: OPENSHELL_GPU_MODULES_DIR (unset), \
         {}, build tree, host /lib/modules/{}. \
         Build modules with `mise run vm:nvidia-modules` \
         or set OPENSHELL_GPU_MODULES_DIR.",
        provisioned.display(),
        GUEST_KERNEL_VERSION,
    ))
}

/// Walk up from the driver executable to find `target/libkrun-build/nvidia-modules/`.
///
/// This is a development convenience — production deployments should use
/// `OPENSHELL_GPU_MODULES_DIR` or pre-provision `<state_dir>/gpu-modules/`.
fn discover_build_tree_modules() -> Option<PathBuf> {
    #[cfg(unix)]
    if nix::unistd::Uid::effective().is_root() {
        tracing::debug!(
            "build-tree GPU module discovery running as root; \
                         prefer OPENSHELL_GPU_MODULES_DIR in production"
        );
    }
    let exe = std::env::current_exe().ok()?;
    // exe is typically target/{debug,release}/openshell-driver-vm
    let target_dir = exe.parent()?.parent()?;
    let modules_dir = target_dir.join("libkrun-build/nvidia-modules");
    if dir_has_ko_files(&modules_dir) {
        tracing::info!(
            path = %modules_dir.display(),
            "auto-discovered GPU modules in build tree"
        );
        return Some(modules_dir);
    }

    // Also try CWD-relative (for `cargo run` or `mise run` from project root).
    let cwd_candidate = PathBuf::from("target/libkrun-build/nvidia-modules");
    if dir_has_ko_files(&cwd_candidate) {
        let abs = cwd_candidate
            .canonicalize()
            .unwrap_or_else(|_| cwd_candidate.clone());
        tracing::info!(
            path = %abs.display(),
            "auto-discovered GPU modules relative to CWD"
        );
        return Some(abs);
    }

    None
}

fn dir_has_ko_files(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let Some(entries) = fs::read_dir(dir).ok() else {
        return false;
    };
    let mut has_uncompressed = false;
    let mut has_compressed = false;
    for entry in entries.flatten() {
        let path = entry.path();
        match path.extension().and_then(|e| e.to_str()) {
            Some("ko") => has_uncompressed = true,
            Some("zst" | "xz")
                if path
                    .file_stem()
                    .and_then(|s| Path::new(s).extension())
                    .is_some_and(|ext| ext == "ko") =>
            {
                has_compressed = true;
            }
            _ => {}
        }
    }
    if !has_uncompressed && has_compressed {
        tracing::warn!(
            path = %dir.display(),
            "directory contains compressed .ko.zst/.ko.xz modules but only uncompressed .ko files are supported"
        );
    }
    has_uncompressed
}

/// Copy NVIDIA GSP firmware into the rootfs. Non-fatal on failure.
///
/// Skips injection if the rootfs already contains `.bin` firmware files
/// (e.g. the sandbox Docker image installed them via the NVIDIA `.run`
/// installer). Overwriting image-provided firmware with build-tree or
/// host firmware causes version mismatches when the host driver differs
/// from the image's driver version.
fn inject_gpu_firmware(rootfs: &Path, modules_dir: &Path) {
    let fw_dst = rootfs.join("lib/firmware/nvidia");

    if rootfs_has_firmware_bins(&fw_dst) {
        tracing::info!(
            path = %fw_dst.display(),
            "rootfs already contains GPU firmware; skipping injection"
        );
        return;
    }

    // Try version-matched firmware next to the modules directory.
    let fw_parent = modules_dir.parent().map(|p| p.join("nvidia-firmware"));

    if let Some(ref fw_dir) = fw_parent
        && fw_dir.is_dir()
    {
        if let Err(e) = copy_dir_contents(fw_dir, &fw_dst) {
            tracing::warn!(error = %e, "failed to copy version-matched firmware");
        } else {
            tracing::info!(src = %fw_dir.display(), "injected GPU firmware (version-matched)");
            return;
        }
    }

    // Fallback: host firmware
    for candidate in ["/lib/firmware/nvidia", "/usr/lib/firmware/nvidia"] {
        let host_fw = Path::new(candidate);
        if host_fw.is_dir() {
            if let Err(e) = copy_dir_contents(host_fw, &fw_dst) {
                tracing::warn!(error = %e, src = candidate, "failed to copy host firmware");
            } else {
                tracing::info!(src = candidate, "injected GPU firmware from host");
                return;
            }
        }
    }

    tracing::warn!(
        "no NVIDIA GSP firmware found; GPU guests may fail to initialize. \
         Place firmware in {:?} or host /lib/firmware/nvidia/",
        fw_parent
            .as_deref()
            .unwrap_or_else(|| Path::new("(unknown)"))
    );
}

/// Check whether a firmware directory (or any subdirectory) contains `.bin` files.
fn rootfs_has_firmware_bins(fw_dir: &Path) -> bool {
    if !fw_dir.is_dir() {
        return false;
    }
    let Ok(entries) = fs::read_dir(fw_dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "bin") {
            return true;
        }
        if path.is_dir() && rootfs_has_firmware_bins(&path) {
            return true;
        }
    }
    false
}

/// Ensure `modprobe`, `insmod`, etc. symlinks exist. Many minimal container
/// images install `kmod` but lack the convenience symlinks in `/usr/sbin`.
fn ensure_kmod_symlinks(rootfs: &Path) {
    let kmod_candidates = ["bin/kmod", "usr/bin/kmod", "sbin/kmod", "usr/sbin/kmod"];
    let kmod_exists = kmod_candidates.iter().any(|p| rootfs.join(p).exists());

    if !kmod_exists {
        tracing::warn!(
            "kmod not found in rootfs; modprobe will fail. \
                        Ensure the sandbox image installs the 'kmod' package."
        );
        return;
    }

    let sbin = rootfs.join("usr/sbin");
    let _ = fs::create_dir_all(&sbin);
    for tool in ["modprobe", "insmod", "rmmod", "lsmod", "depmod"] {
        let link = sbin.join(tool);
        if !link.exists() {
            #[cfg(unix)]
            {
                let _ = std::os::unix::fs::symlink("../../bin/kmod", &link)
                    .or_else(|_| std::os::unix::fs::symlink("/usr/bin/kmod", &link));
            }
        }
    }
}

/// Recursively copy all files from `src` to `dst`, preserving directory structure.
fn copy_dir_contents(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;

    for entry in fs::read_dir(src).map_err(|e| format!("read {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| format!("read entry in {}: {e}", src.display()))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_contents(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path).map_err(|e| {
                format!("copy {} -> {}: {e}", src_path.display(), dst_path.display())
            })?;
        }
    }
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

        fs::create_dir_all(rootfs.join("usr/local/bin")).expect("create usr/local/bin");
        fs::create_dir_all(rootfs.join("etc")).expect("create etc");
        fs::create_dir_all(rootfs.join("var/lib/rancher")).expect("create var/lib/rancher");
        fs::create_dir_all(rootfs.join("opt/openshell/charts")).expect("create charts");
        fs::create_dir_all(rootfs.join("opt/openshell/manifests")).expect("create manifests");
        fs::create_dir_all(rootfs.join("opt/openshell/bin")).expect("create openshell bin");
        fs::write(rootfs.join("usr/local/bin/k3s"), b"k3s").expect("write k3s");
        fs::write(rootfs.join("usr/local/bin/kubectl"), b"kubectl").expect("write kubectl");
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

        assert!(!rootfs.join("usr/local/bin/k3s").exists());
        assert!(!rootfs.join("usr/local/bin/kubectl").exists());
        assert!(!rootfs.join("var/lib/rancher").exists());
        assert!(!rootfs.join("opt/openshell/charts").exists());
        assert!(!rootfs.join("opt/openshell/manifests").exists());
        assert!(rootfs.join("srv/openshell-vm-sandbox-init.sh").is_file());
        assert!(!rootfs.join("sandbox").exists());
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
    fn prepare_sandbox_rootfs_preserves_image_workdir_contents() {
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
    fn refresh_runtime_artifacts_overwrites_stale_init_script() {
        let dir = unique_temp_dir();
        let rootfs = dir.join("rootfs");

        fs::create_dir_all(rootfs.join("srv")).expect("create srv");
        fs::create_dir_all(rootfs.join("opt/openshell/bin")).expect("create openshell bin");
        fs::write(
            rootfs.join("srv/openshell-vm-sandbox-init.sh"),
            b"#!/bin/bash\n# stale placeholder",
        )
        .expect("write stale init");
        fs::write(
            rootfs.join("opt/openshell/bin/openshell-sandbox"),
            b"old-supervisor",
        )
        .expect("write stale supervisor");

        refresh_runtime_artifacts(&rootfs).expect("refresh runtime artifacts");

        let init_content =
            fs::read_to_string(rootfs.join("srv/openshell-vm-sandbox-init.sh")).expect("read init");
        assert!(
            init_content.contains("setup_gpu"),
            "refreshed init script should contain GPU setup logic"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn inject_gpu_modules_copies_ko_files() {
        let dir = unique_temp_dir();
        let modules_dir = dir.join("modules");
        let rootfs = dir.join("rootfs");

        fs::create_dir_all(&modules_dir).expect("create modules dir");
        fs::create_dir_all(&rootfs).expect("create rootfs dir");
        fs::write(modules_dir.join("nvidia.ko"), b"\x7fELF-fake-module-1")
            .expect("write nvidia.ko");
        fs::write(modules_dir.join("nvidia-uvm.ko"), b"\x7fELF-fake-module-2")
            .expect("write nvidia-uvm.ko");

        let result = temp_env::with_var(
            "OPENSHELL_GPU_MODULES_DIR",
            Some(modules_dir.as_os_str()),
            || inject_gpu_modules(&rootfs, Path::new("/dummy/state")),
        );

        result.expect("inject_gpu_modules should succeed");

        let dest = rootfs.join("lib/modules/6.12.76/kernel/drivers/nvidia");
        assert!(dest.join("nvidia.ko").is_file());
        assert!(dest.join("nvidia-uvm.ko").is_file());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn inject_gpu_modules_fails_with_no_ko_files() {
        let dir = unique_temp_dir();
        let modules_dir = dir.join("modules");

        fs::create_dir_all(&modules_dir).expect("create modules dir");
        fs::write(modules_dir.join("readme.txt"), b"not a kernel module").expect("write txt");

        let result = temp_env::with_var(
            "OPENSHELL_GPU_MODULES_DIR",
            Some(modules_dir.as_os_str()),
            || inject_gpu_modules(Path::new("/dummy/rootfs"), Path::new("/dummy/state")),
        );

        let err = result.expect_err("should fail with no .ko files");
        assert!(
            err.contains("no .ko files"),
            "error should mention 'no .ko files', got: {err}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn inject_gpu_modules_fails_with_missing_dir() {
        let dir = unique_temp_dir();
        let missing = dir.join("does-not-exist");

        let result = temp_env::with_var(
            "OPENSHELL_GPU_MODULES_DIR",
            Some(missing.as_os_str()),
            || inject_gpu_modules(Path::new("/dummy/rootfs"), Path::new("/dummy/state")),
        );

        let err = result.expect_err("should fail with missing directory");
        assert!(
            err.contains("not a directory"),
            "error should mention 'not a directory', got: {err}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn inject_gpu_firmware_skips_when_rootfs_has_bins() {
        let dir = unique_temp_dir();
        let rootfs = dir.join("rootfs");
        let modules_dir = dir.join("modules");
        let fw_dir = rootfs.join("lib/firmware/nvidia");

        fs::create_dir_all(&fw_dir).expect("create firmware dir");
        fs::create_dir_all(&modules_dir).expect("create modules dir");
        fs::write(fw_dir.join("gsp.bin"), b"original-firmware-content").expect("write gsp.bin");

        inject_gpu_firmware(&rootfs, &modules_dir);

        let content = fs::read(fw_dir.join("gsp.bin")).expect("read gsp.bin after injection");
        assert_eq!(
            content, b"original-firmware-content",
            "firmware should not be overwritten when rootfs already has .bin files"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_kmod_symlinks_creates_links() {
        let dir = unique_temp_dir();
        let rootfs = dir.join("rootfs");

        fs::create_dir_all(rootfs.join("bin")).expect("create bin");
        fs::write(rootfs.join("bin/kmod"), b"kmod-stub").expect("write kmod");

        ensure_kmod_symlinks(&rootfs);

        assert!(
            rootfs.join("usr/sbin/modprobe").exists(),
            "modprobe symlink should exist"
        );
        assert!(
            rootfs.join("usr/sbin/insmod").exists(),
            "insmod symlink should exist"
        );
        assert!(
            rootfs.join("usr/sbin/depmod").exists(),
            "depmod symlink should exist"
        );
        assert!(
            fs::symlink_metadata(rootfs.join("usr/sbin/modprobe"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "modprobe should be a symlink"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_kmod_symlinks_warns_without_kmod() {
        let dir = unique_temp_dir();
        let rootfs = dir.join("rootfs");

        fs::create_dir_all(&rootfs).expect("create rootfs");

        ensure_kmod_symlinks(&rootfs);

        assert!(
            !rootfs.join("usr/sbin/modprobe").exists(),
            "modprobe should not exist when kmod is missing"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rootfs_has_firmware_bins_detects_nested() {
        let dir1 = unique_temp_dir();
        fs::create_dir_all(dir1.join("subdir")).expect("create subdir");
        fs::write(dir1.join("subdir/file.bin"), b"firmware").expect("write .bin");
        assert!(
            rootfs_has_firmware_bins(&dir1),
            "should detect .bin in nested subdir"
        );
        let _ = fs::remove_dir_all(&dir1);

        let dir2 = unique_temp_dir();
        fs::create_dir_all(dir2.join("subdir")).expect("create subdir");
        fs::write(dir2.join("subdir/file.txt"), b"not firmware").expect("write .txt");
        assert!(
            !rootfs_has_firmware_bins(&dir2),
            "should not detect .txt as firmware"
        );
        let _ = fs::remove_dir_all(&dir2);
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
