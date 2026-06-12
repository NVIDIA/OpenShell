// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM/QEMU-only guest kernel discovery for BlueField VF passthrough.

use std::path::{Path, PathBuf};

pub(crate) fn resolve_qemu_kernel_image(
    explicit: Option<PathBuf>,
    runtime_roots: &[PathBuf],
) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "configured BlueField QEMU kernel image does not exist: {}",
            path.display()
        ));
    }

    for root in runtime_roots {
        let candidate = root.join("vmlinux");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "BlueField QEMU kernel image not found; searched: {}. Set OPENSHELL_BLUEFIELD_KERNEL_IMAGE or place vmlinux in the OpenShell vm-runtime directory. Docker and Kubernetes BlueField runtimes do not use this QEMU kernel path.",
        runtime_roots
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

pub(crate) fn default_runtime_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(path) = std::env::var_os(crate::VM_RUNTIME_DIR_ENV) {
        push_unique(&mut roots, PathBuf::from(path));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(bin_dir) = exe.parent()
    {
        push_unique(&mut roots, bin_dir.join("vm-runtime"));
        push_unique(&mut roots, bin_dir.join("../vm-runtime"));
        push_unique(&mut roots, bin_dir.join("../../vm-runtime"));
    }
    push_unique(
        &mut roots,
        Path::new("/opt/openshell/vm-runtime").to_path_buf(),
    );
    roots
}

fn push_unique(roots: &mut Vec<PathBuf>, path: PathBuf) {
    if !roots.iter().any(|existing| existing == &path) {
        roots.push(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "openshell-bf-qemu-kernel-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn explicit_kernel_wins() {
        let root = temp_root("explicit");
        std::fs::create_dir_all(&root).unwrap();
        let explicit = root.join("custom-vmlinux");
        std::fs::write(&explicit, "kernel").unwrap();

        let resolved = resolve_qemu_kernel_image(Some(explicit.clone()), &[]).unwrap();

        assert_eq!(resolved, explicit);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn finds_vmlinux_in_runtime_roots() {
        let root = temp_root("runtime");
        let runtime = root.join("vm-runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        let kernel = runtime.join("vmlinux");
        std::fs::write(&kernel, "kernel").unwrap();

        let resolved = resolve_qemu_kernel_image(None, &[runtime]).unwrap();

        assert_eq!(resolved, kernel);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_all_searched_roots_when_missing() {
        let root = temp_root("missing");
        std::fs::create_dir_all(&root).unwrap();

        let err = resolve_qemu_kernel_image(None, std::slice::from_ref(&root)).unwrap_err();

        assert!(err.contains("BlueField QEMU kernel image not found"));
        assert!(err.contains(root.to_string_lossy().as_ref()));
        std::fs::remove_dir_all(root).unwrap();
    }
}
