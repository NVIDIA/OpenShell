// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration test for the OCI pipeline minus the network step.
//!
//! Builds a synthetic rootfs using the `flatten` module, injects compat files,
//! runs `mksquashfs` to produce a real RO base image, installs it in the
//! cache, and verifies the resulting fs image is non-empty and the cache
//! lookup round-trips.
//!
//! Gated on `mksquashfs` being present in `$PATH`. Run with:
//!   cargo test -p openshell-driver-vm --tests -- --ignored

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use openshell_driver_vm::oci::{
    CacheLayout, LaunchMetadata, Platform, compat,
    flatten::apply_tar_stream,
    fs_image::{BuildOptions, build},
    metadata::ImageConfig,
};

fn which(bin: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn build_minimal_tar() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);

        for dir in ["bin/", "etc/", "usr/", "usr/bin/"] {
            let mut header = tar::Header::new_gnu();
            header.set_path(dir).unwrap();
            header.set_size(0);
            header.set_mode(0o755);
            header.set_entry_type(tar::EntryType::Directory);
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
        }

        let mut header = tar::Header::new_gnu();
        header.set_path("bin/sh").unwrap();
        let payload = b"#!/bin/sh\n:\n";
        header.set_size(payload.len() as u64);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append(&header, &payload[..]).unwrap();

        let passwd = b"root:x:0:0:root:/root:/bin/sh\n";
        let mut header = tar::Header::new_gnu();
        header.set_path("etc/passwd").unwrap();
        header.set_size(passwd.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append(&header, &passwd[..]).unwrap();

        builder.finish().unwrap();
    }
    buf
}

#[test]
#[ignore = "requires mksquashfs in $PATH; run with `cargo test -- --ignored`"]
fn full_pipeline_without_network_produces_cached_image() {
    let Some(mksquashfs) = which("mksquashfs") else {
        eprintln!("mksquashfs not found on PATH; skipping");
        return;
    };

    let work = tempfile::tempdir().unwrap();

    // 1. Flatten a synthetic "image" layer into a staging tree.
    let staging = work.path().join("stage");
    fs::create_dir_all(&staging).unwrap();
    let tar_bytes = build_minimal_tar();
    apply_tar_stream(&staging, tar_bytes.as_slice()).unwrap();

    // 2. Inject OpenShell compat files.
    compat::inject(&staging).unwrap();
    assert!(staging.join("sandbox").is_dir());
    assert!(staging.join("tmp").is_dir());
    let passwd = fs::read_to_string(staging.join("etc/passwd")).unwrap();
    assert!(passwd.contains("sandbox:x:10001:10001:"));

    // 3. Build squashfs.
    let cache_root = work.path().join("cache");
    let layout = CacheLayout::new(cache_root.clone());
    layout.ensure_dirs().unwrap();
    let built = layout.tmp_dir().join("build.squashfs");
    let opts = BuildOptions::with_binary(mksquashfs);
    build(&staging, &built, &opts).expect("mksquashfs build");
    assert!(built.is_file());
    let size = fs::metadata(&built).unwrap().len();
    assert!(size > 0, "squashfs image should be non-empty");

    // 4. Install + write metadata, then round-trip the lookup.
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let platform = Platform::host().expect("host platform must be supported");

    let metadata = LaunchMetadata::build(
        ImageConfig {
            entrypoint: vec!["/bin/sh".to_string()],
            cmd: vec!["-c".to_string(), "true".to_string()],
            env: vec!["PATH=/bin".to_string()],
            working_dir: "/sandbox".to_string(),
            labels: BTreeMap::new(),
            stop_signal: String::new(),
        },
        &BTreeMap::new(),
        &BTreeMap::new(),
    )
    .unwrap();

    let installed = layout.install_fs_image(digest, platform, &built).unwrap();
    layout.write_metadata(digest, platform, &metadata).unwrap();
    assert!(installed.is_file());
    assert!(!built.exists(), "built image should be moved, not copied");

    let hit = layout
        .lookup(digest, platform)
        .expect("cache lookup should hit after install");
    assert_eq!(hit.fs_image, installed);
    assert_eq!(hit.metadata.argv, metadata.argv);

    // 5. A second install is idempotent (removes + re-moves into the same slot).
    let rebuilt = layout.tmp_dir().join("rebuild.squashfs");
    let mut f = fs::File::create(&rebuilt).unwrap();
    f.write_all(&fs::read(&installed).unwrap()).unwrap();
    drop(f);
    let reinstalled = layout.install_fs_image(digest, platform, &rebuilt).unwrap();
    assert_eq!(reinstalled, installed);
}
