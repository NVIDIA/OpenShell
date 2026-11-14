// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CDI device injection on the Docker and Podman compute drivers.
//!
//! Each test creates a sandbox that selects one scenario device and checks what
//! the workload sees against the scenario's published expectations. See the
//! `cdi` crate for how the scenarios and their checks work. No GPU hardware is
//! needed.

use testkit::Context;

/// A file mounted by the CDI spec under a directory the sandbox baseline
/// already makes read-only needs nothing derived from the spec: the workload
/// can read the mount and cannot write it. The spec-level environment variable
/// and mount every scenario carries show that the spec's edits and the
/// device's edits merge.
#[testkit::test]
async fn mount_under_read_only_baseline(cx: &mut Context) -> testkit::Result {
    cdi::scenario(cx, "mount-under-read-only-baseline").await
}

/// A read-only file mounted outside any directory the sandbox baseline
/// grants. The spec's expectations record whether the workload can read it.
#[testkit::test]
async fn read_only_file(cx: &mut Context) -> testkit::Result {
    cdi::scenario(cx, "read-only-file").await
}

/// A read-only directory mounted outside the baseline grants. The
/// expectations record whether its marker is readable and whether files can be
/// created in it.
#[testkit::test]
async fn read_only_directory(cx: &mut Context) -> testkit::Result {
    cdi::scenario(cx, "read-only-directory").await
}

/// A mount named like a shared library, `libfixture.so.1`, under a directory of
/// its own. The expectations record whether the library's parent directory is
/// granted for the workload.
#[testkit::test]
async fn library_parent(cx: &mut Context) -> testkit::Result {
    cdi::scenario(cx, "library-parent").await
}

/// A mount named like a shared library directly under `/`. Granting its parent
/// would grant the whole root, so the expectations record how that is handled.
#[testkit::test]
async fn broad_library_parent(cx: &mut Context) -> testkit::Result {
    cdi::scenario(cx, "broad-library-parent").await
}

/// A file the CDI spec mounts read-write. The expectations record whether the
/// workload can read or write it.
#[testkit::test]
async fn writable_file(cx: &mut Context) -> testkit::Result {
    cdi::scenario(cx, "writable-file").await
}

/// A directory the CDI spec mounts read-write. The expectations record whether
/// the workload can create files in it.
#[testkit::test]
async fn writable_directory(cx: &mut Context) -> testkit::Result {
    cdi::scenario(cx, "writable-directory").await
}

/// A bind mount whose options omit both `ro` and `rw`, so the access it grants
/// is implicit. The expectations record how the workload can use it.
#[testkit::test]
async fn omitted_access_file(cx: &mut Context) -> testkit::Result {
    cdi::scenario(cx, "omitted-access-file").await
}

/// A character device node injected from `/dev/null` with read-write
/// permissions. The expectations record whether a non-root workload can write
/// it.
#[testkit::test]
async fn device_node(cx: &mut Context) -> testkit::Result {
    cdi::scenario(cx, "device-node").await
}

/// A unix socket mounted on its own, without the directory it lives in. The
/// expectations record that a sibling file in the host directory stays
/// invisible.
#[testkit::test]
async fn unix_socket(cx: &mut Context) -> testkit::Result {
    cdi::scenario(cx, "unix-socket").await
}
