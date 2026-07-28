// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rootfs materialization for the VM driver.
//!
//! Image acquisition produces an unpacked image root. This module converts
//! that root into the ext4 image consumed by the existing libkrun launch path.

use std::path::{Path, PathBuf};

use crate::rootfs::{create_rootfs_image_from_dir, prepare_sandbox_rootfs_from_image_root};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootfsMaterializationRequest {
    pub image_ref: String,
    /// VM-driver staging directory for the rootfs materialization operation.
    pub work_dir: PathBuf,
    pub sandbox_uid: u32,
    pub sandbox_gid: u32,
}

/// An unpacked image root prepared by the VM driver's image acquisition path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnpackedImage {
    pub identity: String,
    pub root: PathBuf,
}

impl UnpackedImage {
    #[must_use]
    pub fn new(identity: impl Into<String>, root: impl Into<PathBuf>) -> Self {
        Self {
            identity: identity.into(),
            root: root.into(),
        }
    }
}

/// The ext4 image consumed by the existing libkrun launch path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmRootfsImage {
    image_identity: String,
    disk_path: PathBuf,
}

impl VmRootfsImage {
    #[must_use]
    pub fn image_identity(&self) -> &str {
        &self.image_identity
    }

    #[must_use]
    pub fn disk_path(&self) -> &Path {
        &self.disk_path
    }
}

/// Adapts the VM driver's existing rootfs preparation and ext4 construction
/// functions to the explicit image-root-to-disk hand-off.
#[derive(Clone, Copy, Debug, Default)]
pub struct VmRootfsMaterializer;

impl VmRootfsMaterializer {
    /// Materialize an image root that has already been unpacked by the VM
    /// driver's image acquisition path.
    pub fn materialize(
        &self,
        request: &RootfsMaterializationRequest,
        image: &UnpackedImage,
    ) -> Result<VmRootfsImage, String> {
        prepare_sandbox_rootfs_from_image_root(
            &image.root,
            &image.identity,
            request.sandbox_uid,
            request.sandbox_gid,
        )
        .map_err(|error| {
            format!(
                "vm sandbox image '{}' is not base-compatible: {error}",
                request.image_ref
            )
        })?;

        let disk_path = request.work_dir.join("rootfs.ext4");
        create_rootfs_image_from_dir(&image.root, &disk_path)?;

        Ok(VmRootfsImage {
            image_identity: image.identity.clone(),
            disk_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_artifact_exposes_disk_path() {
        let artifact = VmRootfsImage {
            image_identity: "sha256:test".to_string(),
            disk_path: PathBuf::from("/var/lib/openshell/rootfs.ext4"),
        };

        assert_eq!(artifact.image_identity(), "sha256:test");
        assert_eq!(
            artifact.disk_path(),
            Path::new("/var/lib/openshell/rootfs.ext4")
        );
    }
}
