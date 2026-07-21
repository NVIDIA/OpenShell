// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rootfs provider boundary for `OpenShell` compute drivers.
//!
//! A *rootfs provider* turns an OCI image reference into a root filesystem
//! a sandbox provisioner can consume — for an OCI/runc provisioner, a set
//! of mounts to assemble under a bundle's `rootfs/`. The provider owns
//! image resolution, acquisition, unpacking, and the lifetime of whatever
//! backend resources (snapshots, leases, caches) realize that root
//! filesystem; those concepts must not leak into the compute-driver
//! contract, so a daemon-backed provider can later be replaced by a
//! daemonless one (or by an adaptation of the VM driver's image pipeline)
//! without redesigning the provisioner sitting on top of it.
//!
//! [`ContainerdRootfsProvider`] is the first implementation, backed by a
//! system-provided containerd. The VM driver's ext4-materializing pipeline
//! is the same boundary shape (image acquisition producing an unpacked
//! root, then a backend-specific materialization step); converging it onto
//! shared types here is tracked follow-up work rather than part of this
//! crate's initial cut.

pub mod containerd;

pub use containerd::ContainerdRootfsProvider;

/// Errors from preparing or releasing a sandbox root filesystem.
#[derive(Debug, thiserror::Error)]
pub enum RootfsError {
    #[error("failed to connect to containerd at {path}: {reason}")]
    Connect { path: String, reason: String },
    #[error("containerd transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("containerd RPC failed: {0}")]
    Rpc(#[from] tonic::Status),
    #[error("malformed image manifest/config for {image}: {reason}")]
    MalformedImage { image: String, reason: String },
    #[error("prepared rootfs for {image} has no mounts")]
    NoMounts { image: String },
}

/// A single mount composing a prepared root filesystem.
///
/// Expressed in provider-neutral terms (the same shape `mount(8)`
/// consumes: filesystem type, source, and options). The consumer chooses
/// the target directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootfsMount {
    /// Filesystem type (e.g. `overlay`, `bind`).
    pub fs_type: String,
    /// Mount source (device, directory, or `overlay`).
    pub source: String,
    /// Mount options, one per element (joined with `,` for `mount -o`).
    pub options: Vec<String>,
}

/// A root filesystem prepared for one sandbox.
///
/// Guaranteed non-empty: providers fail with [`RootfsError::NoMounts`]
/// rather than returning a rootfs that cannot be assembled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRootfs {
    mounts: Vec<RootfsMount>,
}

impl PreparedRootfs {
    /// # Errors
    /// Returns [`RootfsError::NoMounts`] when `mounts` is empty.
    pub fn new(image_ref: &str, mounts: Vec<RootfsMount>) -> Result<Self, RootfsError> {
        if mounts.is_empty() {
            return Err(RootfsError::NoMounts {
                image: image_ref.to_string(),
            });
        }
        Ok(Self { mounts })
    }

    #[must_use]
    pub fn mounts(&self) -> &[RootfsMount] {
        &self.mounts
    }

    /// The mount realizing the root filesystem itself (the first mount).
    #[must_use]
    pub fn root_mount(&self) -> &RootfsMount {
        &self.mounts[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_rootfs_rejects_empty_mounts() {
        let err = PreparedRootfs::new("docker.io/library/busybox:latest", Vec::new())
            .expect_err("empty mounts must be rejected");
        assert!(matches!(err, RootfsError::NoMounts { .. }));
    }

    #[test]
    fn prepared_rootfs_exposes_root_mount() {
        let prepared = PreparedRootfs::new(
            "docker.io/library/busybox:latest",
            vec![RootfsMount {
                fs_type: "overlay".to_string(),
                source: "overlay".to_string(),
                options: vec!["lowerdir=/a".to_string()],
            }],
        )
        .expect("non-empty mounts are valid");
        assert_eq!(prepared.root_mount().fs_type, "overlay");
        assert_eq!(prepared.mounts().len(), 1);
    }
}
