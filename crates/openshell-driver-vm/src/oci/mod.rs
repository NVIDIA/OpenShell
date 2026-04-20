// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side OCI image pipeline for the VM driver.
//!
//! Responsible for resolving a public OCI image reference to a cached,
//! read-only squashfs filesystem image and a launch metadata descriptor
//! that the guest uses to overlay + exec the container entrypoint.

pub mod cache;
pub mod client;
pub mod compat;
pub mod flatten;
pub mod fs_image;
pub mod metadata;
pub mod pipeline;

pub use cache::{CacheLayout, CachedImage};
pub use client::{OciPuller, PullError, PulledImage};
pub use metadata::{LaunchMetadata, Platform};
pub use pipeline::{EnvOverrides, PipelineError, prepare, validate_reference};
