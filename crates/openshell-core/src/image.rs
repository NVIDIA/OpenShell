// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Default workload image selection.

/// Default sandbox workload image.
///
/// `OpenShell` uses a version-qualified NVIDIA Ubuntu Noble image so a fresh
/// installation does not depend on a separately maintained image catalog.
pub const DEFAULT_SANDBOX_BASE_IMAGE: &str = "nvcr.io/nvidia/base/ubuntu:24.04";

/// Return the default sandbox image reference.
///
/// Used by all compute drivers as the fallback image when none is specified in
/// the sandbox spec.
#[must_use]
pub fn default_sandbox_image() -> String {
    DEFAULT_SANDBOX_BASE_IMAGE.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_image_is_version_qualified_nvidia_ubuntu() {
        assert_eq!(default_sandbox_image(), "nvcr.io/nvidia/base/ubuntu:24.04");
    }
}
