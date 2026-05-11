// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub trait DiscoveryContext {
    fn env_var(&self, key: &str) -> Option<String>;

    /// Return `true` if the filesystem path exists.
    ///
    /// The default implementation calls [`std::path::Path::exists`].
    /// Tests override this via [`crate::test_helpers::MockDiscoveryContext`].
    fn path_exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }
}

pub struct RealDiscoveryContext;

impl DiscoveryContext for RealDiscoveryContext {
    fn env_var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}
