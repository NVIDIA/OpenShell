// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::TEST_ENV_LOCK;

pub struct EnvVarGuard {
    key: &'static str,
    original: Option<String>,
}

#[allow(unsafe_code)]
impl EnvVarGuard {
    pub fn set(key: &'static str, value: &str) -> Self {
        let original = std::env::var(key).ok();
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, original }
    }

    pub fn unset(key: &'static str) -> Self {
        let original = std::env::var(key).ok();
        unsafe {
            std::env::remove_var(key);
        }
        Self { key, original }
    }
}

#[allow(unsafe_code)]
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.original {
            unsafe {
                std::env::set_var(self.key, value);
            }
        } else {
            unsafe {
                std::env::remove_var(self.key);
            }
        }
    }
}

pub fn with_tmp_xdg<F: FnOnce()>(tmp: &Path, f: F) {
    let _guard = TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let guard = EnvVarGuard::set(
        "XDG_CONFIG_HOME",
        tmp.to_str().expect("temp path should be utf-8"),
    );
    f();
    drop(guard);
}
