// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

#[path = "../../../tests/support/environment.rs"]
mod environment;
pub use environment::Environment;

pub fn with_tmp_xdg(tmp: &Path, f: impl FnOnce(&Path)) {
    with_tmp_xdg_env(tmp, Environment::new(), f);
}

pub fn with_tmp_xdg_env(tmp: &Path, env: Environment, f: impl FnOnce(&Path)) {
    env.set("XDG_CONFIG_HOME", tmp).run(|| {
        let root = PathBuf::from(std::env::var_os("XDG_CONFIG_HOME").unwrap());
        f(&root);
    });
}
