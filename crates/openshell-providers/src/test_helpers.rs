// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::DiscoveryContext;
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub struct MockDiscoveryContext {
    env: HashMap<String, String>,
    paths: HashSet<String>,
}

impl MockDiscoveryContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_path(mut self, path: &str) -> Self {
        self.paths.insert(path.to_string());
        self
    }
}

impl DiscoveryContext for MockDiscoveryContext {
    fn env_var(&self, key: &str) -> Option<String> {
        self.env.get(key).cloned()
    }

    fn path_exists(&self, path: &str) -> bool {
        self.paths.contains(path)
    }
}
