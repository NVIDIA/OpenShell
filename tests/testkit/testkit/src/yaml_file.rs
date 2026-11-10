// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result, ResultExt as _};

/// YAML in a temporary file, for CLI commands that read one, such as
/// `sandbox create --policy` or `profile import --file`. The file is removed
/// when dropped.
pub struct YamlFile(tempfile::NamedTempFile);

impl YamlFile {
    pub fn new(contents: &str) -> Result<Self> {
        let file = tempfile::Builder::new()
            .suffix(".yaml")
            .tempfile()
            .map_err(|error| Error::from_error(&error))
            .context("create a temporary YAML file")?;
        std::fs::write(file.path(), contents)
            .map_err(|error| Error::from_error(&error))
            .context(format!("write {}", file.path().display()))?;
        Ok(Self(file))
    }

    /// The file's path, as a CLI argument.
    pub fn path(&self) -> Result<&str> {
        let path = self.0.path();
        path.to_str()
            .ok_or_else(|| Error::msg(format!("{} is not UTF-8", path.display())))
    }
}
