// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io;
use std::path::Path;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

#[derive(Clone, Copy)]
pub enum Format {
    Shorthand,
    Ocsf,
}

impl Format {
    fn filename_parts(self) -> (&'static str, &'static str) {
        match self {
            Self::Shorthand => ("openshell", "log"),
            Self::Ocsf => ("openshell-ocsf", "jsonl"),
        }
    }
}

pub fn appender(
    directory: impl AsRef<Path>,
    format: Format,
    rotation: Rotation,
) -> io::Result<RollingFileAppender> {
    let directory = directory.as_ref();
    // Protect legacy JSONL history before either writer can prune *.log files.
    migrate_legacy_ocsf_logs(directory)?;
    let (prefix, suffix) = format.filename_parts();
    RollingFileAppender::builder()
        .rotation(rotation)
        .filename_prefix(prefix)
        .filename_suffix(suffix)
        .max_log_files(3)
        .build(directory)
        .map_err(io::Error::other)
}

fn migrate_legacy_ocsf_logs(directory: &Path) -> io::Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut sources = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        // Match the old appender's case-sensitive filename family exactly.
        if !name.starts_with("openshell-ocsf.") || name.strip_suffix(".log").is_none() {
            continue;
        }
        if !entry.file_type()?.is_file() {
            continue;
        }
        sources.push(entry.path());
    }
    // Finish scanning before changing directory entries.
    for source in sources {
        let destination = source.with_extension("jsonl");
        // Unlike rename(), hard_link() cannot overwrite an existing destination.
        // Both names refer to the same data until the legacy name is removed.
        fs::hard_link(&source, &destination).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "could not migrate {} to {}: {error}",
                    source.display(),
                    destination.display()
                ),
            )
        })?;
        fs::remove_file(source)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
