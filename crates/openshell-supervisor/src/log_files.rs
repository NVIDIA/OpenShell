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
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::io::Write as _;
    use std::time::{Duration, Instant};

    fn history(directory: &Path, format: Format) -> BTreeMap<OsString, Vec<u8>> {
        let (prefix, suffix) = format.filename_parts();
        fs::read_dir(directory)
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(&format!("{prefix}.")) && name.ends_with(&format!(".{suffix}"))
            })
            .map(|entry| (entry.file_name(), fs::read(entry.path()).unwrap()))
            .collect()
    }

    fn seed_history(directory: &Path, format: Format, minutely: bool) {
        let (prefix, suffix) = format.filename_parts();
        for day in 1..=3 {
            let date = format!("2000-01-{day:02}");
            let date = if minutely {
                format!("{date}-00-00")
            } else {
                date
            };
            let filename = format!("{prefix}.{date}.{suffix}");
            fs::write(directory.join(&filename), filename.as_bytes()).unwrap();
        }
    }

    #[test]
    fn suffixes_separate_retention_before_timestamp_selection() {
        // These checks precede both metadata.created() and date parsing in
        // tracing-appender, so separation does not depend on the filesystem.
        let (text_prefix, text_suffix) = Format::Shorthand.filename_parts();
        let (json_prefix, json_suffix) = Format::Ocsf.filename_parts();
        let text = format!("{text_prefix}.2000-01-01.{text_suffix}");
        let json = format!("{json_prefix}.2000-01-01.{json_suffix}");
        assert!(!json.ends_with(text_suffix));
        assert!(!text.ends_with(json_suffix));
    }

    #[test]
    fn daily_initialization_retains_each_format_independently() {
        for formats in [
            [Format::Shorthand, Format::Ocsf],
            [Format::Ocsf, Format::Shorthand],
        ] {
            let directory = tempfile::tempdir().unwrap();
            for format in formats {
                seed_history(directory.path(), format, false);
            }
            eprintln!(
                "log filesystem exposes creation timestamps: {}",
                fs::metadata(directory.path().join("openshell.2000-01-01.log"))
                    .unwrap()
                    .created()
                    .is_ok()
            );
            for (format, other) in [(formats[0], formats[1]), (formats[1], formats[0])] {
                let other_history = history(directory.path(), other);
                let mut writer = appender(directory.path(), format, Rotation::DAILY).unwrap();
                writer.write_all(b"new event\n").unwrap();
                writer.flush().unwrap();
                assert_eq!(history(directory.path(), other), other_history);
                assert_eq!(history(directory.path(), format).len(), 3);
            }
        }
    }

    #[test]
    fn legacy_jsonl_history_is_migrated_before_shorthand_pruning() {
        let directory = tempfile::tempdir().unwrap();
        seed_history(directory.path(), Format::Shorthand, false);
        for day in 1..=3 {
            fs::write(
                directory
                    .path()
                    .join(format!("openshell-ocsf.2000-01-{day:02}.log")),
                format!("legacy event {day}\n"),
            )
            .unwrap();
        }
        let _writer = appender(directory.path(), Format::Shorthand, Rotation::DAILY).unwrap();
        assert_eq!(history(directory.path(), Format::Shorthand).len(), 3);
        assert_eq!(history(directory.path(), Format::Ocsf).len(), 3);
        for day in 1..=3 {
            let legacy = directory
                .path()
                .join(format!("openshell-ocsf.2000-01-{day:02}.log"));
            assert!(!legacy.exists());
            assert_eq!(
                fs::read_to_string(legacy.with_extension("jsonl")).unwrap(),
                format!("legacy event {day}\n")
            );
        }
        // Successful migration is idempotent on subsequent starts.
        migrate_legacy_ocsf_logs(directory.path()).unwrap();
    }

    #[test]
    fn migration_collision_preserves_both_files_and_prevents_pruning() {
        let directory = tempfile::tempdir().unwrap();
        seed_history(directory.path(), Format::Shorthand, false);
        let before = history(directory.path(), Format::Shorthand);
        let legacy = directory.path().join("openshell-ocsf.2000-01-01.log");
        let current = legacy.with_extension("jsonl");
        fs::write(&legacy, b"legacy security records").unwrap();
        fs::write(&current, b"new security records").unwrap();
        for format in [Format::Shorthand, Format::Ocsf] {
            let error = appender(directory.path(), format, Rotation::DAILY).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            assert_eq!(history(directory.path(), Format::Shorthand), before);
            assert_eq!(fs::read(&legacy).unwrap(), b"legacy security records");
            assert_eq!(fs::read(&current).unwrap(), b"new security records");
        }
    }

    #[test]
    fn migration_leaves_unrelated_files_and_directories_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let names = [
            "openshell.2000-01-01.log",
            "openshell-ocsf.2000-01-01.jsonl",
            "openshell-ocsf.2000-01-01.log.bak",
            "openshell-ocsf.2000-01-01.LOG",
            "other.2000-01-01.log",
        ];
        for name in names {
            fs::write(directory.path().join(name), name.as_bytes()).unwrap();
        }
        let nested = directory.path().join("openshell-ocsf.2000-01-02.log");
        fs::create_dir(&nested).unwrap();
        migrate_legacy_ocsf_logs(directory.path()).unwrap();
        for name in names {
            assert_eq!(
                fs::read(directory.path().join(name)).unwrap(),
                name.as_bytes()
            );
        }
        assert!(nested.is_dir());
    }

    #[test]
    fn missing_log_directory_is_created() {
        let directory = tempfile::tempdir().unwrap();
        let logs = directory.path().join("logs");
        let _writer = appender(&logs, Format::Shorthand, Rotation::DAILY).unwrap();
        assert_eq!(history(&logs, Format::Shorthand).len(), 1);
    }

    fn write_until_rollover(
        writer: &mut RollingFileAppender,
        directory: &Path,
        format: Format,
        deadline: Instant,
    ) {
        let before = history(directory, format);
        loop {
            writer.write_all(b"new event\n").unwrap();
            writer.flush().unwrap();
            let current = history(directory, format);
            if current.keys().ne(before.keys()) {
                assert_eq!(current.len(), 3);
                return;
            }
            assert!(Instant::now() < deadline, "no rollover within 65 seconds");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    fn rollover_retains_each_format_independently() {
        // MINUTELY and DAILY share the same pruning path. The dependency's
        // mock clock is private, so cross a real minute boundary for this test.
        let directory = tempfile::tempdir().unwrap();
        for format in [Format::Shorthand, Format::Ocsf] {
            seed_history(directory.path(), format, true);
        }
        let mut text = appender(directory.path(), Format::Shorthand, Rotation::MINUTELY).unwrap();
        let mut json = appender(directory.path(), Format::Ocsf, Rotation::MINUTELY).unwrap();
        let deadline = Instant::now() + Duration::from_secs(65);
        let before = history(directory.path(), Format::Ocsf);
        write_until_rollover(&mut text, directory.path(), Format::Shorthand, deadline);
        assert_eq!(history(directory.path(), Format::Ocsf), before);
        let before = history(directory.path(), Format::Shorthand);
        write_until_rollover(&mut json, directory.path(), Format::Ocsf, deadline);
        assert_eq!(history(directory.path(), Format::Shorthand), before);
    }
}
