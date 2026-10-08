// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

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
    let time = if minutely { "-00-00" } else { "" };
    for day in 1..=3 {
        let filename = format!("{prefix}.2000-01-{day:02}{time}.{suffix}");
        fs::write(directory.join(&filename), filename.as_bytes()).unwrap();
    }
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
            "creation timestamps available: {}",
            fs::metadata(directory.path().join("openshell.2000-01-01.log"))
                .unwrap()
                .created()
                .is_ok()
        );
        for (format, other) in [(formats[0], formats[1]), (formats[1], formats[0])] {
            let before = history(directory.path(), other);
            let _writer = appender(directory.path(), format, Rotation::DAILY).unwrap();
            assert_eq!(history(directory.path(), other), before);
            assert_eq!(history(directory.path(), format).len(), 3);
        }
    }
}

#[test]
fn migration_preserves_legacy_history_before_shorthand_pruning() {
    let directory = tempfile::tempdir().unwrap();
    seed_history(directory.path(), Format::Shorthand, false);
    seed_history(directory.path(), Format::Ocsf, false);
    let expected = history(directory.path(), Format::Ocsf);
    for name in expected.keys() {
        let path = directory.path().join(name);
        fs::rename(&path, path.with_extension("log")).unwrap();
    }
    let _writer = appender(directory.path(), Format::Shorthand, Rotation::DAILY).unwrap();
    assert_eq!(history(directory.path(), Format::Ocsf), expected);
    for name in expected.keys() {
        assert!(!directory.path().join(name).with_extension("log").exists());
    }
}

#[test]
fn migration_collision_does_not_overwrite_or_prune() {
    let directory = tempfile::tempdir().unwrap();
    seed_history(directory.path(), Format::Shorthand, false);
    let before = history(directory.path(), Format::Shorthand);
    let legacy = directory.path().join("openshell-ocsf.2000-01-01.log");
    let current = legacy.with_extension("jsonl");
    fs::write(&legacy, b"legacy records").unwrap();
    fs::write(&current, b"new records").unwrap();
    let error = appender(directory.path(), Format::Shorthand, Rotation::DAILY).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(history(directory.path(), Format::Shorthand), before);
    assert_eq!(fs::read(&legacy).unwrap(), b"legacy records");
    assert_eq!(fs::read(&current).unwrap(), b"new records");
}

fn write_until_rollover(
    writer: &mut RollingFileAppender,
    directory: &Path,
    format: Format,
    deadline: Instant,
) {
    let before = history(directory, format);
    loop {
        writer.write_all(b"event\n").unwrap();
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
    // MINUTELY uses the same pruning path as DAILY and avoids a mock-clock fork.
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
