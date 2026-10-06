// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use tracing_appender::rolling::{InitError, RollingFileAppender, Rotation};

// Retention uses starts_with(prefix), so neither prefix may start with the other.
pub const SHORTHAND_PREFIX: &str = "openshell-text";
pub const OCSF_PREFIX: &str = "openshell-ocsf";

pub fn appender(
    directory: impl AsRef<Path>,
    prefix: &str,
    rotation: Rotation,
) -> Result<RollingFileAppender, InitError> {
    RollingFileAppender::builder()
        .rotation(rotation)
        .filename_prefix(prefix)
        .filename_suffix("log")
        .max_log_files(3)
        .build(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::io::Write as _;
    use std::time::{Duration, Instant};

    fn history(directory: &Path, prefix: &str) -> BTreeMap<OsString, Vec<u8>> {
        std::fs::read_dir(directory)
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{prefix}."))
            })
            .map(|entry| (entry.file_name(), std::fs::read(entry.path()).unwrap()))
            .collect()
    }

    fn seed_history(directory: &Path, prefix: &str, minutely: bool) {
        for day in 1..=3 {
            let date = format!("2000-01-{day:02}");
            let date = if minutely {
                format!("{date}-00-00")
            } else {
                date
            };
            let filename = format!("{prefix}.{date}.log");
            std::fs::write(directory.join(&filename), filename.as_bytes()).unwrap();
        }
    }

    #[test]
    fn retention_prefixes_are_disjoint_before_timestamp_selection() {
        // The prefix checks precede both metadata.created() and the filename
        // date fallback, so this invariant holds on either kind of filesystem.
        assert!(!SHORTHAND_PREFIX.starts_with(OCSF_PREFIX));
        assert!(!OCSF_PREFIX.starts_with(SHORTHAND_PREFIX));
    }

    #[test]
    fn daily_initialization_retains_each_history_independently() {
        for prefixes in [
            [SHORTHAND_PREFIX, OCSF_PREFIX],
            [OCSF_PREFIX, SHORTHAND_PREFIX],
        ] {
            let directory = tempfile::tempdir().unwrap();
            for prefix in prefixes {
                seed_history(directory.path(), prefix, false);
            }
            let legacy = directory.path().join("openshell.1999-12-31.log");
            std::fs::write(&legacy, b"legacy shorthand").unwrap();
            // Report whether this run exercises the original bug's creation-
            // timestamp path; don't silently skip on filesystems without it.
            eprintln!(
                "log filesystem exposes creation timestamps: {}",
                std::fs::metadata(&legacy).unwrap().created().is_ok()
            );

            for (prefix, other) in [(prefixes[0], prefixes[1]), (prefixes[1], prefixes[0])] {
                let other_history = history(directory.path(), other);
                let mut writer = appender(directory.path(), prefix, Rotation::DAILY).unwrap();
                writer.write_all(b"new event\n").unwrap();
                writer.flush().unwrap();
                assert_eq!(history(directory.path(), other), other_history);
                assert_eq!(history(directory.path(), prefix).len(), 3);
                assert_eq!(std::fs::read(&legacy).unwrap(), b"legacy shorthand");
            }
        }
    }

    #[test]
    fn rollover_retains_each_history_independently() {
        // MINUTELY and DAILY share the same pruning path. Use a real minute
        // boundary because tracing-appender's mock clock is private to its tests.
        let directory = tempfile::tempdir().unwrap();
        for prefix in [SHORTHAND_PREFIX, OCSF_PREFIX] {
            seed_history(directory.path(), prefix, true);
        }
        let legacy = directory.path().join("openshell.1999-12-31.log");
        std::fs::write(&legacy, b"legacy shorthand").unwrap();
        let mut shorthand =
            appender(directory.path(), SHORTHAND_PREFIX, Rotation::MINUTELY).unwrap();
        let mut jsonl = appender(directory.path(), OCSF_PREFIX, Rotation::MINUTELY).unwrap();
        let shorthand_history = history(directory.path(), SHORTHAND_PREFIX);
        let jsonl_history = history(directory.path(), OCSF_PREFIX);
        let deadline = Instant::now() + Duration::from_secs(65);

        loop {
            shorthand.write_all(b"shorthand event\n").unwrap();
            shorthand.flush().unwrap();
            let current = history(directory.path(), SHORTHAND_PREFIX);
            if current.keys().ne(shorthand_history.keys()) {
                assert_eq!(current.len(), 3);
                break;
            }
            assert!(Instant::now() < deadline, "no rollover within 65 seconds");
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(history(directory.path(), OCSF_PREFIX), jsonl_history);

        let shorthand_history = history(directory.path(), SHORTHAND_PREFIX);
        loop {
            jsonl.write_all(b"jsonl event\n").unwrap();
            jsonl.flush().unwrap();
            let current = history(directory.path(), OCSF_PREFIX);
            if current.keys().ne(jsonl_history.keys()) {
                assert_eq!(current.len(), 3);
                break;
            }
            assert!(Instant::now() < deadline, "no rollover within 65 seconds");
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            history(directory.path(), SHORTHAND_PREFIX),
            shorthand_history
        );
        assert_eq!(std::fs::read(&legacy).unwrap(), b"legacy shorthand");
    }
}
