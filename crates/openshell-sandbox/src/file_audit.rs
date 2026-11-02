// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in observation of workload-supplied paths at the existing open listener.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use openshell_ocsf::{BaseEventBuilder, FileActivityBuilder, Process, SeverityId, ocsf_emit};

use crate::linux::seccomp_notify::{Notification, NotificationListener};
use crate::linux::task_memory;
use crate::provider_files::{read_path, thread_group_of};

const WINDOW: Duration = Duration::from_secs(1);
const EVENTS_PER_WINDOW: u32 = 100;

struct RateWindow {
    started: Instant,
    emitted: u32,
    dropped: u64,
}

impl Default for RateWindow {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            emitted: 0,
            dropped: 0,
        }
    }
}

impl RateWindow {
    fn flush(&mut self, now: Instant) -> Option<u64> {
        if now.duration_since(self.started) < WINDOW {
            return None;
        }
        self.started = now;
        self.emitted = 0;
        (self.dropped != 0).then(|| std::mem::take(&mut self.dropped))
    }

    fn record(&mut self, now: Instant) -> (bool, Option<u64>) {
        let dropped = self.flush(now);
        if self.emitted < EVENTS_PER_WINDOW {
            self.emitted += 1;
            (true, dropped)
        } else {
            self.dropped = self.dropped.saturating_add(1);
            (false, dropped)
        }
    }
}

#[derive(Default)]
struct AuditState {
    patterns: Option<GlobSet>,
    rate: RateWindow,
    worker_started: bool,
}

/// Shared by the boundary runtime and the notification broker for one sandbox.
#[derive(Clone, Default)]
pub struct FileAudit {
    state: Arc<Mutex<AuditState>>,
    enabled: Arc<AtomicBool>,
}

impl FileAudit {
    /// Bind a validated policy's watch list before the workload starts.
    pub fn configure(&self, paths: &[String]) -> io::Result<()> {
        openshell_policy::validate_audit_paths(paths)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid audit paths"))?;
        let patterns = if paths.is_empty() {
            None
        } else {
            let mut builder = GlobSetBuilder::new();
            for path in paths {
                builder.add(
                    GlobBuilder::new(path)
                        .literal_separator(true)
                        .build()
                        .map_err(io::Error::other)?,
                );
            }
            Some(builder.build().map_err(io::Error::other)?)
        };
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.patterns = patterns;
        state.rate = RateWindow::default();
        self.enabled.store(!paths.is_empty(), Ordering::Release);
        if !paths.is_empty() && !state.worker_started {
            let weak = Arc::downgrade(&self.state);
            let dispatch = tracing::dispatcher::get_default(Clone::clone);
            std::thread::Builder::new()
                .name("openshell-file-audit-drops".to_string())
                .spawn(move || {
                    let _subscriber = tracing::dispatcher::set_default(&dispatch);
                    loop {
                        std::thread::sleep(WINDOW);
                        let Some(state) = weak.upgrade() else {
                            break;
                        };
                        let dropped = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .rate
                            .flush(Instant::now());
                        if let Some(count) = dropped {
                            emit_drop_record(count);
                        }
                    }
                })?;
            state.worker_started = true;
        }
        Ok(())
    }

    /// Observe a notification without changing the syscall's result.
    pub fn observe_open(&self, listener: &NotificationListener, notification: Notification) {
        if !self.enabled.load(Ordering::Acquire) || listener.validate_id(notification.id).is_err() {
            return;
        }
        let syscall = i64::from(notification.syscall);
        let path_address = if syscall == libc::SYS_openat || syscall == libc::SYS_openat2 {
            notification.args[1]
        } else {
            notification.args[0]
        };
        // An opted-in sandbox pays for a full path read on each open. The
        // default path remains the provider-file prefix fast path.
        let Ok(path) = read_path(notification.tid, path_address) else {
            return;
        };
        if path.is_empty() || listener.validate_id(notification.id).is_err() {
            return;
        }
        let (emit, dropped) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state
                .patterns
                .as_ref()
                .is_some_and(|patterns| patterns.is_match(&path))
            {
                return;
            }
            state.rate.record(Instant::now())
        };
        if let Some(count) = dropped {
            emit_drop_record(count);
        }
        if !emit || listener.validate_id(notification.id).is_err() {
            return;
        }
        let actor = process_for_thread(notification.tid);
        let access = requested_access(&notification);
        ocsf_emit!(
            FileActivityBuilder::new(openshell_ocsf::ctx::ctx(), &path, actor, access).build()
        );
    }
}

fn emit_drop_record(count: u64) {
    ocsf_emit!(
        BaseEventBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(SeverityId::Low)
            .activity_name("File audit events dropped")
            .message(format!(
                "Suppressed {count} file audit events in one second"
            ))
            .unmapped("dropped_count", count)
            .unmapped("reason", "rate_limit")
            .build()
    );
}

fn process_for_thread(tid: u32) -> Process {
    let pid = thread_group_of(tid).unwrap_or(tid);
    let path = std::fs::read_link(format!("/proc/{tid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let name = path
        .as_deref()
        .and_then(|path| std::path::Path::new(path).file_name())
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("unknown");
    let process = Process::new(name, i64::from(pid));
    if let Some(path) = path {
        process.with_path(&path)
    } else {
        process
    }
}

fn requested_access(notification: &Notification) -> &'static str {
    let syscall = i64::from(notification.syscall);
    let flags = if syscall == libc::SYS_openat2 {
        let mut raw = [0_u8; 8];
        if notification.args[3] < 8
            || task_memory::read_exact(notification.tid, notification.args[2], &mut raw).is_err()
        {
            return "unknown";
        }
        u64::from_ne_bytes(raw)
    } else if syscall == libc::SYS_openat {
        notification.args[2]
    } else {
        notification.args[1]
    };
    let Ok(flags) = i32::try_from(flags) else {
        return "unknown";
    };
    if flags & libc::O_PATH != 0 {
        "metadata"
    } else if flags & libc::O_CREAT != 0 || flags & libc::O_TMPFILE == libc::O_TMPFILE {
        "create"
    } else if flags & libc::O_ACCMODE == libc::O_RDWR {
        "read_write"
    } else if flags & libc::O_ACCMODE == libc::O_WRONLY || flags & libc::O_TRUNC != 0 {
        "write"
    } else {
        "read"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watched_globs_match_only_requested_path_text() {
        let mut builder = GlobSetBuilder::new();
        builder.add(
            GlobBuilder::new("/sandbox/**/.env")
                .literal_separator(true)
                .build()
                .unwrap(),
        );
        builder.add(
            GlobBuilder::new("/sandbox/.ssh/**")
                .literal_separator(true)
                .build()
                .unwrap(),
        );
        let patterns = builder.build().unwrap();
        assert!(patterns.is_match("/sandbox/project/.env"));
        assert!(patterns.is_match("/sandbox/project/src/deep/.env"));
        assert!(patterns.is_match("/sandbox/.ssh/id_test"));
        assert!(!patterns.is_match("/tmp/.env"));
        assert!(!patterns.is_match("project/.env"));

        let direct_only = GlobBuilder::new("/sandbox/*.env")
            .literal_separator(true)
            .build()
            .unwrap();
        let matcher = direct_only.compile_matcher();
        assert!(matcher.is_match("/sandbox/local.env"));
        assert!(!matcher.is_match("/sandbox/deep/local.env"));
    }

    #[test]
    fn rate_limit_counts_suppressed_events_and_resets() {
        let mut rate = RateWindow::default();
        let now = rate.started;
        for _ in 0..EVENTS_PER_WINDOW {
            assert_eq!(rate.record(now), (true, None));
        }
        assert_eq!(rate.record(now), (false, None));
        assert_eq!(rate.record(now), (false, None));
        assert_eq!(rate.flush(now + WINDOW), Some(2));
        assert_eq!(rate.record(now + WINDOW), (true, None));
    }

    #[test]
    fn open_flags_report_requested_access_without_claiming_outcome() {
        let mut notification = Notification {
            id: 1,
            tid: std::process::id(),
            syscall: i32::try_from(libc::SYS_openat).unwrap(),
            args: [0; 6],
        };
        notification.args[2] = libc::O_RDONLY as u64;
        assert_eq!(requested_access(&notification), "read");
        notification.args[2] = libc::O_WRONLY as u64;
        assert_eq!(requested_access(&notification), "write");
        notification.args[2] = (libc::O_RDWR | libc::O_CREAT) as u64;
        assert_eq!(requested_access(&notification), "create");
        notification.args[2] = (libc::O_RDWR | libc::O_TMPFILE) as u64;
        assert_eq!(requested_access(&notification), "create");
        notification.args[2] = libc::O_TRUNC as u64;
        assert_eq!(requested_access(&notification), "write");
    }
}
