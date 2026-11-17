// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Classification of listener accept errors that must not end a serving loop.

use std::io;
use std::time::{Duration, Instant};

/// Backoff after a transient accept resource error, so the retry does not
/// spin while descriptors or memory are still exhausted.
pub const RESOURCE_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Longest silent stretch while retrying a transient accept resource error:
/// one warn line when the exhaustion episode starts, then at most one per
/// interval, so a sustained condition stays visible without flooding the log.
pub const RESOURCE_WARN_INTERVAL: Duration = Duration::from_secs(30);

/// Transient resource exhaustion reported by `accept`: the listener itself
/// stays healthy, and the call succeeds again once descriptors or memory free
/// up. These errno values have no `io::ErrorKind` of their own.
pub fn is_transient_resource_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

/// A peer that disappeared before the accepted connection could be served.
/// Skipping it must not affect later peers.
pub fn is_peer_reset(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
    )
}

/// A network error already pending on a queued connection, which Linux
/// reports from `accept` itself. The `accept(2)` man page says to treat these
/// like `EAGAIN`, by retrying: they belong to one queued peer, not to the
/// listener.
pub fn is_pending_network_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::ENETDOWN
                | libc::EPROTO
                | libc::ENOPROTOOPT
                | libc::EHOSTDOWN
                | libc::ENONET
                | libc::EHOSTUNREACH
                | libc::EOPNOTSUPP
                | libc::ENETUNREACH
        )
    )
}

/// Warn cadence for transient accept resource backoffs: one line when an
/// exhaustion episode starts, then at most one per
/// [`RESOURCE_WARN_INTERVAL`] while it lasts, and a fresh line when the
/// underlying errno changes. A successful accept ends the episode.
#[derive(Debug, Default)]
pub struct ResourceBackoffLogger {
    logged: Option<(i32, Instant)>,
}

impl ResourceBackoffLogger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this retry deserves a warn line; records the decision.
    pub fn should_log(&mut self, error: &io::Error) -> bool {
        self.should_log_at(error, Instant::now())
    }

    fn should_log_at(&mut self, error: &io::Error, now: Instant) -> bool {
        let code = error.raw_os_error().unwrap_or_default();
        let quiet = self.logged.is_some_and(|(logged_code, at)| {
            logged_code == code && now.duration_since(at) < RESOURCE_WARN_INTERVAL
        });
        if quiet {
            false
        } else {
            self.logged = Some((code, now));
            true
        }
    }

    /// A successful accept ends the exhaustion episode.
    pub fn reset(&mut self) {
        self.logged = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_errors_are_transient() {
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert!(
                is_transient_resource_error(&io::Error::from_raw_os_error(code)),
                "errno {code} should be a transient resource error"
            );
        }
    }

    #[test]
    fn other_errors_are_not_transient_resource_errors() {
        for error in [
            io::Error::from_raw_os_error(libc::EAGAIN),
            io::Error::from_raw_os_error(libc::EBADF),
            io::Error::from_raw_os_error(libc::ECONNABORTED),
            io::Error::new(io::ErrorKind::OutOfMemory, "kind only"),
            io::Error::new(io::ErrorKind::WouldBlock, "kind only"),
        ] {
            assert!(
                !is_transient_resource_error(&error),
                "{error} should not be a transient resource error"
            );
        }
    }

    #[test]
    fn peer_resets_are_detected() {
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::NotConnected,
        ] {
            assert!(is_peer_reset(&io::Error::new(kind, "reset")));
        }
        assert!(!is_peer_reset(&io::Error::from_raw_os_error(libc::EMFILE)));
        assert!(!is_peer_reset(&io::Error::new(
            io::ErrorKind::Interrupted,
            "interrupted"
        )));
    }

    #[test]
    fn pending_network_errors_are_detected() {
        for code in [
            libc::ENETDOWN,
            libc::EPROTO,
            libc::ENOPROTOOPT,
            libc::EHOSTDOWN,
            libc::ENONET,
            libc::EHOSTUNREACH,
            libc::EOPNOTSUPP,
            libc::ENETUNREACH,
        ] {
            assert!(
                is_pending_network_error(&io::Error::from_raw_os_error(code)),
                "errno {code} should be a pending network error"
            );
        }
        assert!(!is_pending_network_error(&io::Error::from_raw_os_error(
            libc::EMFILE
        )));
        assert!(!is_pending_network_error(&io::Error::new(
            io::ErrorKind::ConnectionReset,
            "reset"
        )));
    }

    #[test]
    fn resource_backoff_logging_is_once_per_episode_with_periodic_rewarn() {
        let mut logger = ResourceBackoffLogger::new();
        let start = Instant::now();
        let error = |code| io::Error::from_raw_os_error(code);

        // One line when the episode starts, then silence while it lasts.
        assert!(logger.should_log_at(&error(libc::EMFILE), start));
        assert!(!logger.should_log_at(&error(libc::EMFILE), start + Duration::from_secs(1)));
        assert!(!logger.should_log_at(&error(libc::EMFILE), start + Duration::from_secs(29)));
        // A sustained episode stays visible with a bounded cadence.
        assert!(logger.should_log_at(
            &error(libc::EMFILE),
            start + RESOURCE_WARN_INTERVAL + Duration::from_secs(1)
        ));
        // A different errno during the episode gets its own line.
        assert!(logger.should_log_at(
            &error(libc::ENFILE),
            start + RESOURCE_WARN_INTERVAL + Duration::from_secs(2)
        ));

        // Recovery ends the episode: the next exhaustion warns again.
        logger.reset();
        assert!(logger.should_log_at(
            &error(libc::EMFILE),
            start + RESOURCE_WARN_INTERVAL + Duration::from_secs(3)
        ));
    }
}
