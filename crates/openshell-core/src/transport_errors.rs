// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared classification for transport closes that are expected during shutdown.

use std::io::ErrorKind;

/// Returns `true` when a gRPC status represents the peer closing transport.
///
/// Callers must still decide whether shutdown is already in progress before
/// downgrading the error. Outside shutdown these statuses remain failures.
#[must_use]
pub fn is_expected_transport_close_status(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Cancelled
            | tonic::Code::Unavailable
            | tonic::Code::Unknown
            | tonic::Code::Internal
    ) && is_expected_transport_close_message(&status.to_string())
}

/// Returns `true` when an error looks like an expected transport close.
///
/// This helper intentionally matches only transport-lifecycle failures such as
/// HTTP/2 close races, broken pipes, and reset connections.
#[must_use]
pub fn is_expected_transport_close_error(error: &(dyn std::error::Error + 'static)) -> bool {
    if let Some(status) = error.downcast_ref::<tonic::Status>() {
        return is_expected_transport_close_status(status);
    }
    if let Some(io) = error.downcast_ref::<std::io::Error>() {
        return matches!(
            io.kind(),
            ErrorKind::BrokenPipe
                | ErrorKind::ConnectionAborted
                | ErrorKind::ConnectionReset
                | ErrorKind::UnexpectedEof
        );
    }
    is_expected_transport_close_message(&error.to_string())
}

/// Returns `true` for known text fragments emitted by tonic, hyper, h2, and
/// OS I/O errors when the peer closes a stream or connection.
#[must_use]
pub fn is_expected_transport_close_message(message: &str) -> bool {
    let msg = message.to_ascii_lowercase();
    msg.contains("h2 protocol error")
        || msg.contains("broken pipe")
        || msg.contains("connection reset")
        || msg.contains("connection aborted")
        || msg.contains("connection closed")
        || msg.contains("connection error")
        || msg.contains("error reading a body from connection")
        || msg.contains("peer closed connection")
        || msg.contains("unexpected eof")
        || msg.contains("cancelled")
        || msg.contains("canceled")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_expected_transport_close_statuses() {
        for status in [
            tonic::Status::unknown("h2 protocol error: error reading a body from connection"),
            tonic::Status::unavailable("connection reset by peer"),
            tonic::Status::cancelled("operation cancelled"),
            tonic::Status::internal("broken pipe"),
        ] {
            assert!(
                is_expected_transport_close_status(&status),
                "status should be expected during shutdown: {status}"
            );
        }
    }

    #[test]
    fn keeps_unexpected_statuses_out_of_shutdown_filter() {
        for status in [
            tonic::Status::internal("policy evaluation failed"),
            tonic::Status::invalid_argument("bad relay frame"),
            tonic::Status::permission_denied("cross-sandbox relay"),
        ] {
            assert!(
                !is_expected_transport_close_status(&status),
                "status should stay unexpected: {status}"
            );
        }
    }

    #[test]
    fn classifies_io_transport_closes() {
        for kind in [
            ErrorKind::BrokenPipe,
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::UnexpectedEof,
        ] {
            let error = std::io::Error::new(kind, "peer closed");
            assert!(is_expected_transport_close_error(&error));
        }
    }
}
