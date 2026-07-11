// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Small networking helpers shared across the supervisor-process crate.

use tokio::net::TcpStream;
use tracing::debug;

/// Set `TCP_NODELAY` on a relayed TCP stream so small writes are not delayed.
/// Okay if it fails; things just go a bit slower in some cases, so we log and
/// continue.
pub fn set_nodelay_best_effort(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!(error = %e, "failed to set TCP_NODELAY");
    }
}
