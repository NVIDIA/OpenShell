// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OSC 52 clipboard support.
//!
//! Writes the OSC 52 escape sequence to stdout, which instructs the terminal
//! emulator to copy text to the system clipboard. Works over SSH, tmux, and
//! mosh — the sequence is forwarded to the local terminal.

use base64::Engine;
use std::io::Write;

/// Copy `text` to the system clipboard via the OSC 52 escape sequence.
///
/// Writes directly to `/dev/tty` so the escape sequence reaches the terminal
/// emulator even while ratatui owns stdout via the alternate screen buffer.
///
/// This is fire-and-forget: if `/dev/tty` cannot be opened or the terminal
/// does not support OSC 52, the operation is silently ignored.
pub fn copy_to_clipboard(text: &str) {
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    // OSC 52 ; c ; <base64> ST  — "c" selects the system clipboard.
    let seq = format!("\x1b]52;c;{encoded}\x07");
    if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = tty.write_all(seq.as_bytes());
        let _ = tty.flush();
    }
}
