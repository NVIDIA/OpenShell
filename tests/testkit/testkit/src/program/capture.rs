// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Copying a test's output to the console while keeping it for the report.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How much of each stream is kept for the report. Output beyond this is
/// still shown; the report keeps the end, where failures are.
const KEPT_BYTES: usize = 4 << 20;

/// How long to wait for a stream to close after the test's process group is
/// gone. A process that left the group can hold it open.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// One stream being copied.
pub struct Capture {
    kept: Arc<Mutex<Kept>>,
    thread: JoinHandle<()>,
}

#[derive(Default)]
struct Kept {
    bytes: VecDeque<u8>,
    dropped: usize,
}

impl Capture {
    /// Copy `stream` to `console` on a thread, keeping a copy.
    pub fn start(
        mut stream: impl Read + Send + 'static,
        mut console: impl Write + Send + 'static,
    ) -> Self {
        let kept = Arc::new(Mutex::new(Kept::default()));
        let thread = std::thread::spawn({
            let kept = Arc::clone(&kept);
            move || {
                let mut buffer = [0; 8192];
                loop {
                    let read = match stream.read(&mut buffer) {
                        Ok(0) => return,
                        Ok(read) => read,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => return,
                    };
                    let chunk = &buffer[..read];
                    let _ = console.write_all(chunk).and_then(|()| console.flush());
                    kept.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(chunk);
                }
            }
        });
        Self { kept, thread }
    }

    /// The output kept, once the stream closes or after a short wait.
    pub fn finish(self) -> Vec<u8> {
        let deadline = Instant::now() + CLOSE_TIMEOUT;
        while !self.thread.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if self.thread.is_finished() {
            let _ = self.thread.join();
        }
        let kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        let mut bytes = Vec::with_capacity(kept.bytes.len() + 64);
        if kept.dropped > 0 {
            bytes.extend(format!("[{} earlier bytes not kept]\n", kept.dropped).as_bytes());
        }
        bytes.extend(&kept.bytes);
        bytes
    }
}

impl Kept {
    fn push(&mut self, chunk: &[u8]) {
        self.bytes.extend(chunk);
        let excess = self.bytes.len().saturating_sub(KEPT_BYTES);
        self.bytes.drain(..excess);
        self.dropped += excess;
    }
}

#[cfg(test)]
mod tests {
    use super::{Capture, KEPT_BYTES, Kept};

    #[test]
    fn copies_and_keeps_the_stream() {
        let capture = Capture::start(&b"one\ntwo\n"[..], std::io::sink());
        assert_eq!(capture.finish(), b"one\ntwo\n");
    }

    #[test]
    fn keeps_the_end_of_long_output() {
        let mut kept = Kept::default();
        kept.push(&vec![b'a'; KEPT_BYTES]);
        kept.push(b"end");
        assert_eq!(kept.bytes.len(), KEPT_BYTES);
        let tail: Vec<u8> = kept.bytes.iter().rev().take(4).rev().copied().collect();
        assert_eq!(tail, b"aend");
        assert_eq!(kept.dropped, 3);
    }
}
