// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/// Advances through a scripted sequence of responses.
///
/// When the sequence is exhausted the last entry is repeated indefinitely and a
/// warning is logged on each repeated call.
pub struct Sequence<T> {
    rpc: &'static str,
    entries: Vec<T>,
    index: usize,
}

impl<T> Sequence<T> {
    pub fn new(rpc: &'static str, entries: Vec<T>) -> Self {
        Self {
            rpc,
            entries,
            index: 0,
        }
    }

    /// Return the next entry in the sequence, repeating the last when exhausted.
    ///
    /// Returns `None` only when the sequence is empty.
    pub fn next(&mut self) -> Option<&T> {
        if self.entries.is_empty() {
            return None;
        }
        if self.index < self.entries.len() {
            let entry = &self.entries[self.index];
            self.index += 1;
            Some(entry)
        } else {
            tracing::warn!(
                rpc = self.rpc,
                "scripted sequence exhausted; repeating last entry"
            );
            self.entries.last()
        }
    }
}
