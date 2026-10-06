// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Opaque, epoch-bound cursors for the `WatchSandbox` stream.
//!
//! A cursor is only meaningful inside the cursor space that issued it. A
//! gateway restart, or teardown of a sandbox's buses, starts a new space whose
//! sequence numbers restart at 1, so a bare number cannot tell "caught up"
//! apart from "belongs to a space that no longer exists". Binding the sequence
//! to the space's epoch makes that distinction explicit: a cursor from a dead
//! space is rejected instead of silently suppressing live events beneath it.
//!
//! # Wire contract
//!
//! `v1:<hyphenated-uuid>:<20-digit zero-padded seq>`
//!
//! The token is **opaque to clients**. The only operation a client may perform
//! is comparing two cursors from the same stream and keeping the greater one as
//! its resume point. That comparison is byte-wise: the version prefix and uuid
//! are fixed width, and the sequence is zero-padded, so lexicographic order
//! equals sequence order within one epoch. Every stream observes exactly one
//! epoch (a reset closes the stream), so the comparison is always well defined
//! where clients are allowed to use it.
//!
//! The server does **not** rely on that property. Ordering decisions on the
//! watch path run on the raw `u64` sequence carried alongside each event in
//! [`crate::tracing_bus::CursoredEvent`], so no server-side correctness
//! decision depends on the encoding.

use std::fmt;

use uuid::Uuid;

/// Current cursor encoding version.
const VERSION: &str = "v1";

/// Zero-padded width of the sequence segment. `u64::MAX` is 20 digits.
const SEQ_WIDTH: usize = 20;

/// Exact encoded length: `"v1"` + `':'` + hyphenated uuid + `':'` + seq.
const ENCODED_LEN: usize = VERSION.len() + 1 + 36 + 1 + SEQ_WIDTH;

/// A resume cursor: a sequence number bound to the cursor space that issued it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchCursor {
    pub(crate) epoch: Uuid,
    pub(crate) seq: u64,
}

/// The client supplied a cursor this server could not have issued.
///
/// Deliberately carries no detail from the input: the token is echoed back to
/// nobody, and a single opaque reason keeps malformed input from becoming a
/// reflection vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorParseError;

impl fmt::Display for CursorParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("resume_after_cursor is not a valid watch cursor")
    }
}

impl std::error::Error for CursorParseError {}

impl WatchCursor {
    pub(crate) const fn new(epoch: Uuid, seq: u64) -> Self {
        Self { epoch, seq }
    }

    /// Encode as the opaque wire token.
    pub(crate) fn encode(&self) -> String {
        format!(
            "{VERSION}:{}:{:0SEQ_WIDTH$}",
            self.epoch.as_hyphenated(),
            self.seq
        )
    }

    /// Parse a client-supplied token.
    ///
    /// Strict by design. Anything this server would not have produced is
    /// rejected, so a client cannot hand back a hand-built or truncated cursor
    /// and have it silently treated as a position in the current space.
    pub(crate) fn parse(raw: &str) -> Result<Self, CursorParseError> {
        // Fixed-width encoding, so one length check also bounds the work done
        // on hostile input.
        if raw.len() != ENCODED_LEN {
            return Err(CursorParseError);
        }

        let mut parts = raw.split(':');
        let (Some(version), Some(epoch), Some(seq), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(CursorParseError);
        };

        if version != VERSION {
            return Err(CursorParseError);
        }

        // Re-encode and compare so only the canonical lowercase hyphenated form
        // is accepted. `Uuid::parse_str` also takes braced and simple forms,
        // which would give one epoch several spellings and break the
        // lexicographic ordering clients rely on.
        let parsed_epoch = Uuid::parse_str(epoch).map_err(|_| CursorParseError)?;
        if parsed_epoch.as_hyphenated().to_string() != epoch {
            return Err(CursorParseError);
        }

        if seq.len() != SEQ_WIDTH || !seq.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CursorParseError);
        }
        // 20 digits can exceed u64::MAX, so this also rejects overflow.
        let seq: u64 = seq.parse().map_err(|_| CursorParseError)?;

        // Sequences start at 1; an empty cursor is the only "from the
        // beginning" signal.
        if seq == 0 {
            return Err(CursorParseError);
        }

        Ok(Self {
            epoch: parsed_epoch,
            seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> Uuid {
        Uuid::parse_str("3f2a9c14-7b6e-4d81-9a02-1c5d8e4f7b30").expect("valid uuid")
    }

    #[test]
    fn encode_parse_roundtrip() {
        for seq in [1, 2, 9, 10, 999, u64::MAX] {
            let cursor = WatchCursor::new(epoch(), seq);
            let encoded = cursor.encode();
            assert_eq!(encoded.len(), ENCODED_LEN);
            assert_eq!(WatchCursor::parse(&encoded).expect("roundtrip"), cursor);
        }
    }

    #[test]
    fn encoding_is_lexicographically_ordered_by_seq() {
        // Clients are told they may compare two cursors from one stream
        // byte-wise and keep the greater. That only holds because the sequence
        // is zero-padded to a fixed width; dropping the padding would make
        // "...:9" sort above "...:10" and silently rewind every reconnect.
        let encoded: Vec<String> = [1_u64, 2, 9, 10, 99, 100, u64::MAX]
            .into_iter()
            .map(|seq| WatchCursor::new(epoch(), seq).encode())
            .collect();

        let mut sorted = encoded.clone();
        sorted.sort();
        assert_eq!(sorted, encoded, "lexicographic order must match seq order");
    }

    #[test]
    fn parse_rejects_malformed() {
        let e = epoch().as_hyphenated().to_string();
        let cases = [
            ("empty", String::new()),
            ("bare number", "5".to_string()),
            ("unpadded seq", format!("v1:{e}:5")),
            ("wrong version", format!("v2:{e}:{:020}", 1)),
            (
                "not a uuid",
                format!("v1:not-a-uuid-not-a-uuid-not-a-uuid-x:{:020}", 1),
            ),
            (
                "uppercase uuid",
                format!("v1:{}:{:020}", e.to_uppercase(), 1),
            ),
            (
                "simple uuid",
                format!("v1:{}:{:020}", epoch().as_simple(), 1),
            ),
            ("four segments", format!("v1:{e}:{:020}:x", 1)),
            ("zero seq", format!("v1:{e}:{:020}", 0)),
            ("non-digit seq", format!("v1:{e}:0000000000000000000x")),
            ("seq overflows u64", format!("v1:{e}:99999999999999999999")),
            ("over-long input", "x".repeat(200)),
        ];

        for (name, raw) in cases {
            assert_eq!(
                WatchCursor::parse(&raw),
                Err(CursorParseError),
                "expected rejection for {name}"
            );
        }
    }

    #[test]
    fn parse_error_does_not_echo_input() {
        let rendered = CursorParseError.to_string();
        assert!(!rendered.contains("v1:"), "error must not echo the token");
    }
}
