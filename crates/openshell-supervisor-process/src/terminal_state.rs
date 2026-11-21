// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Terminal state carried across replayed TTY main-process output.
//!
//! A TTY main process writes escape sequences for whichever terminal was
//! attached when the bytes were produced. Replaying retained bytes into a
//! later client's terminal goes wrong in three ways: the retained window can
//! start after the sequences that enabled the alternate screen or input
//! modes, replayed queries make the new terminal answer into the program's
//! stdin, and scroll margins set for an older size no longer fit. Detaching
//! also leaves the client's terminal in the program's modes.
//!
//! [`TerminalState`] follows the escape-sequence structure of the stream
//! without emulating the screen, so it can restore and reset those modes and
//! drop queries from a replay. Screen contents are left to the program's own
//! redraw after an attachment resizes the terminal.

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;

/// Longest sequence held back for classification. Queries and mode changes
/// are far shorter; longer sequences pass through unclassified.
const MAX_SEQUENCE_BYTES: usize = 64;
const MAX_KEYBOARD_FLAGS: usize = 16;

/// DEC private modes that select the alternate screen.
const ALT_SCREEN_MODES: [u16; 3] = [1049, 1047, 47];
/// DEC private modes that change what the terminal sends as input.
const INPUT_MODES: [u16; 10] = [1, 1000, 1002, 1003, 1004, 1005, 1006, 1015, 1016, 2004];
const CURSOR_VISIBLE_MODE: u16 = 25;
/// `CSI Ps t` window operations that ask the terminal for a report.
const WINDOW_REPORTS: [u16; 9] = [11, 13, 14, 15, 16, 18, 19, 20, 21];
/// Resets the scroll margins without moving the cursor.
const RESET_MARGINS: &[u8] = b"\x1b7\x1b[r\x1b8";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Ground,
    Escape,
    EscapeIntermediate,
    Csi,
    /// OSC, DCS, APC, PM, or SOS payload, keyed by its introducer byte.
    String(u8),
    /// An ESC inside a string, which may begin the ST terminator.
    StringEscape(u8),
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default)]
pub struct TerminalState {
    phase: Phase,
    /// The sequence in progress, starting with ESC, while it is short enough
    /// to classify. Replays hold these bytes back until the sequence ends.
    sequence: Vec<u8>,
    /// The sequence in progress outgrew `sequence`; its bytes pass through.
    overflowed: bool,
    alt_screen: Option<u16>,
    cursor_hidden: bool,
    input_modes: Vec<u16>,
    keypad: bool,
    modify_other_keys: u16,
    keyboard_flags: Vec<u16>,
    margins: bool,
}

impl TerminalState {
    /// Follow program output. With `out`, append the bytes a replaying
    /// client should receive, which omits terminal queries; sequences are
    /// held back until they end. Without `out`, only track state.
    pub fn advance(&mut self, data: &[u8], mut out: Option<&mut Vec<u8>>) {
        for &byte in data {
            self.step(byte, out.as_deref_mut());
        }
    }

    /// Bytes that bring a fresh terminal to this state, sent before a replay
    /// that starts here. A held partial sequence is not included: the replay
    /// finishes and emits it.
    #[must_use]
    pub fn restore_sequence(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(mode) = self.alt_screen {
            push_private_mode(&mut out, mode, true);
        }
        if self.cursor_hidden {
            push_private_mode(&mut out, CURSOR_VISIBLE_MODE, false);
        }
        for &mode in &self.input_modes {
            push_private_mode(&mut out, mode, true);
        }
        if self.keypad {
            out.extend_from_slice(b"\x1b=");
        }
        if self.modify_other_keys != 0 {
            out.extend_from_slice(format!("\x1b[>4;{}m", self.modify_other_keys).as_bytes());
        }
        for &flags in &self.keyboard_flags {
            out.extend_from_slice(format!("\x1b[>{flags}u").as_bytes());
        }
        // An overflowed sequence's start was never retained. Open a string of
        // the same kind so the terminal discards the rest instead of printing
        // it; a long CSI continues as one.
        if self.overflowed {
            match self.phase {
                Phase::String(kind) | Phase::StringEscape(kind) => {
                    out.extend_from_slice(&[ESC, kind]);
                }
                Phase::Csi => out.extend_from_slice(b"\x1b["),
                Phase::Ground | Phase::Escape | Phase::EscapeIntermediate => {}
            }
        }
        out
    }

    /// End a replay: reset margins that were set for an older terminal size
    /// and release any held partial sequence, which live output completes.
    pub fn finish_replay(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.overflowed {
            // The client is inside a sequence; a reset now would corrupt it.
            return out;
        }
        if self.margins {
            out.extend_from_slice(RESET_MARGINS);
            self.margins = false;
        }
        // Keep the held bytes: live output only needs them classified.
        out.extend_from_slice(&self.sequence);
        out
    }

    /// Bytes that return the client's terminal to its defaults when an
    /// attachment ends while the program still owns the screen.
    #[must_use]
    pub fn reset_sequence(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.phase != Phase::Ground {
            out.push(CAN);
        }
        out.extend_from_slice(b"\x1b[m");
        if self.margins {
            out.extend_from_slice(RESET_MARGINS);
        }
        for &mode in self.input_modes.iter().rev() {
            push_private_mode(&mut out, mode, false);
        }
        if self.keypad {
            out.extend_from_slice(b"\x1b>");
        }
        if self.modify_other_keys != 0 {
            out.extend_from_slice(b"\x1b[>4;0m");
        }
        if !self.keyboard_flags.is_empty() {
            out.extend_from_slice(format!("\x1b[<{}u", self.keyboard_flags.len()).as_bytes());
        }
        if self.cursor_hidden {
            push_private_mode(&mut out, CURSOR_VISIBLE_MODE, true);
        }
        // Last, so restoring the saved main-screen cursor is not disturbed.
        if let Some(mode) = self.alt_screen {
            push_private_mode(&mut out, mode, false);
        }
        out
    }

    fn step(&mut self, byte: u8, mut out: Option<&mut Vec<u8>>) {
        match self.phase {
            Phase::Ground => {
                if byte == ESC {
                    self.begin();
                } else if let Some(out) = out {
                    out.push(byte);
                }
            }
            Phase::Escape | Phase::EscapeIntermediate | Phase::Csi => match byte {
                ESC => {
                    self.abort(out);
                    self.begin();
                }
                CAN | SUB => self.abort_with(byte, out),
                // Terminals execute C0 controls inside a sequence without
                // ending it, so sending them early keeps their effect.
                0x00..=0x1f => {
                    if let Some(out) = out {
                        out.push(byte);
                    }
                }
                _ => self.sequence_byte(byte, out),
            },
            Phase::String(kind) => match byte {
                ESC => {
                    self.record(byte, out);
                    self.phase = Phase::StringEscape(kind);
                }
                BEL => {
                    self.record(byte, out.as_deref_mut());
                    self.complete(out);
                }
                CAN | SUB => self.abort_with(byte, out),
                _ => self.record(byte, out),
            },
            Phase::StringEscape(kind) => {
                if byte == b'\\' {
                    self.record(byte, out.as_deref_mut());
                    self.phase = Phase::String(kind);
                    self.complete(out);
                } else if self.overflowed {
                    // The string's ESC already reached the client and starts
                    // a sequence there that this tracker no longer follows.
                    self.reset_parser();
                    if let Some(out) = out {
                        out.push(byte);
                    }
                } else {
                    // An ESC that is not ST ends the string and starts a new
                    // sequence.
                    self.sequence.pop();
                    self.phase = Phase::String(kind);
                    self.complete(out.as_deref_mut());
                    self.begin();
                    self.step(byte, out);
                }
            }
        }
    }

    fn sequence_byte(&mut self, byte: u8, mut out: Option<&mut Vec<u8>>) {
        match self.phase {
            Phase::Escape => match byte {
                b'[' => {
                    self.record(byte, out);
                    self.phase = Phase::Csi;
                }
                b']' | b'P' | b'_' | b'^' | b'X' => {
                    self.record(byte, out);
                    self.phase = Phase::String(byte);
                }
                0x20..=0x2f => {
                    self.record(byte, out);
                    self.phase = Phase::EscapeIntermediate;
                }
                0x30..=0x7e => {
                    self.record(byte, out.as_deref_mut());
                    self.complete(out);
                }
                _ => self.abort_with(byte, out),
            },
            Phase::EscapeIntermediate => match byte {
                0x20..=0x2f => self.record(byte, out),
                0x30..=0x7e => {
                    self.record(byte, out.as_deref_mut());
                    self.complete(out);
                }
                _ => self.abort_with(byte, out),
            },
            Phase::Csi => match byte {
                0x20..=0x3f => self.record(byte, out),
                0x40..=0x7e => {
                    self.record(byte, out.as_deref_mut());
                    self.complete(out);
                }
                _ => self.abort_with(byte, out),
            },
            // `step` routes only escape and CSI bytes here.
            Phase::Ground | Phase::String(_) | Phase::StringEscape(_) => self.abort_with(byte, out),
        }
    }

    fn begin(&mut self) {
        self.phase = Phase::Escape;
        self.sequence.clear();
        self.sequence.push(ESC);
        self.overflowed = false;
    }

    fn record(&mut self, byte: u8, out: Option<&mut Vec<u8>>) {
        if self.overflowed {
            if let Some(out) = out {
                out.push(byte);
            }
        } else if self.sequence.len() < MAX_SEQUENCE_BYTES {
            self.sequence.push(byte);
        } else {
            self.overflowed = true;
            if let Some(out) = out {
                out.append(&mut self.sequence);
                out.push(byte);
            }
            self.sequence.clear();
        }
    }

    /// Release an unfinished sequence as the terminal would see it.
    fn abort(&mut self, out: Option<&mut Vec<u8>>) {
        if let Some(out) = out
            && !self.overflowed
        {
            out.extend_from_slice(&self.sequence);
        }
        self.reset_parser();
    }

    fn abort_with(&mut self, byte: u8, mut out: Option<&mut Vec<u8>>) {
        self.abort(out.as_deref_mut());
        if let Some(out) = out {
            out.push(byte);
        }
    }

    fn reset_parser(&mut self) {
        self.phase = Phase::Ground;
        self.sequence.clear();
        self.overflowed = false;
    }

    /// End the sequence in progress, sending it unless it is a query.
    fn complete(&mut self, out: Option<&mut Vec<u8>>) {
        let phase = self.phase;
        let classified = !self.overflowed;
        let sequence = std::mem::take(&mut self.sequence);
        self.reset_parser();
        if classified
            && !self.apply(phase, &sequence)
            && let Some(out) = out
        {
            out.extend_from_slice(&sequence);
        }
    }

    /// Apply a complete sequence's effect on tracked state and report whether
    /// it asks the terminal for a reply.
    fn apply(&mut self, phase: Phase, sequence: &[u8]) -> bool {
        match phase {
            Phase::Escape | Phase::EscapeIntermediate => self.apply_escape(&sequence[1..]),
            Phase::Csi => self.apply_csi(&sequence[2..]),
            Phase::String(kind) => is_string_query(kind, string_payload(&sequence[2..])),
            // `complete` is only called for the phases above.
            Phase::Ground | Phase::StringEscape(_) => false,
        }
    }

    fn apply_escape(&mut self, body: &[u8]) -> bool {
        match body {
            b"=" => self.keypad = true,
            b">" => self.keypad = false,
            // RIS full reset. The parser is already back in its ground state.
            b"c" => *self = Self::default(),
            // DECID asks for the terminal's identity.
            b"Z" => return true,
            _ => {}
        }
        false
    }

    fn apply_csi(&mut self, body: &[u8]) -> bool {
        let Some((&final_byte, rest)) = body.split_last() else {
            return false;
        };
        let (marker, rest) = match rest.first() {
            Some(&marker @ (b'<' | b'=' | b'>' | b'?')) => (Some(marker), &rest[1..]),
            _ => (None, rest),
        };
        let split = rest
            .iter()
            .position(|byte| (0x20..=0x2f).contains(byte))
            .unwrap_or(rest.len());
        let (params, intermediates) = rest.split_at(split);
        let params = parse_params(params);
        let first = params.first().copied().flatten();
        match (marker, intermediates, final_byte) {
            (Some(b'?'), b"", b'h' | b'l') => {
                for mode in params.into_iter().flatten() {
                    self.set_private_mode(mode, final_byte == b'h');
                }
                false
            }
            (None, b"!", b'p') => {
                // DECSTR soft reset.
                self.cursor_hidden = false;
                self.input_modes.retain(|&mode| mode != 1);
                self.keypad = false;
                self.margins = false;
                false
            }
            (None, b"", b'r') => {
                self.margins = !params.is_empty();
                false
            }
            (Some(b'>'), b"", b'm') => {
                if first == Some(4) {
                    self.modify_other_keys = params.get(1).copied().flatten().unwrap_or(0);
                }
                false
            }
            (Some(b'>'), b"", b'u') => {
                if self.keyboard_flags.len() == MAX_KEYBOARD_FLAGS {
                    self.keyboard_flags.remove(0);
                }
                self.keyboard_flags.push(first.unwrap_or(0));
                false
            }
            (Some(b'<'), b"", b'u') => {
                let count = usize::from(first.unwrap_or(1));
                let keep = self.keyboard_flags.len().saturating_sub(count);
                self.keyboard_flags.truncate(keep);
                false
            }
            (Some(b'='), b"", b'u') => {
                let flags = first.unwrap_or(0);
                if let Some(top) = self.keyboard_flags.last_mut() {
                    match params.get(1).copied().flatten().unwrap_or(1) {
                        2 => *top |= flags,
                        3 => *top &= !flags,
                        _ => *top = flags,
                    }
                }
                false
            }
            // Device attributes, device status reports, and mode, version,
            // keyboard-flag, and window reports all make the terminal reply.
            (None | Some(b'>' | b'='), b"", b'c')
            | (None | Some(b'?'), b"", b'n')
            | (_, b"$", b'p')
            | (Some(b'>'), b"", b'q')
            | (Some(b'?'), b"", b'u') => true,
            (None, b"", b't') => first.is_some_and(|op| WINDOW_REPORTS.contains(&op)),
            _ => false,
        }
    }

    fn set_private_mode(&mut self, mode: u16, enabled: bool) {
        if ALT_SCREEN_MODES.contains(&mode) {
            self.alt_screen = enabled.then_some(mode);
        } else if mode == CURSOR_VISIBLE_MODE {
            self.cursor_hidden = !enabled;
        } else if INPUT_MODES.contains(&mode) {
            self.input_modes.retain(|&set| set != mode);
            if enabled {
                self.input_modes.push(mode);
            }
        }
    }
}

fn push_private_mode(out: &mut Vec<u8>, mode: u16, enabled: bool) {
    let action = if enabled { 'h' } else { 'l' };
    out.extend_from_slice(format!("\x1b[?{mode}{action}").as_bytes());
}

fn parse_params(params: &[u8]) -> Vec<Option<u16>> {
    if params.is_empty() {
        return Vec::new();
    }
    params
        .split(|&byte| byte == b';')
        .map(|param| {
            // Ignore colon-separated sub-parameters.
            let digits = param.split(|&byte| byte == b':').next().unwrap_or_default();
            std::str::from_utf8(digits).ok()?.parse().ok()
        })
        .collect()
}

/// The payload of a string sequence, without its BEL or ST terminator.
fn string_payload(body: &[u8]) -> &[u8] {
    body.strip_suffix(&[BEL])
        .or_else(|| body.strip_suffix(b"\x1b\\"))
        .unwrap_or(body)
}

fn is_string_query(kind: u8, payload: &[u8]) -> bool {
    match kind {
        // OSC color, palette, and clipboard queries end with a `?` field.
        b']' => {
            payload.contains(&b';') && payload.rsplit(|&byte| byte == b';').next() == Some(b"?")
        }
        // DECRQSS and XTGETTCAP.
        b'P' => payload.starts_with(b"$q") || payload.starts_with(b"+q"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replay(state: &mut TerminalState, chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in chunks {
            state.advance(chunk, Some(&mut out));
        }
        out
    }

    #[test]
    fn replay_drops_terminal_queries_from_vim_startup() {
        // Captured from vim 9.1 starting under TERM=xterm-256color.
        let startup: &[u8] =
            b"\x1b[?1049h\x1b[22;0;0t\x1b[>4;2m\x1b[?1h\x1b=\x1b[?2004h\x1b[?1004h\
\x1b[1;24r\x1b[H\x1b[2J\x1b[2;1H\xe2\x96\xbd\x1b[6n\x1b[2;1H  \x1b[3;1H\x1bPzz\x1b\\\x1b[0%m\
\x1b[6n\x1b[3;1H   \x1b[1;1H\x1b[>c\x1b]10;?\x07\x1b]11;?\x07\x1b[2;1H~";
        let mut state = TerminalState::default();
        let out = replay(&mut state, &[startup]);
        assert_eq!(
            out,
            b"\x1b[?1049h\x1b[22;0;0t\x1b[>4;2m\x1b[?1h\x1b=\x1b[?2004h\x1b[?1004h\
\x1b[1;24r\x1b[H\x1b[2J\x1b[2;1H\xe2\x96\xbd\x1b[2;1H  \x1b[3;1H\x1bPzz\x1b\\\x1b[0%m\
\x1b[3;1H   \x1b[1;1H\x1b[2;1H~"
        );
        assert_eq!(
            state.reset_sequence(),
            b"\x1b[m\x1b7\x1b[r\x1b8\x1b[?1004l\x1b[?2004l\x1b[?1l\x1b>\x1b[>4;0m\x1b[?1049l"
        );
    }

    #[test]
    fn replay_drops_queries_split_across_chunks() {
        let mut state = TerminalState::default();
        let out = replay(
            &mut state,
            &[
                b"a\x1b",
                b"[",
                b"6",
                b"nb\x1b]11;",
                b"?\x1b",
                b"\\c\x1bP$",
                b"q\"p\x1b\\d",
            ],
        );
        assert_eq!(out, b"abcd");
    }

    #[test]
    fn replay_keeps_sequences_that_are_not_queries() {
        let title = [b"\x1b]2;".as_slice(), &[b'x'; 200], b"\x07"].concat();
        let input = [
            b"\x1b[1;31mred\x1b[m\x1b[2 q\x1b[22;0t\x1b[5n".as_slice(),
            &title,
            b"\x1b[?25l\x1b(0q\x1b(B\x1b[!p\x1b[?12;25h\x1b]8;;https://example.com\x1b\\",
        ]
        .concat();
        let mut state = TerminalState::default();
        let out = replay(&mut state, &[&input]);
        // Only the device status report is removed.
        assert_eq!(out, input.replace(b"\x1b[5n", b""));
        assert_eq!(state.restore_sequence(), b"");
    }

    #[test]
    fn controls_inside_sequences_and_aborts_reach_the_client() {
        let mut state = TerminalState::default();
        let out = replay(&mut state, &[b"\x1b[1\n;2H\x1b[3\x18x\x1b]0;t\x1b[1mz"]);
        assert_eq!(out, b"\n\x1b[1;2H\x1b[3\x18x\x1b]0;t\x1b[1mz");
    }

    #[test]
    fn restore_and_reset_follow_mode_changes() {
        let mut state = TerminalState::default();
        state.advance(
            b"\x1b[?1049h\x1b[?25l\x1b[?1000;1006h\x1b[?2004h\x1b=\x1b[>1u\x1b[>3u\x1b[=5;2u",
            None,
        );
        assert_eq!(
            state.restore_sequence(),
            b"\x1b[?1049h\x1b[?25l\x1b[?1000h\x1b[?1006h\x1b[?2004h\x1b=\x1b[>1u\x1b[>7u"
        );
        assert_eq!(
            state.reset_sequence(),
            b"\x1b[m\x1b[?2004l\x1b[?1006l\x1b[?1000l\x1b>\x1b[<2u\x1b[?25h\x1b[?1049l"
        );

        state.advance(b"\x1b[?1000l\x1b[<u\x1b[?1049l\x1b[?25h\x1b>", None);
        assert_eq!(state.restore_sequence(), b"\x1b[?1006h\x1b[?2004h\x1b[>1u");

        state.advance(b"\x1bc", None);
        assert_eq!(state.restore_sequence(), b"");
        assert_eq!(state.reset_sequence(), b"\x1b[m");
    }

    #[test]
    fn replay_completes_a_sequence_split_by_eviction() {
        let mut evicted = TerminalState::default();
        evicted.advance(b"text\x1b[?104", None);
        assert_eq!(evicted.restore_sequence(), b"");

        let mut client = evicted.clone();
        let out = replay(&mut client, &[b"9hX"]);
        assert_eq!(out, b"\x1b[?1049hX");
        assert_eq!(client.reset_sequence(), b"\x1b[m\x1b[?1049l");
    }

    #[test]
    fn restore_reopens_an_evicted_long_string() {
        let mut evicted = TerminalState::default();
        evicted.advance(b"\x1b]52;c;", None);
        evicted.advance(&[b'A'; 100], None);
        assert_eq!(evicted.restore_sequence(), b"\x1b]");

        let mut client = evicted.clone();
        let out = replay(&mut client, &[b"AAA\x07after"]);
        assert_eq!(out, b"AAA\x07after");
    }

    #[test]
    fn finish_replay_resets_margins_before_a_held_sequence() {
        let mut state = TerminalState::default();
        let out = replay(&mut state, &[b"\x1b[1;24r\x1b[24;1H\x1b[1"]);
        assert_eq!(out, b"\x1b[1;24r\x1b[24;1H");
        assert_eq!(state.finish_replay(), b"\x1b7\x1b[r\x1b8\x1b[1");

        // Live output completes the held sequence without resending it.
        state.advance(b";1H\x1b[?2004h", None);
        assert_eq!(state.restore_sequence(), b"\x1b[?2004h");
        assert_eq!(state.finish_replay(), b"");
    }

    #[test]
    fn string_ended_by_another_escape_starts_a_new_sequence() {
        let mut state = TerminalState::default();
        let out = replay(&mut state, &[b"\x1b]11;?\x1b[?2004hx"]);
        assert_eq!(out, b"\x1b[?2004hx");
        assert_eq!(state.restore_sequence(), b"\x1b[?2004h");
    }

    trait Replace {
        fn replace(&self, from: &[u8], to: &[u8]) -> Vec<u8>;
    }

    impl Replace for Vec<u8> {
        fn replace(&self, from: &[u8], to: &[u8]) -> Vec<u8> {
            let position = self
                .windows(from.len())
                .position(|window| window == from)
                .expect("pattern present");
            [&self[..position], to, &self[position + from.len()..]].concat()
        }
    }
}
