// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Recognize the main-attachment detach keys in client input.
//!
//! Full-screen programs such as vim enable xterm's modifyOtherKeys or the
//! kitty keyboard protocol, after which the client's terminal reports Ctrl-P
//! and Ctrl-Q as CSI sequences instead of control bytes. Both encodings must
//! detach, or a program can make the attachment impossible to leave.

const ESC: u8 = 0x1b;
const CTRL_P: u8 = 0x10;
const CTRL_Q: u8 = 0x11;
const CTRL_D: u8 = 0x04;
/// Longer sequences cannot encode a key this filter acts on.
const MAX_CSI: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    CtrlP,
    CtrlQ,
    CtrlD,
    /// A kitty key-release report, which does not interrupt the sequence.
    Release,
    Other,
}

#[derive(Debug, Default)]
pub(super) struct DetachFilter {
    /// Ctrl-P as the client encoded it, plus any key releases since, held
    /// until the next key shows whether it starts the detach sequence.
    prefix: Option<Vec<u8>>,
    /// A CSI sequence split across reads, held until its final byte.
    partial: Vec<u8>,
}

impl DetachFilter {
    /// Returns the input to forward and whether the client asked to detach.
    pub(super) fn filter(&mut self, data: &[u8]) -> (Vec<u8>, bool) {
        let mut forward = Vec::with_capacity(data.len());
        let mut index = 0;
        while index < data.len() {
            if self.partial.is_empty() {
                if data[index] == ESC && data.get(index + 1) == Some(&b'[') {
                    self.partial.extend_from_slice(b"\x1b[");
                    index += 2;
                } else {
                    index += 1;
                    if self.key(&mut forward, &data[index - 1..index]) {
                        return (forward, true);
                    }
                    continue;
                }
            }
            // Collect the rest of a CSI sequence.
            while index < data.len() {
                let byte = data[index];
                index += 1;
                self.partial.push(byte);
                if (0x40..=0x7e).contains(&byte) || self.partial.len() >= MAX_CSI {
                    let sequence = std::mem::take(&mut self.partial);
                    if self.key(&mut forward, &sequence) {
                        return (forward, true);
                    }
                    break;
                }
                if !(0x20..=0x3f).contains(&byte) {
                    // Not a CSI sequence after all; pass it through as is.
                    forward.append(&mut self.partial);
                    break;
                }
            }
        }
        (forward, false)
    }

    /// Keep recognizing a held Ctrl-P but never forward it: it was typed
    /// without write ownership.
    pub(super) fn forget_prefix_input(&mut self) {
        if let Some(prefix) = &mut self.prefix {
            prefix.clear();
        }
    }

    /// Handles one key. Returns true when it completes a detach sequence.
    fn key(&mut self, forward: &mut Vec<u8>, encoded: &[u8]) -> bool {
        let key = classify(encoded);
        if let Some(prefix) = &mut self.prefix {
            match key {
                Key::CtrlQ => {
                    self.prefix = None;
                    return true;
                }
                Key::Release => {
                    prefix.extend_from_slice(encoded);
                    return false;
                }
                _ => forward.append(prefix),
            }
            self.prefix = None;
        }
        match key {
            Key::CtrlD => return true,
            Key::CtrlP => self.prefix = Some(encoded.to_vec()),
            _ => forward.extend_from_slice(encoded),
        }
        false
    }
}

fn classify(encoded: &[u8]) -> Key {
    match encoded {
        [CTRL_P] => Key::CtrlP,
        [CTRL_Q] => Key::CtrlQ,
        [CTRL_D] => Key::CtrlD,
        [ESC, b'[', rest @ ..] => classify_csi(rest).unwrap_or(Key::Other),
        _ => Key::Other,
    }
}

/// Decodes `CSI 27 ; mods ; code ~` (modifyOtherKeys) and
/// `CSI code ; mods [: event] u` (CSI u and the kitty keyboard protocol).
/// Ctrl-D stays a key for the program when the terminal encodes it: only its
/// plain control byte detaches.
fn classify_csi(body: &[u8]) -> Option<Key> {
    let (&final_byte, params) = body.split_last()?;
    let params = std::str::from_utf8(params).ok()?;
    let fields: Vec<&str> = params.split(';').collect();
    let (code, modifiers) = match (final_byte, fields.as_slice()) {
        (b'~', ["27", modifiers, code]) | (b'u', [code, modifiers, ..]) => (*code, *modifiers),
        _ => return None,
    };
    // Kitty may append shifted and base-layout keys to the code.
    let code: u32 = code.split(':').next()?.parse().ok()?;
    let mut modifiers = modifiers.split(':');
    let mask: u32 = modifiers.next()?.parse().ok()?;
    let event = modifiers.next().unwrap_or("1");
    // Caps Lock and Num Lock do not change the key's meaning.
    if mask.checked_sub(1)? & !(64 | 128) != 4 {
        return None;
    }
    if event == "3" {
        return Some(Key::Release);
    }
    match char::from_u32(code)?.to_ascii_lowercase() {
        'p' => Some(Key::CtrlP),
        'q' => Some(Key::CtrlQ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::DetachFilter;

    #[test]
    fn preserves_prefix_before_ctrl_d() {
        let mut filter = DetachFilter::default();
        assert_eq!(filter.filter(b"\x10"), (Vec::new(), false));
        assert_eq!(filter.filter(b"\x04ignored"), (vec![0x10], true));
        assert_eq!(filter.filter(b"\x10\x11"), (Vec::new(), true));
    }

    #[test]
    fn detaches_on_keys_encoded_by_terminal_keyboard_modes() {
        for (ctrl_p, ctrl_q) in [
            (&b"\x1b[27;5;112~"[..], &b"\x1b[27;5;113~"[..]),
            (b"\x1b[112;5u", b"\x1b[113;5u"),
            // Caps Lock on, and kitty event types with key releases.
            (b"\x1b[112;69u", b"\x1b[113;69u"),
            (b"\x1b[112;5:1u\x1b[112;5:3u", b"\x1b[113;5:1u"),
            // Mixed: the terminal enabled a mode between the two keys.
            (b"\x10", b"\x1b[113;5u"),
        ] {
            let mut filter = DetachFilter::default();
            assert_eq!(filter.filter(b"ab"), (b"ab".to_vec(), false));
            assert_eq!(filter.filter(ctrl_p), (Vec::new(), false));
            assert_eq!(filter.filter(ctrl_q), (Vec::new(), true));
        }
    }

    #[test]
    fn forwards_encoded_prefix_when_another_key_follows() {
        let mut filter = DetachFilter::default();
        assert_eq!(
            filter.filter(b"\x1b[27;5;112~x"),
            (b"\x1b[27;5;112~x".to_vec(), false)
        );
        // Encoded Ctrl-D belongs to the program.
        assert_eq!(
            filter.filter(b"\x1b[100;5u"),
            (b"\x1b[100;5u".to_vec(), false)
        );
        // Ctrl-Shift-Q is not the detach key.
        assert_eq!(
            filter.filter(b"\x1b[112;5u\x1b[113;6u"),
            (b"\x1b[112;5u\x1b[113;6u".to_vec(), false)
        );
    }

    #[test]
    fn recognizes_sequences_split_across_reads() {
        let mut filter = DetachFilter::default();
        assert_eq!(filter.filter(b"x\x1b[11"), (b"x".to_vec(), false));
        assert_eq!(filter.filter(b"2;5u\x1b["), (Vec::new(), false));
        assert_eq!(filter.filter(b"113;5u"), (Vec::new(), true));
    }

    #[test]
    fn passes_other_input_through_unchanged() {
        let mut filter = DetachFilter::default();
        for input in [
            &b"\x1b"[..],
            b"\x1b[A\x1bOP\x1b[200~text\x1b[201~",
            b"\x1b[<0;10;5M",
            b"\x1b[\x07bell",
        ] {
            assert_eq!(filter.filter(input), (input.to_vec(), false));
        }
    }

    #[test]
    fn forgotten_prefix_still_detaches_but_is_never_forwarded() {
        let mut filter = DetachFilter::default();
        assert_eq!(filter.filter(b"\x1b[112;5u"), (Vec::new(), false));
        filter.forget_prefix_input();
        assert_eq!(filter.filter(b"x"), (b"x".to_vec(), false));
        assert_eq!(filter.filter(b"\x10"), (Vec::new(), false));
        filter.forget_prefix_input();
        assert_eq!(filter.filter(b"\x11"), (Vec::new(), true));
    }
}
