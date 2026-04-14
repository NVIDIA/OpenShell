//! ANSI escape sequence sanitization to prevent terminal injection attacks.

use std::fmt::{self, Write};

/// A wrapper that conditionally escapes ANSI sequences when formatted.
pub(super) struct EscapeGuard<T> {
    pub(super) value: T,
    pub(super) sanitize: bool,
}

impl<T> EscapeGuard<T> {
    pub(super) fn new(value: T, sanitize: bool) -> Self {
        Self { value, sanitize }
    }
}

/// Helper struct that escapes ANSI sequences as characters are written
struct EscapingWriter<'a, 'b> {
    inner: &'a mut fmt::Formatter<'b>,
}

impl<'a, 'b> fmt::Write for EscapingWriter<'a, 'b> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // Stream the string character by character, escaping ANSI and C1 control sequences
        for ch in s.chars() {
            match ch {
                // C0 control characters that can be used in terminal escape sequences
                '\x1b' => self.inner.write_str("\\x1b")?, // ESC
                '\x07' => self.inner.write_str("\\x07")?, // BEL
                '\x08' => self.inner.write_str("\\x08")?, // BS
                '\x0c' => self.inner.write_str("\\x0c")?, // FF
                '\x7f' => self.inner.write_str("\\x7f")?, // DEL

                // C1 control characters (\x80-\x9f) - 8-bit control codes
                // These can be used as alternative escape sequences in some terminals
                ch if ch as u32 >= 0x80 && ch as u32 <= 0x9f => {
                    write!(self.inner, "\\u{{{:x}}}", ch as u32)?
                }

                _ => self.inner.write_char(ch)?,
            }
        }
        Ok(())
    }
}

impl<T: fmt::Debug> fmt::Debug for EscapeGuard<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.sanitize {
            let mut escaping_writer = EscapingWriter { inner: f };
            write!(escaping_writer, "{:?}", self.value)
        } else {
            write!(f, "{:?}", self.value)
        }
    }
}

impl<T: fmt::Display> fmt::Display for EscapeGuard<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.sanitize {
            let mut escaping_writer = EscapingWriter { inner: f };
            write!(escaping_writer, "{}", self.value)
        } else {
            write!(f, "{}", self.value)
        }
    }
}
