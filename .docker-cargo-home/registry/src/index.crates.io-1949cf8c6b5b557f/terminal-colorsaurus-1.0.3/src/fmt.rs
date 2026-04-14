use std::fmt;

// Caret notation encodes control characters as ^char.
// See: https://en.wikipedia.org/wiki/Caret_notation
pub(crate) struct CaretNotation<'a>(pub(crate) &'a str);

impl fmt::Display for CaretNotation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.0.chars() {
            if c.is_control() {
                write!(f, "{}", EscapeCaret(c))?;
            } else {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

struct EscapeCaret(char);

impl fmt::Display for EscapeCaret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(escaped) = char::from_u32(u32::from(self.0) ^ 0x40) {
            write!(f, "^{escaped}")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_chars() {
        assert_eq!("^@", format!("{}", CaretNotation("\x00")));
        assert_eq!(
            "^[]11;rgba:0000/0000/4443/cccc^G",
            format!("{}", CaretNotation("\x1b]11;rgba:0000/0000/4443/cccc\x07"))
        )
    }
}
