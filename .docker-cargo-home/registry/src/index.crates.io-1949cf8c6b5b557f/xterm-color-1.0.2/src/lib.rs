//! Parses the subset of X11 [Color Strings][x11] emitted by terminals in response to [`OSC` color queries][osc] (`OSC 10`, `OSC 11`, ...).
//!
//! [osc]: https://www.invisible-island.net/xterm/ctlseqs/ctlseqs.html#h3-Operating-System-Commands
//! [x11]: https://www.x.org/releases/current/doc/libX11/libX11/libX11.html#Color_Strings
//!
//! ```
//! use xterm_color::Color;
//!
//! assert_eq!(
//!    Color::parse(b"rgb:11/aa/ff").unwrap(),
//!    Color::rgb(0x1111, 0xaaaa, 0xffff)
//! );
//! ```

use core::fmt;
use std::error;
use std::marker::PhantomData;
use std::str::from_utf8;

/// An RGB color with 16 bits per channel and an optional alpha channel.
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(clippy::exhaustive_structs)]
pub struct Color {
    /// Red
    pub red: u16,
    /// Green
    pub green: u16,
    /// Blue
    pub blue: u16,
    /// Alpha.
    ///
    /// Can almost always be ignored as it is rarely set to
    /// something other than the default (`0xffff`).
    pub alpha: u16,
}

impl Color {
    /// Construct a new [`Color`] from (r, g, b) components, with the default alpha (`0xffff`).
    pub const fn rgb(red: u16, green: u16, blue: u16) -> Self {
        Self {
            red,
            green,
            blue,
            alpha: u16::MAX,
        }
    }

    /// Parses the subset of X11 [Color Strings](https://www.x.org/releases/current/doc/libX11/libX11/libX11.html#Color_Strings)
    /// emitted by terminals in response to `OSC` color queries (`OSC 10`, `OSC 11`, ...).
    ///
    /// This function is a rough analogue to `XParseColor`.
    ///
    /// ## Accepted Formats
    /// * `#<red><green><blue>`
    /// * `rgb:<red>/<green>/<blue>`
    /// * `rgba:<red>/<green>/<blue>/<alpha>` (rxvt-unicode extension)
    ///
    /// where `<red>`, `<green>` and `<blue>` are hexadecimal numbers with 1-4 digits.
    #[doc(alias = "XParseColor")]
    pub fn parse(input: &[u8]) -> Result<Color, ColorParseError> {
        xparsecolor(input).ok_or(ColorParseError(PhantomData))
    }
}

/// Error which can be returned when parsing a color.
#[derive(Debug, Clone)]
pub struct ColorParseError(PhantomData<()>);

impl error::Error for ColorParseError {}

impl fmt::Display for ColorParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid color spec")
    }
}

fn xparsecolor(input: &[u8]) -> Option<Color> {
    if let Some(stripped) = input.strip_prefix(b"#") {
        parse_sharp(from_utf8(stripped).ok()?)
    } else if let Some(stripped) = input.strip_prefix(b"rgb:") {
        parse_rgb(from_utf8(stripped).ok()?)
    } else if let Some(stripped) = input.strip_prefix(b"rgba:") {
        parse_rgba(from_utf8(stripped).ok()?)
    } else {
        None
    }
}

/// From the `xparsecolor` man page:
/// > For backward compatibility, an older syntax for RGB Device is supported,
/// > but its continued use is not encouraged. The syntax is an initial sharp sign character
/// > followed by a numeric specification, in one of the following formats:
/// >
/// > The R, G, and B represent single hexadecimal digits.
/// > When fewer than 16 bits each are specified, they represent the most significant bits of the value
/// > (unlike the `rgb:` syntax, in which values are scaled).
/// > For example, the string `#3a7` is the same as `#3000a0007000`.
fn parse_sharp(input: &str) -> Option<Color> {
    const NUM_COMPONENTS: usize = 3;
    let len = input.len();
    if len % NUM_COMPONENTS == 0 && len <= NUM_COMPONENTS * 4 {
        let chunk_size = input.len() / NUM_COMPONENTS;
        let red = parse_channel_shifted(&input[0..chunk_size])?;
        let green = parse_channel_shifted(&input[chunk_size..chunk_size * 2])?;
        let blue = parse_channel_shifted(&input[chunk_size * 2..])?;
        Some(Color::rgb(red, green, blue))
    } else {
        None
    }
}

fn parse_channel_shifted(input: &str) -> Option<u16> {
    let value = u16::from_str_radix(input, 16).ok()?;
    Some(value << ((4 - input.len()) * 4))
}

/// From the `xparsecolor` man page:
/// > An RGB Device specification is identified by the prefix `rgb:` and conforms to the following syntax:
/// > ```text
/// > rgb:<red>/<green>/<blue>
/// >
/// >     <red>, <green>, <blue> := h | hh | hhh | hhhh
/// >     h := single hexadecimal digits (case insignificant)
/// > ```
/// > Note that *h* indicates the value scaled in 4 bits,
/// > *hh* the value scaled in 8 bits, *hhh* the value scaled in 12 bits,
/// > and *hhhh* the value scaled in 16 bits, respectively.
fn parse_rgb(input: &str) -> Option<Color> {
    let mut parts = input.split('/');
    let red = parse_channel_scaled(parts.next()?)?;
    let green = parse_channel_scaled(parts.next()?)?;
    let blue = parse_channel_scaled(parts.next()?)?;
    if parts.next().is_none() {
        Some(Color::rgb(red, green, blue))
    } else {
        None
    }
}

/// Some terminals such as urxvt (rxvt-unicode) optionally support
/// an alpha channel and sometimes return colors in the format `rgba:<red>/<green>/<blue>/<alpha>`.
///
/// Dropping the alpha channel is a best-effort thing as
/// the effective color (when combined with a background color)
/// could have a completely different perceived lightness value.
///
/// Test with `urxvt -depth 32 -fg grey90 -bg rgba:0000/0000/4444/cccc`
fn parse_rgba(input: &str) -> Option<Color> {
    let mut parts = input.split('/');
    let red = parse_channel_scaled(parts.next()?)?;
    let green = parse_channel_scaled(parts.next()?)?;
    let blue = parse_channel_scaled(parts.next()?)?;
    let alpha = parse_channel_scaled(parts.next()?)?;
    if parts.next().is_none() {
        Some(Color {
            red,
            green,
            blue,
            alpha,
        })
    } else {
        None
    }
}

fn parse_channel_scaled(input: &str) -> Option<u16> {
    let len = input.len();
    if (1..=4).contains(&len) {
        let max = u32::pow(16, len as u32) - 1;
        let value = u32::from_str_radix(input, 16).ok()?;
        Some((u16::MAX as u32 * value / max) as u16)
    } else {
        None
    }
}

// Implementation of determining the perceived lightness
// follows this excellent answer: https://stackoverflow.com/a/56678483
impl Color {
    /// Perceptual lightness (L*) as a value between 0.0 (black) and 1.0 (white)
    /// where 0.5 is the perceptual middle gray.
    ///
    /// Note that the color's alpha is ignored.
    pub fn perceived_lightness(&self) -> f32 {
        luminance_to_perceived_lightness(self.luminance()) / 100.
    }

    /// Luminance (`Y`) calculated using the [CIE XYZ formula](https://en.wikipedia.org/wiki/Relative_luminance).
    fn luminance(&self) -> f32 {
        let r = gamma_function(f32::from(self.red) / f32::from(u16::MAX));
        let g = gamma_function(f32::from(self.green) / f32::from(u16::MAX));
        let b = gamma_function(f32::from(self.blue) / f32::from(u16::MAX));
        0.2126 * r + 0.7152 * g + 0.0722 * b
    }
}

/// Converts a non-linear sRGB value to a linear one via [gamma correction](https://en.wikipedia.org/wiki/Gamma_correction).
// Taken from bevy_color: https://github.com/bevyengine/bevy/blob/0403948aa23a748abd2a2aac05eef1209d66674e/crates/bevy_color/src/srgba.rs#L211
fn gamma_function(value: f32) -> f32 {
    if value <= 0.0 {
        return value;
    }
    if value <= 0.04045 {
        value / 12.92 // linear falloff in dark values
    } else {
        ((value + 0.055) / 1.055).powf(2.4) // gamma curve in other area
    }
}

/// Perceptual lightness (L*) calculated using the [CIEXYZ to CIELAB formula](https://en.wikipedia.org/wiki/CIELAB_color_space).
fn luminance_to_perceived_lightness(luminance: f32) -> f32 {
    if luminance <= 216. / 24389. {
        luminance * (24389. / 27.)
    } else {
        luminance.cbrt() * 116. - 16.
    }
}

#[cfg(doctest)]
#[doc = include_str!("../readme.md")]
pub mod readme_doctests {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // Tests adapted from alacritty/vte:
    // https://github.com/alacritty/vte/blob/ed51aa19b7ad060f62a75ec55ebb802ced850b1a/src/ansi.rs#L2134
    #[test]
    fn parses_valid_rgb_color() {
        assert_eq!(
            Color::parse(b"rgb:f/e/d").unwrap(),
            Color {
                red: 0xffff,
                green: 0xeeee,
                blue: 0xdddd,
                alpha: u16::MAX,
            }
        );
        assert_eq!(
            Color::parse(b"rgb:11/aa/ff").unwrap(),
            Color {
                red: 0x1111,
                green: 0xaaaa,
                blue: 0xffff,
                alpha: u16::MAX,
            }
        );
        assert_eq!(
            Color::parse(b"rgb:f/ed1/cb23").unwrap(),
            Color {
                red: 0xffff,
                green: 0xed1d,
                blue: 0xcb23,
                alpha: u16::MAX,
            }
        );
        assert_eq!(
            Color::parse(b"rgb:ffff/0/0").unwrap(),
            Color {
                red: 0xffff,
                green: 0x0,
                blue: 0x0,
                alpha: u16::MAX,
            }
        );
    }

    #[test]
    fn parses_valid_rgba_color() {
        assert_eq!(
            Color::parse(b"rgba:0000/0000/4443/cccc").unwrap(),
            Color {
                red: 0x0000,
                green: 0x0000,
                blue: 0x4443,
                alpha: 0xcccc,
            }
        );
    }

    #[test]
    fn fails_for_invalid_rgb_color() {
        assert!(Color::parse(b"rgb:").is_err()); // Empty
        assert!(Color::parse(b"rgb:f/f").is_err()); // Not enough channels
        assert!(Color::parse(b"rgb:f/f/f/f").is_err()); // Too many channels
        assert!(Color::parse(b"rgb:f//f").is_err()); // Empty channel
        assert!(Color::parse(b"rgb:ffff/ffff/fffff").is_err()); // Too many digits for one channel
    }

    // Tests adapted from alacritty/vte:
    // https://github.com/alacritty/vte/blob/ed51aa19b7ad060f62a75ec55ebb802ced850b1a/src/ansi.rs#L2142
    #[test]
    fn parses_valid_sharp_color() {
        assert_eq!(
            Color::parse(b"#1af").unwrap(),
            Color {
                red: 0x1000,
                green: 0xa000,
                blue: 0xf000,
                alpha: u16::MAX,
            }
        );
        assert_eq!(
            Color::parse(b"#1AF").unwrap(),
            Color {
                red: 0x1000,
                green: 0xa000,
                blue: 0xf000,
                alpha: u16::MAX,
            }
        );
        assert_eq!(
            Color::parse(b"#11aaff").unwrap(),
            Color {
                red: 0x1100,
                green: 0xaa00,
                blue: 0xff00,
                alpha: u16::MAX,
            }
        );
        assert_eq!(
            Color::parse(b"#110aa0ff0").unwrap(),
            Color {
                red: 0x1100,
                green: 0xaa00,
                blue: 0xff00,
                alpha: u16::MAX,
            }
        );
        assert_eq!(
            Color::parse(b"#1100aa00ff00").unwrap(),
            Color {
                red: 0x1100,
                green: 0xaa00,
                blue: 0xff00,
                alpha: u16::MAX,
            }
        );
        assert_eq!(
            Color::parse(b"#123456789ABC").unwrap(),
            Color {
                red: 0x1234,
                green: 0x5678,
                blue: 0x9ABC,
                alpha: u16::MAX,
            }
        );
    }

    #[test]
    fn fails_for_invalid_sharp_color() {
        assert!(Color::parse(b"#").is_err()); // Empty
        assert!(Color::parse(b"#1234").is_err()); // Not divisible by three
        assert!(Color::parse(b"#123456789ABCDEF").is_err()); // Too many components
    }

    #[test]
    fn black_has_perceived_lightness_zero() {
        let black = Color::rgb(0, 0, 0);
        assert_eq!(0.0, black.perceived_lightness())
    }

    #[test]
    fn white_has_perceived_lightness_one() {
        let white = Color::rgb(u16::MAX, u16::MAX, u16::MAX);
        assert_eq!(1.0, white.perceived_lightness())
    }
}
