/// An RGB color with 16 bits per channel.
/// You can use [`Color::scale_to_8bit`] to convert to an 8bit RGB color.
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub struct Color {
    /// Red
    pub r: u16,
    /// Green
    pub g: u16,
    /// Blue
    pub b: u16,
    // Alpha field is omitted because only rxvt-unicode supports it.
    // If you need it, open a PR. Thanks to #[non_exhaustive] this would be a non-breaking change.
}

impl Color {
    /// Creates a RGB color from its three channels: Red, Green and Blue.
    pub fn rgb(r: u16, g: u16, b: u16) -> Self {
        Self { r, g, b }
    }

    /// Perceptual lightness (L*) as a value between 0.0 (black) and 1.0 (white)
    /// where 0.5 is the perceptual middle gray.
    ///
    /// Note that the color's alpha is ignored.
    /// ```
    /// # use terminal_colorsaurus::Color;
    /// # let color = Color::default();
    /// let is_dark = color.perceived_lightness() <= 0.5;
    /// ```
    pub fn perceived_lightness(&self) -> f32 {
        let color = xterm_color::Color::rgb(self.r, self.g, self.b);
        color.perceived_lightness()
    }

    /// Converts the color to 8 bit precision per channel by scaling each channel.
    ///
    /// ```
    /// # use terminal_colorsaurus::Color;
    /// let white = Color::rgb(u16::MAX, u16::MAX, u16::MAX);
    /// assert_eq!((u8::MAX, u8::MAX, u8::MAX), white.scale_to_8bit());
    ///
    /// let black = Color::rgb(0, 0, 0);
    /// assert_eq!((0, 0, 0), black.scale_to_8bit());
    /// ```
    pub fn scale_to_8bit(&self) -> (u8, u8, u8) {
        (
            scale_to_u8(self.r),
            scale_to_u8(self.g),
            scale_to_u8(self.b),
        )
    }
}

fn scale_to_u8(channel: u16) -> u8 {
    (channel as u32 * (u8::MAX as u32) / (u16::MAX as u32)) as u8
}

#[cfg(feature = "rgb")]
impl From<Color> for rgb::RGB16 {
    fn from(value: Color) -> Self {
        rgb::RGB16 {
            r: value.r,
            g: value.g,
            b: value.b,
        }
    }
}

#[cfg(feature = "rgb")]
impl From<Color> for rgb::RGB8 {
    fn from(value: Color) -> Self {
        let (r, g, b) = value.scale_to_8bit();
        rgb::RGB8 { r, g, b }
    }
}

#[cfg(feature = "rgb")]
impl From<rgb::RGB16> for Color {
    fn from(value: rgb::RGB16) -> Self {
        Color {
            r: value.r,
            g: value.g,
            b: value.b,
        }
    }
}

#[cfg(feature = "anstyle")]
impl From<Color> for anstyle::RgbColor {
    fn from(value: Color) -> Self {
        let (r, g, b) = value.scale_to_8bit();
        anstyle::RgbColor(r, g, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn black_has_perceived_lightness_zero() {
        let black = Color::default();
        assert_eq!(0.0, black.perceived_lightness())
    }

    #[test]
    fn white_has_perceived_lightness_100() {
        let white = Color {
            r: u16::MAX,
            g: u16::MAX,
            b: u16::MAX,
        };
        assert_eq!(1.0, white.perceived_lightness())
    }
}
