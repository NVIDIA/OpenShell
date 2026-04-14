use crate::{Color, ColorPalette, Error, QueryOptions, Result};

pub(crate) fn color_palette(_options: QueryOptions) -> Result<ColorPalette> {
    Err(Error::unsupported())
}

pub(crate) fn foreground_color(_options: QueryOptions) -> Result<Color> {
    Err(Error::unsupported())
}

pub(crate) fn background_color(_options: QueryOptions) -> Result<Color> {
    Err(Error::unsupported())
}
