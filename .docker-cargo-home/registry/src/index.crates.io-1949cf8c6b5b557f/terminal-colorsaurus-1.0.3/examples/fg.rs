//! This example shows how to retrieve the terminal's foreground color.

use terminal_colorsaurus::{foreground_color, Error, QueryOptions};

fn main() -> Result<(), display::DisplayAsDebug<Error>> {
    let fg = foreground_color(QueryOptions::default())?;
    let fg_8bit = fg.scale_to_8bit();
    println!("rgb16({}, {}, {})", fg.r, fg.g, fg.b);
    println!("rgb8({}, {}, {})", fg_8bit.0, fg_8bit.1, fg_8bit.2);
    Ok(())
}

#[path = "../examples-utils/display.rs"]
mod display;
