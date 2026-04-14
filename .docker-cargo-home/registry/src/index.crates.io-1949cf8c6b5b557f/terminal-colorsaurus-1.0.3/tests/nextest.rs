//! Regression test for <https://github.com/tautropfli/terminal-colorsaurus/issues/38>.
//! Run with `cargo nextest run`.

use terminal_colorsaurus::{theme_mode, QueryOptions, ThemeMode};

#[test]
fn test_does_not_hang() {
    let _ = theme_mode(QueryOptions::default()).unwrap_or(ThemeMode::Dark);
}
