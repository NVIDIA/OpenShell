#![allow(clippy::use_debug)]

//! This example shows how to heuristically avoid having a race condition with a pager (e.g. `less`).
//! The race condition occurs because the pager and colorsaurus simultaneously
//! enable/disable raw mode and read/write to the same terminal.
//!
//! The heuristic checks if stdout is connected to a pipe which is a strong
//! indicator that the output is redirected to another process, for instance a pager.
//! Note that this heuristic has both
//! false negatives (output not piped to a pager) and
//! false positives (stderr piped to a pager).
//!
//! You might want to have an explicit option in your CLI app that
//! allows users to override that heuristic (similar to --color=always/never/auto).
//!
//! Test this example as follows:
//! 1. `cargo run --example pager`—should print the theme mode.
//! 2. `cargo run --example pager | less`—should not print the theme mode.
//! 3. `cargo run --example pager | cat`—should not print the theme mode. This is a false negatives.
//! 4. `cargo run --example pager 2>&1 >/dev/tty | less`—should print the theme mode (or error). This is a false positive.

use std::io::{stdout, IsTerminal as _};
use terminal_colorsaurus::{theme_mode, Error, QueryOptions};

fn main() -> Result<(), display::DisplayAsDebug<Error>> {
    if stdout().is_terminal() {
        eprintln!(
            "Here's the theme mode: {:#?}",
            theme_mode(QueryOptions::default())?
        );
    } else {
        eprintln!("No theme mode for you today :/");
    }

    Ok(())
}

#[path = "../examples-utils/display.rs"]
mod display;
