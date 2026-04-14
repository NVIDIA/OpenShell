# terminal-colorsaurus 🦕

[![Docs](https://img.shields.io/docsrs/terminal-colorsaurus/latest)](https://docs.rs/terminal-colorsaurus)
[![Crate Version](https://img.shields.io/crates/v/terminal-colorsaurus)](https://crates.io/crates/terminal-colorsaurus)

A cross-platform library for determining the terminal's background and foreground color. \
It answers the question *«Is this terminal dark or light?»*.

Works in all major terminals including Windows Terminal (starting with v1.22).

## Example
```rust,no_run
use terminal_colorsaurus::{theme_mode, QueryOptions, ThemeMode};

match theme_mode(QueryOptions::default()).unwrap() {
    ThemeMode::Dark => { /* ... */ },
    ThemeMode::Light => { /* ... */ },
}
```

## [Docs](https://docs.rs/terminal-colorsaurus)

## MSRV Policy

This crate's Minimum Supported Rust Version (MSRV) is based
on the MSRVs of downstream users such as [`delta`] and [`bat`].
Changes to the MSRV will be accompanied by a minor version bump.

The following formula determines the MSRV:
```text
min(msrv(bat), msrv(delta))
```

## Inspiration
This crate borrows ideas from many other projects. This list is by no means exhaustive.

* [xterm-query]: Use `mio` to wait for the terminal's response with a timeout.
* [termbg]: Lists a lot of terminals which served as a good starting point for me to test terminals as well.
* [macOS doesn't like polling /dev/tty][macos-dev-tty] by Nathan Craddock
* [This excellent answer on Stack Overflow][perceived-lightness] for determining the perceived lightness of a color.
* [This comment in the Terminal WG](https://gitlab.freedesktop.org/terminal-wg/specifications/-/issues/8#note_151381) for the `DA1` trick
  to easily detect terminals that don't support querying the colors with `OSC 10` / `OSC 11`.

## License
Licensed under either of

* Apache License, Version 2.0
  ([license-apache.txt](license-apache.txt) or <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license
  ([license-mit.txt](license-mit.txt) or <http://opensource.org/licenses/MIT>)

at your option.

## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[xterm-query]: https://github.com/Canop/xterm-query
[termbg]: https://github.com/dalance/termbg
[macos-dev-tty]: https://nathancraddock.com/blog/macos-dev-tty-polling/
[perceived-lightness]: https://stackoverflow.com/a/56678483
[`delta`]: https://github.com/dandavison/delta
[`bat`]: https://github.com/sharkdp/bat
