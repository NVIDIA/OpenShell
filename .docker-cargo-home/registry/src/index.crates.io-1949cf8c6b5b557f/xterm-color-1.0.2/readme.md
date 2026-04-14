# xterm-color

[![Docs](https://img.shields.io/docsrs/xterm-color/latest)](https://docs.rs/xterm-color)
[![Crate Version](https://img.shields.io/crates/v/xterm-color)](https://crates.io/crates/xterm-color)

Parses the subset of X11 [Color Strings][x11] emitted by terminals in response to [`OSC` color queries][osc] (`OSC 10`, `OSC 11`, ...).

[osc]: https://www.invisible-island.net/xterm/ctlseqs/ctlseqs.html#h3-Operating-System-Commands
[x11]: https://www.x.org/releases/current/doc/libX11/libX11/libX11.html#Color_Strings

## Example
```rust
use xterm_color::Color;
let color = Color::parse(b"rgb:11/aa/ff").unwrap();
assert_eq!(color, Color::rgb(0x1111, 0xaaaa, 0xffff));
```

## [Docs](https://docs.rs/xterm-color)

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
