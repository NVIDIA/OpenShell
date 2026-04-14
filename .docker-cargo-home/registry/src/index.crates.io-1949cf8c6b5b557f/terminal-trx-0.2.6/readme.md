# terminal-trx

[![Docs](https://img.shields.io/docsrs/terminal-trx/latest)](https://docs.rs/terminal-trx)
[![Crate Version](https://img.shields.io/crates/v/terminal-trx)](https://crates.io/crates/terminal-trx)

*Pronounced: Terminal T-Rex* 🦖

Provides a handle to the terminal of the current process that is both readable and writable.

## Example
```rust,no_run
use terminal_trx::terminal;
use std::io::{BufReader, BufRead as _, Write as _};

let mut terminal = terminal().unwrap();

write!(terminal, "hello world").unwrap();

let mut reader = BufReader::new(&mut terminal);
let mut line = String::new();
reader.read_line(&mut line).unwrap();
```

## [Docs](https://docs.rs/terminal-trx)

## Wishlist
These are some features that I would like to include in this crate,
but have not yet had the time to implement. Anyone is welcome to create a PR :)

* [ ] Add integration tests.
* [ ] Share the `Terminal` instance (like `stdout`, `stderr`, `stdin` in the standard library do). (Is this a good idea?)
* [ ] Support enabling raw mode on MSYS/Cygwin.

## Inspiration
This crate draws inspiration from many great resources, such as:
* [This Gist](https://gist.github.com/tavianator/d66d425399a57c51629999ae716bbd24) by Tavian Barnes
* [nix-ptsname_r-shim](https://github.com/Mobivity/nix-ptsname_r-shim/blob/master/src/lib.rs)

## License
Licensed under either of

* Apache License, Version 2.0
  ([license-apache.txt](license-apache.txt) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license
  ([license-mit.txt](license-mit.txt) or http://opensource.org/licenses/MIT)

at your option.

## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions
