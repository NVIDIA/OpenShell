Comparison with other crates in the ecosystem.

### [termbg]
* Is hardcoded to use stdin/stderr for communicating with the terminal. \
  This means that it does not work if some or all of these streams are redirected.
* Pulls in an async runtime for the timeout.
* Does not calculate the perceived lightness, but another metric.

### [terminal-light]
* Is hardcoded to use stdout for communicating with the terminal.
* Does not report the colors, only the color's luma.
* Does not calculate the perceived lightness, but another metric.

[termbg]: https://docs.rs/termbg
[terminal-light]: https://docs.rs/terminal-light
