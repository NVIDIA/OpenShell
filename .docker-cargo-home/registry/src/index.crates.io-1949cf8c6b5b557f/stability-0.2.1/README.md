# Stability

Rust API stability attributes for the rest of us.

[![Crates.io](https://img.shields.io/crates/v/stability.svg)](https://crates.io/crates/stability)
[![Documentation](https://docs.rs/stability/badge.svg)][documentation]
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Minimum supported Rust version](https://img.shields.io/badge/rustc-1.60+-yellow.svg)
[![Build](https://github.com/sagebind/stability/workflows/ci/badge.svg)](https://github.com/sagebind/stability/actions)

## Overview

This crate provides attribute macros for specifying API stability of public API items of a crate. For a quick example:

```rust
/// This function does something really risky!
///
/// Don't use it yet!
#[stability::unstable(feature = "risky-function")]
pub fn risky_function() {
    unimplemented!()
}
```

Please check out the [documentation] for detailed usage.

## Installation

Install via Cargo by adding to your `Cargo.toml` file:

```toml
[dependencies]
stability = "0.2.1"
```

### Supported Rust versions

The current release is only guaranteed to work with the latest stable Rust compiler.

## License

This project's source code and documentation are licensed under the MIT license. See the [LICENSE](LICENSE) file for details.


[documentation]: https://docs.rs/stability
