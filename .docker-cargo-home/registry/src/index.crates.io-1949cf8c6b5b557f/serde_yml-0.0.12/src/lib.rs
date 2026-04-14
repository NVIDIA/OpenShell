//!# Serde YML (a fork of Serde YAML)
//!
//![![Made With Love][made-with-rust]][11] [![Crates.io][crates-badge]][07] [![lib.rs][libs-badge]][12] [![Docs.rs][docs-badge]][08] [![Codecov][codecov-badge]][09] [![Build Status][build-badge]][10] [![GitHub][github-badge]][06]
//!
//![Serde YML][00] is a Rust library for using the [Serde][01] serialization framework with data in [YAML][05] file format.
//!
//! ## Features
//!
//! - Serialization and deserialization of Rust data structures to/from YAML format
//! - Support for custom structs and enums using Serde's derive macros
//! - Handling of YAML's `!tag` syntax for representing enum variants
//! - Direct access to YAML values through the `Value` type and related types like `Mapping` and `Sequence`
//! - Comprehensive error handling with `Error`, `Location`, and `Result` types
//! - Serialization to YAML using `to_string` and `to_writer` functions
//! - Deserialization from YAML using `from_str`, `from_slice`, and `from_reader` functions
//! - Customizable serialization and deserialization behavior using Serde's `#[serde(with = ...)]` attribute
//! - Support for serializing/deserializing enums using a YAML map with a single key-value pair through the `singleton_map` module
//! - Recursive application of `singleton_map` serialization/deserialization to all enums within a data structure using the `singleton_map_recursive` module
//! - Serialization and deserialization of optional enum fields using the `singleton_map_optional` module
//! - Handling of nested enum structures with optional inner enums using the `singleton_map_recursive` module
//! - Customization of serialization and deserialization logic for enums using the `singleton_map_with` module and custom helper functions
//!
//!## Installation
//!
//!Add this to your `Cargo.toml`:
//!
//!```toml
//![dependencies]
//!serde = "1.0"
//!serde_yml = "0.0.12"
//!```
//!
//!## Usage
//!
//!Here's a quick example on how to use Serde YML to serialize and deserialize a struct to and from YAML:
//!
//!```rust
//!use serde::{Serialize, Deserialize};
//!
//!#[derive(Debug, PartialEq, Serialize, Deserialize)]
//!struct Point {
//!    x: f64,
//!    y: f64,
//!}
//!
//!fn main() -> Result<(), serde_yml::Error> {
//!    let point = Point { x: 1.0, y: 2.0 };
//!
//!    // Serialize to YAML
//!    let yaml = serde_yml::to_string(&point)?;
//!    assert_eq!(yaml, "x: 1.0\n'y': 2.0\n");
//!
//!    // Deserialize from YAML
//!    let deserialized_point: Point = serde_yml::from_str(&yaml)?;
//!    assert_eq!(point, deserialized_point);
//!
//!    Ok(())
//!}
//!```
//!
//!## Documentation
//!
//!For full API documentation, please visit [https://doc.libyml.com/serde-yaml/][04] or [https://docs.rs/serde-yaml][08].
//!
//!## Rust Version Compatibility
//!
//!Compiler support: requires rustc 1.56.0+
//!
//! ## Examples
//!
//! Serde YML provides a set of comprehensive examples to demonstrate its usage and capabilities. You can find them in the `examples` directory of the project.
//!
//! To run the examples, clone the repository and execute the following command in your terminal from the project root directory:
//!
//! ```shell
//! cargo run --example example
//! ```
//!
//! The examples cover various scenarios, including serializing and deserializing structs, enums, optional fields, custom structs, and more.
//!
//! [00]: https://serdeyml.com
//! [01]: https://github.com/serde-rs/serde
//! [02]: https://github.com/dtolnay/serde-yaml
//! [03]: https://github.com/dtolnay
//! [04]: https://doc.libyml.com/serde-yaml/
//! [05]: https://yaml.org/
//! [06]: https://github.com/sebastienrousseau/serde_yml
//! [07]: https://crates.io/crates/serde_yml
//! [08]: https://docs.rs/serde_yml
//! [09]: https://codecov.io/gh/sebastienrousseau/serde_yml
//! [10]: https://github.com/sebastienrousseau/serde-yml/actions?query=branch%3Amaster
//! [11]: https://www.rust-lang.org/
//! [12]: https://lib.rs/crates/serde_yml
//! [build-badge]: https://img.shields.io/github/actions/workflow/status/sebastienrousseau/serde_yml/release.yml?branch=master&style=for-the-badge&logo=github "Build Status"
//! [codecov-badge]: https://img.shields.io/codecov/c/github/sebastienrousseau/serde_yml?style=for-the-badge&token=Q9KJ6XXL67&logo=codecov "Codecov"
//! [crates-badge]: https://img.shields.io/crates/v/serde_yml.svg?style=for-the-badge&color=fc8d62&logo=rust "Crates.io"
//! [libs-badge]: https://img.shields.io/badge/lib.rs-v0.0.12-orange.svg?style=for-the-badge "View on lib.rs"
//! [docs-badge]: https://img.shields.io/badge/docs.rs-serde__yml-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs "Docs.rs"
//! [github-badge]: https://img.shields.io/badge/github-sebastienrousseau/serde--yml-8da0cb?style=for-the-badge&labelColor=555555&logo=github "GitHub"
//! [made-with-rust]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust 'Made With Rust'
//!
//!

#![deny(missing_docs)]
#![doc(
    html_favicon_url = "https://kura.pro/serde_yml/images/favicon.ico",
    html_logo_url = "https://kura.pro/serde_yml/images/logos/serde_yml.svg",
    html_root_url = "https://docs.rs/serde_yml"
)]
#![crate_name = "serde_yml"]
#![crate_type = "lib"]

// Re-export commonly used items from other modules
pub use crate::de::{from_reader, from_slice, from_str, Deserializer}; // Deserialization functions
pub use crate::modules::error::{Error, Location, Result}; // Error handling types
pub use crate::ser::{to_string, to_writer, Serializer, State}; // Serialization functions
#[doc(inline)]
pub use crate::value::{
    from_value, to_value, Index, Number, Sequence, Value,
}; // Value manipulation functions

#[doc(inline)]
pub use crate::mapping::Mapping; // Re-export the Mapping type for YAML mappings

/// The `de` module contains the library's YAML deserializer.
pub mod de;

/// The `libyml` module contains the library's YAML parser and emitter.
pub mod libyml;

/// The `loader` module contains the `Loader` type for YAML loading.
pub mod loader;

/// The `mapping` module contains the `Mapping` type for YAML mappings.
pub mod mapping;

/// The `modules` module contains the library's modules.
pub mod modules;

/// The `number` module contains the `Number` type for YAML numbers.
pub mod number;

/// The `ser` module contains the library's YAML serializer.
pub mod ser;

/// The `value` module contains the `Value` type for YAML values.
pub mod value;

/// The `with` module contains the `With` type for YAML values.
pub mod with;

// Prevent downstream code from implementing the Index trait.
mod private {
    pub trait Sealed {}
    impl Sealed for usize {}
    impl Sealed for str {}
    impl Sealed for String {}
    impl Sealed for crate::Value {}
    impl<T> Sealed for &T where T: ?Sized + Sealed {}
}
