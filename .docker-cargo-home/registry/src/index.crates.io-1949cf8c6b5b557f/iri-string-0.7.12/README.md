# iri-string

[![Latest version](https://img.shields.io/crates/v/iri-string.svg)](https://crates.io/crates/iri-string)
[![Documentation](https://docs.rs/iri-string/badge.svg)](https://docs.rs/iri-string)

* Minimum supported Rust version: 1.60

String types for [IRI](https://www.rfc-editor.org/rfc/rfc3987.html)s (Internationalized Resource
Identifiers) and [URI](https://www.rfc-editor.org/rfc/rfc3986.html)s (Uniform Resource Identifiers).

See the [documentation](https://docs.rs/iri-string) for details.

## Features

* `no_std` support.
* String types (both owned and borrowed) for RFC 3986 URIs and RFC 3987 IRIs.
    + Native slice types, so highly operable with `Cow`, `ToOwned`, etc.
    + URIs/IRIs validation.
    + Conversions between URIs and IRIs.
    + Decomposition into components.
* IRI reference resolution algorithm.
* IRI normalization algorithm.
* Masking password part of an IRI (optional and not automatic).
* Percent encoding of user-provided strings.
* IRI builder.
* RFC 6570 URI Template.

### Feature flags

#### Direct
* `alloc` (enabled by default)
    + Enables types and functions which require memory allocation.
    + Requires `std` or `alloc` crate available.
* `std` (enabled by default)
    + Enables all `std` features (such as memory allocations and `std::error::Error` trait).
    + Requires `std` crate available.
    + This automatically enables `alloc` feature.

#### memchr
* `memchr`
    + Enables optimization for internal parsers, using [`memchr`] crate.

[`memchr`]: https://crates.io/crates/memchr

#### serde
* `serde`
    + Implements `Serialize` and `Deserialize` traits for string types.

## CI

CI is running on the main author's private instance of
[Woodpecker CI](https://woodpecker-ci.org/), and CI runs should pass on
`master` and `develop` branches.

While the instance is not public, anyone can run the CI tests if you have (or
they deploy) their own Woodpecker CI instance.

The reason not to use free CI services are:

* Running tests for multiple combinations of feature flags and toolchain
  versions can cause service credits to be consumed very quickly,
* I (the main author) don't like to depend on proprietary services, and
* I'm not using git repository hosting services (including GitHub and GitLab) as
  a primary remote, and don't like to depend on CI runners tied to them even if
  they are free software.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE.txt](LICENSE-APACHE.txt) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT.txt](LICENSE-MIT.txt) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
