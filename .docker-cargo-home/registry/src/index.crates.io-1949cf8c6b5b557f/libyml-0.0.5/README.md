<!-- markdownlint-disable MD033 MD041 -->

<img src="https://kura.pro/libyml/images/logos/libyml.svg"
alt="LibYML logo" width="66" align="right" />

<!-- markdownlint-enable MD033 MD041 -->

# LibYML (a fork of unsafe-libyaml)

[![Made With Love][made-with-rust]][10]
[![Crates.io][crates-badge]][06]
[![lib.rs][libs-badge]][11]
[![Docs.rs][docs-badge]][07]
[![Codecov][codecov-badge]][08]
[![Build Status][build-badge]][09]
[![GitHub][github-badge]][05]

LibYML is a Rust library for working with YAML data, forked from [unsafe-libyaml][01]. It offers a safe and efficient interface for parsing, emitting, and manipulating YAML data.

## Features

- **Serialization and Deserialization**: Easy-to-use APIs for serializing Rust structs and enums to YAML and vice versa.
- **Custom Struct and Enum Support**: Seamless serialization and deserialization of custom data types.
- **Comprehensive Error Handling**: Detailed error messages and recovery mechanisms.
- **Streaming Support**: Efficient processing of large YAML documents.
- **Alias and Anchor Support**: Handling of complex YAML structures with references.
- **Tag Handling**: Support for custom tags and type-specific serialization.
- **Configurable Emitter**: Customizable YAML output generation.
- **Extensive Documentation**: Detailed docs and examples for easy onboarding.
- **Safety and Efficiency**: Minimized unsafe code with an interface designed to prevent common pitfalls.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
libyml = "0.0.5"
```

## Usage

Here's a quick example on how to use LibYML to parse a YAML string:

```rust
use core::mem::MaybeUninit;
use libyml::{
    success::is_success,
    yaml_parser_delete,
    yaml_parser_initialize,
    yaml_parser_parse,
    yaml_parser_set_input_string,
    YamlEventT,
    YamlParserT,
};

fn main() {
    unsafe {
        let mut parser = MaybeUninit::<YamlParserT>::uninit();
        if is_success(yaml_parser_initialize(parser.as_mut_ptr())) {
            let mut parser = parser.assume_init();
            let yaml = "{key1: value1, key2: [item1, item2]}";
            yaml_parser_set_input_string(
                &mut parser,
                yaml.as_ptr(),
                yaml.len() as u64,
            );
            let mut event = MaybeUninit::<YamlEventT>::uninit();
            let result = yaml_parser_parse(&mut parser, event.as_mut_ptr());
            if is_success(result) {
                // Process the event here
            } else {
                // Failed to parse YAML
            }
            yaml_parser_delete(&mut parser);
        } else {
            // Failed to initialize parser
        }
    }
}
```

## Documentation

For full API documentation, please visit [https://doc.libyml.com/libyml/][03] or [https://docs.rs/libyml][07].

## Rust Version Compatibility

Compiler support: requires rustc 1.56.0+

## Contributing

Contributions are welcome! If you'd like to contribute, please feel free to submit a Pull Request on [GitHub][05].

## Credits and Acknowledgements

LibYML is a fork of the work done by [David Tolnay][04] and the maintainers of [unsafe-libyaml][01]. While it has evolved into a separate library, we express our sincere gratitude to them as well as the [libyaml][02] maintainers for their contributions to the Rust and C programming communities.

## License

[MIT license](LICENSE-MIT), same as libyaml.

[00]: https://libyml.com
[01]: https://github.com/dtolnay/unsafe-libyaml
[02]: https://github.com/yaml/libyaml/tree/2c891fc7a770e8ba2fec34fc6b545c672beb37e6
[03]: https://doc.libyml.com/libyml/
[04]: https://github.com/dtolnay
[05]: https://github.com/sebastienrousseau/libyml
[06]: https://crates.io/crates/libyml
[07]: https://docs.rs/libyml
[08]: https://codecov.io/gh/sebastienrousseau/libyml
[09]: https://github.com/sebastienrousseau/libyml/actions?query=branch%3Amaster
[10]: https://www.rust-lang.org/
[11]: https://lib.rs/crates/libyml

[build-badge]: https://img.shields.io/github/actions/workflow/status/sebastienrousseau/libyml/release.yml?branch=master&style=for-the-badge&logo=github "Build Status"
[codecov-badge]: https://img.shields.io/codecov/c/github/sebastienrousseau/libyml?style=for-the-badge&logo=codecov&token=yc9s578xIk "Code Coverage"
[crates-badge]: https://img.shields.io/crates/v/libyml.svg?style=for-the-badge&color=fc8d62&logo=rust "View on Crates.io"
[libs-badge]: https://img.shields.io/badge/lib.rs-v0.0.5-orange.svg?style=for-the-badge "View on lib.rs"
[docs-badge]: https://img.shields.io/badge/docs.rs-libyml-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs "View Documentation"
[github-badge]: https://img.shields.io/badge/github-sebastienrousseau/libyml-8da0cb?style=for-the-badge&labelColor=555555&logo=github "View on GitHub"
[made-with-rust]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust 'Made With Rust'
