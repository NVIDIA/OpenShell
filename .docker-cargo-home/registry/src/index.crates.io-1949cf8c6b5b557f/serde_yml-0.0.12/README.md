<!-- markdownlint-disable MD033 MD041 -->

<img src="https://kura.pro/serde_yml/images/logos/serde_yml.svg"
alt="Serde YML logo" width="66" align="right" />

<!-- markdownlint-enable MD033 MD041 -->

# Serde YML (a fork of Serde YAML)

[![Made With Love][made-with-rust]][11] [![Crates.io][crates-badge]][07] [![lib.rs][libs-badge]][12] [![Docs.rs][docs-badge]][08] [![Codecov][codecov-badge]][09] [![Build Status][build-badge]][10] [![GitHub][github-badge]][06]

[Serde YML][00] is a Rust library for using the [Serde][01] serialization framework with data in [YAML][05] file format.

## Features

- Serialization and deserialization of Rust data structures to/from YAML format
- Support for custom structs and enums using Serde's derive macros
- Handling of YAML's `!tag` syntax for representing enum variants
- Direct access to YAML values through the `Value` type and related types like `Mapping` and `Sequence`
- Comprehensive error handling with `Error`, `Location`, and `Result` types
- Serialization to YAML using `to_string` and `to_writer` functions
- Deserialization from YAML using `from_str`, `from_slice`, and `from_reader` functions
- Customizable serialization and deserialization behavior using Serde's `#[serde(with = ...)]` attribute
- Support for serializing/deserializing enums using a YAML map with a single key-value pair through the `singleton_map` module
- Recursive application of `singleton_map` serialization/deserialization to all enums within a data structure using the `singleton_map_recursive` module
- Serialization and deserialization of optional enum fields using the `singleton_map_optional` module
- Handling of nested enum structures with optional inner enums using the `singleton_map_recursive` module
- Customization of serialization and deserialization logic for enums using the `singleton_map_with` module and custom helper functions

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
serde = "1.0"
serde_yml = "0.0.12"
```

## Usage

Here's a quick example on how to use Serde YML to serialize and deserialize a struct to and from YAML:

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Point {
    x: f64,
    y: f64,
}

fn main() -> Result<(), serde_yml::Error> {
    let point = Point { x: 1.0, y: 2.0 };

    // Serialize to YAML
    let yaml = serde_yml::to_string(&point)?;
    assert_eq!(yaml, "x: 1.0\ny: 2.0\n");

    // Deserialize from YAML
    let deserialized_point: Point = serde_yml::from_str(&yaml)?;
    assert_eq!(point, deserialized_point);

    Ok(())
}
```

## Documentation

For full API documentation, please visit [https://doc.libyml.com/serde-yaml/][04] or [https://docs.rs/serde-yaml][08].

## Rust Version Compatibility

Compiler support: requires rustc 1.56.0+

## Examples

Serde YML provides a set of comprehensive examples. You can find them in the
`examples` directory of the project. To run the examples, clone the repository
and execute the following command in your terminal from the project:

```shell
cargo run --example example
```

The examples cover various scenarios, including serializing and deserializing
structs, enums, optional fields, custom structs, and more.

Here are a few notable examples:

### Serializing and Deserializing Structs

```rust
use serde::{Serialize, Deserialize};
use serde_yml;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Point {
    x: f64,
    y: f64,
}

fn main() -> Result<(), serde_yml::Error> {
    let point = Point { x: 1.0, y: 2.0 };

    // Serialize to YAML
    let yaml = serde_yml::to_string(&point)?;
    assert_eq!(yaml, "x: 1.0\ny: 2.0\n");

    // Deserialize from YAML
    let deserialized_point: Point = serde_yml::from_str(&yaml)?;
    assert_eq!(point, deserialized_point);

    Ok(())
}
```

This example demonstrates how to serialize and deserialize a simple struct
`Point` to and from YAML using the `serde_yml` crate.

### Serializing and Deserializing Enums

```rust
use serde::{Serialize, Deserialize};
use serde_yml;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum Shape {
    Rectangle { width: u32, height: u32 },
    Circle { radius: f64 },
    Triangle { base: u32, height: u32 },
}

fn main() -> Result<(), serde_yml::Error> {
    let shapes = vec![
        Shape::Rectangle { width: 10, height: 20 },
        Shape::Circle { radius: 5.0 },
        Shape::Triangle { base: 8, height: 12 },
    ];

    // Serialize to YAML
    let yaml = serde_yml::to_string(&shapes)?;
    println!("Serialized YAML:\n{}", yaml);

    // Deserialize from YAML
    let deserialized_shapes: Vec<Shape> = serde_yml::from_str(&yaml)?;
    assert_eq!(shapes, deserialized_shapes);

    Ok(())
}
```

This example demonstrates how to serialize and deserialize an enum `Shape`
(with struct variants) to and from YAML using the `serde_yml` crate.

### Serializing and Deserializing Optional Fields

```rust
use serde::{Serialize, Deserialize};
use serde_yml;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct User {
    name: String,
    age: Option<u32>,
    #[serde(default)]
    is_active: bool,
}

fn main() -> Result<(), serde_yml::Error> {
    let user = User {
        name: "John".to_string(),
        age: Some(30),
        is_active: true,
    };

    // Serialize to YAML
    let yaml = serde_yml::to_string(&user)?;
    println!("Serialized YAML:\n{}", yaml);

    // Deserialize from YAML
    let deserialized_user: User = serde_yml::from_str(&yaml)?;
    assert_eq!(user, deserialized_user);

    Ok(())
}
```

This example demonstrates how to serialize and deserialize a struct `User` with
an optional field `age` to and from YAML using the `serde_yml` crate.

### Serializing and Deserializing a HashMap

```rust
use std::collections::HashMap;
use serde_yml;

fn main() -> Result<(), serde_yml::Error> {
    let mut map = HashMap::new();
    map.insert("name".to_string(), "John".to_string());
    map.insert("age".to_string(), "30".to_string());

    let yaml = serde_yml::to_string(&map)?;
    println!("Serialized YAML: {}", yaml);

    let deserialized_map: HashMap<String, serde_yml::Value> = serde_yml::from_str(&yaml)?;
    println!("Deserialized map: {:?}", deserialized_map);

    Ok(())
}
```

This example demonstrates how to serialize and deserialize a `HashMap` to and
from YAML using the `serde_yml` crate.

### Serializing and Deserializing Custom Structs

```rust
use serde::{Serialize, Deserialize};
use serde_yml;

#[derive(Serialize, Deserialize, Debug)]
struct Person {
    name: String,
    age: u32,
    city: String,
}

fn main() -> Result<(), serde_yml::Error> {
    let person = Person {
        name: "Alice".to_string(),
        age: 25,
        city: "New York".to_string(),
    };

    let yaml = serde_yml::to_string(&person)?;
    println!("Serialized YAML: {}", yaml);

    let deserialized_person: Person = serde_yml::from_str(&yaml)?;
    println!("Deserialized person: {:?}", deserialized_person);

    Ok(())
}
```

This example demonstrates how to serialize and deserialize a custom struct
`Person` to and from YAML using the `serde_yml` crate.

### Using Serde derive

It can also be used with Serde's derive macros to handle structs and enums
defined in your program.

Structs serialize in the obvious way:

```rust
use serde_derive::{Serialize, Deserialize};
use serde_yml;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Point {
    x: f64,
    y: f64,
}

fn main() -> Result<(), serde_yml::Error> {
    let point = Point { x: 1.0, y: 2.0 };

    let yaml = serde_yml::to_string(&point)?;
    assert_eq!(yaml, "x: 1.0\n'y': 2.0\n");

    let deserialized_point: Point = serde_yml::from_str(&yaml)?;
    assert_eq!(point, deserialized_point);
    Ok(())
}
```

Enums serialize using YAML's `!tag` syntax to identify the variant name.

```rust
use serde_derive::{Serialize, Deserialize};
use serde_yml;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum Enum {
    Unit,
    Newtype(usize),
    Tuple(usize, usize, usize),
    Struct { x: f64, y: f64 },
}

fn main() -> Result<(), serde_yml::Error> {
    let yaml = "
        - !Newtype 1
        - !Tuple [0, 0, 0]
        - !Struct {x: 1.0, y: 2.0}
    ";
    let values: Vec<Enum> = serde_yml::from_str(yaml).unwrap();
    assert_eq!(values[0], Enum::Newtype(1));
    assert_eq!(values[1], Enum::Tuple(0, 0, 0));
    assert_eq!(values[2], Enum::Struct { x: 1.0, y: 2.0 });

    // The last two in YAML's block style instead:
    let yaml = "
        - !Tuple
        - 0
        - 0
        - 0
        - !Struct
        x: 1.0
        'y': 2.0
    ";
    let values: Vec<Enum> = serde_yml::from_str(yaml).unwrap();
    assert_eq!(values[0], Enum::Tuple(0, 0, 0));
    assert_eq!(values[1], Enum::Struct { x: 1.0, y: 2.0 });

    // Variants with no data can be written using !Tag or just the string name.
    let yaml = "
        - Unit  # serialization produces this one
        - !Unit
    ";
    let values: Vec<Enum> = serde_yml::from_str(yaml).unwrap();
    assert_eq!(values[0], Enum::Unit);
    assert_eq!(values[1], Enum::Unit);

    Ok(())
}
```

This example demonstrates how to use Serde's derive macros to automatically
implement the `Serialize` and `Deserialize` traits for a struct `Point`, and
then serialize and deserialize it to and from YAML using the `serde_yml` crate.

### Serializing and Deserializing Enums with Custom Serialization and Deserialization

```rust
use serde::{Deserialize, Serialize};
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use std::fmt;
use serde_yml;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum MyEnum {
    Variant1(String),
    Variant2 { field: i32 },
}

#[derive(PartialEq, Debug)]
struct MyStruct {
    field: MyEnum,
}

// Include custom Serialize and Deserialize implementations for MyStruct here
// ...

fn main() -> Result<(), serde_yml::Error> {
    let input = MyStruct {
        field: MyEnum::Variant2 { field: 42 },
    };

    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: MyStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);

    assert_eq!(input, output);

    Ok(())
}
```

This example demonstrates how to use custom `Serialize` and `Deserialize`
implementations for a struct containing an enum field, and how to leverage
`serde_yml` to serialize and deserialize the struct to and from YAML.

### Serializing and Deserializing Optional Enums

```rust
use serde::{Deserialize, Serialize};
use serde_yml;
use serde_yml::with::singleton_map_optional;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum OptionalEnum {
    Variant1(String),
    Variant2 { field: i32 },
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct OptionalStruct {
    #[serde(with = "singleton_map_optional")]
    field: Option<OptionalEnum>,
}

fn main() -> Result<(), serde_yml::Error> {
    let input = OptionalStruct {
        field: Some(OptionalEnum::Variant2 { field: 42 }),
    };

    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: OptionalStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);

    assert_eq!(input, output);

    Ok(())
}
```

This example demonstrates how to use the `singleton_map_optional`
attribute to serialize and deserialize an `Option<Enum>` field as a single
YAML mapping entry with the key being the enum variant name.

### Serializing and Deserializing Nested Enums

```rust
use serde::{Deserialize, Serialize};
use serde_yml;
use serde_yml::with::singleton_map_recursive;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum NestedEnum {
    Variant1(String),
    Variant2(Option<InnerEnum>),
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum InnerEnum {
    Inner1(i32),
    Inner2(i32),
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct NestedStruct {
    #[serde(with = "singleton_map_recursive")]
    field: NestedEnum,
}

fn main() -> Result<(), serde_yml::Error> {
    let input = NestedStruct {
        field: NestedEnum::Variant2(Some(InnerEnum::Inner2(42))),
    };

    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: NestedStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);

    assert_eq!(input, output);

    Ok(())
}
```

This example demonstrates how to use the `singleton_map_recursive` attribute to
serialize and deserialize a nested enum structure where one of the enum
variants contains an optional inner enum.

### Serializing and Deserializing Enums with `singleton_map_recursive`

```rust
use serde::{Deserialize, Serialize};
use serde_yml;
use serde_yml::with::singleton_map_recursive;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum MyEnum {
    Variant1(String),
    Variant2 { field: i32 },
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct MyStruct {
    #[serde(with = "singleton_map_recursive")]
    field: MyEnum,
}

fn main() -> Result<(), serde_yml::Error> {
    let input = MyStruct {
        field: MyEnum::Variant2 { field: 42 },
    };

    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: MyStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);

    assert_eq!(input, output);

    Ok(())
}
```

This example demonstrates how to use the `singleton_map_recursive` attribute to
serialize and deserialize an enum field as a single YAML mapping entry with the
key being the enum variant name.

### Serializing and Deserializing Enums with `singleton_map_with` and Custom Serialization

```rust
use serde::{Deserialize, Serialize};
use serde_yml;
use serde_yml::with::singleton_map_with;

fn custom_serialize<T, S>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: serde::Serializer,
{
    // Custom serialization logic
    singleton_map_with::serialize(value, serializer)
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum MyEnum {
    Variant1(String),
    Variant2 { field: i32 },
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct MyStruct {
    #[serde(
        serialize_with = "custom_serialize",
        deserialize_with = "singleton_map_with::deserialize"
    )]
    field: MyEnum,
}

fn main() -> Result<(), serde_yml::Error> {
    let input = MyStruct {
        field: MyEnum::Variant2 { field: 42 },
    };
    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: MyStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);
    assert_eq!(input, output);

    Ok(())
}
```

This example demonstrates how to use the `singleton_map_with` attribute in
combination with a custom serialization function (`custom_serialize`) to
serialize and deserialize an enum field (`MyEnum`) within a struct
(`MyStruct`).

The `custom_serialize` function is used for serialization, while the
`singleton_map_with::deserialize` function is used for deserialization. This
allows for additional customization of the serialization process while still
leveraging the singleton_map_with attribute for deserialization.

### Serializing and Deserializing Enums with `singleton_map_with`

```rust
use serde::{Deserialize, Serialize};
use serde_yml;
use serde_yml::with::singleton_map_with;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum MyEnum {
    Variant1(String),
    Variant2 { field: i32 },
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct MyStruct {
    #[serde(with = "singleton_map_with")]
    field: MyEnum,
}

fn main() -> Result<(), serde_yml::Error> {
    let input = MyStruct {
        field: MyEnum::Variant2 { field: 42 },
    };
    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: MyStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);
    assert_eq!(input, output);

    Ok(())
}
```

This example demonstrates how to use the `singleton_map_with` attribute to
serialize and deserialize an enum field (`MyEnum`) within a struct
(`MyStruct`). The `singleton_map_with` attribute allows for additional
customization of the serialization and deserialization process through the use
of helper functions.

## Contributing

Contributions are welcome! Please submit a Pull Request on [GitHub][06].

## Credits and Acknowledgements

Serde YML is a continuation of the excellent work done by [David Tolnay][03] and the maintainers of the [serde-yaml][02] library. While Serde YML has evolved into a separate library, we express our sincere gratitude to them for their contributions to the Rust community.

## License

Licensed under either of the [Apache License](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

[00]: https://serdeyml.com
[01]: https://github.com/serde-rs/serde
[02]: https://github.com/dtolnay/serde-yaml
[03]: https://github.com/dtolnay
[04]: https://doc.libyml.com/serde-yaml/
[05]: https://yaml.org/
[06]: https://github.com/sebastienrousseau/serde_yml
[07]: https://crates.io/crates/serde_yml
[08]: https://docs.rs/serde_yml
[09]: https://codecov.io/gh/sebastienrousseau/serde_yml
[10]: https://github.com/sebastienrousseau/serde-yml/actions?query=branch%3Amaster
[11]: https://www.rust-lang.org/
[12]: https://lib.rs/crates/serde_yml
[build-badge]: https://img.shields.io/github/actions/workflow/status/sebastienrousseau/serde_yml/release.yml?branch=master&style=for-the-badge&logo=github "Build Status"
[codecov-badge]: https://img.shields.io/codecov/c/github/sebastienrousseau/serde_yml?style=for-the-badge&token=Q9KJ6XXL67&logo=codecov "Codecov"
[crates-badge]: https://img.shields.io/crates/v/serde_yml.svg?style=for-the-badge&color=fc8d62&logo=rust "Crates.io"
[libs-badge]: https://img.shields.io/badge/lib.rs-v0.0.12-orange.svg?style=for-the-badge "View on lib.rs"
[docs-badge]: https://img.shields.io/badge/docs.rs-serde__yml-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs "Docs.rs"
[github-badge]: https://img.shields.io/badge/github-sebastienrousseau/serde--yml-8da0cb?style=for-the-badge&labelColor=555555&logo=github "GitHub"
[made-with-rust]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust 'Made With Rust'
