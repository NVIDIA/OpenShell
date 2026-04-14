//!
//! Example for using `singleton_map_recursive` to serialize and deserialize a nested enum structure.
//!
//! This example demonstrates the usage of `singleton_map_recursive` to seamlessly serialize and
//! deserialize a nested enum structure where one of the enum variants contains an optional inner
//! enum. The nested enums are serialized and deserialized as single YAML mapping entries with the
//! keys being the enum variant names.
//!

use serde::{Deserialize, Serialize};
use serde_yml::with::singleton_map_recursive;

pub(crate) fn main() {
    println!("\n❯ Executing examples/with/singleton_map_recursive_optional.rs");

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

    let input = NestedStruct {
        field: NestedEnum::Variant2(Some(InnerEnum::Inner2(42))),
    };
    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: NestedStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);
    assert_eq!(input, output);
}
