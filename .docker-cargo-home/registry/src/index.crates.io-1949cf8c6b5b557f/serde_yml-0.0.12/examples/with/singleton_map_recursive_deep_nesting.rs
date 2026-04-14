//!
//! Example for the `singleton_map_recursive_deep_nesting` function in the `with` module.
//!
//! This example demonstrates the use of the
//! `singleton_map_recursive_deep_nesting` function to serialize and deserialize
//! a struct field that contains an enum with deeply nested variants into a YAML
//! map with a single key-value pair, where the key is the enum variant name and
//! the value is the inner value of the enum variant.

use serde::{Deserialize, Serialize};
use serde_yml::with::singleton_map_recursive;

pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/with/singleton_map_recursive_deep_nesting.rs");

    // Define an enum with deeply nested enums
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum NestedEnum {
        Variant1(String),
        Variant2(InnerEnum),
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum InnerEnum {
        Inner1(i32),
        Inner2(bool, DeepEnum),
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum DeepEnum {
        Deep1(char),
        Deep2 { field: String },
    }

    // Define a struct containing a field of the deeply nested enum type
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct NestedStruct {
        #[serde(with = "singleton_map_recursive")]
        field: NestedEnum,
    }

    let input = NestedStruct {
        field: NestedEnum::Variant2(InnerEnum::Inner2(
            true,
            DeepEnum::Deep2 {
                field: "nested".to_string(),
            },
        )),
    };

    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: NestedStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);
    assert_eq!(input, output);
}
