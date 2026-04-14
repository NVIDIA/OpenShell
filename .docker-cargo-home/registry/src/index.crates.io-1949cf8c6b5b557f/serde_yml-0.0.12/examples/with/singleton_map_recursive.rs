//!
//! Example for the `singleton_map_recursive` function in the `with` module.
//!
//! This function is used to serialize a struct field that contains an enum with
//! only one variant into a YAML map with a single key-value pair, where the key
//! is the enum variant name and the value is the inner value of the enum
//! variant.
//!

// Import necessary crates.
use serde::{Deserialize, Serialize};
use serde_yml::with::singleton_map_recursive;

// Define the main function.
pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/with/singleton_map_recursive.rs");

    // Define an enum with a single variant.
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum SingleVariantEnum {
        Variant(String),
    }

    // Define a nested enum with two variants, one containing the single variant enum.
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum NestedEnum {
        Variant1(String),
        Variant2(SingleVariantEnum),
    }

    // Define a struct containing the nested enum field serialized using the `singleton_map_recursive` function.
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct NestedStruct {
        #[serde(with = "singleton_map_recursive")]
        field: NestedEnum,
    }

    // Create an instance of the NestedStruct with a nested enum variant.
    let input = NestedStruct {
        field: NestedEnum::Variant2(SingleVariantEnum::Variant(
            "nested".to_string(),
        )),
    };

    // Serialize the input struct to YAML format and print it.
    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    // Deserialize the YAML string back to a NestedStruct and print it.
    let output: NestedStruct = serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);

    // Assert that the input and output are equal.
    assert_eq!(input, output);
}
