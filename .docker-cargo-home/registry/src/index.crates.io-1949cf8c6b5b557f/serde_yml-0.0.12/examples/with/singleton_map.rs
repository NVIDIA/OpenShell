//!
//! Example for the `singleton_map` function in the `with` module.
//!
//! This function is used to serialize a struct field that contains an enum with
//! only one variant into a YAML map with a single key-value pair, where the key
//! is the enum variant name and the value is the inner value of the enum
//! variant.
//!

use serde::{Deserialize, Serialize};
use serde_yml::with::singleton_map;

pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/with/singleton_map.rs");

    // Example 1: Using singleton_map for a single enum field
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum SingleVariantEnum {
        Variant(String),
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct SingleVariantStruct {
        #[serde(with = "singleton_map")]
        field: SingleVariantEnum,
    }

    let input = SingleVariantStruct {
        field: SingleVariantEnum::Variant("value".to_string()),
    };
    let yaml = serde_yml::to_string(&input).unwrap();
    println!("\n✅ Serialized YAML:\n{}", yaml);

    let output: SingleVariantStruct =
        serde_yml::from_str(&yaml).unwrap();
    println!("\n✅ Deserialized YAML:\n{:#?}", output);
    assert_eq!(input, output);
}
