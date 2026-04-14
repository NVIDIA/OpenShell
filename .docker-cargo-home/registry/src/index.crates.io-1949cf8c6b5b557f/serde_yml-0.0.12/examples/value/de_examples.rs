//! This file demonstrates the deserialization of various data structures such as empty tuples,
//! empty tuple structs, newtype variants, sequences, maps, option types, and enums with multiple variants using `serde_yml`.

use serde::Deserialize;
use serde_yml::Value;

pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/de_examples.rs");

    // Example: Deserializing an empty tuple struct.
    fn example_deserialize_empty_tuple_struct() {
        let yaml_str = "---";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();

        #[derive(Deserialize, PartialEq, Debug)]
        struct Empty;

        let result: Empty = serde_yml::from_value(value).unwrap();
        println!("\n✅ Deserialized Empty tuple struct: {:?}", result);
    }

    // Example: Deserializing an empty tuple.
    fn example_deserialize_empty_tuple() {
        let yaml_str = "---";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();

        let result: () = serde_yml::from_value(value).unwrap();
        println!("\n✅ Deserialized Empty tuple: {:?}", result);
    }

    // Example: Deserializing a newtype variant.
    fn example_deserialize_newtype_variant() {
        let yaml_str = "!Variant 0";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();

        #[derive(Deserialize, PartialEq, Debug)]
        enum E {
            Variant(i32),
        }

        let result: E = serde_yml::from_value(value).unwrap();
        println!("\n✅ Deserialized newtype variant: {:?}", result);
    }

    // Example: Deserializing a struct with multiple fields.
    fn example_deserialize_struct_with_fields() {
        let yaml_str = "
name: \"John Doe\"
age: 30
";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();

        #[derive(Deserialize, PartialEq, Debug)]
        struct Person {
            name: String,
            age: i32,
        }

        let result: Person = serde_yml::from_value(value).unwrap();
        println!("\n✅ Deserialized struct with fields: {:?}", result);
    }

    // Example: Deserializing a sequence (Vec).
    fn example_deserialize_sequence() {
        let yaml_str = "
- 1
- 2
- 3
";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();

        let result: Vec<i32> = serde_yml::from_value(value).unwrap();
        println!("\n✅ Deserialized sequence: {:?}", result);
    }

    // Example: Deserializing a map (HashMap).
    fn example_deserialize_map() {
        use std::collections::HashMap;
        let yaml_str = "
key1: value1
key2: value2
";
        let value: Value = serde_yml::from_str(yaml_str).unwrap();

        let result: HashMap<String, String> =
            serde_yml::from_value(value).unwrap();
        println!("\n✅ Deserialized map: {:?}", result);
    }

    // Example: Deserializing an option type.
    fn example_deserialize_option() {
        let yaml_str_some = "some_value";
        let value_some: Value =
            serde_yml::from_str(yaml_str_some).unwrap();
        let result_some: Option<String> =
            serde_yml::from_value(value_some).unwrap();
        println!("\n✅ Deserialized option (Some): {:?}", result_some);

        let yaml_str_none = "---";
        let value_none: Value =
            serde_yml::from_str(yaml_str_none).unwrap();
        let result_none: Option<String> =
            serde_yml::from_value(value_none).unwrap();
        println!("\n✅ Deserialized option (None): {:?}", result_none);
    }
    // Execute the examples
    example_deserialize_empty_tuple_struct();
    example_deserialize_empty_tuple();
    example_deserialize_newtype_variant();
    example_deserialize_struct_with_fields();
    example_deserialize_sequence();
    example_deserialize_map();
    example_deserialize_option();
}
