//! Examples for the `Index` trait and its implementations in the `index` module.
//!
//! This file demonstrates the usage of the `Index` trait with various implementations,
//! including indexing into sequences and mappings, and handling out-of-bounds and invalid indices.

use serde_yml::value::Index;
use serde_yml::Value;

pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/libyml/index_examples.rs");

    // Example: Indexing into a sequence using usize
    let sequence = Value::Sequence(vec![
        Value::Number(1.into()),
        Value::Number(2.into()),
    ]);
    let index = 1;
    match index.index_into(&sequence) {
        Some(value) => {
            println!("\n✅ Indexed into sequence: {:?}", value)
        }
        None => println!("\n❌ Index out of bounds"),
    }

    // Example: Indexing into a mapping using usize
    let mut mapping = serde_yml::Mapping::new();
    mapping
        .insert(Value::Number(1.into()), Value::String("one".into()));
    let value = Value::Mapping(mapping);
    match index.index_into(&value) {
        Some(value) => {
            println!("\n✅ Indexed into mapping: {:?}", value)
        }
        None => println!("\n❌ Key not found"),
    }

    // Example: Indexing into a sequence with out-of-bounds index using usize
    let index = 3;
    match index.index_into(&sequence) {
        Some(value) => {
            println!("\n✅ Indexed into sequence: {:?}", value)
        }
        None => println!("\n❌ Index out of bounds"),
    }

    // Example: Indexing into a mapping with a non-numeric key using usize
    let mut mapping = serde_yml::Mapping::new();
    mapping.insert(
        Value::String("key".into()),
        Value::String("value".into()),
    );
    let value = Value::Mapping(mapping);
    match index.index_into(&value) {
        Some(value) => {
            println!("\n✅ Indexed into mapping: {:?}", value)
        }
        None => println!("\n❌ Key not found"),
    }

    // Example: Mutably indexing into a sequence using usize
    let mut sequence = Value::Sequence(vec![
        Value::Number(1.into()),
        Value::Number(2.into()),
    ]);
    let index = 1;
    if let Some(value) = index.index_into_mut(&mut sequence) {
        *value = Value::Number(3.into());
        println!("\n✅ Mutably indexed into sequence: {:?}", sequence);
    }

    // Example: Mutably indexing into a mapping using usize
    let mut mapping = serde_yml::Mapping::new();
    mapping
        .insert(Value::Number(1.into()), Value::String("one".into()));
    let mut value = Value::Mapping(mapping);
    if let Some(value) = index.index_into_mut(&mut value) {
        *value = Value::String("two".into());
        println!("\n✅ Mutably indexed into mapping: {:?}", value);
    }

    // Example: Mutably indexing into a sequence with out-of-bounds index using usize
    let index = 3;
    if let Some(value) = index.index_into_mut(&mut sequence) {
        *value = Value::Number(4.into());
    } else {
        println!("\n❌ Index out of bounds");
    }

    // Example: Using index_or_insert with a sequence using usize
    let mut sequence = Value::Sequence(vec![Value::Number(1.into())]);
    let index = 1;
    if index >= sequence.as_sequence().unwrap().len() {
        for _ in sequence.as_sequence().unwrap().len()..=index {
            sequence.as_sequence_mut().unwrap().push(Value::Null);
        }
    }
    index
        .index_or_insert(&mut sequence)
        .clone_from(&Value::Number(2.into()));
    println!("\n✅ Used index_or_insert with sequence: {:?}", sequence);

    // Example: Using index_or_insert with a mapping using usize
    let mapping = serde_yml::Mapping::new();
    let mut value = Value::Mapping(mapping);
    index
        .index_or_insert(&mut value)
        .clone_from(&Value::String("one".into()));
    let mut expected_mapping = serde_yml::Mapping::new();
    expected_mapping
        .insert(Value::Number(1.into()), Value::String("one".into()));
    println!("\n✅ Used index_or_insert with mapping: {:?}", value);

    // Example: Indexing into a non-indexable value
    let value = Value::String("hello".into());
    match index.index_into(&value) {
        Some(value) => println!("\n✅ Indexed into value: {:?}", value),
        None => println!("\n❌ Cannot index into non-indexable value"),
    }

    // Example: Mutably indexing into a non-indexable value
    let mut value = Value::String("hello".into());
    if let Some(value) = index.index_into_mut(&mut value) {
        *value = Value::String("world".into());
        println!("\n✅ Mutably indexed into value: {:?}", value);
    } else {
        println!("\n❌ Cannot index into non-indexable value");
    }

    // Example: Using index_or_insert with a non-indexable value
    let value = Value::String("hello".into());
    let result = std::panic::catch_unwind(move || {
        let mut value_owned = value.clone();
        index.index_or_insert(&mut value_owned);
    });
    match result {
        Ok(_) => println!("\n❌ Should have panicked"),
        Err(_) => {
            println!("\n✅ Correctly panicked for non-indexable value")
        }
    }

    // Example: Using index_or_insert with a null value
    let value = Value::Null;
    let result = std::panic::catch_unwind(move || {
        let mut value_owned = value.clone();
        index.index_or_insert(&mut value_owned);
    });
    match result {
        Ok(_) => println!("\n❌ Should have panicked"),
        Err(_) => println!("\n✅ Correctly panicked for null value"),
    }

    // Example: Indexing into a mapping using &str
    let mut mapping = serde_yml::Mapping::new();
    mapping.insert(
        Value::String("key".into()),
        Value::String("value".into()),
    );
    let value = Value::Mapping(mapping);
    let index = "key";
    match index.index_into(&value) {
        Some(value) => {
            println!("\n✅ Indexed into mapping with &str: {:?}", value)
        }
        None => println!("\n❌ Key not found"),
    }

    // Example: Mutably indexing into a mapping using &str
    let mut mapping = serde_yml::Mapping::new();
    mapping.insert(
        Value::String("key".into()),
        Value::String("value".into()),
    );
    let mut value = Value::Mapping(mapping);
    let index = "key";
    if let Some(value) = index.index_into_mut(&mut value) {
        *value = Value::String("new_value".into());
        println!(
            "\n✅ Mutably indexed into mapping with &str: {:?}",
            value
        );
    }

    // Example: Using index_or_insert with a mapping using &str
    let mut mapping = serde_yml::Mapping::new();
    mapping.insert(
        Value::String("key".into()),
        Value::String("value".into()),
    );
    let mut value = Value::Mapping(mapping);
    let index = "new_key";
    index
        .index_or_insert(&mut value)
        .clone_from(&Value::String("new_value".into()));
    println!(
        "\n✅ Used index_or_insert with mapping and &str: {:?}",
        value
    );

    // Example: Indexing into a nested mapping
    let mut nested_mapping = serde_yml::Mapping::new();
    nested_mapping.insert(
        Value::String("inner_key".into()),
        Value::String("inner_value".into()),
    );
    let mut outer_mapping = serde_yml::Mapping::new();
    outer_mapping.insert(
        Value::String("outer_key".into()),
        Value::Mapping(nested_mapping),
    );
    let value = Value::Mapping(outer_mapping);
    let index = Value::String("outer_key".into());
    if let Some(inner_value) = index
        .index_into(&value)
        .and_then(|v| "inner_key".index_into(v))
    {
        println!("\n✅ Indexed into nested mapping: {:?}", inner_value);
    } else {
        println!("\n❌ Key not found in nested mapping");
    }
}
