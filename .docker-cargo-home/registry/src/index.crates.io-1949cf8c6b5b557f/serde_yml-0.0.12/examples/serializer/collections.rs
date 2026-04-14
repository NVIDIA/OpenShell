//!
//! Example for serializing collections with the YAML serializer.
//!
//! This example demonstrates how to serialize various collection types (Vec,
//! HashMap) into YAML format using the `Serializer` provided by the `serde_yml`
//! crate.
//!

use serde_yml::{to_string, Result};
use std::collections::HashMap;

pub(crate) fn main() -> Result<()> {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/serializer/collections.rs");

    let numbers = vec![1, 2, 3, 4, 5];
    let yaml = to_string(&numbers)?;
    println!("\n✅ Vec serialized to YAML:\n{}", yaml);

    let mut map = HashMap::new();
    map.insert("key1", "value1");
    map.insert("key2", "value2");
    map.insert("key3", "value3");

    let yaml = to_string(&map)?;
    println!("\n✅ HashMap serialized to YAML:\n{}", yaml);

    Ok(())
}
