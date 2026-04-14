//!
//! Example for serializing structs with the YAML serializer.
//!
//! This example demonstrates how to serialize nested structs into YAML format
//! using the `Serializer` provided by the `serde_yml` crate.
//!

use serde::Serialize;
use serde_yml::{to_string, Result};

#[derive(Serialize)]
struct Address {
    street: String,
    city: String,
    country: String,
}

#[derive(Serialize)]
struct User {
    name: String,
    age: u32,
    address: Address,
}

pub(crate) fn main() -> Result<()> {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/serializer/structs.rs");

    let user = User {
        name: "Alice".to_string(),
        age: 25,
        address: Address {
            street: "123 Main St".to_string(),
            city: "Anytown".to_string(),
            country: "USA".to_string(),
        },
    };

    let yaml = to_string(&user)?;
    println!("\n✅ User serialized to YAML:\n{}", yaml);

    Ok(())
}
