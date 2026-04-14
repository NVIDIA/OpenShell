//!
//! Example for serializing enums with the YAML serializer.
//!
//! This example demonstrates how to serialize enums with associated data into
//! YAML format using the `Serializer` provided by the `serde_yml` crate.
//!

use serde::Serialize;
use serde_yml::{to_string, Result};

#[derive(Serialize)]
enum Shape {
    Rectangle { width: u32, height: u32 },
    Circle { radius: f64 },
    Triangle { base: u32, height: u32 },
}

pub(crate) fn main() -> Result<()> {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/serializer/enums.rs");

    let shapes = vec![
        Shape::Rectangle {
            width: 10,
            height: 20,
        },
        Shape::Circle { radius: 5.0 },
        Shape::Triangle {
            base: 8,
            height: 12,
        },
    ];

    let yaml = to_string(&shapes)?;
    println!("\n✅ Shapes serialized to YAML:\n{}", yaml);

    Ok(())
}
