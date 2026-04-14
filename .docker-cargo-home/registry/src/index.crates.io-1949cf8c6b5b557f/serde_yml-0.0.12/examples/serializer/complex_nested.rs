//!
//! Example for serializing complex nested data structures with the YAML serializer.
//!
//! This example demonstrates how the serializer handles complex nested data structures
//! when serializing a struct into YAML format using the `Serializer` provided by the `serde_yml` crate.
//!

use serde::Serialize;
use serde_yml::{to_string, Result};
use std::collections::HashMap;

#[derive(Serialize)]
enum Shape {
    Circle { radius: f64 },
    Rectangle { width: f64, height: f64 },
}

#[derive(Serialize)]
struct Node {
    name: String,
    children: Vec<Node>,
    properties: HashMap<String, String>,
    shape: Shape,
}

pub(crate) fn main() -> Result<()> {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/serializer/complex_nested.rs");

    let root = Node {
        name: "root".to_string(),
        children: vec![
            Node {
                name: "child1".to_string(),
                children: vec![],
                properties: HashMap::new(),
                shape: Shape::Circle { radius: 5.0 },
            },
            Node {
                name: "child2".to_string(),
                children: vec![],
                properties: [("color".to_string(), "blue".to_string())]
                    .iter()
                    .cloned()
                    .collect(),
                shape: Shape::Rectangle {
                    width: 10.0,
                    height: 20.0,
                },
            },
        ],
        properties: HashMap::new(),
        shape: Shape::Circle { radius: 10.0 },
    };

    let yaml = to_string(&root)?;
    println!(
        "\n✅ Complex nested data structure serialized to YAML:\n{}",
        yaml
    );

    Ok(())
}
