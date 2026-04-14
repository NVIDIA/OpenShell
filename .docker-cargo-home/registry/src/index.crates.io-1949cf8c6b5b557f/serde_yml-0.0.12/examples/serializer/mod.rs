//! Example modules for demonstrating the usage of the YAML serializer.
//!
//! This module contains example modules that demonstrate the usage of the YAML
//! serializer provided by the `serde_yml` crate. Each example module demonstrates
//! a different aspect of the serializer, such as serializing basic types, structs,
//! enums, and collections.
//!

/// This module contains the `basic` example.
pub(crate) mod basic;

/// This module contains the `collections` example.
pub(crate) mod collections;

/// This module contains the `complex_nested` example.
pub(crate) mod complex_nested;

/// This module contains the `custom_serialization.rs` example.
pub(crate) mod custom_serialization;

/// This module contains the `enums` example.
pub(crate) mod enums;

/// This module contains the `error_handling` example.
pub(crate) mod error_handling;

/// This module contains the `optional_and_default` example.
pub(crate) mod optional_and_default;

/// This module contains the `structs` example.
pub(crate) mod structs;

/// The main function that runs all the example modules.
pub(crate) fn main() {
    // Run the example module `basic`.
    basic::main();

    // Run the example module `collections`.
    let _ = collections::main();

    // Run the example module `complex_nested`.
    let _ = complex_nested::main();

    // Run the example module `custom_serialization`.
    let _ = custom_serialization::main();

    // Run the example module `enums`.
    let _ = enums::main();

    // Run the example module `error_handling`.
    let _ = error_handling::main();

    // Run the example module `optional_and_default`.
    let _ = optional_and_default::main();

    // Run the example module `structs`.
    let _ = structs::main();
}
