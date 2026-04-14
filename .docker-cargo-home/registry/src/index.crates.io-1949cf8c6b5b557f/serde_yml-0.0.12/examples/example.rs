//! # Serde YML Examples
//!
//! This crate contains examples that demonstrate the usage of the Serde YML library.
//!
//! The examples are organized into the following modules:
//!
//! - `loader` - Contains the example modules for the `loader` module.
//! - `with` - Contains the example modules for the `with` module.
//!

/// Contains the example modules for the `loader` module.
mod loader;

/// Contains the example modules for the `modules` module.
mod modules;

/// Contains the example modules for the `serializer` module.
mod serializer;

/// Contains the example modules for the `value` module.
mod value;

/// Examples for the `with` module.
mod with;

/// Examples for the `tag` module.
mod libyml;

/// The main function that runs all the example modules.
///
/// This function is responsible for running all the example modules.
/// It does this by calling the `main` function of each example module.
///
fn main() {
    // Run the example module `loader`.
    loader::main();

    // Run the example module `modules`.
    modules::main();

    // Run the example module `serializer`.
    serializer::main();

    // Run the example module `value`.
    value::main();

    // Run the example module `with`.
    with::main();

    // Run the example module `libyml`.
    libyml::main();
}
