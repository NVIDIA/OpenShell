/// This module contains the `de` examples.
pub(crate) mod de_examples;

/// This module contains the `index` examples.
pub(crate) mod index_examples;

/// The main function that runs all the example modules.
pub(crate) fn main() {
    // Run the example module `de_examples`.
    de_examples::main();

    // Run the example module `index_examples`.
    index_examples::main();
}
