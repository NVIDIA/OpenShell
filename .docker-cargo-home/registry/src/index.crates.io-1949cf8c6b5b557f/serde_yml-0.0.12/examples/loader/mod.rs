/// This module contains the `single_document` example.
pub(crate) mod single_document;

/// This module contains the `multiple_documents` example.
pub(crate) mod multiple_documents;

/// This module contains the `unknown anchor` example.
pub(crate) mod unknown_anchor;

/// This module contains the `anchors_and_aliases` example.
pub(crate) mod anchors_and_aliases;

/// this module contains the `io_errors` example.
pub(crate) mod io_errors;

/// The main function that runs all the example modules.
pub(crate) fn main() {
    // Run the example module `loader_anchors_and_aliases`.
    anchors_and_aliases::main();

    // Run the example module `loader_io_errors`.
    io_errors::main();

    // Run the example module `loader_multiple_documents`.
    multiple_documents::main();

    // Run the example module `loader_single_document`.
    single_document::main();

    // Run the example module `loader_unknown_anchor`.
    unknown_anchor::main();
}
