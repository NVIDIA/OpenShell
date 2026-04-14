// Import necessary modules from the serde_yml crate.
use serde_yml::{
    de::Progress, loader::Loader, modules::error::ErrorImpl,
};

/// Example demonstrating the usage of Serde YML's `Loader` for YAML deserialization.
pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/loader/unknown_anchor.rs");

    // YAML input string with an unknown anchor
    let input = "*unknown";

    // Create a progress indicator for the loader using the input string
    let progress = Progress::Str(input);

    // Create a new loader for deserializing YAML data, unwrapping the result
    let mut loader = match Loader::new(progress) {
        Ok(loader) => loader,
        Err(e) => {
            // If there was an error creating the loader, print the error message and exit
            println!("Failed to create loader: ❌ {}", e);
            return;
        }
    };

    // Attempt to retrieve the next YAML document from the loader
    let document = match loader.next_document() {
        Some(document) => document,
        None => {
            // If no document was returned, print an error message and exit
            println!("Failed to load document: ❌ No document found");
            return;
        }
    };

    // Assert that the number of events in the document is as expected
    assert_eq!(document.events.len(), 0);

    // Assert that there is an error in the document
    assert!(document.error.is_some());

    // Assert that there are no anchor_event_map in the document
    assert_eq!(document.anchor_event_map.len(), 0);

    // Retrieve the error from the document
    let error = document.error.unwrap();

    // Assert that the error matches the expected UnknownAnchor variant
    assert!(matches!(*error, ErrorImpl::UnknownAnchor(_)));

    // Print a success message and present the error to the user
    println!("\n✅ Document loaded with expected error: \n\t{}", error);
}
