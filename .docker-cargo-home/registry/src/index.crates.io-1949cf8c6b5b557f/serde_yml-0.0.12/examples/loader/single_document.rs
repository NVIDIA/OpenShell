// Import necessary modules from the serde_yml crate.
use serde_yml::{de::Progress, loader::Loader};

/// Example demonstrating the usage of Serde YML's `Loader` for YAML deserialization.
pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/loader/single_document.rs");

    // Sample YAML input string
    let input = "key: value";

    // Create a progress indicator for the loader using the input string
    let progress = Progress::Str(input);

    // Attempt to create a new loader for deserializing YAML data
    match Loader::new(progress) {
        Ok(mut loader) => {
            // Attempt to retrieve the next YAML document from the loader
            if let Some(document) = loader.next_document() {
                // Assert that the number of events in the document is as expected
                assert_eq!(document.events.len(), 4);

                // Assert that there are no errors in the document
                assert!(document.error.is_none());

                // Assert that there are no anchor_event_map in the document
                assert_eq!(document.anchor_event_map.len(), 0);

                // Print a success message and present the results to the user
                println!("\n✅ Document successfully loaded:");
                for (event, mark) in &document.events {
                    println!("\tEvent: {:?}, Mark: {:?}", event, mark);
                }
            } else {
                // If no document was returned, print an error message
                println!(
                    "Failed to load document: ❌ No document found"
                );
            }
        }
        Err(e) => {
            // If there was an error creating the loader, print the error message
            println!("Failed to create loader: ❌ {}", e);
        }
    }
}
