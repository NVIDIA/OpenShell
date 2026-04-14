// Import necessary modules from the serde_yml crate.
use serde_yml::{de::Progress, loader::Loader};

// Define the main function.
pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/loader/multiple_documents.rs");

    // Define the YAML input string containing multiple documents.
    let input = "---\nkey1: value1\n...\n---\nkey2: value2\n...";

    // Create a progress indicator for the loader using the input string.
    let progress = Progress::Str(input);

    // Attempt to create a new loader for deserializing YAML data.
    match Loader::new(progress) {
        Ok(mut loader) => {
            // If the loader creation is successful, print a success message.
            println!("\n✅ Loader created successfully");

            // Attempt to load the first document from the loader.
            if let Some(document1) = loader.next_document() {
                // If document loading is successful, print a success message and present the results to the user.
                println!("\n✅ Document 1 successfully loaded:");
                for (event, mark) in &document1.events {
                    println!("\tEvent: {:?}, Mark: {:?}", event, mark);
                }
                println!(); // Add a newline for better formatting
                            // Perform assertions to verify that the loader is working as expected.
                assert_eq!(document1.events.len(), 4);
                assert!(document1.error.is_none());
                assert_eq!(document1.anchor_event_map.len(), 0);
            } else {
                // If document loading fails, print an error message.
                println!("Failed to load document 1");
            }

            // Attempt to load the second document from the loader.
            if let Some(document2) = loader.next_document() {
                // If document loading is successful, print a success message and present the results to the user.
                println!("\n✅ Document 2 successfully loaded:");
                for (event, mark) in &document2.events {
                    println!("\tEvent: {:?}, Mark: {:?}", event, mark);
                }
                println!(); // Add a newline for better formatting
                            // Perform assertions to verify that the loader is working as expected.
                assert_eq!(document2.events.len(), 4);
                assert!(document2.error.is_none());
                assert_eq!(document2.anchor_event_map.len(), 0);
            } else {
                // If document loading fails, print an error message.
                println!("Failed to load document 2");
            }

            // Check if there are more documents in the loader.
            if loader.next_document().is_none() {
                // If no more documents are present, print a success message.
                println!("\n✅ All documents loaded successfully");
            } else {
                // If more documents are present, print an error message.
                println!("Failed to load all documents");
            }
        }
        Err(e) => {
            // If loader creation fails, print an error message.
            println!("Failed to create loader: {}", e);
        }
    }
}
