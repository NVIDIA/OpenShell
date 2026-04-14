//! Examples for the `Tag` struct and its methods in the `tag` module.
//!
//! This file demonstrates the creation, usage, and comparison of `Tag` instances,
//! as well as the usage of its various methods.

use serde_yml::libyml::tag::{Tag, TagFormatError};

pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/libyml/tag_examples.rs");

    // Example: Creating a new Tag instance
    let tag_null = Tag::new(Tag::NULL);
    println!(
        "\n✅ Created a new Tag instance for NULL: {:?}",
        tag_null
    );

    // Example: Creating a Tag instance for a custom tag
    let custom_tag = Tag::new("tag:example.org,2024:custom");
    println!(
        "\n✅ Created a new Tag instance for custom tag: {:?}",
        custom_tag
    );

    // Example: Checking if a Tag starts with a prefix
    match custom_tag.starts_with("tag:example.org") {
        Ok(true) => {
            println!("\n✅ The tag starts with the given prefix.")
        }
        Ok(false) => println!(
            "\n✅ The tag does not start with the given prefix."
        ),
        Err(TagFormatError) => {
            println!("\n✅ Error: The prefix is longer than the tag.")
        }
    }

    // Example: Comparing a Tag with a &str
    let comparison_str = "tag:example.org,2024:custom";
    if custom_tag == comparison_str {
        println!("\n✅ The tag is equal to the given string slice.");
    } else {
        println!(
            "\n✅ The tag is not equal to the given string slice."
        );
    }

    // Example: Using Deref to access the underlying byte slice
    let tag_bytes: &[u8] = &custom_tag;
    println!(
        "\n✅ The underlying byte slice of the tag: {:?}",
        tag_bytes
    );

    // Example: Using the Debug implementation
    println!(
        "\n✅ Debug representation of the custom tag: {:?}",
        custom_tag
    );

    // Example: Using Tag constants
    let tag_bool = Tag::new(Tag::BOOL);
    println!(
        "\n✅ Created a new Tag instance for BOOL: {:?}",
        tag_bool
    );
    let tag_int = Tag::new(Tag::INT);
    println!("\n✅ Created a new Tag instance for INT: {:?}", tag_int);
    let tag_float = Tag::new(Tag::FLOAT);
    println!(
        "\n✅ Created a new Tag instance for FLOAT: {:?}",
        tag_float
    );

    // Example: Handling TagFormatError when the prefix is longer than the tag
    match custom_tag.starts_with("tag:example.org,2024:custom:extra") {
        Ok(_) => println!("\n✅ The tag starts with the given prefix."),
        Err(TagFormatError) => {
            println!("\n✅ Error: The prefix is longer than the tag.")
        }
    }

    // Example: Validating a list of YAML tags
    let tags = vec![
        Tag::new("tag:example.org,2024:custom1"),
        Tag::new("tag:example.org,2024:custom2"),
        Tag::new("tag:example.com,2024:other"),
    ];

    for tag in &tags {
        if tag.starts_with("tag:example.org").unwrap_or(false) {
            println!("\n✅ The tag {:?} starts with the prefix 'tag:example.org'", tag);
        } else {
            println!("\n✅ The tag {:?} does not start with the prefix 'tag:example.org'", tag);
        }
    }

    // Example: Comparing tags with different formats
    let another_custom_tag = Tag::new("tag:example.org,2024:custom");
    if custom_tag == another_custom_tag {
        println!("\n✅ The custom_tag is equal to another_custom_tag.");
    } else {
        println!(
            "\n✅ The custom_tag is not equal to another_custom_tag."
        );
    }

    // Example: Filtering tags based on a prefix
    let filtered_tags: Vec<&Tag> = tags
        .iter()
        .filter(|tag| {
            tag.starts_with("tag:example.org").unwrap_or(false)
        })
        .collect();

    println!(
        "\n✅ Filtered tags that start with 'tag:example.org': {:?}",
        filtered_tags
    );

    // Example: Creating a custom function to process tags
    fn print_tag_info(tag: &Tag) {
        println!("\n📌 Tag info: {:?}", tag);
        if tag.starts_with("tag:example.org").unwrap_or(false) {
            println!("✅ This tag starts with 'tag:example.org'");
        } else {
            println!(
                "❌ This tag does not start with 'tag:example.org'"
            );
        }
    }

    let custom_tag = Tag::new("tag:example.org,2024:custom");
    print_tag_info(&custom_tag);

    // Example: Error handling with invalid tags
    let invalid_tag = "invalid:tag";
    match Tag::new(invalid_tag).starts_with("tag:example.org") {
        Ok(_) => println!(
            "\n✅ The invalid_tag starts with the given prefix."
        ),
        Err(TagFormatError) => {
            println!("\n❌ Error: The prefix is longer than the invalid_tag.")
        }
    }

    // Example: Real-world scenario - parsing and validating tags from a YAML document
    let yaml_tags = vec![
        "tag:example.org,2024:custom1",
        "tag:example.org,2024:custom2",
        "tag:example.com,2024:other",
        "invalid:tag",
    ];

    for yaml_tag in yaml_tags {
        let tag = Tag::new(yaml_tag);
        match tag.starts_with("tag:example.org") {
            Ok(true) => println!("\n✅ The tag {:?} is valid and starts with 'tag:example.org'", tag),
            Ok(false) => println!("\n✅ The tag {:?} is valid but does not start with 'tag:example.org'", tag),
            Err(TagFormatError) => println!("\n❌ The tag {:?} is invalid or the prefix is too long", tag),
        }
    }
}
