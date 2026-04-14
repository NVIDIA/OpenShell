//! Examples for the `Path` enum and its usage in the `path` module.
//!
//! This file demonstrates the creation, usage, and formatting of `Path` instances,
//! as well as handling various path scenarios.

use serde_yml::modules::path::Path;

pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/libyml/path_examples.rs");

    // Example: Creating a Path::Root instance
    let path_root = Path::Root;
    println!("\n✅ Created a Path::Root instance: {}", path_root); // Output: .

    // Example: Creating a Path::Seq instance
    let path_seq = Path::Seq {
        parent: &path_root,
        index: 42,
    };
    println!("\n✅ Created a Path::Seq instance: {}", path_seq); // Output: [42]

    // Example: Creating a Path::Map instance
    let path_map = Path::Map {
        parent: &path_root,
        key: "key",
    };
    println!("\n✅ Created a Path::Map instance: {}", path_map); // Output: key

    // Example: Creating a Path::Alias instance
    let path_alias = Path::Alias { parent: &path_root };
    println!("\n✅ Created a Path::Alias instance: {}", path_alias); // Output: (empty string)

    // Example: Creating a Path::Unknown instance
    let path_unknown = Path::Unknown { parent: &path_root };
    println!("\n✅ Created a Path::Unknown instance: {}", path_unknown); // Output: ?

    // Example: Nested paths
    let path_nested = Path::Unknown {
        parent: &Path::Alias {
            parent: &Path::Map {
                parent: &Path::Seq {
                    parent: &path_root,
                    index: 0,
                },
                key: "key",
            },
        },
    };
    println!("\n✅ Created a nested Path instance: {}", path_nested); // Output: [0].key..?

    // Example: Deeply nested paths
    let path_deeply_nested = Path::Unknown {
        parent: &Path::Alias {
            parent: &Path::Map {
                parent: &Path::Seq {
                    parent: &Path::Map {
                        parent: &Path::Seq {
                            parent: &path_root,
                            index: 1,
                        },
                        key: "first",
                    },
                    index: 2,
                },
                key: "second",
            },
        },
    };
    println!(
        "\n✅ Created a deeply nested Path instance: {}",
        path_deeply_nested
    ); // Output: [1].first[2].second..?

    // Example: Path with an empty key in Path::Map
    let path_map_empty_key = Path::Map {
        parent: &path_root,
        key: "",
    };
    println!(
        "\n✅ Created a Path::Map instance with an empty key: {}",
        path_map_empty_key
    ); // Output: (empty string)

    // Example: Path with maximum index in Path::Seq
    let path_seq_max_index = Path::Seq {
        parent: &path_root,
        index: usize::MAX,
    };
    println!(
        "\n✅ Created a Path::Seq instance with max index: {}",
        path_seq_max_index
    ); // Output: [18446744073709551615]

    // Example: Complex nested paths
    let path_complex_nested = Path::Unknown {
        parent: &Path::Alias {
            parent: &Path::Map {
                parent: &Path::Seq {
                    parent: &Path::Map {
                        parent: &Path::Seq {
                            parent: &Path::Map {
                                parent: &path_root,
                                key: "third",
                            },
                            index: 3,
                        },
                        key: "second",
                    },
                    index: 2,
                },
                key: "first",
            },
        },
    };
    println!(
        "\n✅ Created a complex nested Path instance: {}",
        path_complex_nested
    ); // Output: [2].first[3].second.third..?

    // Example: Path with multiple unknowns
    let path_multiple_unknowns = Path::Unknown {
        parent: &Path::Unknown {
            parent: &Path::Unknown { parent: &path_root },
        },
    };
    println!(
        "\n✅ Created a Path instance with multiple unknowns: {}",
        path_multiple_unknowns
    ); // Output: .?.?.?

    // Example: Path with multiple aliases
    let path_multiple_aliases = Path::Alias {
        parent: &Path::Alias {
            parent: &Path::Alias { parent: &path_root },
        },
    };
    println!(
        "\n✅ Created a Path instance with multiple aliases: {}",
        path_multiple_aliases
    ); // Output: ..

    // Example: Path with multiple sequences
    let path_multiple_sequences = Path::Seq {
        parent: &Path::Seq {
            parent: &Path::Seq {
                parent: &path_root,
                index: 1,
            },
            index: 2,
        },
        index: 3,
    };
    println!(
        "\n✅ Created a Path instance with multiple sequences: {}",
        path_multiple_sequences
    ); // Output: \[1\].\[2\].\[3\]

    // Example: Path with multiple maps
    let path_multiple_maps = Path::Map {
        parent: &Path::Map {
            parent: &Path::Map {
                parent: &path_root,
                key: "first",
            },
            key: "second",
        },
        key: "third",
    };
    println!(
        "\n✅ Created a Path instance with multiple maps: {}",
        path_multiple_maps
    ); // Output: first.second.third

    // Example: Path with multiple aliases, sequences, and maps
    let path_multiple_nested = Path::Alias {
        parent: &Path::Seq {
            parent: &Path::Map {
                parent: &Path::Alias { parent: &path_root },
                key: "first",
            },
            index: 2,
        },
    };
    println!(
        "\n✅ Created a Path instance with multiple nested paths: {}",
        path_multiple_nested
    ); // Output: .first.\[2\].

    // Example: Path with multiple unknowns, aliases, sequences, and maps
    let path_multiple_complex = Path::Unknown {
        parent: &Path::Alias {
            parent: &Path::Seq {
                parent: &Path::Map {
                    parent: &Path::Unknown { parent: &path_root },
                    key: "first",
                },
                index: 2,
            },
        },
    };
    println!(
        "\n✅ Created a Path instance with multiple complex paths: {}",
        path_multiple_complex
    ); // Output: ?.first.\[2\]..?

    // Example: Comparing Path instances
    let another_path_seq = Path::Seq {
        parent: &path_root,
        index: 42,
    };
    if path_seq == another_path_seq {
        println!("\n✅ The path_seq is equal to another_path_seq.");
    } else {
        println!("\n❌ The path_seq is not equal to another_path_seq.");
    }

    // Example: Debug representation of Path instances
    println!("\n✅ Debug representation of path_seq: {:?}", path_seq);
}
