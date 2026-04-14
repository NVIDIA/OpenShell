use serde_yml::{de::Progress, loader::Loader};

pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/loader/io_errors.rs");

    let faulty_reader = std::io::Cursor::new(b"---\n- key: value\n");
    let progress = Progress::Read(Box::new(faulty_reader));

    match Loader::new(progress) {
        Ok(_) => println!("\n✅ Loader created successfully"),
        Err(e) => println!("Failed to create loader: {}", e),
    }
}
