//! Examples for the `CStr` struct and its methods in the `safe_cstr` module.
//!
//! This file demonstrates the creation, usage, and comparison of `CStr` instances,
//! as well as the usage of its various methods.

use serde_yml::libyml::safe_cstr::{CStr, CStrError};
use std::ffi::CString;
use std::ptr::NonNull;

pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/libyml/safe_cstr_examples.rs");

    // Example: Creating a new CStr instance from a byte slice with a null terminator
    let bytes: &'static [u8] = b"hello\0";
    match CStr::from_bytes_with_nul(bytes) {
        Ok(cstr) => {
            println!("\n✅ Created a new CStr instance: {:?}", cstr)
        }
        Err(_) => println!("\n❌ Failed to create CStr instance"),
    }

    // Example: Creating a new CStr instance from a byte slice without a null terminator
    let bytes: &'static [u8] = b"hello";
    match CStr::from_bytes_with_nul(bytes) {
        Ok(_) => println!("\n❌ This should not happen"),
        Err(CStrError) => println!("\n✅ Correctly failed to create CStr instance without null terminator"),
    }

    // Example: Creating a new CStr instance from an empty byte slice
    let bytes: &'static [u8] = b"";
    match CStr::from_bytes_with_nul(bytes) {
        Ok(_) => println!("\n❌ This should not happen"),
        Err(CStrError) => println!("\n✅ Correctly failed to create CStr instance from empty byte slice"),
    }

    // Example: Creating a new CStr instance from a byte slice with only a null terminator
    let bytes: &'static [u8] = b"\0";
    match CStr::from_bytes_with_nul(bytes) {
        Ok(cstr) => {
            println!("\n✅ Created an empty CStr instance: {:?}", cstr)
        }
        Err(_) => println!("\n❌ Failed to create CStr instance"),
    }

    // Example: Creating a new CStr instance from a byte slice with one character and a null terminator
    let bytes: &'static [u8] = b"a\0";
    match CStr::from_bytes_with_nul(bytes) {
        Ok(cstr) => println!(
            "\n✅ Created a CStr instance with one character: {:?}",
            cstr
        ),
        Err(_) => println!("\n❌ Failed to create CStr instance"),
    }

    // Example: Creating a new CStr instance from a non-null pointer
    let c_string = CString::new("hello").unwrap();
    let ptr = NonNull::new(c_string.into_raw()).unwrap();
    let cstr = CStr::from_ptr(ptr);
    println!(
        "\n✅ Created a new CStr instance from a pointer: {:?}",
        cstr
    );

    // Example: Calculating the length of the CStr instance
    let bytes: &'static [u8] = b"hello\0";
    let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
    println!("\n✅ Length of the CStr instance: {}", cstr.len());

    // Example: Checking if the CStr instance is empty
    let bytes: &'static [u8] = b"\0";
    let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
    println!("\n✅ Is the CStr instance empty? {}", cstr.is_empty());

    // Example: Retrieving the underlying byte slice of the CStr instance
    let bytes: &'static [u8] = b"hello\0";
    let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
    println!(
        "\n✅ The underlying byte slice of the CStr instance: {:?}",
        cstr.to_bytes()
    );

    // Example: Using the Display implementation for CStr
    let bytes: &'static [u8] = b"hello\0";
    let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
    println!(
        "\n✅ Display representation of the CStr instance: {}",
        cstr
    );

    // Example: Using the Debug implementation for CStr
    let bytes: &'static [u8] = b"hello\0";
    let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
    println!(
        "\n✅ Debug representation of the CStr instance: {:?}",
        cstr
    );

    // Example: Using the Display implementation for CStr with invalid UTF-8
    let bytes: &'static [u8] = b"hello\xFFworld\0";
    let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
    println!("\n✅ Display representation of the CStr instance with invalid UTF-8: {}", cstr);

    // Example: Using the Debug implementation for CStr with invalid UTF-8
    let bytes: &'static [u8] = b"hello\xFFworld\0";
    let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
    println!("\n✅ Debug representation of the CStr instance with invalid UTF-8: {:?}", cstr);

    // Example: Handling the custom CStrError error type
    let error = CStrError;
    println!("\n✅ Custom CStrError message: {}", error);

    // Example: Creating a CStr instance with a very long string
    const LONG_STRING_SIZE: usize = 10_000;
    let mut long_string = Vec::with_capacity(LONG_STRING_SIZE + 1);
    long_string.extend(std::iter::repeat(b'a').take(LONG_STRING_SIZE));
    long_string.push(b'\0');
    let bytes = Box::leak(long_string.into_boxed_slice());
    match CStr::from_bytes_with_nul(bytes) {
        Ok(cstr) => println!("\n✅ Created a CStr instance with a long string: Length = {}", cstr.len()),
        Err(_) => println!("\n❌ Failed to create CStr instance with long string"),
    }

    // Example: Creating a CStr instance with Unicode characters
    let bytes: &'static [u8] = "hello🌍\0".as_bytes();
    match CStr::from_bytes_with_nul(bytes) {
        Ok(cstr) => println!("\n✅ Created a CStr instance with Unicode characters: {:?}", cstr),
        Err(_) => println!("\n❌ Failed to create CStr instance with Unicode characters"),
    }

    // Example: Creating a CStr instance with multiple null terminators
    let bytes: &'static [u8] = b"hello\0world\0";
    match CStr::from_bytes_with_nul(bytes) {
        Ok(cstr) => println!("\n✅ Created a CStr instance with multiple null terminators: {:?}", cstr),
        Err(_) => println!("\n❌ Failed to create CStr instance with multiple null terminators"),
    }
}
