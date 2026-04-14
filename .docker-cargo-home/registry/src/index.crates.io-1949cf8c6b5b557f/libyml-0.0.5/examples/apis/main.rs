#![allow(missing_docs)]
use core::mem::MaybeUninit;
pub(crate) use core::primitive::u8 as yaml_char_t;
use core::ptr;
use libyml::api::yaml_parser_set_input_string;
use libyml::decode::{yaml_parser_delete, yaml_parser_initialize};
use libyml::memory::{
    yaml_free, yaml_malloc, yaml_realloc, yaml_strdup,
};
use libyml::string::{yaml_string_extend, yaml_string_join};

pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/apis/yaml_parser_delete.rs");

    let mut parser = MaybeUninit::uninit();
    let parser_ptr = parser.as_mut_ptr();

    unsafe {
        let _ = yaml_parser_initialize(parser_ptr);
        println!(
            "✅ Successfully initialized the YAML parser:\n{:#?}",
            parser.assume_init()
        );

        let input = b"key: value\n";
        yaml_parser_set_input_string(
            parser_ptr,
            input.as_ptr(),
            input.len().try_into().unwrap(),
        );
        println!(
            "✅ Successfully set the input string for the YAML parser"
        );

        // Example: yaml_malloc
        let size = 1024;
        let ptr = yaml_malloc(size);
        // Use the allocated memory
        yaml_free(ptr);
        println!("✅ Successfully allocated and freed memory");

        // Example: yaml_realloc
        let size = 1024;
        let ptr = yaml_malloc(size);
        // Reallocate the memory
        let new_size = 2048;
        let new_ptr = yaml_realloc(ptr, new_size);
        // Use the reallocated memory
        yaml_free(new_ptr);
        println!("✅ Successfully reallocated and freed memory");

        // Example: yaml_strdup
        let str = b"Hello, world!\0" as *const yaml_char_t;
        let dup_str = yaml_strdup(str);
        // Use the duplicated string
        yaml_free(dup_str as *mut std::ffi::c_void);
        println!("✅ Successfully duplicated and freed the string");

        // Example: yaml_string_extend
        let mut start = ptr::null_mut::<yaml_char_t>();
        let mut pointer = ptr::null_mut::<yaml_char_t>();
        let mut end = ptr::null_mut::<yaml_char_t>();
        yaml_string_extend(&mut start, &mut pointer, &mut end);
        // Use the extended string buffer
        yaml_free(start as *mut std::ffi::c_void);
        println!(
            "✅ Successfully extended and freed the string buffer"
        );

        // Example: yaml_string_join
        let mut a_start = ptr::null_mut::<yaml_char_t>();
        let mut a_pointer = ptr::null_mut::<yaml_char_t>();
        let mut a_end = ptr::null_mut::<yaml_char_t>();
        let mut b_start = ptr::null_mut::<yaml_char_t>();
        let mut b_pointer = ptr::null_mut::<yaml_char_t>();
        let mut b_end = ptr::null_mut::<yaml_char_t>();
        yaml_string_join(
            &mut a_start,
            &mut a_pointer,
            &mut a_end,
            &mut b_start,
            &mut b_pointer,
            &mut b_end,
        );
        println!("✅ Successfully joined the string buffers");

        // Use the joined string buffer
        yaml_free(a_start as *mut std::ffi::c_void);
        println!("✅ Successfully freed the joined string buffer");

        yaml_parser_delete(parser_ptr);
        println!("✅ Successfully deleted the YAML parser");
    }
}
