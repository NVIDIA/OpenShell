// decode.rs
// Manages the decoding of YAML data structures in Rust, handling the lifecycle of YAML parsers.

use crate::{
    libc,
    memory::{yaml_free, yaml_malloc},
    success::{Success, OK},
    yaml::{size_t, yaml_char_t},
    yaml_token_delete, YamlMarkT, YamlParserStateT, YamlParserT,
    YamlSimpleKeyT, YamlTagDirectiveT, YamlTokenT,
};

use crate::externs::memset;
use core::{
    mem::size_of,
    ptr::{self, addr_of_mut},
};

const INPUT_RAW_BUFFER_SIZE: usize = 16384;
const INPUT_BUFFER_SIZE: usize = INPUT_RAW_BUFFER_SIZE * 3;
// const OUTPUT_BUFFER_SIZE: usize = 16384;
// const OUTPUT_RAW_BUFFER_SIZE: usize = OUTPUT_BUFFER_SIZE * 2 + 2;

/// Initialize a parser.
///
/// This function creates a new parser object. An application is responsible
/// for destroying the object using the yaml_parser_delete() function.
///
/// # Safety
///
/// - `parser` must be a valid, non-null pointer to an uninitialized `YamlParserT` struct.
/// - The `YamlParserT` struct must be properly aligned and have the expected memory layout.
/// - The caller is responsible for properly destroying the parser object using `yaml_parser_delete`.
///
pub unsafe fn yaml_parser_initialize(
    parser: *mut YamlParserT,
) -> Success {
    __assert!(!parser.is_null());
    let _ = memset(
        parser as *mut libc::c_void,
        0,
        size_of::<YamlParserT>() as libc::c_ulong,
    );
    BUFFER_INIT!((*parser).raw_buffer, INPUT_RAW_BUFFER_SIZE);
    BUFFER_INIT!((*parser).buffer, INPUT_BUFFER_SIZE);
    QUEUE_INIT!((*parser).tokens, YamlTokenT);
    STACK_INIT!((*parser).indents, libc::c_int);
    STACK_INIT!((*parser).simple_keys, YamlSimpleKeyT);
    STACK_INIT!((*parser).states, YamlParserStateT);
    STACK_INIT!((*parser).marks, YamlMarkT);
    STACK_INIT!((*parser).tag_directives, YamlTagDirectiveT);
    OK
}

/// Destroy a parser.
///
/// This function frees all memory associated with a parser object, including
/// any dynamically allocated buffers, tokens, and other data structures.
///
/// # Safety
///
/// - `parser` must be a valid, non-null pointer to a properly initialized `YamlParserT` struct.
/// - The `YamlParserT` struct and its associated data structures must have been properly initialized and their memory allocated correctly.
/// - The `YamlParserT` struct and its associated data structures must be properly aligned and have the expected memory layout.
/// - After calling this function, the `parser` pointer should be considered invalid and should not be used again.
///
pub unsafe fn yaml_parser_delete(parser: *mut YamlParserT) {
    __assert!(!parser.is_null());
    BUFFER_DEL!((*parser).raw_buffer);
    BUFFER_DEL!((*parser).buffer);
    while !QUEUE_EMPTY!((*parser).tokens) {
        yaml_token_delete(addr_of_mut!(DEQUEUE!((*parser).tokens)));
    }
    QUEUE_DEL!((*parser).tokens);
    STACK_DEL!((*parser).indents);
    STACK_DEL!((*parser).simple_keys);
    STACK_DEL!((*parser).states);
    STACK_DEL!((*parser).marks);
    while !STACK_EMPTY!((*parser).tag_directives) {
        let tag_directive = POP!((*parser).tag_directives);
        yaml_free(tag_directive.handle as *mut libc::c_void);
        yaml_free(tag_directive.prefix as *mut libc::c_void);
    }
    STACK_DEL!((*parser).tag_directives);
    let _ = memset(
        parser as *mut libc::c_void,
        0,
        size_of::<YamlParserT>() as libc::c_ulong,
    );
}
