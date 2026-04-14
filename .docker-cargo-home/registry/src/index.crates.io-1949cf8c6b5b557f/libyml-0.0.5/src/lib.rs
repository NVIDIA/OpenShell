//! # LibYML (a fork of unsafe-libyaml)
//!
//! [![Made With Love][made-with-rust]][10]
//! [![Crates.io][crates-badge]][06]
//! [![lib.rs][libs-badge]][11]
//! [![Docs.rs][docs-badge]][07]
//! [![Codecov][codecov-badge]][08]
//! [![Build Status][build-badge]][09]
//! [![GitHub][github-badge]][05]
//!
//! LibYML is a Rust library for working with YAML data, forked from [unsafe-libyaml][01]. It offers a safe and efficient interface for parsing, emitting, and manipulating YAML data.
//!
//! ## Features
//!
//! - **Serialization and Deserialization**: Easy-to-use APIs for serializing Rust structs and enums to YAML and vice versa.
//! - **Custom Struct and Enum Support**: Seamless serialization and deserialization of custom data types.
//! - **Comprehensive Error Handling**: Detailed error messages and recovery mechanisms.
//! - **Streaming Support**: Efficient processing of large YAML documents.
//! - **Alias and Anchor Support**: Handling of complex YAML structures with references.
//! - **Tag Handling**: Support for custom tags and type-specific serialization.
//! - **Configurable Emitter**: Customizable YAML output generation.
//! - **Extensive Documentation**: Detailed docs and examples for easy onboarding.
//! - **Safety and Efficiency**: Minimized unsafe code with an interface designed to prevent common pitfalls.
//!
//! ## Installation
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! libyml = "0.0.5"
//! ```
//!
//! ## Documentation
//!
//! For full API documentation, please visit [https://doc.libyml.com/libyml/][03] or [https://docs.rs/libyml][07].
//!
//! ## Rust Version Compatibility
//!
//! Compiler support: requires rustc 1.56.0+
//!
//! ## Contributing
//!
//! Contributions are welcome! If you'd like to contribute, please feel free to submit a Pull Request on [GitHub][05].
//!
//! ## Credits and Acknowledgements
//!
//! LibYML is a fork of the work done by [David Tolnay][04] and the maintainers of [unsafe-libyaml][01]. While it has evolved into a separate library, we express our sincere gratitude to them as well as the [libyaml][02] maintainers for their contributions to the Rust and C programming communities.
//!
//! ## License
//!
//! [MIT license](https://opensource.org/license/MIT), same as libyaml.
//!
//! [00]: https://libyml.com
//! [01]: https://github.com/dtolnay/unsafe-libyaml
//! [02]: https://github.com/yaml/libyaml/tree/2c891fc7a770e8ba2fec34fc6b545c672beb37e6
//! [03]: https://doc.libyml.com/libyml/
//! [04]: https://github.com/dtolnay
//! [05]: https://github.com/sebastienrousseau/libyml
//! [06]: https://crates.io/crates/libyml
//! [07]: https://docs.rs/libyml
//! [08]: https://codecov.io/gh/sebastienrousseau/libyml
//! [09]: https://github.com/sebastienrousseau/libyml/actions?query=branch%3Amaster
//! [10]: https://www.rust-lang.org/
//! [11]: https://lib.rs/crates/libyml
//!
//! [build-badge]: https://img.shields.io/github/actions/workflow/status/sebastienrousseau/libyml/release.yml?branch=master&style=for-the-badge&logo=github "Build Status"
//! [codecov-badge]: https://img.shields.io/codecov/c/github/sebastienrousseau/libyml?style=for-the-badge&logo=codecov&token=yc9s578xIk "Code Coverage"
//! [crates-badge]: https://img.shields.io/crates/v/libyml.svg?style=for-the-badge&color=fc8d62&logo=rust "View on Crates.io"
//! [libs-badge]: https://img.shields.io/badge/lib.rs-v0.0.5-orange.svg?style=for-the-badge "View on lib.rs"
//! [docs-badge]: https://img.shields.io/badge/docs.rs-libyml-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs "View Documentation"
//! [github-badge]: https://img.shields.io/badge/github-sebastienrousseau/libyml-8da0cb?style=for-the-badge&labelColor=555555&logo=github "View on GitHub"
//! [made-with-rust]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust 'Made With Rust'
//!

#![no_std]
#![doc(
    html_favicon_url = "https://kura.pro/libyml/images/favicon.ico",
    html_logo_url = "https://kura.pro/libyml/images/logos/libyml.svg",
    html_root_url = "https://docs.rs/libyml"
)]
#![crate_name = "libyml"]
#![crate_type = "lib"]

extern crate alloc;
use core::mem::size_of;

/// Declarations for C library functions used within the LibYML library.
///
/// This module contains the necessary types and constants required for
/// interfacing with C libraries, particularly in the context of memory management
/// and low-level operations within LibYML.
pub mod libc {
    pub use core::ffi::c_void;
    pub use core::primitive::{
        i32 as c_int, i64 as c_long, i8 as c_char, u32 as c_uint,
        u64 as c_ulong, u8 as c_uchar,
    };
}

/// Extern functions and macros for interacting with the underlying libyaml C library.
///
/// This module includes low-level functions for memory allocation, comparison, and
/// movement that bridge Rust and C. It also contains some internal macros for
/// asserting conditions in a way that integrates with the C code.
#[macro_use]
pub mod externs {
    use crate::libc;
    use crate::ops::{die, ForceAdd as _, ForceInto as _};
    use alloc::alloc::{self as rust, Layout};
    use core::mem::MaybeUninit;
    use core::mem::{align_of, size_of};
    use core::ptr;
    use core::slice;

    const HEADER: usize = {
        let need_len = size_of::<usize>();
        (need_len + MALLOC_ALIGN - 1) & !(MALLOC_ALIGN - 1)
    };

    const MALLOC_ALIGN: usize = {
        let int_align = align_of::<libc::c_ulong>();
        let ptr_align = align_of::<usize>();
        if int_align >= ptr_align {
            int_align
        } else {
            ptr_align
        }
    };

    /// Allocates memory.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it directly manipulates raw memory. The caller must ensure that
    /// the allocated memory is properly managed and freed when no longer needed.
    pub unsafe fn malloc(size: libc::c_ulong) -> *mut libc::c_void {
        let size = HEADER.force_add(size.force_into());
        let layout = Layout::from_size_align(size, MALLOC_ALIGN)
            .ok()
            .unwrap_or_else(die);
        let memory = rust::alloc(layout);
        if memory.is_null() {
            return die();
        }
        memory.cast::<usize>().write(size);
        memory.add(HEADER).cast()
    }

    /// Reallocates memory.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it directly manipulates raw memory.
    /// The caller must ensure that the original memory was allocated by `malloc`.
    pub(crate) unsafe fn realloc(
        ptr: *mut libc::c_void,
        new_size: libc::c_ulong,
    ) -> *mut libc::c_void {
        let mut memory = ptr.cast::<u8>().sub(HEADER);
        let size = memory.cast::<usize>().read();
        let layout =
            Layout::from_size_align_unchecked(size, MALLOC_ALIGN);
        let new_size = HEADER.force_add(new_size.force_into());
        memory = rust::realloc(memory, layout, new_size);
        if memory.is_null() {
            return die();
        }
        memory.cast::<usize>().write(new_size);
        memory.add(HEADER).cast()
    }

    /// Frees allocated memory.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it deallocates memory pointed to by `ptr`.
    /// The caller must ensure that `ptr` was previously allocated by `malloc` or `realloc`.
    pub unsafe fn free(ptr: *mut libc::c_void) {
        let memory = ptr.cast::<u8>().sub(HEADER);
        let size = memory.cast::<usize>().read();
        let layout =
            Layout::from_size_align_unchecked(size, MALLOC_ALIGN);
        rust::dealloc(memory, layout);
    }

    /// Compares two memory blocks.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it compares raw memory. The caller must ensure the pointers
    /// and size are correct.
    pub(crate) unsafe fn memcmp(
        lhs: *const libc::c_void,
        rhs: *const libc::c_void,
        count: libc::c_ulong,
    ) -> libc::c_int {
        let lhs =
            slice::from_raw_parts(lhs.cast::<u8>(), count as usize);
        let rhs =
            slice::from_raw_parts(rhs.cast::<u8>(), count as usize);
        lhs.cmp(rhs) as libc::c_int
    }

    /// Copies memory from `src` to `dest`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory areas do not overlap and that the destination is large
    /// enough to hold the data.
    pub(crate) unsafe fn memcpy(
        dest: *mut libc::c_void,
        src: *const libc::c_void,
        count: libc::c_ulong,
    ) -> *mut libc::c_void {
        if dest.is_null() || src.is_null() {
            return die();
        }
        ptr::copy_nonoverlapping(
            src.cast::<MaybeUninit<u8>>(),
            dest.cast::<MaybeUninit<u8>>(),
            count as usize,
        );
        dest
    }

    /// Moves memory from `src` to `dest`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory areas do not overlap or are correctly managed.
    pub unsafe fn memmove(
        dest: *mut libc::c_void,
        src: *const libc::c_void,
        count: libc::c_ulong,
    ) -> *mut libc::c_void {
        if dest.is_null() || src.is_null() {
            return die();
        }
        ptr::copy(
            src.cast::<MaybeUninit<u8>>(),
            dest.cast::<MaybeUninit<u8>>(),
            count as usize,
        );
        dest
    }

    /// Fills memory with a constant byte.
    ///
    /// # Safety
    ///
    /// The caller must ensure the memory is valid and the length is correct.
    pub unsafe fn memset(
        dest: *mut libc::c_void,
        ch: libc::c_int,
        count: libc::c_ulong,
    ) -> *mut libc::c_void {
        ptr::write_bytes(dest.cast::<u8>(), ch as u8, count as usize);
        dest
    }

    /// Compares two strings.
    ///
    /// # Safety
    ///
    /// The caller must ensure the strings are null-terminated and valid.
    pub(crate) unsafe fn strcmp(
        lhs: *const libc::c_char,
        rhs: *const libc::c_char,
    ) -> libc::c_int {
        if lhs.is_null() || rhs.is_null() {
            return die();
        }
        let lhs = slice::from_raw_parts(
            lhs.cast::<u8>(),
            strlen(lhs) as usize,
        );
        let rhs = slice::from_raw_parts(
            rhs.cast::<u8>(),
            strlen(rhs) as usize,
        );
        lhs.cmp(rhs) as libc::c_int
    }

    /// Returns the length of a string.
    ///
    /// # Safety
    ///
    /// The caller must ensure the string is null-terminated and valid.
    pub(crate) unsafe fn strlen(
        str: *const libc::c_char,
    ) -> libc::c_ulong {
        let mut end = str;
        while *end != 0 {
            end = end.add(1);
        }
        end.offset_from(str) as libc::c_ulong
    }

    /// Compares up to `count` characters of two strings.
    ///
    /// # Safety
    ///
    /// The caller must ensure the strings are null-terminated and valid.
    pub(crate) unsafe fn strncmp(
        lhs: *const libc::c_char,
        rhs: *const libc::c_char,
        mut count: libc::c_ulong,
    ) -> libc::c_int {
        if lhs.is_null() || rhs.is_null() {
            return die();
        }
        let mut lhs = lhs.cast::<u8>();
        let mut rhs = rhs.cast::<u8>();
        while count > 0 && *lhs != 0 && *lhs == *rhs {
            lhs = lhs.add(1);
            rhs = rhs.add(1);
            count -= 1;
        }
        if count == 0 {
            0
        } else {
            (*lhs).cmp(&*rhs) as libc::c_int
        }
    }

    /// Macro for asserting conditions.
    ///
    /// This macro is used internally to assert conditions and handle failures.
    macro_rules! __assert {
        (false $(,)?) => {
            $crate::externs::__assert_fail(
                stringify!(false),
                file!(),
                line!(),
            )
        };
        ($assertion:expr $(,)?) => {
            if !$assertion {
                $crate::externs::__assert_fail(
                    stringify!($assertion),
                    file!(),
                    line!(),
                );
            }
        };
    }

    /// Internal function for handling assertion failures.
    ///
    /// # Safety
    ///
    /// This function is called when an assertion fails, and it triggers a panic.
    pub(crate) unsafe fn __assert_fail(
        __assertion: &'static str,
        __file: &'static str,
        __line: u32,
    ) -> ! {
        struct Abort;
        impl Drop for Abort {
            fn drop(&mut self) {
                panic!("arithmetic overflow");
            }
        }
        let _abort_on_panic = Abort;
        panic!(
            "{}:{}: Assertion `{}` failed.",
            __file, __line, __assertion
        );
    }
}

/// Module for formatting utilities.
///
/// This module provides utilities for formatting data,
/// particularly for writing formatted strings to pointers.
mod fmt {
    use crate::yaml::yaml_char_t;
    use core::fmt::{self, Write};
    use core::ptr;

    /// Struct for writing formatted data to a pointer.
    pub(crate) struct WriteToPtr {
        ptr: *mut yaml_char_t,
    }

    impl WriteToPtr {
        /// Creates a new `WriteToPtr`.
        ///
        /// # Safety
        ///
        /// This function is unsafe because it directly manipulates raw pointers.
        pub(crate) unsafe fn new(ptr: *mut yaml_char_t) -> Self {
            WriteToPtr { ptr }
        }

        /// Writes formatted data to the pointer.
        pub(crate) fn write_fmt(&mut self, args: fmt::Arguments<'_>) {
            let _ = Write::write_fmt(self, args);
        }
    }

    impl Write for WriteToPtr {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            unsafe {
                ptr::copy_nonoverlapping(s.as_ptr(), self.ptr, s.len());
                self.ptr = self.ptr.add(s.len());
            }
            Ok(())
        }
    }
}

/// Trait extension for pointers.
///
/// This trait provides methods for working with pointers,
/// particularly for calculating the offset between two pointers.
trait PointerExt: Sized {
    fn c_offset_from(self, origin: Self) -> isize;
}

impl<T> PointerExt for *const T {
    fn c_offset_from(self, origin: *const T) -> isize {
        (self as isize - origin as isize) / size_of::<T>() as isize
    }
}

impl<T> PointerExt for *mut T {
    fn c_offset_from(self, origin: *mut T) -> isize {
        (self as isize - origin as isize) / size_of::<T>() as isize
    }
}

/// Macros module for LibYML.
///
/// This module contains various macros used throughout the LibYML library.
#[macro_use]
pub mod macros;

/// Utility functions for LibYML.
///
/// This module contains utility functions and macros that are used throughout the LibYML library.
#[macro_use]
pub mod utils;

/// API module for LibYML.
///
/// This module provides the public API functions for working with YAML data.
pub mod api;

/// String utilities for LibYML.
///
/// This module provides utilities for working with YAML strings.
pub mod string;

/// Dumper module for LibYML.
///
/// This module contains functions related to dumping YAML data.
pub mod dumper;

/// Emitter module for LibYML.
///
/// This module provides functions for emitting YAML data.
mod emitter;

/// Loader module for LibYML.
///
/// This module contains functions for loading YAML data.
pub mod loader;

/// Decode module for LibYML.
///
/// This module contains functions for decoding YAML data.
pub mod decode;

/// Document module for LibYML.
///
/// This module provides functions for working with YAML documents.
pub mod document;

/// Internal utilities for LibYML.
///
/// This module contains internal utility functions and structures for the library.
pub mod internal;

/// Memory management for LibYML.
///
/// This module provides functions for managing memory within the library.
pub mod memory;

mod ops;
mod parser;
mod reader;
mod scanner;

/// Success and Failure types for LibYML.
///
/// This module provides types for representing the success and failure of various operations within the library.
pub mod success;

mod writer;

/// YAML API module for LibYML.
///
/// This module provides functions and types for working directly with YAML data structures.
pub mod yaml;

pub use crate::api::{
    yaml_alias_event_initialize, yaml_emitter_delete,
    yaml_emitter_initialize, yaml_emitter_set_break,
    yaml_emitter_set_canonical, yaml_emitter_set_encoding,
    yaml_emitter_set_indent, yaml_emitter_set_output,
    yaml_emitter_set_output_string, yaml_emitter_set_unicode,
    yaml_emitter_set_width, yaml_event_delete,
    yaml_mapping_end_event_initialize,
    yaml_mapping_start_event_initialize, yaml_parser_set_encoding,
    yaml_parser_set_input, yaml_parser_set_input_string,
    yaml_scalar_event_initialize, yaml_sequence_end_event_initialize,
    yaml_sequence_start_event_initialize,
    yaml_stream_end_event_initialize,
    yaml_stream_start_event_initialize, yaml_token_delete,
};
pub use crate::decode::{yaml_parser_delete, yaml_parser_initialize};
pub use crate::document::{
    yaml_document_delete, yaml_document_get_node,
    yaml_document_get_root_node, yaml_document_initialize,
};
pub use crate::dumper::{
    yaml_emitter_close, yaml_emitter_dump, yaml_emitter_open,
};
pub use crate::emitter::yaml_emitter_emit;
pub use crate::loader::yaml_parser_load;
pub use crate::parser::yaml_parser_parse;
pub use crate::scanner::yaml_parser_scan;
pub use crate::writer::yaml_emitter_flush;
pub use crate::yaml::{
    YamlAliasDataT, YamlBreakT, YamlDocumentT, YamlEmitterStateT,
    YamlEmitterT, YamlEncodingT, YamlErrorTypeT, YamlEventT,
    YamlEventTypeT, YamlMappingStyleT, YamlMarkT, YamlNodeItemT,
    YamlNodePairT, YamlNodeT, YamlNodeTypeT, YamlParserStateT,
    YamlParserT, YamlReadHandlerT, YamlScalarStyleT,
    YamlSequenceStyleT, YamlSimpleKeyT, YamlStackT, YamlTagDirectiveT,
    YamlTokenT, YamlTokenTypeT, YamlVersionDirectiveT,
    YamlWriteHandlerT,
};
#[doc(hidden)]
pub use crate::yaml::{
    YamlBreakT::*, YamlEmitterStateT::*, YamlEncodingT::*,
    YamlErrorTypeT::*, YamlEventTypeT::*, YamlMappingStyleT::*,
    YamlNodeTypeT::*, YamlParserStateT::*, YamlScalarStyleT::*,
    YamlSequenceStyleT::*, YamlTokenTypeT::*,
};
