//! Macros for memory management operations.
//!
//! This module provides a set of macros that wrap the unsafe memory management
//! functions, providing a slightly safer interface while still allowing
//! for low-level memory operations in a no_std environment.

/// Allocates memory using the system's `malloc` function.
///
/// This macro wraps the `yaml_malloc` function, providing a more Rust-like interface.
///
/// # Arguments
///
/// * `size` - The number of bytes to allocate.
///
/// # Returns
///
/// Returns a `*mut T` pointer to the allocated memory, or `None` if the allocation failed.
///
/// # Safety
///
/// While this macro provides a safer interface than direct use of `yaml_malloc`,
/// it is still unsafe because:
/// - It allocates uninitialized memory.
/// - The caller is responsible for properly freeing the allocated memory using `yaml_free!`.
/// - The caller must ensure the allocated memory is properly initialized before use.
///
/// # Examples
///
/// ```
/// use libyml::{yaml_malloc,yaml_free};
///
/// let size = 1024;
/// unsafe {
///     if let Some(ptr) = yaml_malloc!(u8, size) {
///         // Use the allocated memory
///         // ...
///         yaml_free!(ptr);
///     }
/// }
/// ```
#[macro_export]
macro_rules! yaml_malloc {
    ($t:ty, $size:expr) => {{
        let ptr = unsafe { $crate::memory::yaml_malloc($size) };
        if ptr.is_null() {
            None
        } else {
            Some(ptr as *mut $t)
        }
    }};
}

/// Reallocates memory using the system's `realloc` function.
///
/// This macro wraps the `yaml_realloc` function, providing a more Rust-like interface.
///
/// # Arguments
///
/// * `ptr` - A pointer to the memory block to reallocate.
/// * `size` - The new size of the memory block in bytes.
///
/// # Returns
///
/// Returns a `*mut T` pointer to the reallocated memory, or `None` if the reallocation failed.
///
/// # Safety
///
/// While this macro provides a safer interface than direct use of `yaml_realloc`,
/// it is still unsafe because:
/// - It may move the memory to a new location.
/// - The caller must ensure that `ptr` was previously allocated by `yaml_malloc!` or `yaml_realloc!`.
/// - The caller is responsible for properly freeing the reallocated memory using `yaml_free!`.
/// - The contents of the reallocated memory beyond the original size are undefined.
///
/// # Examples
///
/// ```
/// use libyml::{yaml_malloc, yaml_realloc, yaml_free};
///
/// unsafe {
///     let mut size = 1024;
///     if let Some(mut ptr) = yaml_malloc!(u8, size) {
///         // Use the allocated memory
///         // ...
///         size = 2048;
///         if let Some(new_ptr) = yaml_realloc!(ptr, u8, size) {
///             ptr = new_ptr;
///             // Use the reallocated memory
///             // ...
///             yaml_free!(ptr);
///         }
///     }
/// }
/// ```
#[macro_export]
macro_rules! yaml_realloc {
    ($ptr:expr, $t:ty, $size:expr) => {{
        let new_ptr = unsafe {
            $crate::memory::yaml_realloc($ptr as *mut _, $size)
        };
        if new_ptr.is_null() {
            None
        } else {
            Some(new_ptr as *mut $t)
        }
    }};
}

/// Frees memory allocated by `yaml_malloc!` or `yaml_realloc!`.
///
/// This macro wraps the `yaml_free` function, providing a more Rust-like interface.
///
/// # Arguments
///
/// * `ptr` - A pointer to the memory block to free.
///
/// # Safety
///
/// While this macro provides a safer interface than direct use of `yaml_free`,
/// it is still unsafe because:
/// - The caller must ensure that `ptr` was allocated by `yaml_malloc!` or `yaml_realloc!`.
/// - After calling this macro, `ptr` becomes invalid and must not be used.
///
/// # Examples
///
/// ```
/// use libyml::{yaml_malloc, yaml_free};
///
/// unsafe {
///     let size = 1024;
///     if let Some(ptr) = yaml_malloc!(u8, size) {
///         // Use the allocated memory
///         // ...
///         yaml_free!(ptr);
///         // ptr is now invalid and must not be used
///     }
/// }
/// ```
#[macro_export]
macro_rules! yaml_free {
    ($ptr:expr) => {
        unsafe { $crate::memory::yaml_free($ptr as *mut _) }
    };
}

/// Duplicates a string using the system's `malloc` function and manual copy.
///
/// This macro wraps the `yaml_strdup` function, providing a more Rust-like interface.
///
/// # Arguments
///
/// * `str` - A pointer to the null-terminated string to duplicate.
///
/// # Returns
///
/// Returns a `*mut yaml_char_t` pointer to the newly allocated string, or `None` if the allocation failed or the input was null.
///
/// # Safety
///
/// While this macro provides a safer interface than direct use of `yaml_strdup`,
/// it is still unsafe because:
/// - It involves memory allocation and raw pointer manipulation.
/// - The caller must ensure that `str` is a valid, null-terminated string.
/// - The caller is responsible for freeing the returned pointer using `yaml_free!`.
///
/// # Examples
///
/// ```
/// use libyml::yaml::yaml_char_t;
/// use libyml::{yaml_strdup, yaml_free};
///
/// unsafe {
///     let original = b"Hello, world!\0".as_ptr() as *const yaml_char_t;
///     if let Some(copy) = yaml_strdup!(original) {
///         // Use the duplicated string
///         // ...
///         yaml_free!(copy);
///     }
/// }
/// ```
#[macro_export]
macro_rules! yaml_strdup {
    ($str:expr) => {{
        let new_str = unsafe { $crate::memory::yaml_strdup($str) };
        if new_str.is_null() {
            None
        } else {
            Some(new_str)
        }
    }};
}
