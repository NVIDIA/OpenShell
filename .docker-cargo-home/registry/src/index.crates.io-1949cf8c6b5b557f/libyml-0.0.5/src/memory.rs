use crate::{
    externs::{free, malloc, realloc, strlen},
    libc,
    yaml::{size_t, yaml_char_t},
};
use core::{mem::size_of, ptr};
use libc::c_void;

/// Allocate memory using the system's `malloc` function.
///
/// This function allocates `size` bytes of uninitialized memory and returns a pointer to it.
///
/// # Arguments
///
/// * `size` - The number of bytes to allocate.
///
/// # Returns
///
/// Returns a pointer to the allocated memory, or a null pointer if the allocation failed.
///
/// # Safety
///
/// This function is unsafe because:
/// - It directly calls the system's `malloc` function, which is not memory-safe.
/// - The caller must ensure that the allocated memory is properly freed using `yaml_free`.
/// - The caller is responsible for initializing the allocated memory before use.
///
/// # Examples
///
/// ```
/// use libyml::memory::yaml_malloc;
/// use libyml::yaml::size_t;
/// use libyml::memory::yaml_free;
///
/// unsafe {
///     let size: size_t = 1024;
///     let ptr = yaml_malloc(size);
///     if !ptr.is_null() {
///         // Use the allocated memory
///         // ...
///         yaml_free(ptr);
///     }
/// }
/// ```
pub unsafe fn yaml_malloc(size: size_t) -> *mut c_void {
    malloc(size)
}

/// Reallocate memory using the system's `realloc` function.
///
/// This function changes the size of the memory block pointed to by `ptr` to `size` bytes.
///
/// # Arguments
///
/// * `ptr` - A pointer to the memory block to reallocate. If null, this function behaves like `yaml_malloc`.
/// * `size` - The new size of the memory block in bytes.
///
/// # Returns
///
/// Returns a pointer to the reallocated memory, which may be different from `ptr`, or a null pointer if the reallocation failed.
///
/// # Safety
///
/// This function is unsafe because:
/// - It directly calls the system's `realloc` function, which is not memory-safe.
/// - The caller must ensure that `ptr` is either null or was previously allocated by `yaml_malloc` or `yaml_realloc`.
/// - The caller must ensure that the reallocated memory is properly freed using `yaml_free`.
/// - The contents of the reallocated memory beyond the original size are undefined.
///
/// # Note
///
/// If the reallocation fails, the original memory block is left untouched and a null pointer is returned.
///
/// # Examples
///
/// ```
/// use libyml::memory::{yaml_malloc, yaml_realloc, yaml_free};
/// use libyml::yaml::size_t;
///
/// unsafe {
///     let mut size: size_t = 1024;
///     let mut ptr = yaml_malloc(size);
///     if !ptr.is_null() {
///         // Use the allocated memory
///         // ...
///         size = 2048;
///         ptr = yaml_realloc(ptr, size);
///         if !ptr.is_null() {
///             // Use the reallocated memory
///             // ...
///             yaml_free(ptr);
///         }
///     }
/// }
/// ```
pub unsafe fn yaml_realloc(
    ptr: *mut c_void,
    size: size_t,
) -> *mut c_void {
    if !ptr.is_null() {
        realloc(ptr, size)
    } else {
        malloc(size)
    }
}

/// Free memory allocated by `yaml_malloc` or `yaml_realloc`.
///
/// This function deallocates the memory previously allocated by `yaml_malloc` or `yaml_realloc`.
///
/// # Arguments
///
/// * `ptr` - A pointer to the memory block to free. If null, no operation is performed.
///
/// # Safety
///
/// This function is unsafe because:
/// - It directly calls the system's `free` function, which is not memory-safe.
/// - The caller must ensure that `ptr` was allocated by `yaml_malloc` or `yaml_realloc`.
/// - After calling this function, `ptr` becomes invalid and must not be used.
///
/// # Examples
///
/// ```
/// use libyml::memory::{yaml_malloc, yaml_free};
/// use libyml::yaml::size_t;
///
/// unsafe {
///     let size: size_t = 1024;
///     let ptr = yaml_malloc(size);
///     if !ptr.is_null() {
///         // Use the allocated memory
///         // ...
///         yaml_free(ptr);
///         // ptr is now invalid and must not be used
///     }
/// }
/// ```
pub unsafe fn yaml_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        free(ptr);
    }
}

/// Duplicate a string using the system's `malloc` function and manual copy due to type mismatch.
///
/// This function creates a new copy of the input string, allocating new memory for it.
///
/// # Arguments
///
/// * `str` - A pointer to the null-terminated string to duplicate.
///
/// # Returns
///
/// Returns a pointer to the newly allocated string, or a null pointer if the allocation failed or the input was null.
///
/// # Safety
///
/// This function is unsafe because:
/// - It involves memory allocation and raw pointer manipulation.
/// - The caller must ensure that `str` is a valid, null-terminated string.
/// - The caller is responsible for freeing the returned pointer using `yaml_free`.
///
/// # Examples
///
/// ```
/// use libyml::memory::{yaml_strdup, yaml_free};
/// use libyml::yaml::yaml_char_t;
/// use core::ffi::c_void;
///
/// unsafe {
///     // Note: The cast to *const yaml_char_t is necessary because yaml_char_t
///     // might not be the same as u8 on all systems.
///     let original: *const yaml_char_t = b"Hello, world!\0".as_ptr() as *const yaml_char_t;
///     let copy = yaml_strdup(original);
///     if !copy.is_null() {
///         // Use the duplicated string
///         // ...
///         yaml_free(copy as *mut c_void);
///     }
/// }
/// ```
pub unsafe fn yaml_strdup(str: *const yaml_char_t) -> *mut yaml_char_t {
    if str.is_null() {
        return ptr::null_mut();
    }
    let len = strlen(str as *const libc::c_char) as usize;
    let new_size = (len + 1) * size_of::<yaml_char_t>();
    let new_str =
        malloc(new_size.try_into().unwrap()) as *mut yaml_char_t;
    if new_str.is_null() {
        return ptr::null_mut();
    }
    ptr::copy_nonoverlapping(str, new_str, len + 1);
    new_str
}
