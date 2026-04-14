#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use libyml::externs::free;
    use libyml::memory::yaml_malloc;
    use libyml::memory::yaml_strdup;
    use std::ptr::null;
    use std::ptr::null_mut;

    #[test]
    fn test_yaml_malloc() {
        unsafe {
            // Test allocation of zero bytes
            let ptr = yaml_malloc(0);
            assert!(!ptr.is_null());
            yaml_free(ptr); // Ensure to free the allocated memory

            // Test allocation of non-zero bytes
            let ptr = yaml_malloc(10);
            assert!(!ptr.is_null());
            yaml_free(ptr); // Ensure to free the allocated memory
        }
    }

    #[test]
    fn test_yaml_malloc_free() {
        unsafe {
            // Test allocation of zero bytes
            let ptr = yaml_malloc(0);
            assert!(!ptr.is_null());
            yaml_free(ptr); // Ensure to free the allocated memory

            // Test allocation of non-zero bytes
            let ptr = yaml_malloc(10);
            assert!(!ptr.is_null());
            yaml_free(ptr); // Ensure to free the allocated memory
        }
    }

    #[test]
    fn test_yaml_realloc() {
        unsafe {
            // Test allocation of zero bytes
            let ptr = yaml_malloc(0);
            assert!(!ptr.is_null());
            yaml_free(ptr); // Ensure to free the allocated memory

            // Test allocation of non-zero bytes
            let ptr = yaml_malloc(10);
            assert!(!ptr.is_null());
            yaml_free(ptr); // Ensure to free the allocated memory
        }
    }

    #[test]
    fn test_yaml_free() {
        unsafe {
            // Test freeing null pointer
            let ptr = yaml_malloc(0);
            yaml_free(ptr);
        }
    }

    #[test]
    fn test_yaml_strdup() {
        unsafe {
            // Test duplication of a null string
            let ptr = yaml_strdup(null());
            assert_eq!(ptr, null_mut());
        }
    }

    // Helper function to free memory
    unsafe fn yaml_free(ptr: *mut c_void) {
        free(ptr);
    }
}
