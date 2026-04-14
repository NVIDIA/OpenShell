#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use core::ptr;
    use libyml::memory::*;

    /// Tests that `yaml_malloc` successfully allocates memory.
    #[test]
    fn test_yaml_malloc() {
        unsafe {
            let ptr = yaml_malloc(10);
            assert!(!ptr.is_null());
            yaml_free(ptr);
        }
    }

    /// Tests that `yaml_realloc` successfully reallocates memory.
    #[test]
    fn test_yaml_realloc() {
        unsafe {
            let ptr = yaml_malloc(10);
            assert!(!ptr.is_null());

            let new_ptr = yaml_realloc(ptr, 20);
            assert!(!new_ptr.is_null());

            yaml_free(new_ptr);
        }
    }

    /// Tests that `yaml_realloc` behaves correctly when given a null pointer.
    #[test]
    fn test_yaml_realloc_null() {
        unsafe {
            let ptr = yaml_realloc(ptr::null_mut(), 10);
            assert!(!ptr.is_null());
            yaml_free(ptr);
        }
    }

    /// Tests that `yaml_free` successfully frees allocated memory.
    #[test]
    fn test_yaml_free() {
        unsafe {
            let ptr = yaml_malloc(10);
            assert!(!ptr.is_null());
            yaml_free(ptr);
            // We can't really test much after freeing, as using the pointer would be undefined behavior
        }
    }

    /// Tests that `yaml_free` behaves correctly when given a null pointer.
    #[test]
    fn test_yaml_free_null() {
        unsafe {
            // This should not cause any errors
            yaml_free(ptr::null_mut());
        }
    }

    /// Tests that `yaml_strdup` correctly duplicates a string.
    #[test]
    fn test_yaml_strdup() {
        unsafe {
            let original = b"test string\0" as *const u8;

            let duped_ptr = yaml_strdup(original);
            assert!(!duped_ptr.is_null());

            // Compare the strings
            let mut i = 0;
            while *original.add(i) != 0 {
                assert_eq!(*original.add(i), *duped_ptr.add(i));
                i += 1;
            }
            assert_eq!(*duped_ptr.add(i), 0); // Null terminator

            yaml_free(duped_ptr as *mut c_void);
        }
    }

    /// Tests that `yaml_strdup` returns a null pointer when given a null pointer.
    #[test]
    fn test_yaml_strdup_null() {
        unsafe {
            let duped_ptr = yaml_strdup(ptr::null());
            assert!(duped_ptr.is_null());
        }
    }

    /// Tests that `yaml_strdup` correctly duplicates an empty string.
    #[test]
    fn test_yaml_strdup_empty_string() {
        unsafe {
            let original = b"\0" as *const u8;

            let duped_ptr = yaml_strdup(original);
            assert!(!duped_ptr.is_null());

            assert_eq!(*duped_ptr, 0); // Should only contain null terminator

            yaml_free(duped_ptr as *mut c_void);
        }
    }
}
