#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use core::ptr;
    use libyml::memory::{yaml_free, yaml_malloc};
    use libyml::string::*;
    use libyml::yaml::yaml_char_t;

    /// Tests that `yaml_string_duplicate` correctly duplicates a non-null string.
    #[test]
    fn test_yaml_string_duplicate() {
        unsafe {
            let original = b"test string\0" as *const u8;
            let duped_ptr = yaml_string_duplicate(original);
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

    /// Tests that `yaml_string_duplicate` returns a null pointer when given a null pointer.
    #[test]
    fn test_yaml_string_duplicate_null() {
        unsafe {
            let duped_ptr = yaml_string_duplicate(ptr::null());
            assert!(duped_ptr.is_null());
        }
    }

    /// Tests that `yaml_string_duplicate` can correctly duplicate an empty string,
    /// ensuring the duplicate is not null and contains only the null terminator.
    #[test]
    fn test_yaml_string_duplicate_empty_string() {
        unsafe {
            let original = b"\0" as *const u8;
            let duped_ptr = yaml_string_duplicate(original);
            assert!(!duped_ptr.is_null());
            assert_eq!(*duped_ptr, 0); // Should only contain null terminator

            yaml_free(duped_ptr as *mut c_void);
        }
    }

    /// Tests that `yaml_string_join` correctly joins two non-empty string buffers,
    /// verifying the content and length of the result.
    #[test]
    fn test_yaml_string_join() {
        unsafe {
            let mut a_start = yaml_malloc(10) as *mut yaml_char_t;
            let mut a_pointer = a_start;
            let mut a_end = a_start.add(10);

            let mut b_start = b"test" as *const u8 as *mut yaml_char_t;
            let mut b_pointer = b_start.add(4);
            let mut b_end = b_start.add(4);

            yaml_string_join(
                &mut a_start,
                &mut a_pointer,
                &mut a_end,
                &mut b_start,
                &mut b_pointer,
                &mut b_end,
            );

            assert_eq!(a_pointer.offset_from(a_start), 4);
            assert_eq!(*a_start, b't');
            assert_eq!(*a_start.add(1), b'e');
            assert_eq!(*a_start.add(2), b's');
            assert_eq!(*a_start.add(3), b't');

            yaml_free(a_start as *mut c_void);
        }
    }

    /// Tests that `yaml_string_join` handles joining with an empty buffer correctly,
    /// ensuring that nothing is copied and pointers remain unchanged.
    #[test]
    fn test_yaml_string_join_empty() {
        unsafe {
            let mut a_start = yaml_malloc(10) as *mut yaml_char_t;
            let mut a_pointer = a_start;
            let mut a_end = a_start.add(10);

            let mut b_start = b"\0" as *const u8 as *mut yaml_char_t;
            let mut b_pointer = b_start;
            let mut b_end = b_start;

            yaml_string_join(
                &mut a_start,
                &mut a_pointer,
                &mut a_end,
                &mut b_start,
                &mut b_pointer,
                &mut b_end,
            );

            assert_eq!(a_pointer.offset_from(a_start), 0); // Nothing should be copied

            yaml_free(a_start as *mut c_void);
        }
    }

    /// Tests that `yaml_string_join` can correctly extend the buffer when the initial buffer
    /// is too small to contain the joined result, ensuring correct reallocation and copying.
    #[test]
    fn test_yaml_string_join_extend() {
        unsafe {
            let mut a_start = yaml_malloc(2) as *mut yaml_char_t;
            let mut a_pointer = a_start;
            let mut a_end = a_start.add(2);

            let mut b_start =
                b"longer string" as *const u8 as *mut yaml_char_t;
            let mut b_pointer = b_start.add(12);
            let mut b_end = b_start.add(12);

            yaml_string_join(
                &mut a_start,
                &mut a_pointer,
                &mut a_end,
                &mut b_start,
                &mut b_pointer,
                &mut b_end,
            );

            assert!(a_pointer.offset_from(a_start) >= 12);
            assert_eq!(*a_start, b'l');
            assert_eq!(*a_start.add(1), b'o');
            assert_eq!(*a_start.add(2), b'n');
            assert_eq!(*a_start.add(3), b'g');

            yaml_free(a_start as *mut c_void);
        }
    }

    /// Verifies that `yaml_string_duplicate` can accurately duplicate a string that fills
    /// the entire buffer, ensuring correct memory allocation and duplication integrity.
    #[test]
    fn test_yaml_string_duplicate_exact_size() {
        unsafe {
            let original = b"exact size\0" as *const u8;
            let duped_ptr = yaml_string_duplicate(original);
            assert!(!duped_ptr.is_null());
            let mut i = 0;
            while *original.add(i) != 0 {
                assert_eq!(*original.add(i), *duped_ptr.add(i));
                i += 1;
            }
            assert_eq!(*duped_ptr.add(i), 0); // Null terminator

            yaml_free(duped_ptr as *mut c_void);
        }
    }

    /// Ensures that `yaml_string_join` properly handles cases where the buffer is exactly
    /// full, confirming that the join operation completes without overflow.
    #[test]
    fn test_yaml_string_join_full_buffer() {
        unsafe {
            let mut a_start = yaml_malloc(4) as *mut yaml_char_t;
            let mut a_pointer = a_start;
            let mut a_end = a_start.add(4);

            let mut b_start = b"full" as *const u8 as *mut yaml_char_t;
            let mut b_pointer = b_start.add(4);
            let mut b_end = b_start.add(4);

            yaml_string_join(
                &mut a_start,
                &mut a_pointer,
                &mut a_end,
                &mut b_start,
                &mut b_pointer,
                &mut b_end,
            );

            assert_eq!(a_pointer.offset_from(a_start), 4);
            assert_eq!(*a_start.add(3), b'l');

            yaml_free(a_start as *mut c_void);
        }
    }

    /// Confirms that `yaml_string_join` can handle near-full buffer conditions effectively,
    /// verifying that the content and pointers are correctly managed without overflow.
    #[test]
    fn test_yaml_string_join_near_full_buffer() {
        unsafe {
            let mut a_start = yaml_malloc(4) as *mut yaml_char_t;
            let mut a_pointer = a_start;
            let mut a_end = a_start.add(4);
            let b_content = b"full\0";
            let mut b_start = b_content.as_ptr() as *mut yaml_char_t;
            let mut b_pointer = b_start.add(4); // Point to the end of the string
            let mut b_end = b_start.add(4);

            yaml_string_join(
                &mut a_start,
                &mut a_pointer,
                &mut a_end,
                &mut b_start,
                &mut b_pointer,
                &mut b_end,
            );

            let offset = a_pointer.offset_from(a_start);

            assert_eq!(
                offset, 4,
                "Expected offset to be 4, but got {}",
                offset
            );
            assert_eq!(
                *a_start.add(3),
                b'l',
                "Expected last character to be 'l', but got {}",
                *a_start.add(3) as char
            );

            // Verify the contents of the buffer
            assert_eq!(*a_start.add(0), b'f');
            assert_eq!(*a_start.add(1), b'u');
            assert_eq!(*a_start.add(2), b'l');
            assert_eq!(*a_start.add(3), b'l');

            yaml_free(a_start as *mut c_void);
        }
    }
}
