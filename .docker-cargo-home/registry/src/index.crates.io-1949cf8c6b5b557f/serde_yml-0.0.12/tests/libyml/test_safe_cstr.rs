#[cfg(test)]
mod tests {
    use serde_yml::libyml::safe_cstr::{CStr, CStrError};
    use std::{ffi::CString, ptr::NonNull, sync::Arc, thread};

    /// Tests creating a `CStr` from a static byte slice with a null terminator.
    /// Verifies that the `CStr` is created successfully.
    #[test]
    fn test_from_bytes_with_nul() {
        let bytes: &'static [u8] = b"hello\0";
        let cstr = CStr::from_bytes_with_nul(bytes);
        assert!(cstr.is_ok());
        let cstr = cstr.unwrap();
        assert_eq!(cstr.to_bytes(), b"hello");
    }

    /// Tests creating a `CStr` from a static byte slice without a null terminator.
    /// Verifies that an error is returned.
    #[test]
    fn test_from_bytes_without_nul() {
        let bytes: &'static [u8] = b"hello";
        let cstr = CStr::from_bytes_with_nul(bytes);
        assert!(cstr.is_err());
    }

    /// Tests creating a `CStr` from an empty byte slice.
    /// Verifies that an error is returned.
    #[test]
    fn test_from_bytes_empty() {
        let bytes: &'static [u8] = b"";
        let cstr = CStr::from_bytes_with_nul(bytes);
        assert!(cstr.is_err());
    }

    /// Tests creating a `CStr` from a byte slice with only a null terminator.
    /// Verifies that the `CStr` is created successfully and is empty.
    #[test]
    fn test_from_bytes_with_only_nul() {
        let bytes: &'static [u8] = b"\0";
        let cstr = CStr::from_bytes_with_nul(bytes);
        assert!(cstr.is_ok());
        let cstr = cstr.unwrap();
        assert!(cstr.is_empty());
    }

    /// Tests creating a `CStr` from a byte slice with one character and a null terminator.
    /// Verifies that the `CStr` is created successfully and has the correct length.
    #[test]
    fn test_from_bytes_with_one_char() {
        let bytes: &'static [u8] = b"a\0";
        let cstr = CStr::from_bytes_with_nul(bytes);
        assert!(cstr.is_ok());
        let cstr = cstr.unwrap();
        assert_eq!(cstr.to_bytes(), b"a");
    }

    /// Tests creating a `CStr` from a non-null pointer.
    /// Verifies that the `CStr` is created successfully.
    #[test]
    fn test_from_ptr() {
        let c_string = CString::new("hello").unwrap();
        let ptr = NonNull::new(c_string.into_raw()).unwrap();
        let cstr = CStr::from_ptr(ptr);
        assert_eq!(cstr.to_bytes(), b"hello");
    }

    /// Tests calculating the length of the `CStr`.
    /// Verifies that the length is correct.
    #[test]
    fn test_len() {
        let bytes: &'static [u8] = b"hello\0";
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        assert_eq!(cstr.len(), 5);
    }

    /// Tests checking if the `CStr` is empty.
    /// Verifies that the correct result is returned.
    #[test]
    fn test_is_empty() {
        let bytes: &'static [u8] = b"\0";
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        assert!(cstr.is_empty());
    }

    /// Tests retrieving the underlying byte slice of the `CStr`.
    /// Verifies that the byte slice is correct.
    #[test]
    fn test_to_bytes() {
        let bytes: &'static [u8] = b"hello\0";
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        assert_eq!(cstr.to_bytes(), b"hello");
    }

    /// Tests the `Display` implementation for `CStr`.
    /// Verifies that the formatted string is correct.
    #[test]
    fn test_display() {
        let bytes: &'static [u8] = b"hello\0";
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        let display = format!("{}", cstr);
        assert_eq!(display, "hello");
    }

    /// Tests the `Debug` implementation for `CStr`.
    /// Verifies that the debug representation is correct.
    #[test]
    fn test_debug() {
        let bytes: &'static [u8] = b"hello\0";
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        let debug = format!("{:?}", cstr);
        assert_eq!(debug, "\"hello\"");
    }

    /// Tests the `Display` implementation for `CStr` with invalid UTF-8.
    /// Verifies that the formatted string uses replacement characters.
    #[test]
    fn test_display_invalid_utf8() {
        let bytes: &'static [u8] = b"hello\xFFworld\0";
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        let display = format!("{}", cstr);
        assert_eq!(display, "hello�world");
    }

    /// Tests the `Debug` implementation for `CStr` with invalid UTF-8.
    /// Verifies that the debug representation uses escape sequences.
    #[test]
    fn test_debug_invalid_utf8() {
        let bytes: &'static [u8] = b"hello\xFFworld\0";
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        let debug = format!("{:?}", cstr);
        assert_eq!(debug, "\"hello\\xffworld\"");
    }

    /// Tests thread safety of `CStr` struct by sending it between threads.
    #[test]
    fn test_send_sync() {
        let cstr = CStr::from_bytes_with_nul(b"hello\0").unwrap();
        let arc_cstr = Arc::new(cstr);

        let arc_clone = Arc::clone(&arc_cstr);
        let handle = thread::spawn(move || {
            assert_eq!(arc_clone.to_bytes(), b"hello");
        });

        handle.join().unwrap();
    }

    /// Tests proper handling of null pointers.
    /// Verifies that creating a `CStr` from a null pointer is not allowed.
    #[test]
    fn test_null_pointer() {
        let ptr = NonNull::new(std::ptr::null_mut::<i8>());
        assert!(ptr.is_none());
    }

    /// Tests that allocated resources are properly released.
    #[test]
    fn test_resource_release() {
        let c_string = CString::new("hello").unwrap();
        let raw = c_string.into_raw();
        unsafe {
            let _ = CString::from_raw(raw);
        }
    }

    /// Tests the custom `CStrError` error type.
    /// Verifies that the error message is correct.
    #[test]
    fn test_cstr_error() {
        let error = CStrError;
        assert_eq!(format!("{}", error), "CStr error occurred");
    }

    /// Tests the `to_bytes` method with a complex byte array.
    /// Verifies that the byte slice is correct.
    #[test]
    fn test_to_bytes_complex() {
        let bytes: &'static [u8] = b"hello\xFFworld\0";
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        assert_eq!(cstr.to_bytes(), b"hello\xFFworld");
    }

    /// Tests the `to_bytes` method with an empty byte array.
    /// Verifies that the byte slice is correct.
    #[test]
    fn test_to_bytes_empty() {
        let bytes: &'static [u8] = b"\0";
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        assert_eq!(cstr.to_bytes(), b"");
    }

    /// Tests the `to_bytes` method with a byte array containing a single character.
    /// Verifies that the byte slice is correct.
    #[test]
    fn test_to_bytes_single_char() {
        let bytes: &'static [u8] = b"a\0";
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        assert_eq!(cstr.to_bytes(), b"a");
    }

    /// Tests the `to_bytes` method with a byte array containing a single character and a null terminator.
    /// Verifies that the byte slice is correct.
    #[test]
    fn test_to_bytes_single_char_with_nul() {
        let bytes: &'static [u8] = b"a\0";
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        assert_eq!(cstr.to_bytes(), b"a");
    }

    /// Tests the `to_bytes` method with a byte array containing a single null terminator.
    /// Verifies that the byte slice is correct.
    #[test]
    fn test_to_bytes_single_nul() {
        let bytes: &'static [u8] = b"\0";
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        assert_eq!(cstr.to_bytes(), b"");
    }

    /// Tests the `to_bytes` method with a very long byte array.
    /// Verifies that the byte slice is correct.
    #[test]
    fn test_to_bytes_long_string() {
        const LONG_STRING_SIZE: usize = 10_000;
        let mut long_string = Vec::with_capacity(LONG_STRING_SIZE + 1);
        long_string
            .extend(std::iter::repeat(b'a').take(LONG_STRING_SIZE));
        long_string.push(b'\0');
        let bytes = Box::leak(long_string.into_boxed_slice());

        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        assert_eq!(cstr.to_bytes().len(), LONG_STRING_SIZE);
    }

    /// Tests the `to_bytes` method with Unicode characters.
    /// Verifies that the byte slice is correct.
    #[test]
    fn test_to_bytes_unicode() {
        let bytes: &'static [u8] = "hello🌍\0".as_bytes();
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        assert_eq!(cstr.to_bytes(), "hello🌍".as_bytes());
    }

    /// Tests the `to_bytes` method with multiple null terminators within the byte array.
    /// Verifies that the byte slice is correct up to the first null terminator.
    #[test]
    fn test_to_bytes_multiple_nulls() {
        let bytes: &'static [u8] = b"hello\0world\0";
        let cstr = CStr::from_bytes_with_nul(bytes).unwrap();
        assert_eq!(cstr.to_bytes(), b"hello");
    }
}
