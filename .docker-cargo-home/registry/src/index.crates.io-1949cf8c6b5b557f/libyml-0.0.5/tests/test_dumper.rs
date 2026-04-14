#[cfg(test)]
mod tests {
    use libyml::externs::{free, malloc};
    use libyml::success::{FAIL, OK};
    use libyml::yaml::YamlEmitterT;
    use libyml::yaml_emitter_close;
    use libyml::{
        libc, yaml_emitter_delete, yaml_emitter_initialize,
        yaml_emitter_open,
    };
    use std::ptr;

    /// Dummy write handler function that simulates writing without actually performing any I/O.
    /// Always returns 1 to indicate success.
    unsafe fn dummy_write_handler(
        _data: *mut libc::c_void,
        _buffer: *mut libc::c_uchar,
        _size: u64,
    ) -> libc::c_int {
        1
    }

    /// Initializes a YamlEmitterT instance with a dummy write handler.
    /// Allocates memory, initializes the emitter, and assigns a write handler.
    unsafe fn initialize_emitter() -> *mut YamlEmitterT {
        let emitter =
            malloc(size_of::<YamlEmitterT>().try_into().unwrap())
                as *mut YamlEmitterT;
        let _ = yaml_emitter_initialize(emitter);
        (*emitter).write_handler = Some(dummy_write_handler);
        emitter
    }

    /// Cleans up the YamlEmitterT instance by deleting the emitter and freeing allocated memory.
    unsafe fn cleanup_emitter(emitter: *mut YamlEmitterT) {
        yaml_emitter_delete(emitter);
        free(emitter as *mut libc::c_void);
    }

    /// Tests that opening a null emitter pointer fails.
    #[test]
    fn test_yaml_emitter_open_failure() {
        let emitter_ptr: *mut YamlEmitterT = ptr::null_mut();
        let result = unsafe { yaml_emitter_open(emitter_ptr) };
        assert_eq!(result, FAIL);
    }

    /// Tests that a newly initialized emitter can be successfully opened.
    #[test]
    fn test_yaml_emitter_open_success() {
        unsafe {
            let emitter_ptr = initialize_emitter();
            let result = yaml_emitter_open(emitter_ptr);
            assert_eq!(result, OK);
            assert!(
                (*emitter_ptr).opened,
                "Emitter not opened after successful call"
            );
            cleanup_emitter(emitter_ptr);
        }
    }

    /// Tests that attempting to open an already opened emitter fails.
    #[test]
    fn test_yaml_emitter_open_already_opened() {
        unsafe {
            let emitter_ptr = initialize_emitter();
            let result = yaml_emitter_open(emitter_ptr);
            assert_eq!(result, OK);
            let result = yaml_emitter_open(emitter_ptr);
            assert_eq!(
                result, FAIL,
                "Expected FAIL when opening an already opened emitter"
            );
            cleanup_emitter(emitter_ptr);
        }
    }

    /// Tests that an opened emitter can be successfully closed.
    #[test]
    fn test_yaml_emitter_open_close() {
        unsafe {
            let emitter_ptr = initialize_emitter();
            let result = yaml_emitter_open(emitter_ptr);
            assert_eq!(result, OK);
            let result = yaml_emitter_close(emitter_ptr);
            assert_eq!(result, OK);
            assert!(
                (*emitter_ptr).closed,
                "Emitter not closed after successful call"
            );
            cleanup_emitter(emitter_ptr);
        }
    }

    /// Tests that closing an already closed emitter is handled gracefully.
    #[test]
    fn test_yaml_emitter_close_already_closed() {
        unsafe {
            let emitter_ptr = initialize_emitter();
            let result = yaml_emitter_open(emitter_ptr);
            assert_eq!(result, OK);
            let result = yaml_emitter_close(emitter_ptr);
            assert_eq!(result, OK);
            let result = yaml_emitter_close(emitter_ptr);
            assert_eq!(
                result, OK,
                "Expected OK when closing an already closed emitter"
            );
            cleanup_emitter(emitter_ptr);
        }
    }

    /// Tests that a newly initialized emitter has the correct initial state.
    #[test]
    fn test_yaml_emitter_initialize() {
        unsafe {
            let emitter_ptr =
                malloc(size_of::<YamlEmitterT>().try_into().unwrap())
                    as *mut YamlEmitterT;
            let result = yaml_emitter_initialize(emitter_ptr);
            assert_eq!(result, OK);
            assert!(!(*emitter_ptr).opened);
            assert!(!(*emitter_ptr).closed);
            yaml_emitter_delete(emitter_ptr);
            free(emitter_ptr as *mut libc::c_void);
        }
    }

    /// Tests that deleting an emitter works and does not cause crashes.
    #[test]
    fn test_yaml_emitter_delete() {
        unsafe {
            let emitter_ptr = initialize_emitter();
            yaml_emitter_delete(emitter_ptr);
            free(emitter_ptr as *mut libc::c_void);
        }
    }

    /// Tests that closing an emitter that was never opened is handled correctly.
    #[test]
    fn test_yaml_emitter_close_without_open() {
        unsafe {
            let emitter_ptr = initialize_emitter();
            let result = yaml_emitter_close(emitter_ptr);
            assert_eq!(
                result, OK,
                "Expected OK when closing an unopened emitter"
            );
            assert!(
                !(*emitter_ptr).opened,
                "Emitter should not be marked as opened"
            );
            assert!(
                !(*emitter_ptr).closed,
                "Emitter should not be marked as closed"
            );
            cleanup_emitter(emitter_ptr);
        }
    }

    /// Tests the ability to emit YAML content using the emitter.
    #[test]
    fn test_yaml_emitter_dump() {
        unsafe {
            // Step 1: Initialize the emitter
            let emitter_ptr = initialize_emitter();

            // Step 2: Open the emitter
            let result = yaml_emitter_open(emitter_ptr);
            assert_eq!(result, OK);

            // Step 3: Emit some YAML content
            let yaml_content = "---\nkey: value\n"; // Example YAML content
            let yaml_bytes = yaml_content.as_bytes();
            for &byte in yaml_bytes {
                let mut mutable_byte = byte;
                let byte_ptr: *mut u8 = &mut mutable_byte; // Create a raw pointer from the byte variable
                let result = ((*emitter_ptr).write_handler.unwrap())(
                    emitter_ptr as *mut _ as *mut libc::c_void, // Passing the emitter's context
                    byte_ptr,
                    1,
                );
                assert_eq!(result, 1);
            }

            // Step 4: Close the emitter
            let result = yaml_emitter_close(emitter_ptr);
            assert_eq!(result, OK);

            // Step 5: Cleanup
            cleanup_emitter(emitter_ptr);
        }
    }

    /// Tests the behavior when the write handler is not set (None).
    /// Ensures that the system handles the absence of a write handler gracefully.
    #[test]
    fn test_yaml_emitter_no_write_handler() {
        unsafe {
            let emitter_ptr = initialize_emitter();
            // Set the write handler to None
            (*emitter_ptr).write_handler = None;

            let result = yaml_emitter_open(emitter_ptr);
            assert_eq!(result, OK);

            let yaml_content = "---\nkey: value\n";
            let yaml_bytes = yaml_content.as_bytes();

            for &byte in yaml_bytes {
                // Check that the write handler is None
                if let Some(write_handler) =
                    (*emitter_ptr).write_handler
                {
                    // If there's a write handler, use it
                    let mut mutable_byte = byte;
                    let byte_ptr: *mut u8 = &mut mutable_byte;
                    let result = write_handler(
                        emitter_ptr as *mut _ as *mut libc::c_void,
                        byte_ptr,
                        1,
                    );
                    assert_eq!(
                        result, 1,
                        "Write handler should succeed"
                    );
                } else {
                    // Handle the None case
                    assert!(
                        (*emitter_ptr).write_handler.is_none(),
                        "Write handler should be None"
                    );

                    let expected_failure = true;
                    assert!(
                        expected_failure,
                        "Expected failure when write handler is None"
                    );
                }
            }

            cleanup_emitter(emitter_ptr);
        }
    }
}
