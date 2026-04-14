#[cfg(test)]
mod tests {
    use serde_yml::libyml::util::{InitPtr, Owned};
    use std::mem::MaybeUninit;
    use std::ops::Deref;

    /// Tests that a new uninitialized `Owned` instance can be created.
    /// Verifies that the pointer in the `Owned` instance is not null.
    #[test]
    fn test_new_uninit() {
        let uninit_owned: Owned<MaybeUninit<i32>, i32> =
            Owned::new_uninit();
        assert!(!uninit_owned.ptr.is_null());
    }

    /// Tests the `assume_init` function to ensure that it correctly converts
    /// an uninitialized `Owned` instance to an initialized one.
    /// Verifies that the pointer in the initialized `Owned` instance is not null.
    #[test]
    fn test_assume_init() {
        let uninit_owned: Owned<MaybeUninit<i32>, i32> =
            Owned::new_uninit();
        let init_owned: Owned<i32> =
            unsafe { Owned::assume_init(uninit_owned) };
        assert!(!init_owned.ptr.is_null());
    }

    /// Tests the `deref` implementation for `Owned`.
    /// Verifies that the dereferenced pointer matches the original pointer.
    #[test]
    fn test_deref() {
        let uninit_owned: Owned<MaybeUninit<i32>, i32> =
            Owned::new_uninit();
        let init_ptr = uninit_owned.ptr;
        assert_eq!(
            uninit_owned.deref().ptr as *mut MaybeUninit<i32>,
            init_ptr as *mut MaybeUninit<i32>
        );
    }

    /// Tests the `drop` implementation for `Owned`.
    /// Ensures that dropping an uninitialized `Owned` instance does not cause a panic.
    #[test]
    fn test_drop() {
        let uninit_owned: Owned<MaybeUninit<i32>, i32> =
            Owned::new_uninit();
        drop(uninit_owned);
    }

    /// Tests that an `InitPtr` instance is correctly created and its pointer is not null.
    #[test]
    fn test_init_ptr() {
        let mut value: i32 = 42;
        let init_ptr = InitPtr { ptr: &mut value };
        assert!(!init_ptr.ptr.is_null());
        assert_eq!(unsafe { *init_ptr.ptr }, 42);
    }

    /// Tests the `deref` implementation for initialized `Owned`.
    /// Verifies that the dereferenced pointer matches the original pointer after initialization.
    #[test]
    fn test_deref_after_init() {
        let uninit_owned: Owned<MaybeUninit<i32>, i32> =
            Owned::new_uninit();
        let init_owned: Owned<i32> =
            unsafe { Owned::assume_init(uninit_owned) };
        let init_ptr = init_owned.ptr;
        assert_eq!(init_owned.deref().ptr, init_ptr);
    }

    /// Tests creating and initializing an `Owned` instance with a different type (f64).
    #[test]
    fn test_new_uninit_f64() {
        let uninit_owned: Owned<MaybeUninit<f64>, f64> =
            Owned::new_uninit();
        assert!(!uninit_owned.ptr.is_null());
    }

    /// Tests the `assume_init` function with a different type (f64).
    #[test]
    fn test_assume_init_f64() {
        let uninit_owned: Owned<MaybeUninit<f64>, f64> =
            Owned::new_uninit();
        let init_owned: Owned<f64> =
            unsafe { Owned::assume_init(uninit_owned) };
        assert!(!init_owned.ptr.is_null());
    }

    /// Tests the `deref` implementation for `Owned` with a different type (f64).
    #[test]
    fn test_deref_f64() {
        let uninit_owned: Owned<MaybeUninit<f64>, f64> =
            Owned::new_uninit();
        let init_ptr = uninit_owned.ptr;
        assert_eq!(
            uninit_owned.deref().ptr as *mut MaybeUninit<f64>,
            init_ptr as *mut MaybeUninit<f64>
        );
    }

    /// Tests the `drop` implementation for `Owned` with a different type (f64).
    #[test]
    fn test_drop_f64() {
        let uninit_owned: Owned<MaybeUninit<f64>, f64> =
            Owned::new_uninit();
        drop(uninit_owned);
    }
}
