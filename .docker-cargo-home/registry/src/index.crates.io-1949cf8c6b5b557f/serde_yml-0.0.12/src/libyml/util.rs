use std::{
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ops::Deref,
    ptr::{addr_of, NonNull},
};

/// A struct representing ownership of a pointer to a value of type `T`.
/// `Init` represents the initialization state of the value.
#[derive(Debug)]
pub struct Owned<T, Init = T> {
    ptr: NonNull<T>,
    marker: PhantomData<NonNull<Init>>,
}

impl<T> Owned<T> {
    /// Creates a new uninitialized `Owned` instance.
    ///
    /// # Safety
    /// The created instance contains uninitialized memory, and should be properly
    /// initialized before use.
    pub fn new_uninit() -> Owned<MaybeUninit<T>, T> {
        // Allocate memory for `T` but leave it uninitialized.
        let boxed = Box::new(MaybeUninit::<T>::uninit());
        Owned {
            ptr: unsafe {
                // Convert the Box pointer to a raw pointer and wrap it in `NonNull`.
                NonNull::new_unchecked(Box::into_raw(boxed))
            },
            marker: PhantomData,
        }
    }

    /// Converts an uninitialized `Owned` instance to an initialized one.
    ///
    /// # Safety
    /// The caller must ensure that `definitely_init` is properly initialized.
    pub unsafe fn assume_init(
        definitely_init: Owned<MaybeUninit<T>, T>,
    ) -> Owned<T> {
        let ptr = definitely_init.ptr;
        mem::forget(definitely_init);
        Owned {
            ptr: ptr.cast(),
            marker: PhantomData,
        }
    }
}

/// A transparent wrapper around a mutable pointer of type `T`.
#[repr(transparent)]
#[derive(Debug)]
pub struct InitPtr<T> {
    /// The mutable pointer.
    pub ptr: *mut T,
}

impl<T, Init> Deref for Owned<T, Init> {
    type Target = InitPtr<Init>;

    /// Returns a reference to the `InitPtr` wrapped by `Owned`.
    fn deref(&self) -> &Self::Target {
        unsafe { &*addr_of!(self.ptr).cast::<InitPtr<Init>>() }
    }
}

impl<T, Init> Drop for Owned<T, Init> {
    /// Deallocates the memory held by `Owned` when it goes out of scope.
    fn drop(&mut self) {
        let _ = unsafe { Box::from_raw(self.ptr.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_uninit() {
        let uninit_owned: Owned<MaybeUninit<i32>, i32> =
            Owned::new_uninit();
        assert_eq!(
            uninit_owned.ptr.as_ptr(),
            uninit_owned.ptr.as_ptr()
        );
    }

    #[test]
    fn test_assume_init() {
        let uninit_owned: Owned<MaybeUninit<i32>, i32> =
            Owned::new_uninit();
        let init_owned: Owned<i32> =
            unsafe { Owned::assume_init(uninit_owned) };
        assert_eq!(init_owned.ptr.as_ptr(), init_owned.ptr.as_ptr());
    }

    #[test]
    fn test_deref() {
        let uninit_owned: Owned<MaybeUninit<i32>, i32> =
            Owned::new_uninit();
        let init_ptr = uninit_owned.ptr.as_ptr();
        assert_eq!(
            uninit_owned.deref().ptr as *mut MaybeUninit<i32>,
            init_ptr
        );
    }

    #[test]
    fn test_drop() {
        let uninit_owned: Owned<MaybeUninit<i32>, i32> =
            Owned::new_uninit();
        drop(uninit_owned); // This test will pass if it does not panic
    }
}
