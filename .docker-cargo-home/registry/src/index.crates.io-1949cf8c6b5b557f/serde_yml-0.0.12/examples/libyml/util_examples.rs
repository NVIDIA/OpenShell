//! Examples for the `Owned` and `InitPtr` structs and their methods in the `util` module.
//!
//! This file demonstrates the creation, usage, and safety considerations of `Owned` and `InitPtr` instances,
//! as well as the usage of their various methods.

use serde_yml::libyml::util::{InitPtr, Owned};
use std::mem::MaybeUninit;
use std::ops::Deref;

pub(crate) fn main() {
    // Print a message to indicate the file being executed.
    println!("\n❯ Executing examples/libyml/util_examples.rs");

    // Example: Creating a new uninitialized Owned instance
    let uninit_owned: Owned<MaybeUninit<i32>, i32> =
        Owned::new_uninit();
    println!(
        "\n✅ Created a new uninitialized Owned instance: {:?}",
        uninit_owned
    );

    // Example: Converting an uninitialized Owned instance to an initialized one
    let init_owned: Owned<i32> =
        unsafe { Owned::assume_init(uninit_owned) };
    println!(
        "\n✅ Converted to an initialized Owned instance: {:?}",
        init_owned
    );

    // Example: Dereferencing an Owned instance
    let init_ptr = init_owned.deref().ptr;
    println!(
        "\n✅ Dereferenced the Owned instance to get the InitPtr: {:?}",
        init_ptr
    );

    // Example: Creating an InitPtr instance
    let mut value: i32 = 42;
    let init_ptr = InitPtr { ptr: &mut value };
    println!(
        "\n✅ Created an InitPtr instance: {:?} with value: {}",
        init_ptr,
        unsafe { *init_ptr.ptr }
    );

    // Example: Using the Drop implementation
    {
        let drop_owned: Owned<MaybeUninit<i32>, i32> =
            Owned::new_uninit();
        println!(
            "\n✅ Created a new Owned instance to be dropped: {:?}",
            drop_owned
        );
    } // drop_owned goes out of scope here, and memory is deallocated.

    // Example: Creating Owned instances with different types
    let uninit_owned_f64: Owned<MaybeUninit<f64>, f64> =
        Owned::new_uninit();
    println!(
        "\n✅ Created a new uninitialized Owned<f64> instance: {:?}",
        uninit_owned_f64
    );
    let init_owned_f64: Owned<f64> =
        unsafe { Owned::assume_init(uninit_owned_f64) };
    println!(
        "\n✅ Converted to an initialized Owned<f64> instance: {:?}",
        init_owned_f64
    );
}
