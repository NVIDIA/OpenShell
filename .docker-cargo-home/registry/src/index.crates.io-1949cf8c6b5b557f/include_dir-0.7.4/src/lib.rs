//! An extension to the `include_str!()` and `include_bytes!()` macro for
//! embedding an entire directory tree into your binary.
//!
//! # Environment Variables
//!
//! When invoking the [`include_dir!()`] macro you should try to avoid using
//! relative paths because `rustc` makes no guarantees about the current
//! directory when it is running a procedural macro.
//!
//! Environment variable interpolation can be used to remedy this. You might
//! want to read the [*Environment Variables*][cargo-vars] section of *The
//! Cargo Book* for a list of variables provided by `cargo`.
//!
//! Most crates will want to use the `$CARGO_MANIFEST_DIR` or `$OUT_DIR`
//! variables. For example, to include a folder relative to your crate you might
//! use `include_dir!("$CARGO_MANIFEST_DIR/assets")`.
//!
//! # Examples
//!
//! Here is an example that embeds the `include_dir` crate's source code in a
//! `static` so we can play around with it.
//!
//! ```rust
//! use include_dir::{include_dir, Dir};
//! use std::path::Path;
//!
//! static PROJECT_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR");
//!
//! // of course, you can retrieve a file by its full path
//! let lib_rs = PROJECT_DIR.get_file("src/lib.rs").unwrap();
//!
//! // you can also inspect the file's contents
//! let body = lib_rs.contents_utf8().unwrap();
//! assert!(body.contains("SOME_INTERESTING_STRING"));
//!
//! // if you enable the `glob` feature, you can for files (and directories) using glob patterns
//! #[cfg(feature = "glob")]
//! {
//!     let glob = "**/*.rs";
//!     for entry in PROJECT_DIR.find(glob).unwrap() {
//!         println!("Found {}", entry.path().display());
//!     }
//! }
//! ```
//!
//! # Features
//!
//! This library exposes a couple feature flags for enabling and disabling extra
//! functionality. These are:
//!
//! - `glob` - search for files using glob patterns
//! - `metadata` - include some basic filesystem metadata like last modified
//!   time. This is not enabled by default to allow for more reproducible builds
//!   and to hide potentially identifying information.
//! - `nightly` - enables nightly APIs like [`track_path`][track-path]
//!   and  [`proc_macro_tracked_env`][tracked-env]. This gives the compiler
//!   more information about what is accessed by the procedural macro, enabling
//!   better caching. **Functionality behind this feature flag is unstable and
//!   may change or stop compiling at any time.**
//!
//! # Compile Time Considerations
//!
//! While the `include_dir!()` macro executes relatively quickly, it expands
//! to a fairly large amount of code (all your files are essentially embedded
//! as Rust byte strings) and this may have a flow-on effect on the build
//! process.
//!
//! In particular, including a large number or files or files which are
//! particularly big may cause the compiler to use large amounts of RAM or spend
//! a long time parsing your crate.
//!
//! As one data point, this crate's `target/` directory contained 620 files with
//! a total of 64 MB, with a full build taking about 1.5 seconds and 200MB of
//! RAM to generate a 7MB binary.
//!
//! Using `include_dir!("target/")` increased the compile time to 5 seconds
//! and used 730MB of RAM, generating a 72MB binary.
//!
//! [tracked-env]: https://github.com/rust-lang/rust/issues/74690
//! [track-path]: https://github.com/rust-lang/rust/issues/73921
//! [cargo-vars]: https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-crates

#![deny(
    elided_lifetimes_in_paths,
    future_incompatible,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms
)]
#![cfg_attr(feature = "nightly", feature(doc_cfg))]

mod dir;
mod dir_entry;
mod file;

#[cfg(feature = "metadata")]
mod metadata;

#[cfg(feature = "glob")]
mod globs;

#[cfg(feature = "metadata")]
pub use crate::metadata::Metadata;

pub use crate::{dir::Dir, dir_entry::DirEntry, file::File};
pub use include_dir_macros::include_dir;

#[doc = include_str!("../README.md")]
#[allow(dead_code)]
fn check_readme_examples() {}
