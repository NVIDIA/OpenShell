//! This build script checks if the current Rustc version is at least the
//! minimum required version.
//! If the current Rustc version is less than the minimum required version,
//! the build script will exit the build process with a non-zero exit code.
//!
//! The minimum required version is specified in the `min_version` variable.

use std::process;

/// Checks if the current Rustc version is at least the minimum required version
///
/// # Arguments
///
/// * `min_version` - The minimum required Rustc version as a string.
///
/// # Returns
///
/// * `Some(true)` - If the current Rustc version is at least the minimum
///    required version.
/// * `Some(false)` - If the current Rustc version is less than the minimum
///    required version.
/// * `None` - If the current Rustc version cannot be determined.
///
/// # Errors
///
/// This function will exit the build process with a non-zero exit code if the
/// current Rustc version is less than the minimum required version.
///
/// # Examples
///
/// ```rust
/// let min_version = "1.56";
///
/// match version_check::is_min_version(min_version) {
///     Some(true) => println!("Rustc version is at least {}", min_version),
///     Some(false) => {
///         eprintln!("Rustc version is less than {}", min_version);
///         process::exit(1);
///     }
///     None => {
///         eprintln!("Unable to determine Rustc version");
///         process::exit(1);
///     }
/// }
/// ```
fn main() {
    let min_version = "1.56";

    match version_check::is_min_version(min_version) {
        Some(true) => {}
        _ => {
            eprintln!("'fd' requires Rustc version >= {}", min_version);
            process::exit(1);
        }
    }
}
