use std::process::Command;

fn main() {
    // On macOS, embed rpath entries for libkrun and libkrunfw so the binary
    // can find them at runtime without DYLD_LIBRARY_PATH.
    //
    // Background: navigator-gateway links against libkrun (a system cdylib
    // installed via Homebrew).  At runtime libkrun loads libkrunfw via dlopen.
    // The gateway crate's build.rs already emits link-search paths so the
    // *linker* can find the dylibs, but cargo:rustc-link-arg from a library
    // crate does NOT propagate to the final binary.  We must emit the rpath
    // flags from the binary crate's build.rs.
    #[cfg(target_os = "macos")]
    {
        for formula in &["libkrun", "libkrunfw"] {
            if let Some(lib_dir) = brew_lib_path(formula) {
                println!("cargo:rustc-link-arg=-Wl,-rpath,{lib_dir}");
            }
        }
    }
}

/// Ask Homebrew for the install prefix of a formula and return its `lib/` path.
#[cfg(target_os = "macos")]
fn brew_lib_path(formula: &str) -> Option<String> {
    let output = Command::new("brew")
        .args(["--prefix", formula])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if prefix.is_empty() {
        return None;
    }

    Some(format!("{prefix}/lib"))
}
