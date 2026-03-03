use std::process::Command;

fn main() {
    // Tell cargo to link against libkrun (the system dynamic library).
    // On macOS this expects libkrun.dylib to be findable by the linker.
    println!("cargo:rustc-link-lib=dylib=krun");

    // Discover Homebrew install prefixes for libkrun and libkrunfw.
    // We need both:
    //   - link-search: so the *linker* can find the .dylib at build time
    //   - link-arg -rpath: so the *dynamic linker* (dyld) can find them at runtime
    //
    // Without the rpath entries, the binary would require DYLD_LIBRARY_PATH
    // to be set, which is fragile and easy to forget.

    for formula in &["libkrun", "libkrunfw"] {
        if let Some(lib_dir) = brew_lib_path(formula) {
            println!("cargo:rustc-link-search=native={lib_dir}");
            // NOTE: cargo:rustc-link-arg from a *library* crate does NOT
            // propagate to the final binary.  The rpath is set in
            // navigator-cli's build.rs instead.
        }
    }
}

/// Ask Homebrew for the install prefix of a formula and return its `lib/` path.
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
