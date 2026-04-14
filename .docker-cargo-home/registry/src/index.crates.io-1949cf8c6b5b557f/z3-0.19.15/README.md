# z3

[![](https://img.shields.io/crates/v/z3.svg)](https://crates.io/crates/z3)

High-level rust bindings to the Z3 SMT solver

Licensed under the MIT license.

See [https://github.com/Z3Prover/z3](https://github.com/Z3Prover/z3) for details on Z3.

## Documentation

The API is fully documented with examples:
[https://docs.rs/z3/](https://docs.rs/z3/)

## Installation

This crate works with Cargo and is on
[crates.io](https://crates.io/crates/z3).
Add it to your project with `cargo add`:

```bash 
$ cargo add z3
```

### Finding Z3 Libraries

**Note:** This library has a dependency on Z3.

There are 4 ways for this crate to currently find Z3, controlled by the feature
flags `bundled`, `vcpkg` and `gh-release`.

This might look like:

```toml
[dependencies]
z3 = {version="0", features = ["gh-release"]}
```

or:

```toml
[dependencies]
z3 = {version="0", features = ["vcpkg"]}
```

#### 1. Default: System-installed Z3

By default, cargo will look for a system-installed copy of Z3.
On Linux, this would be via the package manager. On macOS, this
might be via Homebrew (`brew install z3`).

If installed with Homebrew, cargo may be unable to find the Z3 headers. In this
case set the `Z3_SYS_Z3_HEADER` environment variable to your copy of the `z3.h`
file. On Apple Silicon, this will typically be `/opt/homebrew/include/z3.h`:

```bash
Z3_SYS_Z3_HEADER=/opt/homebrew/include/z3.h cargo build
```

You may further have to set `Z3_LIBRARY_PATH_OVERRIDE` to `/opt/homebrew/lib` for the linker
to find the Z3 library. You can store these settings in the cargo configuration
file `.cargo/config.toml` of your project as follows: 

```toml
[env]
Z3_LIBRARY_PATH_OVERRIDE = "/opt/homebrew/lib"
Z3_SYS_Z3_HEADER = "/opt/homebrew/include/z3.h"
```


#### 2. Bundled: Build Z3 from source

Enabling the `bundled` feature will use `cmake` to build and statically
link Z3 from source. Despite the name, **Z3 source is not included in the
crate tarball**. On a first build from crates.io, the build script queries
the GitHub Contents API to find which Z3 commit the `z3-sys` submodule
pointed to at release time (via the `z3-sys-vX.Y.Z` git tag), then downloads
and extracts that Z3 source archive. The result is cached in Cargo's build
output directory and reused until `cargo clean`.

**Using your own Z3 checkout:** Set `Z3_SYS_BUNDLED_DIR_OVERRIDE` to the
**absolute path** of a Z3 source tree:

```bash
Z3_SYS_BUNDLED_DIR_OVERRIDE=/absolute/path/to/z3 cargo build
```

To use a path relative to your project root, add the following to your
project's `.cargo/config.toml`. The `relative = true` key tells Cargo to
resolve the path relative to the config file's location rather than as an
absolute path:

```toml
[env]
Z3_SYS_BUNDLED_DIR_OVERRIDE = { value = "path/to/z3", relative = true }
```

**Note:** A `z3` directory in your own project or workspace is **not**
picked up automatically. Even if you have a Z3 git submodule in your repo,
you must point `Z3_SYS_BUNDLED_DIR_OVERRIDE` at it explicitly.

**Pinning a Z3 version without a source checkout:** The `gh-release` feature
(see below) lets you pin a specific Z3 version via `Z3_SYS_Z3_VERSION`
without managing a source tree yourself.

#### 3. VCPKG: Use a copy of Z3 installed via vcpkg

Enabling the `vcpkg` feature will use `vcpkg` to build and
install a copy of Z3 which is then used.

#### 4. GitHub Release: Use a pre-compiled copy of Z3

Enabling the `gh-release` feature will download a pre-compiled
copy of Z3 from the GitHub release page for the current platform,
if available. You may specify the version of Z3 to download via the
`Z3_SYS_Z3_VERSION` environment variable.

## Support and Maintenance

I am developing this library largely on my own so far. I am able
to offer support and maintenance, but would very much appreciate
donations via [Patreon](https://patreon.com/endoli). I can also
provide commercial support, so feel free to
[contact me](mailto:bruce.mitchener@gmail.com).

## Contribution

Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in the work by you,
shall be dual licensed as above, without any additional
terms or conditions.
