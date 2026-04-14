# autotools/configure&make support for build.rs

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![dependency status](https://deps.rs/repo/github/lu-zero/autotools-rs/status.svg)](https://deps.rs/repo/github/lu-zero/autotools-rs)
[![crates.io](https://img.shields.io/crates/v/autotools.svg?style=flat)](https://crates.io/crates/autotools)
[![docs.rs](https://docs.rs/autotools/badge.svg)](https://docs.rs/autotools)
[![Actions Status](https://github.com/lu-zero/autotools-rs/workflows/autotools-rs-compact/badge.svg)](https://github.com/lu-zero/autotools-rs/actions)


A build dependency to compile a native library that uses [autotools][1] or
a compatible `configure` script + `make`.

It is based on [cmake-rs](https://github.com/alexcrichton/cmake-rs) and
the API tries to be as similar as possible to it.

## Autotools concern
The generated `configure` script that is often bundled in release tarballs tends to be fairly big, convoluted and at least once has been a vector for
delivering malicious code ([CVE-2024-3094][cve-xz].

It is advised to review `configure.ac` and always regenerate `configure` using [`reconf`][reconf].

[cve-xz]: https://nvd.nist.gov/vuln/detail/CVE-2024-3094
[reconf]: https://docs.rs/autotools/latest/autotools/struct.Config.html#method.reconf

## Cross compiling

### Emscripten
For Emscripten targets like "wasm32-unknown-emscripten", `configure` and
`make` invocations are passed as arguments to `emconfigure` and `emmake`
respectively as described in the [Emscripten docs](https://emscripten.org/docs/compiling/Building-Projects.html#integrating-with-a-build-system).

### Custom LLVM on macOS
Make sure to set the env to `CC=clang-{version}` and that the compiler is in the `PATH`. If you are using [install-llvm-action](https://github.com/KyleMayes/install-llvm-action),
make sure to set [`env: true`](https://github.com/KyleMayes/install-llvm-action#env).

### Other compilers
Keep in mind that we rely on `cc-rs` heuristics to select the C and C++ compilers. Some may be missing on your system, please make sure to set
the [enviroment variables](https://github.com/rust-lang/cc-rs#external-configuration-via-environment-variables) to select the correct compiler if
the heuristics fail (e.g. `musl-gcc` might not exist while `x86_64-linux-musl-gcc` does).



``` toml
# Cargo.toml
[build-dependencies]
autotools = "0.2"
```

``` rust
// build.rs
use autotools;

// Build the project in the path `foo` and installs it in `$OUT_DIR`
let dst = autotools::build("foo");

// Simply link the library without using pkg-config
println!("cargo:rustc-link-search=native={}", dst.display());
println!("cargo:rustc-link-lib=static=foo");
```

``` rust
// build.rs
use autotools::Config;

let dst = Config::new("foo")
    .reconf("-ivf")
    .enable("feature", None)
    .with("dep", None)
    .disable("otherfeature", None)
    .without("otherdep", None)
    .cflag("-Wall")
    .build();
```

[1]: https://www.gnu.org/software/autoconf/autoconf.html
