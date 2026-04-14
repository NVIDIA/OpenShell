# `supports-unicode` Release Changelog

<a name="3.0.0"></a>
## 3.0.0 (2024-02-04)

### Features

* **deps:** Switch to std::io::IsTerminal (#5) ([e286df87](https://github.com/zkat/supports-unicode/commit/e286df87e0df4d611bae9565941a0de9eccd9986))
    * **BREAKING CHANGE**: This bumps the MSRV to 1.70.0 in order to use `std::io::IsTerminal` directly.

<a name="2.1.0"></a>
## 2.1.0 (2024-01-19)

### Features

* **env:** Provide direct access to env introspection (#6) ([88f56c71](https://github.com/zkat/supports-unicode/commit/88f56c71811eadc59270f7705122d1e16bac5a22))

<a name="2.0.0"></a>
## 2.0.0 (2023-03-14)

This semver-major release is just for switching away from `atty` due to
soundness and maintenance concerns. See [this issue in `supports-color` for
more details](https://github.com/zkat/supports-color/issues/9)

### Features

* **tty:** Switch from `atty` to `is-terminal` (#4) ([86bf7583](https://github.com/zkat/supports-unicode/commit/86bf758334e8698784045fc92786039a76eefb1c))
    * **BREAKING CHANGE**: the exported `Stream` enum is no longer an `atty` type, and this crate no longer accepts `atty` types as input.

<a name="1.0.2"></a>
## 1.0.2 (2021-09-27)

### Bug Fixes

* **linux:** Ignore case when detecting UTF-8 locales. (#1) ([38082d27](https://github.com/zkat/supports-unicode/commit/38082d27b13c6c3289cc126babeb8b20e2f72d3b))

<a name="1.0.1"></a>
## 1.0.1 (2021-09-11)

### Bug Fixes

* **cargo:** fix stuff in cargo.toml ([bcabb6ab](https://github.com/zkat/supports-unicode/commit/bcabb6ab3540e8cd3ce8cf8de51c00fe531936fe))

<a name="1.0.0"></a>
## 1.0.0 (2021-09-11)

### Features

* **api:** initial commit ([0b57e63a](https://github.com/zkat/supports-unicode/commit/0b57e63a443d4aab57ecf24868394e0d06984465))
