# `supports-hyperlinks` Release Changelog

<a name="3.2.0"></a>

## 3.2.0 (2025-12-17)

### Features

- **term:** detect Zed's intergrated terminal (#8) ([cc8e2187](https://github.com/zkat/supports-hyperlinks/commit/cc8e21877059098549ce9351ec928bcfdfd32648))

<a name="3.1.0"></a>

## 3.1.0 (2024-11-26)

### Features

- **term_programs:** add ghostty as a supported terminal (#5) ([cd892367](https://github.com/zkat/supports-hyperlinks/commit/cd8923675fb77ee336b0c5b7f7f851851a2a6b5c))

### Bug Fixes

- **crates.io:** 'terminal' is not a valid category ([130c715d](https://github.com/zkat/supports-hyperlinks/commit/130c715ddd8fdc047a5e63f2b1f7734ca72f6b51))

<a name="3.0.0"></a>

## 3.0.0 (2024-02-04)

### Features

- **deps:** Use `std::io::IsTerminal` instead of `is-terminal`. (#4) ([fb84fe60](https://github.com/zkat/supports-hyperlinks/commit/fb84fe60224e82cd7da5f16e8ae6ccc577e980f4))
  - **BREAKING CHANGE**: This bumps the MSRV to 1.70.0

<a name="2.1.0"></a>

## 2.1.0 (2023-04-18)

### Features

- **terms:** add support for a couple more terminals ([0a7728c5](https://github.com/zkat/supports-hyperlinks/commit/0a7728c5b2d67a7bb52d497c2ce567a2d496d9db))

### Miscellaneous Tasks

- **edition:** bump edition to 2021 ([5cd860b1](https://github.com/zkat/supports-hyperlinks/commit/5cd860b1c36ebc0820ad66bf5736609f83365830))

<a name="2.0.0"></a>

## 2.0.0 (2023-03-13)

This semver-major release is just for switching away from `atty` due to
soundness and maintenance concerns. See [this issue in `supports-color` for
more details](https://github.com/zkat/supports-color/issues/9)

### Features

- **tty:** Switch from `atty` to `is-terminal` (#3) ([a321f355](https://github.com/zkat/supports-hyperlinks/commit/a321f35558f9dcb47d225c25e74d8c0d911bbaa8))
  - **BREAKING CHANGE**: the exported `Stream` enum is no longer an `atty` type, and this crate no longer accepts `atty` types as input.

<a name="1.2.0"></a>

## 1.2.0 (2021-09-16)

### Bug Fixes

- **conditions:** allow fallthrough when nested checks are false ([3aa5ffbb](https://github.com/zkat/supports-hyperlinks/commit/3aa5ffbba5bd1c902864f4fa4f3f9bbd0c0bcb0b))

### Features

- **force:** add support for forcing hyperlinks ([96d75a7c](https://github.com/zkat/supports-hyperlinks/commit/96d75a7ce7bac6a6fd3f7630eb0579750d4ebb82))

<a name="1.1.0"></a>

## 1.1.0 (2021-09-11)

### Features

- **on:** add atty and on() function for ease of use ([bf17421f](https://github.com/zkat/supports-hyperlinks/commit/bf17421f14791ab6308d209c5c0eda72081bd664))

<a name="1.0.0"></a>

## 1.0.0 (2021-09-11)

### Features

- **api:** initial commit ([4eb64a5b](https://github.com/zkat/supports-hyperlinks/commit/4eb64a5b67ff913ce269077e01f430d45a5aa40d))
