# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to [Semantic
Versioning].

<!-- #release:next-header -->

## [Unreleased] <!-- #release:date -->

## [1.1.0] - 2022-09-02

* Upgrade to libprotobuf v21.5.

## [1.0.5+3.19.3] - 2022-01-28

* Upgrade to libprotobuf v3.19.3.

## [1.0.4+3.19.1] - 2022-01-18

* Don't fail to build if `$OUTDIR/build` already exists, which can happen with
  repeated `cargo build` commands.

## [1.0.3+3.19.1] - 2022-01-18

* Don't fail to build if `$OUTDIR/install` already exists, which can happen
  with repeated `cargo build` commands.

## [1.0.2+3.19.1] - 2022-01-18

* Patch the vendored copy of `libprotobuf` with [protocolbuffers/protobuf#9344]
  to fix programmatic access to parser warnings.

* Install `libprotobuf` to `$OUTDIR/install` rather than `$OUTDIR` directly.
  This makes it easier for build tools downstream of Cargo to extract the
  compiled artifacts without the build artifacts.

## [1.0.1+3.19.1] - 2021-12-23

* Correct the documentation and repository links in the crate metadata.

## [1.0.0+3.19.1] - 2021-12-22

* Expose `protoc` and `include` functions to retrieve the path to the vendored
  protoc binary and include directory, respectively.

## 0.1.0+3.19.1 - 2021-12-22

Initial release.

<!-- #release:next-url -->
[Unreleased]: https://github.com/MaterializeInc/rust-protobuf-native/compare/protobuf-src-v1.1.0...HEAD
[1.1.0]: https://github.com/MaterializeInc/rust-protobuf-native/compare/protobuf-src-v1.0.5+3.19.3...protobuf-src-v1.1.0
[1.0.5+3.19.3]: https://github.com/MaterializeInc/rust-protobuf-native/compare/protobuf-src-v1.0.4+3.19.1...protobuf-src-v1.0.5+3.19.3
[1.0.4+3.19.1]: https://github.com/MaterializeInc/rust-protobuf-native/compare/protobuf-src-v1.0.3+3.19.1...protobuf-src-v1.0.4+3.19.1
[1.0.3+3.19.1]: https://github.com/MaterializeInc/rust-protobuf-native/compare/protobuf-src-v1.0.2+3.19.1...protobuf-src-v1.0.3+3.19.1
[1.0.2+3.19.1]: https://github.com/MaterializeInc/rust-protobuf-native/compare/protobuf-src-v1.0.1+3.19.1...protobuf-src-v1.0.2+3.19.1
[1.0.1+3.19.1]: https://github.com/MaterializeInc/rust-protobuf-native/compare/protobuf-src-v1.0.0+3.19.1...protobuf-src-v1.0.1+3.19.1
[1.0.0+3.19.1]: https://github.com/MaterializeInc/rust-protobuf-native/compare/protobuf-src-v0.1.0+3.19.1...protobuf-src-v1.0.0+3.19.1

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[protocolbuffers/protobuf#9344]: https://github.com/protocolbuffers/protobuf/pull/9344
