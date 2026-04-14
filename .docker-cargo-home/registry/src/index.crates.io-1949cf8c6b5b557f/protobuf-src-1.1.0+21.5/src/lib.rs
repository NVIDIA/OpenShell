// Copyright Materialize, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License in the LICENSE file at the
// root of this repository, or online at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! [<img src="https://materialize.com/wp-content/uploads/2020/01/materialize_logo_primary.png" width=180 align=right>](https://materialize.com)
//! Build system integration with `libprotobuf`, the C++ implementation of
//! [Protocol Buffers], Google's data interchange format.
//!
//! # Maintainership
//!
//! This crate is maintained by [Materialize]. Contributions are encouraged:
//!
//! * [View source code](https://github.com/MaterializeInc/rust-protobuf-native/tree/master/src/protobuf-src)
//! * [Report an issue](https://github.com/MaterializeInc/rust-protobuf-native/issues/new/choose)
//! * [Submit a pull request](https://github.com/MaterializeInc/rust-protobuf-native/compare)
//!
//! # Details
//!
//! This crate builds a vendored copy of libprotobuf and protoc using Cargo's
//! support for custom build scripts. It is not intended for direct consumption,
//! but as a dependency for other crates that need libprotobuf or protoc
//! available, like [prost-build].
//!
//! protobuf-src is currently bundling protobuf [v3.19.1].
//!
//! To use this crate, declare a `dependency` or `dev-dependency` on
//! `protobuf-src`. Then, in the build script for your crate, the environment
//! variable `DEP_PROTOBUF_SRC_ROOT` will point to the directory in which the
//! bundled copy of protobuf has been installed. You can build and link another
//! C/C++ library against this copy of libprotobuf or generate Rust bindings and
//! link Rust code against this copy of libprotobuf.
//!
//! If you simply need to invoke the vendored protoc binary, [`protoc`] returns
//! the path to pass to [`std::process::Command`].
//!
//! [Materialize]: https://materialize.com
//! [Protocol Buffers]: https://developers.google.com/protocol-buffers
//! [v3.19.1]: https://github.com/protocolbuffers/protobuf/releases/tag/v3.19.1
//! [prost-build]: https://docs.rs/prost-build/latest/prost_build/

use std::path::PathBuf;

/// Returns the path to the vendored protoc binary.
pub fn protoc() -> PathBuf {
    PathBuf::from(env!("INSTALL_DIR"))
        .join("bin")
        .join("protoc")
}

/// Returns the path to the vendored include directory.
pub fn include() -> PathBuf {
    PathBuf::from(env!("INSTALL_DIR")).join("include")
}
